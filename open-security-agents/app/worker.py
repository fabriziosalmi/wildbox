"""
Celery worker for Open Security Agents

Handles asynchronous AI-powered threat analysis tasks.
"""

import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
import redis

from .config import settings
from .agents.threat_enrichment_agent import get_threat_enrichment_agent
from .failures import INTERNAL, NO_CALLER, NOT_CONFIGURED, TIMED_OUT, AnalysisFailed
from .stats import COMPLETED, FAILED, count_today
from .tools.wildbox_client import CallerIdentityUnavailable, caller_identity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "open-security-agents",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.worker"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.task_timeout,
    task_soft_time_limit=settings.task_timeout - 30,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    result_expires=settings.task_result_expires,
)

# Redis client for additional state management
redis_client = redis.from_url(settings.redis_url)


@celery_app.task(bind=True, name="run_threat_enrichment_task")
def run_threat_enrichment_task(
    self, task_id: str, ioc: Dict[str, Any], caller: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Main Celery task for AI-powered threat enrichment

    This task orchestrates the entire analysis process:
    1. Initialize the AI agent
    2. Run the analysis
    3. Generate structured report
    4. Update task status

    Args:
        task_id: Unique task identifier
        ioc: IOC dictionary with 'type' and 'value'
        caller: Gateway identity of the requesting user (user_id/team_id/role).
            Forwarded to downstream services so tool calls run with the user's
            real team scope instead of the legacy service key (#175).

    Returns:
        The analysis result: the report the model produced. A task that
        returns has a report; there is no other kind of result.

    Raises:
        CallerIdentityUnavailable: ``caller`` is missing or incomplete. The
            task is refused before any work, so no tool call is made (#594).
        AnalysisFailed: the analysis could not run or could not finish
            (app/failures.py). Like every other exception, it leaves the
            task FAILED, with the reason recorded for the API to show; it
            is never turned into a report (#717).
    """
    # The worker runs task after task in the same context. Each task sets the
    # identity from its own caller, or is refused, and the previous value is
    # restored when it ends however it ends, so one task's identity is never
    # what the next one's tool calls send (#594). It is set before the event
    # loop runs: the task wrapping the agent coroutine, and the tool calls it
    # gathers, copy the context they start from.
    try:
        with caller_identity(caller):
            return _run_threat_enrichment(self, task_id, ioc)
    except CallerIdentityUnavailable as e:
        logger.error(f"Threat enrichment task {task_id} has no identity to send: {e}")
        _record_failure(task_id, NO_CALLER)
        raise
    except AnalysisFailed as e:
        logger.error(
            f"Threat enrichment task {task_id} failed ({e.code}): "
            f"{type(e.__cause__).__name__ if e.__cause__ else e.reason}",
            exc_info=e.__cause__ is not None,
        )
        _record_failure(task_id, e.code)
        raise
    except SoftTimeLimitExceeded:
        logger.error(f"Threat enrichment task {task_id} reached its time limit")
        _record_failure(task_id, TIMED_OUT)
        raise
    except Exception:
        # Whatever it was, the task failed: it is recorded as failed and the
        # exception goes on to Celery, which records FAILURE. It used to be
        # caught for five builtin types and answered with a report (#717).
        logger.error(f"Threat enrichment task {task_id} failed", exc_info=True)
        _record_failure(task_id, INTERNAL)
        raise


def _record_failure(task_id: str, code: str) -> None:
    """Mark a task failed in Redis, with why, without masking the failure.

    ``code`` is one of app/failures.py's: the API shows its reason to the
    task's owner. Recording must not replace the exception that brought the
    task here, so a Redis error is logged and the caller raises its own.
    """
    try:
        redis_client.setex(
            f"task:{task_id}:status", settings.task_result_expires, "failed"
        )
        redis_client.setex(
            f"task:{task_id}:error", settings.task_result_expires, code
        )
        count_today(redis_client, FAILED)
    except Exception:
        logger.error(f"Could not record the failure of task {task_id}", exc_info=True)


def _run_threat_enrichment(task, task_id: str, ioc: Dict[str, Any]) -> Dict[str, Any]:
    """The body of run_threat_enrichment_task, run inside the caller's scope.

    Returns the report, or raises: the caller records the failure.
    """
    logger.info(f"Starting threat enrichment task {task_id} for IOC type: {ioc['type']}")

    # Update task status to running
    task.update_state(
        state="STARTED",
        meta={"progress": "Initializing AI agent..."}
    )

    # Update Redis with task status
    redis_client.setex(
        f"task:{task_id}:status",
        settings.task_result_expires,
        "running"
    )

    # Without a model key nothing can be analyzed. Say so, instead of
    # letting the first call to the model fail on its authentication.
    if not model_configured():
        raise AnalysisFailed(NOT_CONFIGURED)

    # Run the AI analysis (we need to handle async in sync context)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # Update progress
        task.update_state(
            state="STARTED",
            meta={"progress": "Running AI analysis..."}
        )

        # Execute the analysis
        result = loop.run_until_complete(
            get_threat_enrichment_agent().analyze_ioc(ioc)
        )
    finally:
        loop.close()

    # Set the task_id in the result
    result["task_id"] = task_id

    # Update Redis with completion
    redis_client.setex(
        f"task:{task_id}:status",
        settings.task_result_expires,
        "completed"
    )

    # Update stats
    count_today(redis_client, COMPLETED)

    logger.info(f"Completed threat enrichment task {task_id} - Verdict: {result.get('verdict', 'Unknown')}")

    return result


def model_configured() -> bool:
    """Whether a model API key is set (the template's placeholder is not one)."""
    key = (settings.anthropic_api_key or "").strip()
    return bool(key) and key != "your_anthropic_api_key_here"


@celery_app.task(name="health_check_task")
def health_check_task() -> Dict[str, Any]:
    """
    Health check task for monitoring
    
    Returns:
        Health status information
    """
    try:
        # Test Redis connection
        redis_client.ping()
        
        # Test AI agent initialization
        agent_status = "healthy" if settings.anthropic_api_key else "unhealthy"
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "redis": "healthy",
            "agent": agent_status
        }
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }


@celery_app.task(name="cleanup_expired_tasks")
def cleanup_expired_tasks() -> Dict[str, Any]:
    """
    Cleanup expired task data from Redis
    
    This task should be run periodically to clean up old task data.
    """
    try:
        # Find all task keys
        task_keys = redis_client.keys("task:*")
        
        cleaned_count = 0
        for key in task_keys:
            # Check if key is expired or very old
            ttl = redis_client.ttl(key)
            if ttl == -1:  # No expiration set
                redis_client.expire(key, settings.task_result_expires)
            elif ttl == -2:  # Key doesn't exist (race condition)
                continue
            elif ttl < 60:  # About to expire
                cleaned_count += 1
        
        return {
            "status": "completed",
            "cleaned_keys": cleaned_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        return {
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# Periodic task setup (if using celery beat)
celery_app.conf.beat_schedule = {
    "cleanup-expired-tasks": {
        "task": "cleanup_expired_tasks",
        "schedule": 3600.0,  # Run every hour
    },
}

if __name__ == "__main__":
    # For running the worker directly
    celery_app.start()
