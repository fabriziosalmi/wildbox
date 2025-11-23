"""
Celery worker for Open Security Agents

Handles asynchronous AI-powered threat analysis tasks.
"""

import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any

from celery import Celery
import redis

from .config import settings
from .agents.threat_enrichment_agent import threat_enrichment_agent

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
def run_threat_enrichment_task(self, task_id: str, ioc: Dict[str, Any]) -> Dict[str, Any]:
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
        
    Returns:
        Complete analysis result dictionary
    """
    
    try:
        logger.info(f"Starting threat enrichment task {task_id} for IOC {ioc['type']}:{ioc['value']}")
        
        # Update task status to running
        self.update_state(
            state="STARTED",
            meta={"progress": "Initializing AI agent..."}
        )
        
        # Update Redis with task status
        redis_client.setex(
            f"task:{task_id}:status", 
            settings.task_result_expires,
            "running"
        )
        
        # Run the AI analysis (we need to handle async in sync context)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Update progress
            self.update_state(
                state="STARTED",
                meta={"progress": "Running AI analysis..."}
            )
            
            # Execute the analysis
            result = loop.run_until_complete(
                threat_enrichment_agent.analyze_ioc(ioc)
            )
            
            # Set the task_id in the result
            result["task_id"] = task_id
            
            # Update Redis with completion
            redis_client.setex(
                f"task:{task_id}:status",
                settings.task_result_expires,
                "completed"
            )
            
            # Update stats
            redis_client.incr("stats:completed_today")
            
            logger.info(f"Completed threat enrichment task {task_id} - Verdict: {result.get('verdict', 'Unknown')}")
            
            return result
            
        finally:
            loop.close()
    
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Error in threat enrichment task {task_id}: {e}")
        
        # Update Redis with failure
        redis_client.setex(
            f"task:{task_id}:status",
            settings.task_result_expires,
            "failed"
        )
        
        # Update stats
        redis_client.incr("stats:failed_today")
        
        # Update task state
        self.update_state(
            state="FAILURE",
            meta={"error": str(e)}
        )
        
        # Return error result
        return {
            "task_id": task_id,
            "ioc": ioc,
            "verdict": "Informational",
            "confidence": 0.0,
            "executive_summary": f"Analysis failed: {str(e)}",
            "evidence": [],
            "recommended_actions": ["Retry analysis", "Check system configuration"],
            "full_report": f"# Analysis Failed\n\nThe analysis could not be completed due to an error:\n\n```\n{str(e)}\n```\n\nPlease check the system logs and try again.",
            "raw_data": {"error": str(e)},
            "analysis_duration": 0.0,
            "tools_used": []
        }


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
        agent_status = "healthy" if threat_enrichment_agent else "unhealthy"
        
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
