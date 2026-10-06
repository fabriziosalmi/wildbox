"""
Celery worker for asynchronous CSPM scans
"""

import asyncio
import logging
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from celery import Celery, Task
from celery.signals import worker_ready, worker_shutting_down
import redis as redis_lib

from .config import settings
from .credential_crypto import decrypt_credentials
from . import providers
from .checks.runner import check_runner
from .checks.framework import CloudProvider, ScanReport
from . import schemas
from . import scan_store
from . import connections
from open_security_shared.log_safety import quiet_http_client_loggers

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format=settings.log_format
)
# With LOG_LEVEL=DEBUG, botocore logs each request it signs, session token
# of the scanned account included, and urllib3 each URL it calls. A worker
# makes no application, so it says here what the API process is told through
# its error handlers: those libraries log warnings and errors only (#755).
quiet_http_client_loggers()
logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "csmp-worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.worker"]
)

# Configure Celery
celery_app.conf.update(
    task_serializer=settings.celery_task_serializer,
    accept_content=settings.celery_accept_content,
    result_serializer=settings.celery_result_serializer,
    timezone=settings.celery_timezone,
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.scan_timeout_seconds,
    task_soft_time_limit=settings.scan_timeout_seconds - 60,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=100,
    # Explicit, and short: reports are stored by scan_store with their own
    # retention (CSPM_REPORT_RETENTION_DAYS), so nothing reads a finished
    # task's result for its report any more. Celery's default kept results
    # for a day, and the compliance pages lost every scan older than that
    # (#591). What the backend still serves is the state of queued and
    # running scans, which GET /api/v1/scans/{id} reports; twice the scan
    # time limit keeps that state for as long as a scan can run.
    result_expires=2 * settings.scan_timeout_seconds,
    # Redis hands an unacknowledged task to another worker once this many
    # seconds have passed since it was delivered. Tasks are acknowledged
    # late (task_acks_late, above), so with the default of an hour a scan
    # running close to SCAN_TIMEOUT_SECONDS would be started a second time.
    # Longer than the time limit, so that never happens.
    broker_transport_options={"visibility_timeout": settings.scan_timeout_seconds + 600},
)

# The queue each task is published to. cspm-worker consumes exactly these
# (its -Q in docker-compose.yml; a unit test compares the two), so no task
# is published to a queue nobody reads, which is what happened to every
# scan while the worker was commented out (#601). "celery" is the queue
# these tasks always went to without a route, so the scans an earlier
# release queued are consumed after an upgrade: their credentials have
# expired, and they end as failed instead of staying queued.
SCAN_QUEUE = "celery"
TASK_QUEUES = {
    SCAN_QUEUE: ("run_cspm_scan", "get_available_checks", "health_check"),
}
celery_app.conf.task_default_queue = SCAN_QUEUE
celery_app.conf.task_routes = {
    name: {"queue": queue} for queue, names in TASK_QUEUES.items() for name in names
}

# Redis holds the scan records (scan_store). from_url does not connect, so
# importing this module needs no Redis.
#
# With the limits the API's client has (app.connections): 2 seconds to open
# a connection, 3 for each reply. The worker's had none, so a Redis that
# accepts and never answers (a paused container, a host that stopped) held
# the scan's task where it was, for ever: at its first read, or at its last
# write with the account already scanned (#788). The worker's Celery clients
# keep Celery's own waits: its broker connection is the one it waits on for
# tasks.
redis_client = connections.redis_client(settings.redis_url)

# What the scan store's client raises when Redis cannot be reached or does
# not answer in time. Not the builtins: both derive from RedisError.
STORE_UNAVAILABLE = (
    redis_lib.exceptions.ConnectionError,
    redis_lib.exceptions.TimeoutError,
)

# A limit on the store's replies can fail the write that ends a scan: the
# report of an account scanned for an hour, lost to a Redis that was slow for
# three seconds, or restarting. So that write is made again, after each of
# these pauses, in seconds: four attempts, the last one 13 seconds after the
# first and, with a server that takes every reply to its limit, done within
# 25. Bounded: a store that stays away ends the task, it does not hold the
# worker.
FINAL_WRITE_PAUSES = (1.0, 3.0, 9.0)


class ScanReportNotStored(RuntimeError):
    """The scan ran to its end and the store did not take its report.

    No ``__init__`` of its own: Celery hands ``on_failure`` a copy made from
    the error's arguments, and for a class it cannot make that way the copy
    is of the nearest base class it can, a plain RuntimeError.
    """


REPORT_NOT_STORED_MESSAGE = (
    "The scan ran and its report could not be stored: the scan store did not "
    "answer."
)


def _pause(seconds: float) -> None:
    time.sleep(seconds)


def _write_the_end(write, scan_id: str, what: str):
    """Make the write that ends a scan, again after a pause for as long as
    the store does not answer and FINAL_WRITE_PAUSES has a pause left.

    Each attempt that fails is logged; the last one's error is the caller's.
    The write is scan_store's transaction on the scan's metadata, so one
    that is made again does no harm: when the first reached Redis and only
    its reply was lost, the second finds the scan already ended, and says
    so.
    """
    attempts = len(FINAL_WRITE_PAUSES) + 1
    for attempt, pause in enumerate((*FINAL_WRITE_PAUSES, None), start=1):
        try:
            return write()
        except STORE_UNAVAILABLE as error:
            if pause is None:
                logger.error(
                    "Scan %s: %s could not be written, attempt %d of %d (%s): "
                    "given up",
                    scan_id, what, attempt, attempts, type(error).__name__,
                )
                raise
            logger.warning(
                "Scan %s: %s could not be written, attempt %d of %d (%s): "
                "trying again in %.0f seconds",
                scan_id, what, attempt, attempts, type(error).__name__, pause,
            )
            _pause(pause)


class ScanTask(Task):
    """Marks the scan failed in its metadata, whatever made the task fail.

    The task's own except clause catches only some errors, and once the
    Celery result expires the stored status is the only record of the
    failure.

    A scan whose report the store did not take (ScanReportNotStored) fails
    with that reason in its metadata. Marking a scan failed is a last write
    too, made again like the other. When the store stays away for all of
    it, the scan's record still says that it is in progress: this says so,
    by its id, and the record expires with the retention like any other.
    """

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        reason = (
            scan_store.REPORT_NOT_STORED
            if isinstance(exc, ScanReportNotStored)
            else None
        )
        try:
            _write_the_end(
                lambda: scan_store.fail_scan(
                    redis_client, task_id, datetime.utcnow().isoformat(), reason
                ),
                task_id,
                "its failure",
            )
        except STORE_UNAVAILABLE as error:
            logger.error(
                "Scan %s failed and could not be marked failed (%s): its "
                "record says it is in progress until it expires, "
                "CSPM_REPORT_RETENTION_DAYS after it started",
                task_id, type(error).__name__,
            )
        except (redis_lib.RedisError, ValueError, TypeError) as error:
            logger.error(f"Could not mark scan {task_id} failed: {error}")


@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Called when worker is ready to receive tasks."""
    logger.info("CSPM Worker is ready to process scans")


@worker_shutting_down.connect
def worker_shutting_down_handler(sender=None, **kwargs):
    """Called when worker is shutting down."""
    logger.info("CSPM Worker is shutting down")


@celery_app.task(bind=True, base=ScanTask, name="run_cspm_scan")
def run_cspm_scan_task(
    self,
    scan_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Execute a CSPM scan asynchronously.
    
    Args:
        scan_config: Dictionary containing scan configuration:
            - provider: Cloud provider (one of app.providers.supported_providers())
            - credentials: Provider-specific credentials
            - account_id: Cloud account identifier
            - account_name: Optional friendly name
            - regions: Optional list of regions to scan
            - check_ids: Optional list of specific checks to run
            - metadata: Additional metadata for the scan
    
    Returns:
        Dictionary containing scan results and metadata
    """
    scan_id = self.request.id
    provider_str = scan_config["provider"]
    redis_worker = redis_client
    credential_ref = scan_config.get("credential_ref")

    # A scan cancelled before a worker took it is not run. Celery keeps a
    # revocation in the memory of the workers that were up when it was
    # sent: with none up, or after a restart, the task is delivered all
    # the same. DELETE had answered that the scan was cancelled, and the
    # account was then scanned (#766). The stored status is what says so
    # to every worker; the credentials go with it.
    metadata = scan_store.load_metadata(redis_worker, scan_id)
    if metadata is not None and metadata.get("status") == "cancelled":
        if credential_ref:
            redis_worker.delete(credential_ref)
        logger.info(f"CSPM scan {scan_id} was cancelled before it started; not run")
        return {"scan_id": scan_id, "status": "cancelled"}

    logger.info(f"Starting CSPM scan {scan_id} for {provider_str}")

    # Retrieve credentials from secure Redis reference (not from task args)
    if not credential_ref:
        raise ValueError("Missing credential reference in scan config")

    cred_data = redis_worker.get(credential_ref)
    if not cred_data:
        raise ValueError("Credentials expired or not found. Re-submit the scan.")

    # Credentials are encrypted at rest in Redis (WILDBO-SEC-02).
    credentials = decrypt_credentials(cred_data)
    # Delete credentials from Redis immediately after retrieval
    redis_worker.delete(credential_ref)

    try:
        # Validate provider
        try:
            provider = CloudProvider(provider_str)
        except ValueError:
            raise ValueError(f"Unsupported cloud provider: {provider_str}")

        # Create cloud session from retrieved credentials
        session = _create_cloud_session(provider, credentials)
        
        # Extract scan parameters
        account_id = scan_config["account_id"]
        account_name = scan_config.get("account_name")
        regions = scan_config.get("regions")
        check_ids = scan_config.get("check_ids")
        
        # Update task state
        self.update_state(
            state="PROGRESS",
            meta={
                "status": "initializing",
                "provider": provider_str,
                "account_id": account_id,
                "started_at": datetime.utcnow().isoformat()
            }
        )
        
        # Run the scan using asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            report = loop.run_until_complete(
                check_runner.run_scan(
                    provider=provider,
                    session=session,
                    account_id=account_id,
                    account_name=account_name,
                    regions=regions,
                    check_ids=check_ids,
                    scan_id=scan_id
                )
            )
        finally:
            loop.close()
        
        completed_at = datetime.utcnow().isoformat()

        # Store the report under the scan, with the retention its metadata
        # and its team index entry have, and mark the scan completed (#591).
        # The report is no longer part of the task's result: the result
        # backend keeps results for hours, and nothing reads reports there.
        report_data = report.model_dump(mode="json")
        try:
            stored = _write_the_end(
                lambda: scan_store.complete_scan(
                    redis_worker, scan_id, report_data, completed_at
                ),
                scan_id,
                "its report",
            )
        except STORE_UNAVAILABLE:
            # Not the store's error as it is: the task fails saying what
            # was lost, and ScanTask.on_failure records it with the scan.
            raise ScanReportNotStored(REPORT_NOT_STORED_MESSAGE) from None
        if not stored:
            # Cancelled while it ran, and the revocation did not stop this
            # process in time: the scan stays cancelled, as DELETE answered,
            # and its report is not kept. The task says what the store says.
            ended = (scan_store.load_metadata(redis_worker, scan_id) or {}).get("status")
            if ended in scan_store.FINAL_STATUSES and ended != "completed":
                logger.info(f"CSPM scan {scan_id} ran to its end but is {ended}; report not stored")
                return {"scan_id": scan_id, "status": ended}

        logger.info(
            f"CSMP scan {scan_id} completed: "
            f"{report.passed_checks} passed, {report.failed_checks} failed"
        )

        return {
            "scan_id": scan_id,
            "status": "completed",
            "provider": provider_str,
            "account_id": account_id,
            "completed_at": completed_at,
            "total_checks": report.total_checks,
            "failed_checks": report.failed_checks,
            "compliance_score": report.compliance_score,
        }

    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"CSPM scan {scan_id} failed: {e}", exc_info=True)

        # Fail the task with an error that carries no detail: the result
        # backend stores the exception, and the logged one may name the
        # account or the cause. This used to store a FAILURE state whose
        # meta was a plain dict, which Celery cannot read back as an
        # exception: GET /api/v1/scans/{id} answered 500 ("Exception
        # information must include the exception type") until the task's
        # own failure replaced it. ScanTask.on_failure marks the scan failed.
        raise RuntimeError("Scan failed. Check server logs for details.") from None


def _create_cloud_session(provider: CloudProvider, credentials: Dict[str, Any]):
    """Create a cloud provider session, with the factory app.providers registers.

    The API refuses scans of providers without one (#612); a scan queued
    before that check existed fails here.
    """
    return providers.create_session(provider, credentials)


@celery_app.task(name="get_available_checks")
def get_available_checks_task(provider: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Get available security checks.
    
    Args:
        provider: Optional provider filter
        
    Returns:
        List of available checks metadata
    """
    try:
        provider_enum = CloudProvider(provider) if provider else None
        return check_runner.get_available_checks(provider_enum)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to get available checks: {e}")
        raise


@celery_app.task(name="health_check")
def health_check_task() -> Dict[str, Any]:
    """Health check task for monitoring worker status."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "worker_id": f"{celery_app.control.inspect().stats()}",
        "available_providers": providers.supported_provider_ids()
    }


# Periodic tasks (if using celery-beat)
celery_app.conf.beat_schedule = {
    "health-check": {
        "task": "health_check",
        "schedule": 300.0,  # Every 5 minutes
    },
}


if __name__ == "__main__":
    # For running worker directly
    celery_app.start()
