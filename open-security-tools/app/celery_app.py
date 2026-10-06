"""
Celery application configuration for async tool execution.
"""

from celery import Celery
from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Create Celery instance
celery_app = Celery(
    'wildbox_tools',
    broker=settings.redis_url,
    backend=settings.redis_url
)

# How long the broker keeps a task for the worker that took it before it
# gives the task to another (#743). With task_acks_late a task is
# acknowledged when it ends, so a worker that is killed whole (`docker kill`,
# the kernel's out-of-memory killer on the container, a host that goes down)
# leaves the tasks it was running unacknowledged: they are in Redis, in the
# transport's `unacked` hash, not in the queue, and their stored state stays
# "running". Measured with a worker killed by SIGKILL while it ran a task:
# nothing returns the task while no worker runs; a worker looks for such
# tasks when it starts and every hundred seconds after that (kombu's
# restore_visible), and puts back on the queue those taken longer ago than
# this timeout. So a task held by a killed worker starts again between this
# long and this long plus a hundred seconds after it was first taken,
# provided a worker is running then; a worker restarted at once finds the
# task too young and leaves it for a later look.
#
# It is the Redis transport's default, written here so that it is a setting
# of this service and not of a library version. It must stay longer than a
# task can be held by a live worker, or the broker hands a task that is
# still running to a second worker: a retry waits up to retry_backoff_max
# (600 s, app/tasks.py) in the worker's memory and then runs for up to
# task_time_limit (600 s). A tools test fails if it is not.
VISIBILITY_TIMEOUT_SECONDS = 3600

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,  # 10 minutes hard limit
    task_soft_time_limit=540,  # 9 minutes soft limit
    worker_prefetch_multiplier=1,  # One task at a time per worker
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks (prevent memory leaks)
    result_expires=3600,  # Results expire after 1 hour
    task_acks_late=True,  # Acknowledge task after completion
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    broker_transport_options={'visibility_timeout': VISIBILITY_TIMEOUT_SECONDS},
    # Auto-discover tasks
    imports=('app.tasks',),
)

# Task routing (disabled for now - using default 'celery' queue)
# Future enhancement: categorize tools by priority
# celery_app.conf.task_routes = {
#     'app.tasks.execute_tool_async': {'queue': 'tools'},
#     'app.tasks.execute_tool_async_high_priority': {'queue': 'tools_priority'},
# }

logger.info("Celery app configured", extra={
    "broker": settings.redis_url,
    "backend": settings.redis_url
})
