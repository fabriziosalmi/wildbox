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
