"""
Celery configuration for Open Security Guardian
"""

import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'guardian.settings')

app = Celery('guardian')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Configure queue routing for specialized task handling
app.conf.task_routes = {
    'queue_management.tasks.*': {'queue': 'queue_management'},
    'vulnerability_scanning.*': {'queue': 'scanning'},
    'analytics.tasks.*': {'queue': 'analytics'},
    'reporting.tasks.*': {'queue': 'reporting'},
}

# Configure queue priorities
app.conf.task_default_queue = 'default'
app.conf.task_create_missing_queues = True

# Configure worker settings for better performance
app.conf.worker_prefetch_multiplier = 1
app.conf.task_acks_late = True
app.conf.worker_disable_rate_limits = False
app.conf.task_compression = 'gzip'
app.conf.result_compression = 'gzip'

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
