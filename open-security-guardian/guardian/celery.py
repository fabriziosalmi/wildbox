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

# The queue of every guardian task, by registered name (#545).
#
# The routes used to be globs such as 'reporting.tasks.*' while the tasks
# register as 'apps.reporting.tasks.*', so none matched and every task went
# to 'default'; two of them named modules that do not exist
# ('queue_management', 'analytics'). Each task is now listed by its real
# name, 'default' ones included, so adding a task means choosing its queue:
# tests/unit/test_celery_routing.py fails for a registered task missing
# here and for a name here that no task registers.
#
#   scanning   network-bound and slow (discovery, port scans): kept off the
#              queue that carries notifications and SLA checks
#   reporting  report generation and alert-rule evaluation
#   analytics  full recomputation of risk scores and compliance metrics
#   default    notifications, enrichment and the maintenance sweeps
#
# guardian-worker in docker-compose.yml consumes exactly these queues; the
# same test compares its -Q list with the keys below.
TASK_QUEUES = {
    'scanning': (
        'apps.assets.tasks.discover_assets',
        'apps.assets.tasks.execute_discovery_rule',
        'apps.assets.tasks.scan_asset_ports',
        'apps.vulnerabilities.tasks.scan_vulnerability_remediation',
    ),
    'reporting': (
        'apps.reporting.tasks.generate_report',
        'apps.reporting.tasks.update_report_metrics',
        'apps.reporting.tasks.check_alert_rule',
        'apps.reporting.tasks.check_all_alert_rules',
        'apps.reporting.tasks.cleanup_expired_reports',
        'apps.compliance.tasks.generate_compliance_report',
        'apps.vulnerabilities.tasks.generate_vulnerability_reports',
    ),
    'analytics': (
        'apps.vulnerabilities.tasks.update_vulnerability_risk_scores',
        'apps.compliance.tasks.calculate_compliance_metrics',
    ),
    'default': (
        'apps.assets.tasks.update_asset_inventory',
        'apps.compliance.tasks.send_compliance_notification',
        'apps.compliance.tasks.check_overdue_assessments',
        'apps.compliance.tasks.check_expiring_exceptions',
        'apps.vulnerabilities.tasks.notify_vulnerability_assignment',
        'apps.vulnerabilities.tasks.check_sla_violations',
        'apps.vulnerabilities.tasks.enrich_vulnerability_with_threat_intel',
        'apps.vulnerabilities.tasks.cleanup_old_vulnerability_history',
        'guardian.celery.debug_task',
    ),
}

app.conf.task_routes = {
    name: {'queue': queue}
    for queue, names in TASK_QUEUES.items()
    for name in names
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
