"""
Management command to run scheduled tasks and maintenance
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run scheduled maintenance tasks'

    def add_arguments(self, parser):
        parser.add_argument(
            '--task',
            type=str,
            choices=[
                'cleanup_expired_reports',
                'check_overdue_assessments',
                'check_expiring_exceptions',
                'update_asset_inventory',
                'generate_metrics',
                'all'
            ],
            default='all',
            help='Specific task to run'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Perform a dry run without making changes'
        )

    def handle(self, *args, **options):
        task = options['task']
        dry_run = options['dry_run']
        
        self.stdout.write(
            self.style.SUCCESS(f'Running maintenance task: {task}')
        )
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN MODE - No changes will be made')
            )

        try:
            if task == 'all':
                self.run_all_tasks(dry_run)
            elif task == 'cleanup_expired_reports':
                self.cleanup_expired_reports(dry_run)
            elif task == 'check_overdue_assessments':
                self.check_overdue_assessments(dry_run)
            elif task == 'check_expiring_exceptions':
                self.check_expiring_exceptions(dry_run)
            elif task == 'update_asset_inventory':
                self.update_asset_inventory(dry_run)
            elif task == 'generate_metrics':
                self.generate_metrics(dry_run)

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Task failed: {str(e)}')
            )

    def run_all_tasks(self, dry_run):
        """Run all maintenance tasks"""
        tasks = [
            'cleanup_expired_reports',
            'check_overdue_assessments',
            'check_expiring_exceptions',
            'update_asset_inventory',
            'generate_metrics'
        ]
        
        for task in tasks:
            self.stdout.write(f'\nRunning task: {task}')
            try:
                getattr(self, task)(dry_run)
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Task {task} failed: {str(e)}')
                )

    def cleanup_expired_reports(self, dry_run):
        """Clean up expired reports"""
        from apps.reporting.models import Report
        import os
        
        expired_reports = Report.objects.filter(
            expires_at__lt=timezone.now(),
            status='completed'
        )
        
        count = expired_reports.count()
        self.stdout.write(f'Found {count} expired reports')
        
        if dry_run:
            for report in expired_reports:
                self.stdout.write(f'Would delete: {report.name}')
            return
        
        deleted_count = 0
        for report in expired_reports:
            try:
                # Delete file
                if report.file_path and os.path.exists(report.file_path):
                    os.remove(report.file_path)
                
                # Delete record
                report.delete()
                deleted_count += 1
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Failed to delete report {report.name}: {str(e)}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Deleted {deleted_count} expired reports')
        )

    def check_overdue_assessments(self, dry_run):
        """Check for overdue compliance assessments"""
        from apps.compliance.models import ComplianceAssessment
        
        overdue_assessments = ComplianceAssessment.objects.filter(
            due_date__lt=timezone.now(),
            status__in=['planned', 'in_progress']
        )
        
        count = overdue_assessments.count()
        self.stdout.write(f'Found {count} overdue assessments')
        
        if dry_run:
            for assessment in overdue_assessments:
                days_overdue = (timezone.now() - assessment.due_date).days
                self.stdout.write(
                    f'Would notify: {assessment.name} ({days_overdue} days overdue)'
                )
            return
        
        # Send notifications
        from apps.compliance.tasks import send_compliance_notification
        
        for assessment in overdue_assessments:
            days_overdue = (timezone.now() - assessment.due_date).days
            send_compliance_notification.delay(
                'assessment_overdue',
                assessment.id,
                {
                    'assessment': assessment.name,
                    'framework': assessment.framework.name,
                    'due_date': assessment.due_date.isoformat(),
                    'days_overdue': days_overdue
                }
            )
        
        self.stdout.write(
            self.style.SUCCESS(f'Sent overdue notifications for {count} assessments')
        )

    def check_expiring_exceptions(self, dry_run):
        """Check for expiring compliance exceptions"""
        from apps.compliance.models import ComplianceException
        
        expiring_soon = ComplianceException.objects.filter(
            valid_until__lte=timezone.now() + timedelta(days=30),
            valid_until__gt=timezone.now(),
            status='approved'
        )
        
        count = expiring_soon.count()
        self.stdout.write(f'Found {count} exceptions expiring in 30 days')
        
        if dry_run:
            for exception in expiring_soon:
                days_until_expiry = (exception.valid_until - timezone.now()).days
                self.stdout.write(
                    f'Would notify: {exception.title} (expires in {days_until_expiry} days)'
                )
            return
        
        # Send notifications
        from apps.compliance.tasks import send_compliance_notification
        
        for exception in expiring_soon:
            days_until_expiry = (exception.valid_until - timezone.now()).days
            send_compliance_notification.delay(
                'exception_expiring',
                exception.id,
                {
                    'exception': exception.title,
                    'control': exception.control.control_id,
                    'expiry_date': exception.valid_until.isoformat(),
                    'days_until_expiry': days_until_expiry
                }
            )
        
        self.stdout.write(
            self.style.SUCCESS(f'Sent expiry notifications for {count} exceptions')
        )

    def update_asset_inventory(self, dry_run):
        """Update asset inventory status"""
        from apps.assets.models import Asset
        
        # Mark assets as inactive if not seen in 30 days
        stale_assets = Asset.objects.filter(
            last_seen__lt=timezone.now() - timedelta(days=30),
            is_active=True
        )
        
        count = stale_assets.count()
        self.stdout.write(f'Found {count} stale assets')
        
        if dry_run:
            for asset in stale_assets:
                self.stdout.write(f'Would mark inactive: {asset.hostname}')
            return
        
        updated = stale_assets.update(is_active=False)
        self.stdout.write(
            self.style.SUCCESS(f'Marked {updated} assets as inactive')
        )

    def generate_metrics(self, dry_run):
        """Generate system metrics"""
        from apps.assets.models import Asset
        from apps.vulnerabilities.models import Vulnerability
        from apps.compliance.models import ComplianceAssessment
        
        # Calculate basic metrics
        metrics = {
            'total_assets': Asset.objects.count(),
            'active_assets': Asset.objects.filter(is_active=True).count(),
            'total_vulnerabilities': Vulnerability.objects.count(),
            'open_vulnerabilities': Vulnerability.objects.filter(status='open').count(),
            'critical_vulnerabilities': Vulnerability.objects.filter(
                severity='critical',
                status='open'
            ).count(),
            'total_assessments': ComplianceAssessment.objects.count(),
            'completed_assessments': ComplianceAssessment.objects.filter(
                status='completed'
            ).count(),
        }
        
        self.stdout.write('System Metrics:')
        for key, value in metrics.items():
            self.stdout.write(f'  {key}: {value}')
        
        if not dry_run:
            # Store metrics in database or send to monitoring system
            logger.info(f'System metrics generated: {metrics}')
        
        self.stdout.write(
            self.style.SUCCESS('Metrics generated successfully')
        )
