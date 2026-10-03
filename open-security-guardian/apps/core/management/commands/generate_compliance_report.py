"""
Management command to generate compliance reports
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from apps.compliance.models import ComplianceFramework, ComplianceAssessment
from apps.reporting.models import ReportTemplate
from apps.reporting.tasks import generate_report
from apps.reporting.models import Report
from apps.core.tenancy import scope_to_team
import json
import uuid

class Command(BaseCommand):
    help = 'Generate compliance reports'

    def add_arguments(self, parser):
        parser.add_argument(
            '--framework',
            type=str,
            help='Framework name or ID to generate report for'
        )
        parser.add_argument(
            '--assessment',
            type=str,
            help='Assessment ID to generate report for'
        )
        parser.add_argument(
            '--format',
            type=str,
            choices=['pdf', 'html', 'json', 'csv'],
            default='pdf',
            help='Output format'
        )
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path'
        )
        parser.add_argument(
            '--template',
            type=str,
            help='Report template name'
        )
        parser.add_argument(
            '--all-frameworks',
            action='store_true',
            help='Generate reports for all active frameworks'
        )
        parser.add_argument(
            '--team-id',
            type=uuid.UUID,
            required=True,
            help=(
                'The team (identity team UUID) the report is for: it holds '
                "that team's data only, and belongs to it (#642)"
            ),
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting compliance report generation...')
        )

        self.team_id = options['team_id']
        try:
            if options['all_frameworks']:
                self.generate_all_framework_reports(options)
            elif options['framework']:
                self.generate_framework_report(options)
            elif options['assessment']:
                self.generate_assessment_report(options)
            else:
                raise CommandError(
                    'Must specify --framework, --assessment, or --all-frameworks'
                )

        except Exception as e:
            raise CommandError(f'Report generation failed: {str(e)}')

    def frameworks(self):
        """The frameworks the team sees: its own and the shared ones."""
        return scope_to_team(ComplianceFramework.objects.all(), self.team_id)

    def generate_all_framework_reports(self, options):
        """Generate reports for all active frameworks"""
        frameworks = self.frameworks().filter(is_active=True)
        
        self.stdout.write(f'Generating reports for {frameworks.count()} frameworks')
        
        for framework in frameworks:
            try:
                self.generate_single_framework_report(framework, options)
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Failed to generate report for {framework.name}: {str(e)}')
                )

    def generate_framework_report(self, options):
        """Generate report for specific framework"""
        framework_identifier = options['framework']
        
        try:
            # Try to get by ID first, then by name
            try:
                framework = self.frameworks().get(id=framework_identifier)
            except (ComplianceFramework.DoesNotExist, ValueError):
                framework = self.frameworks().get(name__icontains=framework_identifier)
            
            self.generate_single_framework_report(framework, options)
            
        except ComplianceFramework.DoesNotExist:
            raise CommandError(f'Framework not found: {framework_identifier}')

    def generate_single_framework_report(self, framework, options):
        """Generate report for a single framework"""
        template_name = options.get('template', 'compliance_status')
        
        # Get or create report template
        template, created = ReportTemplate.objects.get_or_create(
            team_id=self.team_id,
            name=f"{framework.name} Compliance Report",
            defaults={
                'report_type': 'compliance_status',
                'template_content': self.get_default_template_content(),
                'default_format': options['format'],
                'is_active': True
            }
        )
        
        # Create report
        report = Report.objects.create(
            name=f"{framework.name} Compliance Report - {timezone.now().strftime('%Y-%m-%d')}",
            template=template,
            format=options['format'],
            parameters={'framework_id': str(framework.id)},
            filters={'framework': framework.id}
        )
        
        # Generate report
        self.stdout.write(f'Generating report for {framework.name}...')
        
        # Run synchronously for management command
        from apps.reporting.tasks import generate_report as generate_report_task
        result = generate_report_task(report.id)
        
        if result:
            self.stdout.write(
                self.style.SUCCESS(f'Report generated: {report.name}')
            )
            
            # Copy to specified output path if provided
            if options.get('output') and report.file_path:
                import shutil
                shutil.copy2(report.file_path, options['output'])
                self.stdout.write(f'Report saved to: {options["output"]}')
        else:
            self.stdout.write(
                self.style.ERROR(f'Failed to generate report for {framework.name}')
            )

    def generate_assessment_report(self, options):
        """Generate report for specific assessment"""
        assessment_id = options['assessment']
        
        try:
            assessment = scope_to_team(
                ComplianceAssessment.objects.all(), self.team_id
            ).get(id=assessment_id)

            template, created = ReportTemplate.objects.get_or_create(
                team_id=self.team_id,
                name=f"{assessment.name} Assessment Report",
                defaults={
                    'report_type': 'compliance_status',
                    'template_content': self.get_default_template_content(),
                    'default_format': options['format'],
                    'is_active': True
                }
            )
            
            report = Report.objects.create(
                name=f"{assessment.name} Report - {timezone.now().strftime('%Y-%m-%d')}",
                template=template,
                format=options['format'],
                parameters={'assessment_id': str(assessment.id)},
                filters={'assessment': assessment.id}
            )
            
            self.stdout.write(f'Generating report for assessment: {assessment.name}')
            
            from apps.reporting.tasks import generate_report as generate_report_task
            result = generate_report_task(report.id)
            
            if result:
                self.stdout.write(
                    self.style.SUCCESS(f'Assessment report generated: {report.name}')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'Failed to generate assessment report')
                )
                
        except ComplianceAssessment.DoesNotExist:
            raise CommandError(f'Assessment not found: {assessment_id}')

    def get_default_template_content(self):
        """Get default template content for compliance reports"""
        return """
        <html>
        <head>
            <title>{{ template.name }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { border-bottom: 2px solid #333; padding-bottom: 20px; }
                .summary { margin: 20px 0; }
                .results { margin: 20px 0; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .compliant { color: green; }
                .non-compliant { color: red; }
                .partially-compliant { color: orange; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ template.name }}</h1>
                <p>Generated: {{ data.report_date }}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Framework: {{ data.framework }}</p>
                <p>Compliance Percentage: {{ data.compliance_percentage }}%</p>
                <p>Total Controls: {{ data.total_controls }}</p>
                <p>Compliant: {{ data.compliant_controls }}</p>
                <p>Non-Compliant: {{ data.non_compliant_controls }}</p>
                <p>High Risk Findings: {{ data.high_risk_findings }}</p>
            </div>
            
            {% if data.controls %}
            <div class="results">
                <h2>Control Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Control ID</th>
                            <th>Title</th>
                            <th>Status</th>
                            <th>Risk Level</th>
                            <th>Last Tested</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for control in data.controls %}
                        <tr>
                            <td>{{ control.control_id }}</td>
                            <td>{{ control.title }}</td>
                            <td class="{{ control.status }}">{{ control.status|title }}</td>
                            <td>{{ control.risk_level|title }}</td>
                            <td>{{ control.last_tested }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </body>
        </html>
        """
