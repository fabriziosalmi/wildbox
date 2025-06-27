"""
Setup Guardian Command

Initialize the Guardian platform with sample data and configurations.
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.utils import timezone
from apps.assets.models import Asset, AssetType, AssetCriticality, Environment
from apps.vulnerabilities.models import VulnerabilityTemplate
from apps.scanners.models import Scanner, ScanProfile, ScannerType
from apps.remediation.models import RemediationTemplate
from apps.integrations.models import ExternalSystem, IntegrationType
import uuid


class Command(BaseCommand):
    help = 'Initialize Guardian platform with sample data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--create-admin',
            action='store_true',
            help='Create admin user',
        )
        parser.add_argument(
            '--admin-username',
            type=str,
            default='admin',
            help='Admin username (default: admin)',
        )
        parser.add_argument(
            '--admin-email',
            type=str,
            default='admin@example.com',
            help='Admin email (default: admin@example.com)',
        )
        parser.add_argument(
            '--admin-password',
            type=str,
            default='Guardian123!',
            help='Admin password (default: Guardian123!)',
        )
        parser.add_argument(
            '--sample-data',
            action='store_true',
            help='Create sample data for testing',
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🛡️  Initializing Open Security Guardian...')
        )

        # Create admin user
        if options['create_admin']:
            self.create_admin_user(
                options['admin_username'],
                options['admin_email'],
                options['admin_password']
            )

        # Create sample data
        if options['sample_data']:
            self.create_sample_assets()
            self.create_vulnerability_templates()
            self.create_scanner_configurations()
            self.create_remediation_templates()
            self.create_integration_examples()

        self.stdout.write(
            self.style.SUCCESS('✅ Guardian initialization complete!')
        )

    def create_admin_user(self, username, email, password):
        """Create admin user if it doesn't exist"""
        self.stdout.write('Creating admin user...')
        
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'User {username} already exists')
            )
            return

        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password
        )
        
        self.stdout.write(
            self.style.SUCCESS(f'✅ Admin user created: {username}')
        )

    def create_sample_assets(self):
        """Create sample assets for testing"""
        self.stdout.write('Creating sample assets...')
        
        # First create environments
        prod_env, created = Environment.objects.get_or_create(
            name='Production',
            defaults={'description': 'Production environment', 'risk_weight': 2.0}
        )
        dev_env, created = Environment.objects.get_or_create(
            name='Development',
            defaults={'description': 'Development environment', 'risk_weight': 0.5}
        )
        
        sample_assets = [
            {
                'name': 'Web Server 01',
                'asset_type': AssetType.SERVER,
                'ip_address': '192.168.1.10',
                'hostname': 'web01.company.com',
                'operating_system': 'Ubuntu 20.04 LTS',
                'criticality': AssetCriticality.HIGH,
                'environment': prod_env,
                'description': 'Production web server hosting main application'
            },
            {
                'name': 'Database Server',
                'asset_type': AssetType.SERVER,
                'ip_address': '192.168.1.20',
                'hostname': 'db01.company.com',
                'operating_system': 'CentOS 8',
                'criticality': AssetCriticality.CRITICAL,
                'environment': prod_env,
                'description': 'Primary database server'
            },
            {
                'name': 'Developer Workstation',
                'asset_type': AssetType.WORKSTATION,
                'ip_address': '192.168.2.50',
                'hostname': 'dev-ws-01',
                'operating_system': 'Windows 10',
                'criticality': AssetCriticality.MEDIUM,
                'environment': dev_env,
                'description': 'Developer workstation'
            },
            {
                'name': 'Main Router',
                'asset_type': AssetType.NETWORK_DEVICE,
                'ip_address': '192.168.1.1',
                'hostname': 'router-main',
                'vendor': 'Cisco',
                'model': 'ISR 4321',
                'criticality': AssetCriticality.HIGH,
                'environment': prod_env,
                'description': 'Main network router'
            },
            {
                'name': 'Corporate Website',
                'asset_type': AssetType.APPLICATION,
                'hostname': 'www.company.com',
                'criticality': AssetCriticality.HIGH,
                'environment': prod_env,
                'description': 'Corporate website'
            }
        ]

        for asset_data in sample_assets:
            if not Asset.objects.filter(name=asset_data['name']).exists():
                asset = Asset.objects.create(**asset_data)
                self.stdout.write(f'  ✅ Created asset: {asset.name}')

    def create_vulnerability_templates(self):
        """Create common vulnerability templates"""
        self.stdout.write('Creating vulnerability templates...')
        
        templates = [
            {
                'cve_id': 'CVE-2023-0001',
                'title': 'Remote Code Execution in Web Framework',
                'description_template': 'A remote code execution vulnerability exists in the web framework that allows attackers to execute arbitrary code.',
                'solution_template': 'Update to the latest version of the web framework and implement input validation.',
                'severity': 'critical',
                'cvss_v3_score': 9.8,
                'category': 'Remote Code Execution',
                'cwe_id': 'CWE-94',
                'default_priority': 'p1',
                'default_sla_hours': 24
            },
            {
                'cve_id': 'CVE-2023-0002',
                'title': 'SQL Injection Vulnerability',
                'description_template': 'A SQL injection vulnerability allows attackers to manipulate database queries.',
                'solution_template': 'Implement parameterized queries and input sanitization.',
                'severity': 'high',
                'cvss_v3_score': 8.1,
                'category': 'Injection',
                'cwe_id': 'CWE-89',
                'default_priority': 'p2',
                'default_sla_hours': 72
            },
            {
                'cve_id': 'CVE-2023-0003',
                'title': 'Cross-Site Scripting (XSS)',
                'description_template': 'A cross-site scripting vulnerability allows injection of malicious scripts.',
                'solution_template': 'Implement output encoding and Content Security Policy.',
                'severity': 'medium',
                'cvss_v3_score': 6.1,
                'category': 'Cross-Site Scripting',
                'cwe_id': 'CWE-79',
                'default_priority': 'p3',
                'default_sla_hours': 168
            }
        ]

        for template_data in templates:
            if not VulnerabilityTemplate.objects.filter(cve_id=template_data['cve_id']).exists():
                template = VulnerabilityTemplate.objects.create(**template_data)
                self.stdout.write(f'  ✅ Created vulnerability template: {template.title}')

    def create_scanner_configurations(self):
        """Create sample scanner configurations"""
        self.stdout.write('Creating scanner configurations...')
        
        scanners = [
            {
                'name': 'Nessus Professional',
                'description': 'Tenable Nessus vulnerability scanner',
                'scanner_type': ScannerType.NESSUS,
                'base_url': 'https://nessus.company.com:8834',
                'supports_authenticated_scans': True,
                'supports_compliance_scans': True,
                'supports_agent_scans': True
            },
            {
                'name': 'OpenVAS Scanner',
                'description': 'Open source vulnerability scanner',
                'scanner_type': ScannerType.OPENVAS,
                'base_url': 'https://openvas.company.com:9392',
                'supports_authenticated_scans': True,
                'supports_compliance_scans': False,
                'supports_agent_scans': False
            }
        ]

        for scanner_data in scanners:
            if not Scanner.objects.filter(name=scanner_data['name']).exists():
                scanner = Scanner.objects.create(**scanner_data)
                self.stdout.write(f'  ✅ Created scanner: {scanner.name}')
                
                # Create sample scan profile
                if scanner.scanner_type == ScannerType.NESSUS:
                    ScanProfile.objects.create(
                        name='Basic Network Scan',
                        description='Basic network vulnerability scan',
                        scanner=scanner,
                        enable_safe_checks=True,
                        scan_speed='normal'
                    )

    def create_remediation_templates(self):
        """Create remediation workflow templates"""
        self.stdout.write('Creating remediation templates...')
        
        templates = [
            {
                'name': 'Software Patch Deployment',
                'description': 'Standard workflow for deploying software patches',
                'category': 'Patching',
                'remediation_type': 'patch',
                'default_priority': 'high',
                'estimated_effort_hours': 4.0,
                'step_templates': [
                    {
                        'title': 'Review Patch Details',
                        'description': 'Review patch notes and compatibility',
                        'instructions': 'Check vendor documentation and compatibility matrix',
                        'estimated_duration_minutes': 30
                    },
                    {
                        'title': 'Test in Development',
                        'description': 'Deploy and test patch in development environment',
                        'instructions': 'Deploy patch and run regression tests',
                        'estimated_duration_minutes': 120
                    },
                    {
                        'title': 'Schedule Maintenance Window',
                        'description': 'Schedule production deployment window',
                        'instructions': 'Coordinate with operations team for maintenance window',
                        'estimated_duration_minutes': 15
                    },
                    {
                        'title': 'Deploy to Production',
                        'description': 'Deploy patch to production environment',
                        'instructions': 'Follow change management process and deploy patch',
                        'estimated_duration_minutes': 60
                    },
                    {
                        'title': 'Verify Deployment',
                        'description': 'Verify successful deployment and functionality',
                        'instructions': 'Run post-deployment tests and monitoring checks',
                        'estimated_duration_minutes': 30
                    }
                ],
                'rollback_template': 'If issues occur, roll back using previous system backup',
                'testing_template': 'Verify all critical functions work correctly after patch'
            },
            {
                'name': 'Configuration Hardening',
                'description': 'Security configuration hardening workflow',
                'category': 'Configuration',
                'remediation_type': 'configuration',
                'default_priority': 'medium',
                'estimated_effort_hours': 2.0,
                'step_templates': [
                    {
                        'title': 'Backup Current Configuration',
                        'description': 'Create backup of current system configuration',
                        'instructions': 'Export and backup current configuration files',
                        'estimated_duration_minutes': 15
                    },
                    {
                        'title': 'Apply Security Settings',
                        'description': 'Apply recommended security configuration',
                        'instructions': 'Update configuration according to security baseline',
                        'estimated_duration_minutes': 45
                    },
                    {
                        'title': 'Test Functionality',
                        'description': 'Verify system functionality after changes',
                        'instructions': 'Run functional tests to ensure no regression',
                        'estimated_duration_minutes': 30
                    },
                    {
                        'title': 'Update Documentation',
                        'description': 'Update system documentation with new configuration',
                        'instructions': 'Document configuration changes in system docs',
                        'estimated_duration_minutes': 15
                    }
                ],
                'rollback_template': 'Restore from configuration backup if issues occur',
                'testing_template': 'Verify all services function correctly with new configuration'
            }
        ]

        for template_data in templates:
            if not RemediationTemplate.objects.filter(name=template_data['name']).exists():
                template = RemediationTemplate.objects.create(**template_data)
                self.stdout.write(f'  ✅ Created remediation template: {template.name}')

    def create_integration_examples(self):
        """Create example external system integrations"""
        self.stdout.write('Creating integration examples...')
        
        systems = [
            {
                'name': 'JIRA Production',
                'description': 'Production JIRA instance for ticket management',
                'system_type': IntegrationType.TICKETING,
                'vendor': 'Atlassian',
                'base_url': 'https://company.atlassian.net',
                'auth_type': 'api_key',
                'supports_bidirectional_sync': True,
                'supports_webhooks': True
            },
            {
                'name': 'Splunk SIEM',
                'description': 'Enterprise SIEM for security monitoring',
                'system_type': IntegrationType.SIEM,
                'vendor': 'Splunk',
                'base_url': 'https://splunk.company.com:8089',
                'auth_type': 'bearer',
                'supports_bidirectional_sync': False,
                'supports_real_time': True
            },
            {
                'name': 'ServiceNow ITSM',
                'description': 'IT Service Management platform',
                'system_type': IntegrationType.TICKETING,
                'vendor': 'ServiceNow',
                'base_url': 'https://company.service-now.com',
                'auth_type': 'basic',
                'supports_bidirectional_sync': True,
                'supports_webhooks': True
            }
        ]

        for system_data in systems:
            if not ExternalSystem.objects.filter(name=system_data['name']).exists():
                system = ExternalSystem.objects.create(**system_data)
                self.stdout.write(f'  ✅ Created integration: {system.name}')

        self.stdout.write(
            self.style.SUCCESS('✅ Sample data creation complete!')
        )
