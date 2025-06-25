"""
Management command to import vulnerability data from external sources
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone
from apps.vulnerabilities.models import Vulnerability
from apps.assets.models import Asset
import json
import csv
import requests
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Import vulnerability data from various sources'

    def add_arguments(self, parser):
        parser.add_argument(
            '--source',
            type=str,
            required=True,
            choices=['nessus', 'openvas', 'csv', 'json', 'nist'],
            help='Source type for import'
        )
        parser.add_argument(
            '--file',
            type=str,
            help='File path for local imports (CSV, JSON)'
        )
        parser.add_argument(
            '--url',
            type=str,
            help='URL for remote imports'
        )
        parser.add_argument(
            '--api-key',
            type=str,
            help='API key for authenticated imports'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Perform a dry run without saving data'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force import and overwrite existing data'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting vulnerability import...')
        )

        source = options['source']
        dry_run = options['dry_run']
        force = options['force']

        try:
            if source == 'csv':
                self.import_from_csv(options['file'], dry_run, force)
            elif source == 'json':
                self.import_from_json(options['file'], dry_run, force)
            elif source == 'nist':
                self.import_from_nist(options.get('url'), dry_run, force)
            elif source in ['nessus', 'openvas']:
                self.import_from_scanner(source, options, dry_run, force)
            else:
                raise CommandError(f'Unsupported source: {source}')

        except Exception as e:
            raise CommandError(f'Import failed: {str(e)}')

    def import_from_csv(self, file_path, dry_run, force):
        """Import vulnerabilities from CSV file"""
        if not file_path:
            raise CommandError('File path is required for CSV import')

        self.stdout.write(f'Importing from CSV: {file_path}')
        
        imported_count = 0
        updated_count = 0
        
        with open(file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            
            with transaction.atomic():
                for row in reader:
                    if dry_run:
                        self.stdout.write(f'Would import: {row.get("title", "Unknown")}')
                        imported_count += 1
                        continue
                    
                    # Process row
                    vuln_data = self.normalize_csv_data(row)
                    
                    # Check if vulnerability exists
                    existing = Vulnerability.objects.filter(
                        cve_id=vuln_data.get('cve_id'),
                        asset__hostname=vuln_data.get('hostname')
                    ).first()
                    
                    if existing and not force:
                        self.stdout.write(
                            self.style.WARNING(f'Skipping existing: {vuln_data.get("cve_id")}')
                        )
                        continue
                    
                    # Get or create asset
                    asset = self.get_or_create_asset(vuln_data.get('hostname'))
                    
                    if existing:
                        # Update existing
                        for key, value in vuln_data.items():
                            if key != 'hostname':
                                setattr(existing, key, value)
                        existing.save()
                        updated_count += 1
                    else:
                        # Create new
                        Vulnerability.objects.create(
                            asset=asset,
                            **vuln_data
                        )
                        imported_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'CSV import completed: {imported_count} imported, {updated_count} updated'
            )
        )

    def import_from_json(self, file_path, dry_run, force):
        """Import vulnerabilities from JSON file"""
        if not file_path:
            raise CommandError('File path is required for JSON import')

        self.stdout.write(f'Importing from JSON: {file_path}')
        
        with open(file_path, 'r') as jsonfile:
            data = json.load(jsonfile)
        
        imported_count = 0
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        with transaction.atomic():
            for vuln_data in vulnerabilities:
                if dry_run:
                    self.stdout.write(f'Would import: {vuln_data.get("title", "Unknown")}')
                    imported_count += 1
                    continue
                
                # Get or create asset
                asset = self.get_or_create_asset(vuln_data.get('hostname'))
                
                # Create vulnerability
                Vulnerability.objects.create(
                    asset=asset,
                    title=vuln_data.get('title'),
                    description=vuln_data.get('description'),
                    severity=vuln_data.get('severity', 'medium'),
                    cvss_score=vuln_data.get('cvss_score', 5.0),
                    cve_id=vuln_data.get('cve_id'),
                    discovered_at=timezone.now()
                )
                imported_count += 1

        self.stdout.write(
            self.style.SUCCESS(f'JSON import completed: {imported_count} imported')
        )

    def import_from_nist(self, url, dry_run, force):
        """Import vulnerabilities from NIST NVD"""
        if not url:
            url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
        
        self.stdout.write(f'Importing from NIST NVD: {url}')
        
        # This would implement NIST NVD API integration
        # For now, just a placeholder
        self.stdout.write(
            self.style.WARNING('NIST import not yet implemented')
        )

    def import_from_scanner(self, scanner_type, options, dry_run, force):
        """Import from vulnerability scanners"""
        self.stdout.write(f'Importing from {scanner_type}')
        
        # This would implement scanner-specific import logic
        self.stdout.write(
            self.style.WARNING(f'{scanner_type} import not yet implemented')
        )

    def normalize_csv_data(self, row):
        """Normalize CSV row data to vulnerability format"""
        return {
            'title': row.get('title', row.get('vulnerability', 'Unknown')),
            'description': row.get('description', ''),
            'severity': row.get('severity', 'medium').lower(),
            'cvss_score': float(row.get('cvss_score', 5.0)),
            'cve_id': row.get('cve_id', row.get('cve')),
            'hostname': row.get('hostname', row.get('host', row.get('target'))),
            'port': int(row.get('port', 0)) if row.get('port') else None,
            'protocol': row.get('protocol', 'tcp'),
        }

    def get_or_create_asset(self, hostname):
        """Get or create asset by hostname"""
        if not hostname:
            hostname = 'unknown-host'
        
        asset, created = Asset.objects.get_or_create(
            hostname=hostname,
            defaults={
                'asset_type': 'server',
                'environment': 'unknown',
                'criticality': 'medium',
                'is_active': True,
                'created_at': timezone.now()
            }
        )
        
        if created:
            self.stdout.write(f'Created asset: {hostname}')
        
        return asset
