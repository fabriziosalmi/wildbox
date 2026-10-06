"""
Management command to import vulnerability data from external sources

A file, CSV or JSON, holds one finding per row or per object of its
``vulnerabilities`` list, under these names:

    title (or vulnerability), description, severity, cvss_score,
    cve_id (or cve), hostname (or host, or target), port, protocol

They are not all the model's names, and the command used to hand them to
the models as they were (#788): ``cvss_score`` and ``discovered_at`` to
``Vulnerability``, which has ``cvss_v3_score`` and sets ``first_discovered``
itself; ``hostname`` to it too, which is the asset's; and to ``Asset`` an
``environment`` that is a text where the model has a foreign key, an
``is_active`` and a ``created_at`` it does not take. No file could be
imported: the first row ended the run with a FieldError. ``finding_fields``
is now the one place where a row becomes the fields of the model, for both
formats, and the model's own validation says whether it takes them.
"""

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from apps.vulnerabilities.models import Vulnerability
from apps.assets.models import Asset
import json
import csv
import uuid
import requests
import logging

logger = logging.getLogger(__name__)

# The sources the command accepts and has no code for. They printed "not yet
# implemented" and ended with status 0, as an import that worked does.
NOT_IMPLEMENTED = ('nist', 'nessus', 'openvas')

# Field of Vulnerability -> the name a file gives it, where they differ: an
# error names the column the operator wrote.
FILE_NAMES = {'cvss_v3_score': 'cvss_score'}

MAX_PORT = 65535


def _text(value):
    """A value of a row as text: '' for one that is missing or null."""
    return '' if value is None else str(value).strip()


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
        parser.add_argument(
            '--team-id',
            type=uuid.UUID,
            required=True,
            help=(
                'The team (identity team UUID) the imported assets and '
                'vulnerabilities belong to (#642)'
            ),
        )

    def handle(self, *args, **options):
        source = options['source']
        if source in NOT_IMPLEMENTED:
            # Nothing was imported, and the exit status says so.
            raise CommandError(f'{source} import is not implemented')

        self.stdout.write(
            self.style.SUCCESS('Starting vulnerability import...')
        )

        self.team_id = options['team_id']
        dry_run = options['dry_run']
        force = options['force']

        try:
            if source == 'csv':
                self.import_from_csv(options['file'], dry_run, force)
            elif source == 'json':
                self.import_from_json(options['file'], dry_run, force)
            else:
                raise CommandError(f'Unsupported source: {source}')

        except Exception as e:
            raise CommandError(f'Import failed: {str(e)}')

    def import_from_csv(self, file_path, dry_run, force):
        """Import vulnerabilities from CSV file"""
        if not file_path:
            raise CommandError('File path is required for CSV import')

        self.stdout.write(f'Importing from CSV: {file_path}')

        with open(file_path, 'r', newline='') as csvfile:
            self.import_rows('CSV', csv.DictReader(csvfile), dry_run, force)

    def import_from_json(self, file_path, dry_run, force):
        """Import vulnerabilities from JSON file"""
        if not file_path:
            raise CommandError('File path is required for JSON import')

        self.stdout.write(f'Importing from JSON: {file_path}')

        with open(file_path, 'r') as jsonfile:
            data = json.load(jsonfile)

        rows = data.get('vulnerabilities') if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise CommandError(
                'The JSON file must be an object with a "vulnerabilities" list'
            )

        self.import_rows('JSON', rows, dry_run, force)

    def import_rows(self, label, rows, dry_run, force):
        """Store the findings of a file, all of them or none.

        A finding the team already has is skipped, or updated with --force.
        """
        imported_count = 0
        updated_count = 0

        with transaction.atomic():
            for number, row in enumerate(rows, start=1):
                # Checked in a dry run too: it says what an import would do.
                hostname, fields = self.finding_fields(row, number)

                if dry_run:
                    self.stdout.write(f'Would import: {fields["title"]}')
                    imported_count += 1
                    continue

                existing = self.existing_finding(hostname, fields)

                if existing and not force:
                    self.stdout.write(
                        self.style.WARNING(
                            f'Skipping existing: {fields["cve_id"] or fields["title"]}'
                        )
                    )
                    continue

                if existing:
                    for key, value in fields.items():
                        setattr(existing, key, value)
                    existing.save()
                    updated_count += 1
                else:
                    Vulnerability.objects.create(
                        asset=self.get_or_create_asset(hostname),
                        **fields
                    )
                    imported_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'{label} import completed: {imported_count} imported, '
                f'{updated_count} updated'
            )
        )

    def finding_fields(self, row, number):
        """One row of a file as (hostname, fields of Vulnerability).

        The values are checked by the model's fields, so what a file may hold
        is what the model holds: a severity of its choices, a score from 0 to
        10, texts of its lengths. A row it does not take stops the import
        with the row's number and title.
        """
        if not isinstance(row, dict):
            raise CommandError(f'row {number}: not an object with named values')

        title = _text(row.get('title')) or _text(row.get('vulnerability')) or 'Unknown'
        hostname = (
            _text(row.get('hostname')) or _text(row.get('host'))
            or _text(row.get('target')) or 'unknown-host'
        )
        port = _text(row.get('port'))
        fields = {
            'title': title,
            'description': _text(row.get('description')),
            'severity': (_text(row.get('severity')) or 'medium').lower(),
            # No score is no score: 5.0 was written for a finding without one.
            'cvss_v3_score': _text(row.get('cvss_score')) or None,
            'cve_id': _text(row.get('cve_id')) or _text(row.get('cve')),
            # 0 is how a scanner's export writes "no port".
            'port': None if port in ('', '0') else port,
            'protocol': _text(row.get('protocol')),
        }

        finding = Vulnerability(**fields)
        # description: the model asks for one, and a file may have none.
        checked = set(fields) - {'description'}
        try:
            finding.clean_fields(
                exclude=[
                    field.name for field in Vulnerability._meta.fields
                    if field.name not in checked
                ]
            )
        except ValidationError as error:
            problems = '; '.join(
                f'{FILE_NAMES.get(name, name)}: {" ".join(messages)}'
                for name, messages in sorted(error.message_dict.items())
            )
            raise CommandError(f'row {number} ({title}): {problems}')
        if finding.port is not None and finding.port > MAX_PORT:
            raise CommandError(
                f'row {number} ({title}): port: a port is a number from 0 to {MAX_PORT}'
            )

        # As the fields converted them: the score a float, the port a number.
        return hostname, {name: getattr(finding, name) for name in fields}

    def existing_finding(self, hostname, fields):
        """The team's finding this row is, by what the model tells findings
        apart by: the asset, the CVE and the port.

        A row with neither a CVE nor a port has nothing to be known by; it is
        always a new finding, as it is for the API.
        """
        if not fields['cve_id'] and fields['port'] is None:
            return None
        return Vulnerability.objects.filter(
            asset__team_id=self.team_id,
            asset__hostname=hostname,
            cve_id=fields['cve_id'],
            port=fields['port'],
        ).first()

    def get_or_create_asset(self, hostname):
        """Get or create the team's asset by hostname"""
        asset, created = Asset.objects.get_or_create(
            team_id=self.team_id,
            hostname=hostname,
            defaults={
                'name': hostname,
                'asset_type': 'server',
                'criticality': 'medium',
                'status': 'active',
                'discovered_by': 'import_vulnerabilities',
            }
        )

        if created:
            self.stdout.write(f'Created asset: {hostname}')

        return asset
