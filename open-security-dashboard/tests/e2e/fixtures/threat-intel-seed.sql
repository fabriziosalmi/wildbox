-- Threat-intel rows for the @backend Playwright specs (#103).
--
-- Applied to the data service's database by .github/workflows/e2e-fullstack.yml
-- before Playwright runs:
--
--   docker compose exec -T postgres psql -U postgres -d data \
--     -v ON_ERROR_STOP=1 < open-security-dashboard/tests/e2e/fixtures/threat-intel-seed.sql
--
-- Why SQL and not the API: the data service exposes no route that creates an
-- indicator. Indicators arrive only through its feed collectors, which fetch
-- from the internet on a schedule -- neither deterministic nor something a test
-- should wait for. tests/integration/test_data_cross_tenant.py seeds the same
-- way for the same reason.
--
-- The rows are global (team_id NULL), so every team can read them, and use
-- documentation-only values (RFC 5737 address, a domain under wildbox.io, the
-- sha256 of "wildbox-e2e-seed"). The values must match SEEDED_INDICATORS in
-- tests/e2e/support/backend.ts. Re-running the file replaces the rows.

BEGIN;

DELETE FROM indicators WHERE source_id = '0e2e0000-0000-4000-8000-000000000103';
DELETE FROM sources WHERE id = '0e2e0000-0000-4000-8000-000000000103';

INSERT INTO sources (id, team_id, name, source_type, enabled)
VALUES ('0e2e0000-0000-4000-8000-000000000103', NULL, 'e2e-playwright-seed', 'feed', TRUE);

INSERT INTO indicators
  (id, source_id, team_id, indicator_type, value, normalized_value,
   threat_types, confidence, severity, description, tags,
   first_seen, last_seen, collection_date, active)
VALUES
  (gen_random_uuid(), '0e2e0000-0000-4000-8000-000000000103', NULL,
   'ip_address', '203.0.113.66', '203.0.113.66',
   '["malware", "c2"]', 'high', 9, 'E2E seeded command-and-control host', '["e2e"]',
   now(), now(), now(), TRUE),
  (gen_random_uuid(), '0e2e0000-0000-4000-8000-000000000103', NULL,
   'domain', 'c2-panel.e2e-wildbox.io', 'c2-panel.e2e-wildbox.io',
   '["phishing"]', 'medium', 6, 'E2E seeded phishing panel', '["e2e"]',
   now(), now(), now(), TRUE),
  (gen_random_uuid(), '0e2e0000-0000-4000-8000-000000000103', NULL,
   'file_hash',
   'ab0055ed8ed61a8dae075a1e5e5cdb58e3bf19f79ef3706d45f74de459ec85cd',
   'ab0055ed8ed61a8dae075a1e5e5cdb58e3bf19f79ef3706d45f74de459ec85cd',
   '["ransomware"]', 'verified', 10, 'E2E seeded ransomware sample', '["e2e"]',
   now(), now(), now(), TRUE);

COMMIT;
