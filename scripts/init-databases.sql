-- Provision the per-service databases on first PostgreSQL init (empty data
-- volume). identity uses the default POSTGRES_DB; guardian (Django) and data
-- (FastAPI) keep their own databases. Idempotent via \gexec.
SELECT 'CREATE DATABASE guardian'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'guardian')\gexec

SELECT 'CREATE DATABASE data'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'data')\gexec
