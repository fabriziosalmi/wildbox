-- Create the Guardian service database if it does not already exist.
-- Runs once on first PostgreSQL init (empty data volume). Guardian is a Django
-- service and keeps its own tables separate from the FastAPI identity service.
SELECT 'CREATE DATABASE guardian'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'guardian')\gexec
