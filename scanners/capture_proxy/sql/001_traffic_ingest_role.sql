-- Scoped INSERT-only Postgres role for the traffic-ingest worker (plan §15.2).
--
-- The ingest worker is the ONLY capture component that holds a DB credential,
-- and this role can do exactly one thing: INSERT into captured_http_transactions.
-- No SELECT (cannot read any tenant's data), no other tables, no DDL. So even a
-- fully compromised ingest worker can only append rows (INSERT-only, purgeable,
-- non-readable), never exfiltrate or tamper.
--
-- Apply once after `prisma db push` has created the table:
--   docker compose exec -T postgres psql -U whitehat -d whitehat \
--     -v role_password="'<strong-secret>'" -f - < scanners/capture_proxy/sql/001_traffic_ingest_role.sql
-- then set the ingest DSN:
--   TRAFFIC_INGEST_DATABASE_URL=postgresql://traffic_ingest:<secret>@postgres:5432/whitehat

-- Create the role idempotently. \gexec runs the SELECT's result as SQL; the
-- password is substituted client-side by psql (-v role_password=...). A DO block
-- cannot be used here because psql does not substitute :'vars' inside $$-quotes.
SELECT format('CREATE ROLE traffic_ingest LOGIN PASSWORD %L', :'role_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'traffic_ingest')\gexec

-- Re-applying rotates the password.
ALTER ROLE traffic_ingest LOGIN PASSWORD :'role_password';

-- Exactly one privilege on exactly one table: INSERT, nothing else.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM traffic_ingest;
GRANT USAGE ON SCHEMA public TO traffic_ingest;         -- needed to name the table
GRANT INSERT ON TABLE captured_http_transactions TO traffic_ingest;
REVOKE SELECT ON captured_http_transactions FROM traffic_ingest;  -- never read back
