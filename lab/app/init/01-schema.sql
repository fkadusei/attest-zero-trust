-- Schema for the Attest evidence store.
--
-- Runs once, as the SUPERUSER, when the container is first created. The
-- application never connects as this role — see the next paragraph.
--
-- ---------------------------------------------------------------------------
-- WHY THERE ARE TWO ROLES, AND WHY IT IS NOT PEDANTRY
--
-- PostgreSQL Row-Level Security is bypassed by:
--   * SUPERUSER roles, always
--   * the table OWNER, unless FORCE ROW LEVEL SECURITY is set
--
-- So an application connecting as a superuser gets NO row-level security at all,
-- silently. Every query succeeds, every test passes, and the tenant boundary is
-- absent. That is the worst possible outcome: a control that appears present.
--
-- The application therefore connects as `attest_app`, which is NOT a superuser and
-- NOT the table owner. The table is additionally marked FORCE so that even the
-- owner is subject to the policy. The superuser remains available to TESTS, on
-- purpose, as the negative control that proves the policy is what is doing the
-- work.
-- ---------------------------------------------------------------------------

-- The role the application uses. NOSUPERUSER and NOBYPASSRLS are the whole point,
-- and are stated explicitly rather than left to defaults.
CREATE ROLE attest_app LOGIN PASSWORD 'lab-only-not-a-secret'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

-- The table is owned by the container's superuser role, NOT by attest_app, so the
-- app has no ownership privileges over it.
CREATE TABLE evidence (
  id           text        NOT NULL,
  tenant_id    text        NOT NULL,
  control      text        NOT NULL,
  artifact_ref text        NOT NULL,
  sha256       text        NOT NULL,
  collected_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- THE TENANT BOUNDARY, ENFORCED BY THE DATABASE
--
-- `app.current_tenant` is set per transaction by the repository. A query that
-- FORGETS to filter by tenant still cannot return another tenant's rows, because
-- the database removes them before the query sees them. This is a rule the engine
-- refuses to break, which is what distinguishes it from a convention the
-- application is asked to honour.
--
-- `current_setting(..., true)` returns NULL when unset rather than raising, so an
-- unset tenant matches NOTHING — fail closed, not open.
-- ---------------------------------------------------------------------------
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON evidence
  USING (tenant_id = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true));

-- Least privilege: the app may read and write rows, and nothing else. It cannot
-- drop the policy, alter the table, or grant itself anything.
GRANT SELECT, INSERT, UPDATE, DELETE ON evidence TO attest_app;
