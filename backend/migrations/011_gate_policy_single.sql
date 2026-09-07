-- One policy, no revision history. `version` is not a user-facing revision
-- number: it only bumps on every save so the verdict cache key changes and
-- stale decisions are never reused after a policy edit.
CREATE TABLE IF NOT EXISTS gate_policy (
  id          SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version     INTEGER     NOT NULL DEFAULT 1,
  source      TEXT        NOT NULL DEFAULT 'ui',   -- ui | yaml | builtin
  body        JSONB       NOT NULL,
  updated_by  TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Carry over the active revision if the previous, revisioned table exists.
DO $$
BEGIN
  IF to_regclass('public.gate_policies') IS NOT NULL THEN
    INSERT INTO gate_policy (id, version, source, body, updated_by)
    SELECT 1, revision, source, body, created_by
      FROM gate_policies WHERE active
      LIMIT 1
    ON CONFLICT (id) DO NOTHING;
  END IF;
END $$;

DROP TABLE IF EXISTS gate_policies;
