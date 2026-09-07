-- A fail-closed answer (OSV unreachable) was logged as a policy block, so the
-- Proxy view counted it among blocked packages and showed "gate-error" as the
-- reason. It is an error, not a verdict: relabel the history and drop those
-- rows from the denial log, which is meant to be what the policy rejected.
UPDATE proxy_events
   SET decision = 'error', reasons = 'scan data unavailable'
 WHERE decision = 'deny' AND reasons = 'gate-error';

DELETE FROM gate_denials WHERE rules = 'gate-error';

COMMENT ON COLUMN proxy_events.decision IS 'allow | deny | error (could not be evaluated)';
