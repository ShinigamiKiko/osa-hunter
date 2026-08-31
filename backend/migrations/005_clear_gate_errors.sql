-- Gate outages must never remain cached as package decisions.
DELETE FROM scan_cache
WHERE type = 'gate'
  AND payload->'reasons' @> '[{"rule":"gate-error"}]'::jsonb;
