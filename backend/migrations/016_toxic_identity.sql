-- Recompute results that may contain toxic-repo matches based only on a basename.
DELETE FROM scan_cache WHERE type IN ('gate', 'lib', 'dep', 'composer', 'sast');
