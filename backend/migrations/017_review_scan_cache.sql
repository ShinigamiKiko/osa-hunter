-- Older results can contain incomplete dependency/SAST scans or fixes from a
-- different version branch. Rescan these once using the corrected semantics.
DELETE FROM scan_cache WHERE type IN ('lib', 'dep', 'composer', 'sast', 'gate');
