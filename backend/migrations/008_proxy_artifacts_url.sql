-- Composer (and any adapter that rewrites absolute dist URLs) needs to remember
-- the real upstream URL for a gated download path.
ALTER TABLE proxy_artifacts ADD COLUMN IF NOT EXISTS url TEXT;
