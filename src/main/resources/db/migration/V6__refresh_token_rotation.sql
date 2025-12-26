-- V6: Add refresh token rotation with family tracking
--
-- This migration implements OWASP-recommended refresh token rotation
-- with reuse detection and family-based revocation.
--
-- Features:
-- - family_id: Groups rotated tokens from same authentication session
-- - previous_token_jti: Links tokens in rotation chain
-- - revoked: Enables explicit token revocation
-- - Indexes for fast family lookups and cleanup operations

-- Add family_id column to track token families
ALTER TABLE refresh_tokens
ADD COLUMN family_id VARCHAR(255);

-- Add previous_token_jti for chain tracking
ALTER TABLE refresh_tokens
ADD COLUMN previous_token_jti VARCHAR(255);

-- Add revoked flag (default false)
ALTER TABLE refresh_tokens
ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT FALSE;

-- Create index on family_id for fast family revocation
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);

-- Create index on revoked flag for cleanup queries
CREATE INDEX idx_refresh_tokens_revoked ON refresh_tokens(revoked);

-- Create composite index for user + family queries
CREATE INDEX idx_refresh_tokens_username_family ON refresh_tokens(username, family_id);

-- Add comment documentation
COMMENT ON COLUMN refresh_tokens.family_id IS 'UUID grouping rotated tokens from same auth session';
COMMENT ON COLUMN refresh_tokens.previous_token_jti IS 'JTI of the token that was rotated to create this one';
COMMENT ON COLUMN refresh_tokens.revoked IS 'True if token has been explicitly revoked (logout, reuse detection)';

-- Backfill family_id for existing tokens (if any)
-- Each existing token becomes its own family
UPDATE refresh_tokens
SET family_id = jti_hash
WHERE family_id IS NULL;

-- Make family_id NOT NULL after backfill
ALTER TABLE refresh_tokens
ALTER COLUMN family_id SET NOT NULL;

-- Create index on expires_at for cleanup job performance
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
