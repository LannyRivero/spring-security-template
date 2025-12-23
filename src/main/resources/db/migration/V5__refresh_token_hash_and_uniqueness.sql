-- ===================================================================
-- V5__refresh_token_hash_and_uniqueness.sql
--
-- Purpose:
-- - Prevent refresh token double-spend
-- - Avoid storing JTI in clear text
-- - Enforce DB-level uniqueness
-- ===================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE refresh_tokens
ADD COLUMN jti_hash VARCHAR(64),
ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT FALSE;

-- Hash existing JTI values (SHA-256)
UPDATE refresh_tokens
SET jti_hash = encode(digest(jti, 'sha256'), 'hex');

-- Remove clear-text JTI
ALTER TABLE refresh_tokens
DROP COLUMN jti;

-- Enforce NOT NULL after migration
ALTER TABLE refresh_tokens
ALTER COLUMN jti_hash SET NOT NULL;

-- DB-level protection against token reuse
CREATE UNIQUE INDEX uk_refresh_token_jti_hash
ON refresh_tokens (jti_hash);
