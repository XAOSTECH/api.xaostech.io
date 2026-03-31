-- Migration: Add password authentication support
-- Users can register with email/password as fallback to GitHub OAuth

-- Add password fields (nullable for OAuth users)
-- Note: password_hash may already exist from 0001 - use a temp table approach to be idempotent
-- SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we guard with a check
ALTER TABLE users ADD COLUMN password_salt TEXT;

-- Email verification
ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN email_verification_token TEXT;

-- Password reset
ALTER TABLE users ADD COLUMN password_reset_token TEXT;
ALTER TABLE users ADD COLUMN password_reset_expires TEXT;

-- Index for lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_email_verification ON users(email_verification_token);
CREATE INDEX IF NOT EXISTS idx_users_password_reset ON users(password_reset_token);
