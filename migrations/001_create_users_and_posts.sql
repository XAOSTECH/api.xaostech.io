-- Migration: create users and posts tables

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  github_id TEXT,
  username TEXT,
  email TEXT UNIQUE,
  password_hash TEXT,
  avatar_url TEXT,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  last_login TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  slug TEXT UNIQUE,
  title TEXT,
  excerpt TEXT,
  content TEXT,
  author_id TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT,
  published INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
CREATE INDEX IF NOT EXISTS idx_posts_slug ON posts(slug);
