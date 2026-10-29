CREATE TABLE IF NOT EXISTS users (
  telegram_id INTEGER PRIMARY KEY,
  first_name TEXT NOT NULL,
  username TEXT,
  salt BLOB NOT NULL,
  pin_verifier BLOB NOT NULL,
  recovery_salt BLOB NOT NULL,
  recovery_verifier BLOB NOT NULL,
  timeout_minutes INTEGER NOT NULL DEFAULT 5,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  service_name TEXT NOT NULL,
  account_label TEXT,
  encrypted_secret BLOB NOT NULL,
  iv BLOB NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(telegram_id) ON DELETE CASCADE,
  UNIQUE(user_id, service_name, account_label)
);

CREATE TABLE IF NOT EXISTS sessions (
  user_id INTEGER PRIMARY KEY,
  encrypted_key BLOB NOT NULL,
  iv BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(telegram_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
