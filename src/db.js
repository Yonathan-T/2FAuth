export async function createUser(
  db,
  telegramId,
  firstName,
  username,
  salt,
  pinVerifier,
  recoverySalt,
  recoveryVerifier,
  timeoutMinutes = 5
) {
  const statement = db.prepare(
    `INSERT INTO users (telegram_id, first_name, username, salt, pin_verifier, recovery_salt, recovery_verifier, timeout_minutes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(telegram_id) DO UPDATE SET
       first_name = excluded.first_name,
       username = excluded.username,
       salt = excluded.salt,
       pin_verifier = excluded.pin_verifier,
       recovery_salt = excluded.recovery_salt,
       recovery_verifier = excluded.recovery_verifier,
       timeout_minutes = excluded.timeout_minutes`
  );
  return statement
    .bind(telegramId, firstName, username, salt, pinVerifier, recoverySalt, recoveryVerifier, timeoutMinutes)
    .run();
}

export async function getUser(db, telegramId) {
  const statement = db.prepare(
    `SELECT telegram_id, first_name, username, salt, pin_verifier, recovery_salt, recovery_verifier, timeout_minutes, created_at
     FROM users
     WHERE telegram_id = ?`
  );
  return statement.bind(telegramId).first();
}

export async function updateUserCredentials(db, telegramId, salt, pinVerifier, recoverySalt, recoveryVerifier) {
  const statement = db.prepare(
    `UPDATE users
     SET salt = ?, pin_verifier = ?, recovery_salt = ?, recovery_verifier = ?
     WHERE telegram_id = ?`
  );
  return statement.bind(salt, pinVerifier, recoverySalt, recoveryVerifier, telegramId).run();
}

export async function updateTimeout(db, telegramId, timeoutMinutes) {
  const statement = db.prepare(
    `UPDATE users
     SET timeout_minutes = ?
     WHERE telegram_id = ?`
  );
  return statement.bind(timeoutMinutes, telegramId).run();
}

export async function createSession(db, userId, encryptedKey, iv, expiresAt) {
  const statement = db.prepare(
    `INSERT INTO sessions (user_id, encrypted_key, iv, expires_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       encrypted_key = excluded.encrypted_key,
       iv = excluded.iv,
       expires_at = excluded.expires_at`
  );
  return statement.bind(userId, encryptedKey, iv, expiresAt).run();
}

export async function getSession(db, userId) {
  const now = Math.floor(Date.now() / 1000);
  const statement = db.prepare(
    `SELECT user_id, encrypted_key, iv, expires_at
     FROM sessions
     WHERE user_id = ? AND expires_at > ?`
  );
  return statement.bind(userId, now).first();
}

export async function deleteSession(db, userId) {
  const statement = db.prepare(
    `DELETE FROM sessions
     WHERE user_id = ?`
  );
  return statement.bind(userId).run();
}

export async function purgeExpiredSessions(db) {
  const now = Math.floor(Date.now() / 1000);
  const statement = db.prepare(
    `DELETE FROM sessions
     WHERE expires_at <= ?`
  );
  return statement.bind(now).run();
}

export async function upsertAccount(db, userId, serviceName, accountLabel, encryptedSecret, iv) {
  const statement = db.prepare(
    `INSERT INTO accounts (user_id, service_name, account_label, encrypted_secret, iv)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(user_id, service_name, account_label) DO UPDATE SET
       encrypted_secret = excluded.encrypted_secret,
       iv = excluded.iv`
  );
  return statement.bind(userId, serviceName, accountLabel || null, encryptedSecret, iv).run();
}

export async function listAccounts(db, userId) {
  const statement = db.prepare(
    `SELECT id, service_name, account_label, created_at
     FROM accounts
     WHERE user_id = ?
     ORDER BY service_name ASC, account_label ASC`
  );
  const result = await statement.bind(userId).all();
  return result.results || [];
}

export async function getAccount(db, userId, serviceName, accountLabel = null) {
  if (accountLabel) {
    const statement = db.prepare(
      `SELECT id, service_name, account_label, encrypted_secret, iv, created_at
       FROM accounts
       WHERE user_id = ? AND service_name = ? AND account_label = ?`
    );
    return statement.bind(userId, serviceName, accountLabel).first();
  }

  const statement = db.prepare(
    `SELECT id, service_name, account_label, encrypted_secret, iv, created_at
     FROM accounts
     WHERE user_id = ? AND service_name = ?`
  );
  return statement.bind(userId, serviceName).first();
}

export async function getAccountById(db, userId, accountId) {
  const statement = db.prepare(
    `SELECT id, service_name, account_label, encrypted_secret, iv, created_at
     FROM accounts
     WHERE id = ? AND user_id = ?`
  );
  return statement.bind(accountId, userId).first();
}

export async function deleteAccount(db, userId, serviceName, accountLabel = null) {
  if (accountLabel) {
    const statement = db.prepare(
      `DELETE FROM accounts
       WHERE user_id = ? AND service_name = ? AND account_label = ?`
    );
    return statement.bind(userId, serviceName, accountLabel).run();
  }

  const statement = db.prepare(
    `DELETE FROM accounts
     WHERE user_id = ? AND service_name = ?`
  );
  return statement.bind(userId, serviceName).run();
}

export async function deleteAccountById(db, userId, accountId) {
  const statement = db.prepare(
    `DELETE FROM accounts
     WHERE id = ? AND user_id = ?`
  );
  return statement.bind(accountId, userId).run();
}
