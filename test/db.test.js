import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import {
  createUser,
  getUser,
  updateTimeout,
  updateUserCredentials,
  createSession,
  getSession,
  deleteSession,
  upsertAccount,
  listAccounts,
  getAccount,
  getAccountById,
  deleteAccount,
  deleteAccountById,
} from '../src/db.js';

function createMockD1() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (
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
    CREATE TABLE accounts (
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
    CREATE TABLE sessions (
      user_id INTEGER PRIMARY KEY,
      encrypted_key BLOB NOT NULL,
      iv BLOB NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(telegram_id) ON DELETE CASCADE
    );
  `);

  return {
    prepare(sql) {
      let boundParams = [];
      return {
        bind(...params) {
          boundParams = params;
          return this;
        },
        async run() {
          const stmt = db.prepare(sql);
          return stmt.run(...boundParams);
        },
        async first() {
          const stmt = db.prepare(sql);
          const row = stmt.get(...boundParams);
          return row || null;
        },
        async all() {
          const stmt = db.prepare(sql);
          const results = stmt.all(...boundParams);
          return { results };
        },
      };
    },
  };
}

test('Database creates and retrieves user credentials with recovery keys and timeout', async () => {
  const d1 = createMockD1();
  const salt = new Uint8Array([1, 2]);
  const verifier = new Uint8Array([3, 4]);
  const recSalt = new Uint8Array([5, 6]);
  const recVerifier = new Uint8Array([7, 8]);

  await createUser(d1, 1001, 'Alex', 'alex_dev', salt, verifier, recSalt, recVerifier, 10);
  const user = await getUser(d1, 1001);

  assert.ok(user);
  assert.equal(user.telegram_id, 1001);
  assert.equal(user.first_name, 'Alex');
  assert.equal(user.username, 'alex_dev');
  assert.equal(user.timeout_minutes, 10);
  assert.deepEqual(new Uint8Array(user.salt), salt);

  await updateTimeout(d1, 1001, 15);
  const updated = await getUser(d1, 1001);
  assert.equal(updated.timeout_minutes, 15);
});

test('Database manages active unlock sessions with automatic expiration', async () => {
  const d1 = createMockD1();
  const salt = new Uint8Array([1, 2]);
  const verifier = new Uint8Array([3, 4]);
  await createUser(d1, 3003, 'Sam', null, salt, verifier, salt, verifier, 5);

  const keyBytes = new Uint8Array([10, 20, 30, 40]);
  const iv = new Uint8Array([1, 2, 3]);
  const futureExpiry = Math.floor(Date.now() / 1000) + 300;

  await createSession(d1, 3003, keyBytes, iv, futureExpiry);
  const session = await getSession(d1, 3003);
  assert.ok(session);
  assert.deepEqual(new Uint8Array(session.encrypted_key), keyBytes);

  await deleteSession(d1, 3003);
  const cleared = await getSession(d1, 3003);
  assert.equal(cleared, null);
});

test('Database supports multiple accounts for same service under different labels', async () => {
  const d1 = createMockD1();
  const salt = new Uint8Array([1, 2, 3]);
  const verifier = new Uint8Array([4, 5, 6]);
  await createUser(d1, 2002, 'Sarah', null, salt, verifier, salt, verifier, 5);

  const secret1 = new Uint8Array([10, 20, 30]);
  const iv1 = new Uint8Array([1, 1, 1]);
  await upsertAccount(d1, 2002, 'GitHub', 'work@company.com', secret1, iv1);

  const secret2 = new Uint8Array([40, 50, 60]);
  const iv2 = new Uint8Array([2, 2, 2]);
  await upsertAccount(d1, 2002, 'GitHub', 'personal@gmail.com', secret2, iv2);

  const list = await listAccounts(d1, 2002);
  assert.equal(list.length, 2);
  assert.equal(list[0].service_name, 'GitHub');
  assert.equal(list[0].account_label, 'personal@gmail.com');
  assert.equal(list[1].service_name, 'GitHub');
  assert.equal(list[1].account_label, 'work@company.com');

  const workGithub = await getAccount(d1, 2002, 'GitHub', 'work@company.com');
  assert.deepEqual(new Uint8Array(workGithub.encrypted_secret), secret1);

  const workById = await getAccountById(d1, 2002, workGithub.id);
  assert.equal(workById.service_name, 'GitHub');
  assert.equal(workById.account_label, 'work@company.com');

  await deleteAccountById(d1, 2002, workGithub.id);
  const remaining = await listAccounts(d1, 2002);
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].account_label, 'personal@gmail.com');
});

test('Database replaces existing account secret on duplicate service and label (or empty label)', async () => {
  const d1 = createMockD1();
  const salt = new Uint8Array([1, 2, 3]);
  const verifier = new Uint8Array([4, 5, 6]);
  await createUser(d1, 3003, 'Alex', null, salt, verifier, salt, verifier, 5);

  const secA = new Uint8Array([1, 1, 1]);
  const secB = new Uint8Array([2, 2, 2]);
  const iv = new Uint8Array([9, 9, 9]);

  const res1 = await upsertAccount(d1, 3003, 'GitHub', null, secA, iv);
  assert.equal(res1.action, 'created');

  const res2 = await upsertAccount(d1, 3003, 'github', '', secB, iv);
  assert.equal(res2.action, 'updated');

  const accounts = await listAccounts(d1, 3003);
  assert.equal(accounts.length, 1);

  const acc = await getAccount(d1, 3003, 'GitHub');
  assert.deepEqual(new Uint8Array(acc.encrypted_secret), secB);
});
