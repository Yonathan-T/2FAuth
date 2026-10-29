import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveKey,
  encryptSecret,
  decryptSecret,
  generateRecoveryKey,
  computeVerifier,
  verifySecret,
} from '../src/vault.js';

test('PBKDF2 derives valid CryptoKey from user PIN and salt', async () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey('1234', salt);
  assert.ok(key instanceof CryptoKey);
  assert.equal(key.algorithm.name, 'AES-GCM');
  const raw = await crypto.subtle.exportKey('raw', key);
  assert.equal(raw.byteLength, 32);
});

test('computeVerifier and verifySecret authenticate matching PIN', async () => {
  const pin = '5678';
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const verifier = await computeVerifier(pin, salt);

  assert.equal(await verifySecret(pin, salt, verifier), true);
  assert.equal(await verifySecret('0000', salt, verifier), false);
});

test('generateRecoveryKey returns 24-char hyphenated alphanumeric string', () => {
  const key = generateRecoveryKey();
  assert.equal(key.length, 24);
  assert.match(key, /^[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{4}$/);
});

test('AES-256-GCM round trip encrypts and decrypts secret correctly', async () => {
  const pin = '9876';
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pin, salt);

  const secret = 'JBSWY3DPEHPK3PXP';
  const { ciphertext, iv } = await encryptSecret(secret, key);

  assert.ok(ciphertext instanceof Uint8Array);
  assert.ok(iv instanceof Uint8Array);
  assert.notEqual(new TextDecoder().decode(ciphertext), secret);

  const decrypted = await decryptSecret(ciphertext, key, iv);
  assert.equal(decrypted, secret);
});

test('Decryption with incorrect PIN fails authentication check', async () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const correctKey = await deriveKey('1234', salt);
  const wrongKey = await deriveKey('9999', salt);

  const { ciphertext, iv } = await encryptSecret('SECRET123', correctKey);

  await assert.rejects(
    async () => {
      await decryptSecret(ciphertext, wrongKey, iv);
    },
    /operation failed|OperationError/i
  );
});
