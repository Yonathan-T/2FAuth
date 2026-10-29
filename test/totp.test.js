import test from 'node:test';
import assert from 'node:assert/strict';
import { generateTOTP, verifyTOTP, base32Decode } from '../src/totp.js';

const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('Base32 Decoder decodes standard RFC secret correctly', () => {
  const bytes = base32Decode('JBSWY3DPEHPK3PXP');
  assert.ok(bytes instanceof Uint8Array);
  assert.equal(bytes.length, 10);
});

test('Base32 Decoder rejects empty or whitespace-only strings', () => {
  assert.throws(() => base32Decode(''), /cannot be empty/);
  assert.throws(() => base32Decode('   '), /cannot be empty/);
});

test('Base32 Decoder rejects invalid characters', () => {
  assert.throws(() => base32Decode('JBSWY1DPEHPK3PXP'), /Invalid Base32 character/);
  assert.throws(() => base32Decode('JBSWY8DPEHPK3PXP'), /Invalid Base32 character/);
});

test('generateTOTP validates parameters strictly', async () => {
  await assert.rejects(
    async () => generateTOTP(RFC_SECRET, -1),
    /nonnegative safe integer/
  );
  await assert.rejects(
    async () => generateTOTP(RFC_SECRET, 100, 0),
    /positive integer/
  );
  await assert.rejects(
    async () => generateTOTP(RFC_SECRET, 100, 30, 7),
    /Digits must be 6 or 8/
  );
});

test('Timestamps in the same 30-second window produce identical codes', async () => {
  const res1 = await generateTOTP(RFC_SECRET, 990);
  const res2 = await generateTOTP(RFC_SECRET, 1005);
  const res3 = await generateTOTP(RFC_SECRET, 1019);
  const next = await generateTOTP(RFC_SECRET, 1020);

  assert.equal(res1.code, res2.code);
  assert.equal(res2.code, res3.code);
  assert.notEqual(res3.code, next.code);
});

test('RFC 6238 official test vector: timestamp = 59s -> 6 digits', async () => {
  const result = await generateTOTP(RFC_SECRET, 59);
  assert.equal(result.code, '287082');
  assert.equal(result.remainingSeconds, 1);
});

test('RFC 6238 official test vector: timestamp = 59s -> 8 digits', async () => {
  const result = await generateTOTP(RFC_SECRET, 59, 30, 8);
  assert.equal(result.code, '94287082');
});

test('RFC 6238 official test vector: timestamp = 1111111109s -> 6 digits', async () => {
  const result = await generateTOTP(RFC_SECRET, 1111111109);
  assert.equal(result.code, '081804');
  assert.equal(result.remainingSeconds, 1);
});

test('RFC 6238 official test vector: timestamp = 1234567890s -> leading zeros', async () => {
  const result = await generateTOTP(RFC_SECRET, 1234567890);
  assert.equal(result.code, '005924');
  assert.equal(result.remainingSeconds, 30);
});

test('RFC 6238 official test vector: timestamp = 2000000000s -> 6 digits', async () => {
  const result = await generateTOTP(RFC_SECRET, 2000000000);
  assert.equal(result.code, '279037');
  assert.equal(result.remainingSeconds, 10);
});

test('verifyTOTP accepts valid code within drift window and rejects invalid', async () => {
  const timestamp = 1234567890;
  const { code } = await generateTOTP(RFC_SECRET, timestamp);

  const isValidCurrent = await verifyTOTP(code, RFC_SECRET, timestamp);
  assert.equal(isValidCurrent, true);

  const isValidDriftPrev = await verifyTOTP(code, RFC_SECRET, timestamp + 30, 1);
  assert.equal(isValidDriftPrev, true);

  const isInvalidFar = await verifyTOTP(code, RFC_SECRET, timestamp + 90, 1);
  assert.equal(isInvalidFar, false);

  const isInvalidCode = await verifyTOTP('000000', RFC_SECRET, timestamp);
  assert.equal(isInvalidCode, false);
});
