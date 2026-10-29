import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAddInput } from '../src/parser.js';

test('Parses full otpauth URI with issuer and email label', () => {
  const uri = 'otpauth://totp/GitHub:alice@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
  const result = parseAddInput(uri);

  assert.equal(result.serviceName, 'GitHub');
  assert.equal(result.accountLabel, 'alice@gmail.com');
  assert.equal(result.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(result.digits, 6);
  assert.equal(result.step, 30);
});

test('Parses otpauth URI with label-only issuer prefix', () => {
  const uri = 'otpauth://totp/Vercel:team@org.co?secret=JBSWY3DPEHPK3PXP';
  const result = parseAddInput(uri);

  assert.equal(result.serviceName, 'Vercel');
  assert.equal(result.accountLabel, 'team@org.co');
  assert.equal(result.secret, 'JBSWY3DPEHPK3PXP');
});

test('Parses /add command with service name and secret', () => {
  const cmd = '/add AWS JBSWY3DPEHPK3PXP';
  const result = parseAddInput(cmd);

  assert.equal(result.serviceName, 'AWS');
  assert.equal(result.accountLabel, null);
  assert.equal(result.secret, 'JBSWY3DPEHPK3PXP');
});

test('Parses /add command with service name, secret, and email label', () => {
  const cmd = '/add Google JBSWY3DPEHPK3PXP user@gmail.com';
  const result = parseAddInput(cmd);

  assert.equal(result.serviceName, 'Google');
  assert.equal(result.accountLabel, 'user@gmail.com');
  assert.equal(result.secret, 'JBSWY3DPEHPK3PXP');
});

test('Parses bare Base32 string and marks serviceName as null for prompt', () => {
  const raw = 'JBSWY3DPEHPK3PXP';
  const result = parseAddInput(raw);

  assert.equal(result.serviceName, null);
  assert.equal(result.accountLabel, null);
  assert.equal(result.secret, 'JBSWY3DPEHPK3PXP');
});

test('Rejects invalid otpauth protocol and non-totp types', () => {
  assert.throws(
    () => parseAddInput('https://example.com'),
    /URI protocol must be otpauth:/
  );
  assert.throws(
    () => parseAddInput('otpauth://hotp/test?secret=JBSWY3DPEHPK3PXP&counter=1'),
    /Only TOTP mode is supported/
  );
});
