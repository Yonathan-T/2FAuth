export async function deriveKey(pin, salt, extractable = true) {
  const pinBytes = new TextEncoder().encode(pin);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    pinBytes,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    extractable,
    ['encrypt', 'decrypt']
  );
}

export async function computeVerifier(secret, salt) {
  const data = new TextEncoder().encode(secret + ',' + Array.from(salt).join('.'));
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

export async function verifySecret(secret, salt, targetVerifier) {
  const calculated = await computeVerifier(secret, salt);
  if (calculated.length !== targetVerifier.length) return false;
  for (let i = 0; i < calculated.length; i++) {
    if (calculated[i] !== targetVerifier[i]) return false;
  }
  return true;
}

export function generateRecoveryKey() {
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += chars[bytes[i] % chars.length];
  }
  return (
    result.slice(0, 4) +
    '-' +
    result.slice(4, 8) +
    '-' +
    result.slice(8, 12) +
    '-' +
    result.slice(12, 16) +
    '-' +
    result.slice(16, 20)
  );
}

export async function encryptSecret(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encoded
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    iv,
  };
}

export async function decryptSecret(ciphertext, key, iv) {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}
