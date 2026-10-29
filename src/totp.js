const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  if (typeof input !== 'string' || input.trim() === '') {
    throw new Error('Base32 secret cannot be empty');
  }

  const cleaned = input.toUpperCase().replace(/[\s\-_=]/g, '');
  if (cleaned.length === 0) {
    throw new Error('Base32 secret cannot be empty');
  }

  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned[i];
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base32 character encountered: '${char}'`);
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) {
    throw new Error('Invalid Base32 trailing bits');
  }

  if (output.length === 0) {
    throw new Error('Base32 secret produced zero bytes');
  }

  return new Uint8Array(output);
}

export async function generateTOTP(secret, timestamp = Math.floor(Date.now() / 1000), step = 30, digits = 6) {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new Error('Timestamp must be a nonnegative safe integer');
  }
  if (!Number.isInteger(step) || step <= 0) {
    throw new Error('Step must be a positive integer');
  }
  if (![6, 8].includes(digits)) {
    throw new Error('Digits must be 6 or 8');
  }

  const remainingSeconds = step - (timestamp % step);
  const counter = Math.floor(timestamp / step);

  const timeBuffer = new ArrayBuffer(8);
  const timeView = new DataView(timeBuffer);
  timeView.setBigUint64(0, BigInt(counter), false);

  const keyBytes = base32Decode(secret);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: 'SHA-1' } },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, timeBuffer);
  const hash = new Uint8Array(signature);

  const offset = hash[hash.length - 1] & 0x0f;

  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const modulo = 10 ** digits;
  const otp = binary % modulo;
  const code = otp.toString().padStart(digits, '0');

  return { code, remainingSeconds };
}

export async function verifyTOTP(token, secret, timestamp = Math.floor(Date.now() / 1000), window = 1, step = 30, digits = 6) {
  if (typeof token !== 'string' || token.length !== digits) {
    return false;
  }

  for (let offset = -window; offset <= window; offset++) {
    const checkTime = timestamp + offset * step;
    const { code } = await generateTOTP(secret, checkTime, step, digits);
    if (code === token) {
      return true;
    }
  }

  return false;
}
