const BASE32_REGEX = /^[A-Z2-7=]+$/;

export function parseAddInput(input) {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }

  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error('Input cannot be empty');
  }

  if (trimmed.includes('://')) {
    return parseOtpAuthUri(trimmed);
  }

  return parseCommandOrRaw(trimmed);
}

function parseOtpAuthUri(uriString) {
  let url;
  try {
    url = new URL(uriString);
  } catch {
    throw new Error('Invalid otpauth URI format');
  }

  if (url.protocol !== 'otpauth:') {
    throw new Error('URI protocol must be otpauth:');
  }

  if (url.host.toLowerCase() !== 'totp') {
    throw new Error('Only TOTP mode is supported');
  }

  const secret = url.searchParams.get('secret');
  if (!secret) {
    throw new Error('URI missing required secret parameter');
  }

  const rawLabel = decodeURIComponent(url.pathname.replace(/^\//, ''));
  let serviceName = url.searchParams.get('issuer') || '';
  let accountLabel = null;

  if (rawLabel.includes(':')) {
    const parts = rawLabel.split(':');
    if (!serviceName) {
      serviceName = parts[0].trim();
    }
    accountLabel = parts.slice(1).join(':').trim();
  } else if (rawLabel) {
    if (!serviceName) {
      serviceName = rawLabel.trim();
    } else {
      accountLabel = rawLabel.trim();
    }
  }

  if (!serviceName) {
    serviceName = 'Unknown';
  }

  const digits = parseInt(url.searchParams.get('digits') || '6', 10);
  const step = parseInt(url.searchParams.get('period') || '30', 10);

  return {
    serviceName,
    accountLabel,
    secret: secret.toUpperCase().replace(/\s+/g, ''),
    digits,
    step,
  };
}

function parseCommandOrRaw(text) {
  let clean = text.replace(/^\/add\s+/i, '').trim();
  const parts = clean.split(/\s+/);

  if (parts.length === 1) {
    const candidate = parts[0].toUpperCase().replace(/[=\-_]/g, '');
    if (candidate.length >= 8 && BASE32_REGEX.test(candidate)) {
      return {
        serviceName: null,
        accountLabel: null,
        secret: candidate,
        digits: 6,
        step: 30,
      };
    }
    throw new Error('Could not parse secret key');
  }

  const serviceName = parts[0];
  const secret = parts[1].toUpperCase().replace(/[=\-_]/g, '');
  if (!BASE32_REGEX.test(secret)) {
    throw new Error('Invalid Base32 characters in secret');
  }

  const accountLabel = parts.length > 2 ? parts.slice(2).join(' ') : null;

  return {
    serviceName,
    accountLabel,
    secret,
    digits: 6,
    step: 30,
  };
}
