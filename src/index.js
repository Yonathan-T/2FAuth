import { generateTOTP } from './totp.js';
import {
  deriveKey,
  computeVerifier,
  verifySecret,
  generateRecoveryKey,
  encryptSecret,
  decryptSecret,
} from './vault.js';
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
  getAccountById,
  deleteAccountById,
} from './db.js';
import { parseAddInput } from './parser.js';
import { decodeQRFromImage } from './image.js';

const PIN_REGEX = /^\d{4,8}$/;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/') {
      return new Response('2FAuth Worker is running.', { status: 200 });
    }

    if (request.method === 'POST' && url.pathname === '/webhook') {
      env.BOT_TOKEN = (env.BOT_TOKEN || '').trim();
      try {
        const update = await request.json();
        await handleUpdate(update, env, ctx);
      } catch (err) {
        console.error('Webhook error:', err);
      }
      return new Response('OK', { status: 200 });
    }

    return new Response('Not Found', { status: 404 });
  },
};

async function handleUpdate(update, env, ctx) {
  if (update.message) {
    await handleMessage(update.message, env, ctx);
  } else if (update.callback_query) {
    await handleCallbackQuery(update.callback_query, env, ctx);
  }
}

async function handleMessage(msg, env, ctx) {
  const chatId = msg.chat.id;
  const user = msg.from;
  const token = (env.BOT_TOKEN || '').trim();

  if (msg.photo && msg.photo.length > 0) {
    await handlePhotoMessage(msg, env);
    return;
  }

  const text = (msg.text || '').trim();
  if (!text) {
    return;
  }

  if (text.startsWith('/start')) {
    await handleStart(chatId, user, env);
    return;
  }

  if (text.startsWith('/help')) {
    await sendHelp(token, chatId);
    return;
  }

  if (text.startsWith('/setpin')) {
    await handleSetPin(chatId, user, text, env);
    return;
  }

  if (text.startsWith('/unlock') || text.startsWith('/login')) {
    await handleUnlock(msg, env);
    return;
  }

  if (text.startsWith('/lock')) {
    await handleLock(chatId, user.id, env);
    return;
  }

  if (text.startsWith('/timeout')) {
    await handleTimeout(chatId, user.id, text, env);
    return;
  }

  if (text.startsWith('/recover')) {
    await handleRecover(msg, env);
    return;
  }

  if (text.startsWith('/newrecoverykey')) {
    await handleNewRecoveryKey(chatId, user.id, env);
    return;
  }

  if (text.startsWith('/list') || text.startsWith('/vault')) {
    await renderVaultList(token, chatId, user.id, env);
    return;
  }

  if (text.startsWith('/delete')) {
    await handleDeleteCommand(msg, env);
    return;
  }

  if (text.startsWith('/add') || text.startsWith('otpauth://')) {
    await handleAddCommand(chatId, user.id, text, env);
    return;
  }
}

async function handleStart(chatId, user, env) {
  const token = env.BOT_TOKEN;
  const existing = await getUser(env.DB, user.id);

  if (!existing) {
    const text =
      `👋 Welcome to <b>2FAuth</b>, ${escapeHtml(user.first_name)}!\n\n` +
      `Your personal zero-knowledge 2FA authenticator vault.\n\n` +
      `<b>Step 1:</b> Create a 4 to 8 digit Master PIN:\n` +
      `Send: <code>/setpin 1234</code> (replace with your personal PIN)\n\n` +
      `Your PIN is never saved. It derives an AES-256 key to encrypt all your secrets.`;

    await sendMessage(token, chatId, text);
    return;
  }

  await renderVaultList(token, chatId, user.id, env);
}

async function handleSetPin(chatId, user, text, env) {
  const token = env.BOT_TOKEN;
  const parts = text.split(/\s+/);

  if (parts.length < 2 || !PIN_REGEX.test(parts[1])) {
    await sendMessage(token, chatId, '⚠️ PIN must be between 4 and 8 digits. Example: <code>/setpin 1234</code>');
    return;
  }

  const pin = parts[1];
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const pinVerifier = await computeVerifier(pin, salt);

  const recoveryKey = generateRecoveryKey();
  const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
  const recoveryVerifier = await computeVerifier(recoveryKey, recoverySalt);

  await createUser(
    env.DB,
    user.id,
    user.first_name,
    user.username || null,
    salt,
    pinVerifier,
    recoverySalt,
    recoveryVerifier,
    5
  );

  const sessionKey = await deriveKey(pin, salt);
  const exported = await crypto.subtle.exportKey('raw', sessionKey);
  const sessionIv = crypto.getRandomValues(new Uint8Array(12));
  const expiresAt = Math.floor(Date.now() / 1000) + 5 * 60;
  await createSession(env.DB, user.id, new Uint8Array(exported), sessionIv, expiresAt);

  const confirmation =
    `✅ <b>Master PIN successfully configured!</b>\n\n` +
    `🚨 <b>EMERGENCY RECOVERY KEY</b> 🚨\n` +
    `<code>${recoveryKey}</code>\n\n` +
    `<i>Save this key in a secure place. If you ever forget your PIN, this is the only way to recover your vault.</i>\n\n` +
    `<b>Commands:</b>\n` +
    `• <code>/unlock &lt;PIN&gt;</code> — Unlock your vault for 5 minutes\n` +
    `• <code>/timeout &lt;minutes&gt;</code> — Change auto-lock duration\n` +
    `• <code>/add &lt;Service&gt; &lt;Secret&gt;</code> — Add a 2FA account`;

  await sendMessage(token, chatId, confirmation);
}

async function handleUnlock(msg, env) {
  const token = env.BOT_TOKEN;
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const parts = msg.text.trim().split(/\s+/);

  await deleteMessage(token, chatId, msg.message_id);

  if (parts.length < 2 || !PIN_REGEX.test(parts[1])) {
    await sendMessage(token, chatId, '⚠️ Format: <code>/unlock &lt;PIN&gt;</code>');
    return;
  }

  const pin = parts[1];
  const user = await getUser(env.DB, userId);
  if (!user) {
    await sendMessage(token, chatId, '🔒 Please configure your Master PIN first using /start.');
    return;
  }

  const isValid = await verifySecret(pin, new Uint8Array(user.salt), new Uint8Array(user.pin_verifier));
  if (!isValid) {
    await sendMessage(token, chatId, '❌ Incorrect Master PIN.');
    return;
  }

  const key = await deriveKey(pin, new Uint8Array(user.salt));
  const exported = await crypto.subtle.exportKey('raw', key);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const timeoutMinutes = user.timeout_minutes || 5;
  const expiresAt = Math.floor(Date.now() / 1000) + timeoutMinutes * 60;

  await createSession(env.DB, userId, new Uint8Array(exported), iv, expiresAt);

  const text = `🔓 <b>Vault Unlocked!</b> (Active for ${timeoutMinutes} minutes)\nSelect an account below to view its code immediately.`;
  await sendMessage(token, chatId, text);
  await renderVaultList(token, chatId, userId, env);
}

async function handleLock(chatId, userId, env) {
  const token = env.BOT_TOKEN;
  await deleteSession(env.DB, userId);
  await sendMessage(token, chatId, '🔒 <b>Vault Locked.</b> All active sessions cleared.');
}

async function handleTimeout(chatId, userId, text, env) {
  const token = env.BOT_TOKEN;
  const parts = text.trim().split(/\s+/);
  const minutes = parseInt(parts[1], 10);

  if (isNaN(minutes) || minutes < 1 || minutes > 60) {
    await sendMessage(token, chatId, '⚠️ Please provide a timeout between 1 and 60 minutes. Example: <code>/timeout 10</code>');
    return;
  }

  await updateTimeout(env.DB, userId, minutes);
  await sendMessage(token, chatId, `⏱️ Auto-lock timeout set to <b>${minutes} minutes</b>.`);
}

async function handleRecover(msg, env) {
  const token = env.BOT_TOKEN;
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const parts = msg.text.trim().split(/\s+/);

  await deleteMessage(token, chatId, msg.message_id);

  if (parts.length < 3 || !PIN_REGEX.test(parts[2])) {
    await sendMessage(token, chatId, '⚠️ Format: <code>/recover &lt;RECOVERY_KEY&gt; &lt;NEW_PIN&gt;</code>');
    return;
  }

  const recoveryKey = parts[1].toUpperCase().replace(/\s+/g, '');
  const newPin = parts[2];

  const user = await getUser(env.DB, userId);
  if (!user) {
    await sendMessage(token, chatId, '🔒 Account not found.');
    return;
  }

  const isValid = await verifySecret(
    recoveryKey,
    new Uint8Array(user.recovery_salt),
    new Uint8Array(user.recovery_verifier)
  );

  if (!isValid) {
    await sendMessage(token, chatId, '❌ Invalid Recovery Key.');
    return;
  }

  const newSalt = crypto.getRandomValues(new Uint8Array(16));
  const newPinVerifier = await computeVerifier(newPin, newSalt);

  const newRecoveryKey = generateRecoveryKey();
  const newRecoverySalt = crypto.getRandomValues(new Uint8Array(16));
  const newRecoveryVerifier = await computeVerifier(newRecoveryKey, newRecoverySalt);

  await updateUserCredentials(
    env.DB,
    userId,
    newSalt,
    newPinVerifier,
    newRecoverySalt,
    newRecoveryVerifier
  );

  await deleteSession(env.DB, userId);

  const text =
    `🔓 <b>Vault Successfully Recovered!</b>\n\n` +
    `Your Master PIN has been reset.\n\n` +
    `🚨 <b>NEW EMERGENCY RECOVERY KEY</b> 🚨\n` +
    `<code>${newRecoveryKey}</code>\n\n` +
    `<i>Save this new key. Your old recovery key is now invalid.</i>`;

  await sendMessage(token, chatId, text);
}

async function handleNewRecoveryKey(chatId, userId, env) {
  const token = env.BOT_TOKEN;
  const session = await getSession(env.DB, userId);

  if (!session) {
    await sendMessage(token, chatId, '🔒 Vault is locked. Send <code>/unlock &lt;PIN&gt;</code> first to rotate your recovery key.');
    return;
  }

  const user = await getUser(env.DB, userId);
  const newRecoveryKey = generateRecoveryKey();
  const newRecoverySalt = crypto.getRandomValues(new Uint8Array(16));
  const newRecoveryVerifier = await computeVerifier(newRecoveryKey, newRecoverySalt);

  await updateUserCredentials(
    env.DB,
    userId,
    user.salt,
    user.pin_verifier,
    newRecoverySalt,
    newRecoveryVerifier
  );

  const text =
    `🔑 <b>New Emergency Recovery Key Generated:</b>\n\n` +
    `<code>${newRecoveryKey}</code>\n\n` +
    `<i>Your previous recovery key is permanently revoked.</i>`;

  await sendMessage(token, chatId, text);
}

async function handleAddCommand(chatId, userId, text, env) {
  const token = env.BOT_TOKEN;
  const user = await getUser(env.DB, userId);

  if (!user) {
    await sendMessage(token, chatId, '🔒 Please configure your Master PIN first using /start.');
    return;
  }

  const session = await getSession(env.DB, userId);
  if (!session) {
    await sendMessage(token, chatId, '🔒 Vault is locked. Send <code>/unlock &lt;PIN&gt;</code> before adding accounts.');
    return;
  }

  let parsed;
  try {
    parsed = parseAddInput(text);
  } catch (err) {
    await sendMessage(token, chatId, `⚠️ ${escapeHtml(err.message)}`);
    return;
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(session.encrypted_key),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  const { ciphertext, iv } = await encryptSecret(parsed.secret, key);
  await upsertAccount(env.DB, user.telegram_id, parsed.serviceName, parsed.accountLabel, ciphertext, iv);

  const confirmText =
    `✅ Saved <b>${escapeHtml(parsed.serviceName)}</b>` +
    (parsed.accountLabel ? ` (${escapeHtml(parsed.accountLabel)})` : '') +
    ` to your vault!`;

  await sendMessage(token, chatId, confirmText);
  await renderVaultList(token, chatId, user.telegram_id, env);
}

async function handleDeleteCommand(msg, env) {
  const token = env.BOT_TOKEN;
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const parts = msg.text.trim().split(/\s+/);

  await deleteMessage(token, chatId, msg.message_id);

  if (parts.length < 2) {
    await sendMessage(token, chatId, '⚠️ Format: <code>/delete &lt;ID&gt;</code>');
    return;
  }

  const targetNum = parseInt(parts[1], 10);
  const session = await getSession(env.DB, userId);

  if (!session) {
    await sendMessage(token, chatId, '🔒 Vault is locked. Send <code>/unlock &lt;PIN&gt;</code> before deleting accounts.');
    return;
  }

  const allAccounts = await listAccounts(env.DB, userId);
  let targetAccount = await getAccountById(env.DB, userId, targetNum);

  if (!targetAccount && targetNum >= 1 && targetNum <= allAccounts.length) {
    targetAccount = allAccounts[targetNum - 1];
  }

  if (!targetAccount) {
    await sendMessage(token, chatId, '⚠️ Account not found.');
    return;
  }

  await deleteAccountById(env.DB, userId, targetAccount.id);
  await sendMessage(token, chatId, `🗑️ Deleted <b>${escapeHtml(targetAccount.service_name)}</b> from your vault.`);
  await renderVaultList(token, chatId, userId, env);
}

async function handlePhotoMessage(msg, env) {
  const token = env.BOT_TOKEN;
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  const user = await getUser(env.DB, userId);
  if (!user) {
    await sendMessage(token, chatId, '🔒 Please run /start to initialize your vault first.');
    return;
  }

  const session = await getSession(env.DB, userId);
  if (!session) {
    await sendMessage(token, chatId, '🔒 Vault is locked. Send <code>/unlock &lt;PIN&gt;</code> before adding accounts.');
    return;
  }

  const largestPhoto = msg.photo[msg.photo.length - 1];
  const fileInfo = await callTelegram(token, 'getFile', { file_id: largestPhoto.file_id });

  if (!fileInfo.ok || !fileInfo.result.file_path) {
    await sendMessage(token, chatId, '⚠️ Could not download photo from Telegram.');
    return;
  }

  const cleanToken = (token || '').trim();
  const downloadUrl = `https://api.telegram.org/file/bot${cleanToken}/${fileInfo.result.file_path}`;
  const response = await fetch(downloadUrl);

  if (!response.ok) {
    const errorText = await response.text();
    console.error('File download failed:', response.status, errorText);
    await sendMessage(token, chatId, `⚠️ Telegram file download error (${response.status})`);
    return;
  }

  const buffer = new Uint8Array(await response.arrayBuffer());

  let qrText;
  try {
    qrText = decodeQRFromImage(buffer);
  } catch (err) {
    await sendMessage(token, chatId, `⚠️ QR scan error: ${escapeHtml(err.message)}`);
    return;
  }

  let parsed;
  try {
    parsed = parseAddInput(qrText);
  } catch (err) {
    await sendMessage(token, chatId, `⚠️ Invalid QR contents: ${escapeHtml(err.message)}`);
    return;
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(session.encrypted_key),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  const { ciphertext, iv } = await encryptSecret(parsed.secret, key);
  await upsertAccount(env.DB, user.telegram_id, parsed.serviceName, parsed.accountLabel, ciphertext, iv);

  const text =
    `✅ <b>Account Added!</b>\n\n` +
    `• Service: <b>${escapeHtml(parsed.serviceName)}</b>\n` +
    (parsed.accountLabel ? `• Account: <code>${escapeHtml(parsed.accountLabel)}</code>\n` : '');

  await sendMessage(token, chatId, text);
  await renderVaultList(token, chatId, user.telegram_id, env);
}

async function renderVaultList(token, chatId, userId, env, messageId = null) {
  const accounts = await listAccounts(env.DB, userId);

  if (accounts.length === 0) {
    const emptyText =
      `📂 <b>Your 2FAuth Vault is empty.</b>\n\n` +
      `Add your first service:\n` +
      `• <code>/add GitHub &lt;SECRET&gt;</code>\n` +
      `• Send a 2FA QR code screenshot`;
    if (messageId) {
      await editMessageText(token, chatId, messageId, emptyText);
    } else {
      await sendMessage(token, chatId, emptyText);
    }
    return;
  }

  const accountLines = accounts
    .map((acc, index) => {
      const label = acc.account_label ? ` (${escapeHtml(acc.account_label)})` : '';
      return `${index + 1}. <b>${escapeHtml(acc.service_name)}</b>${label}`;
    })
    .join('\n');

  const keyboard = accounts.map((acc) => {
    const label = acc.account_label ? `${acc.service_name} (${acc.account_label})` : acc.service_name;
    return [{ text: `🔑 ${label}`, callback_data: `get:${acc.id}` }];
  });

  const text =
    `🗄️ <b>Your 2FAuth Vault</b>\n\n` +
    accountLines +
    `\n\nSelect an account below to view its one-time password:`;

  if (messageId) {
    await editMessageText(token, chatId, messageId, text, {
      reply_markup: { inline_keyboard: keyboard },
    });
  } else {
    await sendMessage(token, chatId, text, {
      reply_markup: { inline_keyboard: keyboard },
    });
  }
}

async function handleCallbackQuery(cb, env, ctx) {
  const token = (env.BOT_TOKEN || '').trim();
  const data = cb.data || '';
  const chatId = cb.message.chat.id;
  const messageId = cb.message.message_id;
  const userId = cb.from.id;

  if (data.startsWith('get:')) {
    const accountId = parseInt(data.replace('get:', ''), 10);
    await answerCallbackQuery(token, cb.id);
    await handleRevealCode(token, chatId, messageId, accountId, userId, env, ctx);
    return;
  }

  if (data.startsWith('del_prompt:')) {
    const accountId = parseInt(data.replace('del_prompt:', ''), 10);
    await answerCallbackQuery(token, cb.id);
    const account = await getAccountById(env.DB, userId, accountId);
    if (!account) {
      await renderVaultList(token, chatId, userId, env, messageId);
      return;
    }
    const confirmText = `🗑️ <b>Delete ${escapeHtml(account.service_name)}?</b>\n\nAre you sure you want to remove this account from your vault?`;
    await editMessageText(token, chatId, messageId, confirmText, {
      reply_markup: {
        inline_keyboard: [
          [
            { text: '❌ Cancel', callback_data: `get:${accountId}` },
            { text: '🗑️ Yes, Delete', callback_data: `del_confirm:${accountId}` },
          ],
        ],
      },
    });
    return;
  }

  if (data.startsWith('del_confirm:')) {
    const accountId = parseInt(data.replace('del_confirm:', ''), 10);
    await answerCallbackQuery(token, cb.id, 'Account deleted');
    await deleteAccountById(env.DB, userId, accountId);
    await renderVaultList(token, chatId, userId, env, messageId);
    return;
  }

  if (data === 'list') {
    await answerCallbackQuery(token, cb.id);
    await renderVaultList(token, chatId, userId, env, messageId);
    return;
  }

  if (data === 'lock') {
    await answerCallbackQuery(token, cb.id);
    await deleteSession(env.DB, userId);
    await editMessageText(token, chatId, messageId, '🔒 <b>Vault Locked.</b>');
    return;
  }
}

async function handleRevealCode(token, chatId, messageId, accountId, userId, env, ctx) {
  const session = await getSession(env.DB, userId);

  if (!session) {
    const lockText = `🔒 <b>Vault is Locked.</b>\nSend <code>/unlock &lt;PIN&gt;</code> to access your codes.`;
    if (messageId) {
      await editMessageText(token, chatId, messageId, lockText);
    } else {
      await sendMessage(token, chatId, lockText);
    }
    return;
  }

  const account = await getAccountById(env.DB, userId, accountId);
  if (!account) {
    const notFoundText = '⚠️ Account not found.';
    if (messageId) {
      await editMessageText(token, chatId, messageId, notFoundText);
    } else {
      await sendMessage(token, chatId, notFoundText);
    }
    return;
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(session.encrypted_key),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  let secret;
  try {
    secret = await decryptSecret(
      new Uint8Array(account.encrypted_secret),
      key,
      new Uint8Array(account.iv)
    );
  } catch (err) {
    await sendMessage(token, chatId, '⚠️ Decryption error.');
    return;
  }

  const { code, remainingSeconds } = await generateTOTP(secret);
  const progressBars = Math.round((remainingSeconds / 30) * 10);
  const bar = '▓'.repeat(progressBars) + '░'.repeat(10 - progressBars);

  const display =
    `🔑 <b>${escapeHtml(account.service_name)}</b>` +
    (account.account_label ? ` (${escapeHtml(account.account_label)})` : '') +
    `\n\n` +
    `<code>${code}</code>  <i>(tap code to copy)</i>\n` +
    `Formatted: <b>${code.slice(0, 3)} ${code.slice(3)}</b>\n\n` +
    `⏱️ Expires in <b>${remainingSeconds}s</b> <code>[${bar}]</code>`;

  const replyMarkup = {
    inline_keyboard: [
      [
        { text: '🔄 Refresh', callback_data: `get:${accountId}` },
        { text: '« Back', callback_data: 'list' },
      ],
      [
        { text: '🗑️ Delete Account', callback_data: `del_prompt:${accountId}` },
        { text: '🔒 Lock Vault', callback_data: 'lock' },
      ],
    ],
  };

  let targetMsgId = messageId;
  if (messageId) {
    await editMessageText(token, chatId, messageId, display, {
      reply_markup: replyMarkup,
    });
  } else {
    const sent = await sendMessage(token, chatId, display, {
      reply_markup: replyMarkup,
    });
    if (sent && sent.result && sent.result.message_id) {
      targetMsgId = sent.result.message_id;
    }
  }

  if (ctx && typeof ctx.waitUntil === 'function' && targetMsgId) {
    const waitMs = Math.max(1000, (remainingSeconds + 1) * 1000);
    ctx.waitUntil(
      new Promise((resolve) => {
        setTimeout(async () => {
          try {
            const freshSession = await getSession(env.DB, userId);
            if (!freshSession) {
              resolve();
              return;
            }
            const { code: newCode, remainingSeconds: newRemaining } = await generateTOTP(secret);
            const newBars = Math.round((newRemaining / 30) * 10);
            const newBar = '▓'.repeat(newBars) + '░'.repeat(10 - newBars);
            const refreshedDisplay =
              `🔑 <b>${escapeHtml(account.service_name)}</b>` +
              (account.account_label ? ` (${escapeHtml(account.account_label)})` : '') +
              `\n\n` +
              `<code>${newCode}</code>  <i>(tap code to copy)</i>\n` +
              `Formatted: <b>${newCode.slice(0, 3)} ${newCode.slice(3)}</b>\n\n` +
              `⏱️ Expires in <b>${newRemaining}s</b> <code>[${newBar}]</code>`;

            await editMessageText(token, chatId, targetMsgId, refreshedDisplay, {
              reply_markup: replyMarkup,
            });
          } catch (_) {
            // Silently ignore if message was deleted or chat closed
          }
          resolve();
        }, waitMs);
      })
    );
  }
}

async function sendHelp(token, chatId) {
  const text =
    `ℹ️ <b>2FAuth Help</b>\n\n` +
    `• <code>/unlock &lt;PIN&gt;</code> — Unlock your vault\n` +
    `• <code>/lock</code> — Lock your vault immediately\n` +
    `• <code>/list</code> — View all stored accounts\n` +
    `• <code>/add &lt;Service&gt; &lt;Secret&gt;</code> — Add a new account\n` +
    `• <code>/timeout &lt;minutes&gt;</code> — Set auto-lock timeout\n` +
    `• <code>/delete &lt;ID&gt;</code> — Remove an account\n` +
    `• <code>/recover &lt;KEY&gt; &lt;NEW_PIN&gt;</code> — Recover lost PIN`;

  await sendMessage(token, chatId, text);
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function callTelegram(token, method, payload) {
  const cleanToken = (token || '').trim();
  const url = `https://api.telegram.org/bot${cleanToken}/${method}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!data.ok) {
    console.error(`Telegram API [${method}] error:`, data);
  }
  return data;
}

async function sendMessage(token, chatId, text, options = {}) {
  return callTelegram(token, 'sendMessage', {
    chat_id: chatId,
    text,
    parse_mode: 'HTML',
    ...options,
  });
}

async function editMessageText(token, chatId, messageId, text, options = {}) {
  return callTelegram(token, 'editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: 'HTML',
    ...options,
  });
}

async function answerCallbackQuery(token, callbackQueryId, text = '') {
  return callTelegram(token, 'answerCallbackQuery', {
    callback_query_id: callbackQueryId,
    text,
  });
}

async function deleteMessage(token, chatId, messageId) {
  return callTelegram(token, 'deleteMessage', {
    chat_id: chatId,
    message_id: messageId,
  });
}
