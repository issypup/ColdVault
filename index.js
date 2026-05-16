// ============================================================================
// ColdVault.js
// ----------------------------------------------------------------------------
const APP_VERSION = '0.9.0-beta';
// Fully offline encrypted credential vault built with Node.js and Blessed.
//
// File layout:
//   01. Imports
//   02. Paths, files, and crash handling
//   03. Crypto configuration and encrypted vault storage
//   04. General helpers, validation, clipboard, and breach checking
//   05. Runtime state and auto-lock helpers
//   06. Blessed screen layout
//   07. View/list rendering helpers
//   08. Lock, unlock, and master-password flow
//   09. Shared prompt/modal helpers
//   10. Account forms and account actions
//   11. OTP/TOTP/HOTP forms, import/export, and code actions
//   12. Secure-note forms and note actions
//   13. Shared entry actions
//   14. OTP render loop
//   15. Global keyboard shortcuts
//   16. Boot/startup
// ============================================================================

// ============================================================================
// 01. Imports
// ============================================================================
import fs from 'fs';
import path from 'path';
import blessed from 'blessed';
import crypto from 'crypto';
import argon2 from 'argon2';
import https from 'https';
import { spawnSync } from 'child_process';
import { authenticator, hotp } from 'otplib';
import { customAlphabet } from 'nanoid';
import { fileURLToPath } from 'url';

// ============================================================================
// 02. Paths, files, and crash handling
// ============================================================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isPkg = typeof process.pkg !== 'undefined';

const APP_DIR = isPkg
  ? path.dirname(process.execPath)
  : process.cwd();

const DATA_DIR = path.join(APP_DIR, 'data');
const DATA_FILE = path.join(DATA_DIR, 'ColdVault.json');
const CRASH_LOG_FILE = path.join(APP_DIR, 'ColdVault-crash.log');

function writeCrashLog(error) {
  try {
    const msg = error && error.stack ? error.stack : String(error);
    fs.appendFileSync(
      CRASH_LOG_FILE,
      `\n[${new Date().toISOString()}]\n${msg}\n`,
      'utf8'
    );
  } catch {}
}

function hardExit(code = 1) {
  try { process.stdout.write('\x1b[0m\x1b[?25h\n'); } catch {}

  // pkg + blessed can crash during process.exit() cleanup if screen setup failed.
  // Removing exit listeners prevents blessed from calling Screen.destroy() on
  // a half-created screen and hiding the real error.
  try { process.removeAllListeners('exit'); } catch {}
  try { process.removeAllListeners('SIGINT'); } catch {}
  try { process.removeAllListeners('SIGTERM'); } catch {}

  process.exit(code);
}

process.prependListener('uncaughtException', (error) => {
  writeCrashLog(error);
  console.error('Fatal error. Details written to:', CRASH_LOG_FILE);
  console.error(error && error.stack ? error.stack : error);
  hardExit(1);
});

process.prependListener('unhandledRejection', (reason) => {
  writeCrashLog(reason);
  console.error('Unhandled rejection. Details written to:', CRASH_LOG_FILE);
  console.error(reason && reason.stack ? reason.stack : reason);
  hardExit(1);
});

// Legacy files are read once if vault.json does not exist.
const LEGACY_TOTP_FILE = path.join(DATA_DIR, 'totp.json');
const LEGACY_PASSWORD_FILE = path.join(DATA_DIR, 'passwords.json');
const LEGACY_NOTES_FILE = path.join(DATA_DIR, 'notes.json');

// ============================================================================
// 03. Crypto configuration and encrypted vault storage
// ============================================================================
const ENCRYPTION_VERSION = 2;
const KDF = 'argon2id';
const LEGACY_KDF = 'scrypt';
const CIPHER = 'aes-256-gcm';

const SCRYPT_N = 65536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

const ARGON2_MEMORY_COST = 65536;
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32;

fs.mkdirSync(DATA_DIR, { recursive: true });

function requestBiggerTerminal(columns = 132, rows = 34) {
  try {
    if (process.stdout.isTTY) {
      process.stdout.write(`\x1b[8;${rows};${columns}t`);
    }
  } catch {}
}

requestBiggerTerminal();

let MASTER_KEY = null;

const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 12);

// ---- Envelope detection and key derivation ----
function isEncryptedDb(j) {
  return (
    j &&
    j.encrypted === true &&
    typeof j.version === 'number' &&
    typeof j.kdf === 'string' &&
    j.cipher === CIPHER &&
    typeof j.salt === 'string' &&
    typeof j.iv === 'string' &&
    typeof j.authTag === 'string' &&
    typeof j.data === 'string'
  );
}

async function deriveArgon2idKey(password, salt, argon2Options = {}) {
  const hash = await argon2.hash(String(password || ''), {
    type: argon2.argon2id,
    memoryCost: Number(argon2Options.memoryCost || ARGON2_MEMORY_COST),
    timeCost: Number(argon2Options.timeCost || ARGON2_TIME_COST),
    parallelism: Number(argon2Options.parallelism || ARGON2_PARALLELISM),
    hashLength: Number(argon2Options.hashLength || ARGON2_HASH_LENGTH),
    raw: true,
    salt: Buffer.from(salt)
  });

  return Buffer.from(hash);
}

async function deriveKey(password, salt, options = {}) {
  const kdf = options.kdf || KDF;

  if (kdf === 'argon2id') {
    return await deriveArgon2idKey(password, salt, options.argon2id || {});
  }

  if (kdf === 'scrypt') {
    const scryptOptions = options.scrypt || options || {};
    const N = Number(scryptOptions.N || SCRYPT_N);
    const r = Number(scryptOptions.r || SCRYPT_R);
    const p = Number(scryptOptions.p || SCRYPT_P);

    return crypto.scryptSync(password, salt, 32, {
      N,
      r,
      p,
      maxmem: 128 * 1024 * 1024
    });
  }

  throw new Error(`Unsupported KDF: ${kdf}`);
}

async function encryptDbObject(db, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = await deriveKey(password, salt, { kdf: KDF });

  const cipher = crypto.createCipheriv(CIPHER, key, iv);
  const plaintext = Buffer.from(JSON.stringify(normaliseVault(db)), 'utf8');

  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return {
    encrypted: true,
    version: ENCRYPTION_VERSION,
    kdf: KDF,
    cipher: CIPHER,
    argon2id: {
      memoryCost: ARGON2_MEMORY_COST,
      timeCost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
      hashLength: ARGON2_HASH_LENGTH
    },
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    data: encrypted.toString('base64')
  };
}

async function decryptDbObject(envelope, password) {
  const salt = Buffer.from(envelope.salt, 'base64');
  const iv = Buffer.from(envelope.iv, 'base64');
  const authTag = Buffer.from(envelope.authTag, 'base64');
  const encrypted = Buffer.from(envelope.data, 'base64');

  const key = await deriveKey(password, salt, {
    kdf: envelope.kdf || LEGACY_KDF,
    scrypt: envelope.scrypt || {},
    argon2id: envelope.argon2id || {}
  });

  const decipher = crypto.createDecipheriv(CIPHER, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  MASTER_KEY = password;

  return normaliseVault(JSON.parse(decrypted.toString('utf8')));
}

function readJsonFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function tryDecryptFile(file, password) {
  if (!fs.existsSync(file)) return null;

  const rawText = fs.readFileSync(file, 'utf8').trim();
  if (!rawText) return { entries: [] };

  const raw = JSON.parse(rawText);

  if (isEncryptedDb(raw)) {
    const previousKey = MASTER_KEY;
    try {
      const out = await decryptDbObject(raw, password);
      MASTER_KEY = previousKey;
      return out;
    } catch (err) {
      MASTER_KEY = previousKey;
      throw err;
    }
  }

  if (raw && Array.isArray(raw.entries)) {
    return raw;
  }

  return null;
}

// ---- Vault data normalisation ----
function normaliseAccount(entry = {}) {
  return {
    id: entry.id || nanoid(),
    title: String(entry.title || entry.name || 'Untitled'),
    username: String(entry.username || ''),
    password: String(entry.password || ''),
    url: String(entry.url || ''),
    notes: String(entry.notes || ''),
    tags: Array.isArray(entry.tags)
      ? entry.tags.map(String).map(s => s.trim()).filter(Boolean)
      : String(entry.tags || '').split(',').map(s => s.trim()).filter(Boolean),
    createdAt: entry.createdAt || new Date().toISOString(),
    updatedAt: entry.updatedAt || new Date().toISOString()
  };
}

function normaliseNote(entry = {}) {
  return {
    id: entry.id || nanoid(),
    title: String(entry.title || entry.name || 'Untitled Note'),
    body: String(entry.body || entry.notes || ''),
    tags: Array.isArray(entry.tags)
      ? entry.tags.map(String).map(s => s.trim()).filter(Boolean)
      : String(entry.tags || '').split(',').map(s => s.trim()).filter(Boolean),
    createdAt: entry.createdAt || new Date().toISOString(),
    updatedAt: entry.updatedAt || new Date().toISOString()
  };
}

function normaliseTotp(entry = {}) {
  const type = sanitizeOtpType(entry.type || entry.otpType || (Object.prototype.hasOwnProperty.call(entry, 'counter') ? 'hotp' : 'totp'));

  return {
    id: entry.id || nanoid(),
    type,
    name: String(entry.name || entry.title || 'Untitled'),
    secret: String(entry.secret || '').replace(/\s+/g, '').toUpperCase(),
    digits: sanitizeDigits(entry.digits ?? 6),
    period: sanitizePeriod(entry.period ?? 30),
    counter: sanitizeCounter(entry.counter ?? 0),
    algorithm: sanitizeAlgorithm(entry.algorithm || 'sha1'),
    createdAt: entry.createdAt || new Date().toISOString(),
    updatedAt: entry.updatedAt || new Date().toISOString()
  };
}

function normaliseVault(vault) {
  if (!vault || typeof vault !== 'object') vault = {};

  // New shape.
  if (!Array.isArray(vault.accounts)) vault.accounts = [];
  if (!Array.isArray(vault.totps)) vault.totps = [];
  if (!Array.isArray(vault.notes)) vault.notes = [];

  // Gracefully accept older single-list shapes.
  if (Array.isArray(vault.entries)) {
    const looksLikeTotp = vault.entries.some(e => e && Object.prototype.hasOwnProperty.call(e, 'secret'));
    const looksLikeAccount = vault.entries.some(e => e && (
      Object.prototype.hasOwnProperty.call(e, 'password') ||
      Object.prototype.hasOwnProperty.call(e, 'username') ||
      Object.prototype.hasOwnProperty.call(e, 'url')
    ));
    const looksLikeNote = vault.entries.some(e => e && (
      Object.prototype.hasOwnProperty.call(e, 'body') ||
      (
        Object.prototype.hasOwnProperty.call(e, 'notes') &&
        !Object.prototype.hasOwnProperty.call(e, 'password') &&
        !Object.prototype.hasOwnProperty.call(e, 'secret')
      )
    ));

    if (looksLikeTotp && !vault.totps.length) {
      vault.totps = vault.entries.map(normaliseTotp);
    } else if (looksLikeAccount && !vault.accounts.length) {
      vault.accounts = vault.entries.map(normaliseAccount);
    } else if (looksLikeNote && !vault.notes.length) {
      vault.notes = vault.entries.map(normaliseNote);
    }
  }

  vault.accounts = vault.accounts.map(normaliseAccount);
  vault.totps = vault.totps.map(normaliseTotp);
  vault.notes = vault.notes.map(normaliseNote);
  vault.updatedAt = vault.updatedAt || new Date().toISOString();

  return vault;
}

// ---- Crash-safe save/load helpers ----
function writeFileAtomicSync(filePath, data) {
  const dir = path.dirname(filePath);

  fs.mkdirSync(dir, { recursive: true });

  const tempPath = path.join(
    dir,
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`
  );

  let fd;

  try {
    fd = fs.openSync(tempPath, 'w', 0o600);

    fs.writeSync(fd, data, null, 'utf8');

    fs.fsyncSync(fd);
    fs.closeSync(fd);

    fd = null;

    // Atomic replace
    fs.renameSync(tempPath, filePath);

  } catch (err) {

    try {
      if (fd !== undefined && fd !== null) {
        fs.closeSync(fd);
      }
    } catch {}

    try {
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
    } catch {}

    throw err;
  }
}

async function saveEncryptedDb(vault) {
  if (!MASTER_KEY) {
    throw new Error('Cannot save: master password is not unlocked.');
  }

  const clean = normaliseVault(vault);
  clean.updatedAt = new Date().toISOString();

  const encrypted = await encryptDbObject(clean, MASTER_KEY);

  // Crash-safe atomic write
  writeFileAtomicSync(
    DATA_FILE,
    JSON.stringify(encrypted, null, 2)
  );
}

async function importLegacyData(password) {
  const vault = { accounts: [], totps: [], notes: [] };

  if (fs.existsSync(LEGACY_PASSWORD_FILE)) {
    try {
      const old = await tryDecryptFile(LEGACY_PASSWORD_FILE, password);
      if (old && Array.isArray(old.entries)) {
        vault.accounts = old.entries.map(normaliseAccount);
      }
    } catch {}
  }

  if (fs.existsSync(LEGACY_TOTP_FILE)) {
    try {
      const old = await tryDecryptFile(LEGACY_TOTP_FILE, password);
      if (old && Array.isArray(old.entries)) {
        vault.totps = old.entries.map(normaliseTotp);
      }
    } catch {}
  }

  if (fs.existsSync(LEGACY_NOTES_FILE)) {
    try {
      const old = await tryDecryptFile(LEGACY_NOTES_FILE, password);
      if (old && Array.isArray(old.entries)) {
        vault.notes = old.entries.map(normaliseNote);
      }
    } catch {}
  }

  return normaliseVault(vault);
}

async function loadDbFromDisk(password) {
  if (!fs.existsSync(DATA_FILE)) {
    const imported = await importLegacyData(password);
    MASTER_KEY = password;
    await saveEncryptedDb(imported);
    return imported;
  }

  const rawText = fs.readFileSync(DATA_FILE, 'utf8').trim();

  if (!rawText) {
    const empty = normaliseVault({});
    MASTER_KEY = password;
    await saveEncryptedDb(empty);
    return empty;
  }

  const raw = JSON.parse(rawText);

  if (isEncryptedDb(raw)) {
    return await decryptDbObject(raw, password);
  }

  // Plain vault import/upgrade.
  if (raw && typeof raw === 'object') {
    const backupFile = `${DATA_FILE}.plaintext-backup-${Date.now()}.json`;
    fs.copyFileSync(DATA_FILE, backupFile);

    const db = normaliseVault(raw);
    MASTER_KEY = password;
    await saveEncryptedDb(db);

    return db;
  }

  throw new Error('Unrecognised vault file format.');
}

async function loadDb() {
  // Do not repeatedly decrypt from disk during normal UI refreshes.
  // Once unlocked, db in memory is the source of truth.
  return normaliseVault(db);
}

async function reloadDbFromDisk() {
  if (!MASTER_KEY) return normaliseVault({});
  db = await loadDbFromDisk(MASTER_KEY);
  return db;
}

async function saveDb(nextDb) {
  db = normaliseVault(nextDb);
  await saveEncryptedDb(db);
}
// ============================================================================
// 04. General helpers, validation, clipboard, and breach checking
// ============================================================================
// ---- Input sanitisation / formatting ----
function sanitizeAlgorithm(a) {
  const v = (a || 'sha1').toString().trim().toLowerCase();
  return ['sha1', 'sha256', 'sha512'].includes(v) ? v : 'sha1';
}

function sanitizeDigits(d) {
  const n = parseInt(d, 10);
  if (!Number.isFinite(n)) return 6;
  return Math.max(6, Math.min(8, n));
}

function sanitizePeriod(p) {
  const n = parseInt(p, 10);
  if (!Number.isFinite(n) || n <= 0) return 30;
  return Math.max(5, Math.min(300, n));
}

function sanitizeOtpType(type) {
  const v = String(type || 'totp').trim().toLowerCase();
  return v === 'hotp' ? 'hotp' : 'totp';
}

function sanitizeCounter(counter) {
  const n = Number.parseInt(counter, 10);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function sanitizeTags(value) {
  if (Array.isArray(value)) {
    return value.map(String).map(s => s.trim()).filter(Boolean);
  }

  return String(value || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}

function formatTags(tags) {
  return Array.isArray(tags) && tags.length ? tags.join(', ') : '';
}

function maskValue(value) {
  const s = String(value || '');
  if (!s) return '';
  return '•'.repeat(Math.min(12, Math.max(6, s.length)));
}

// ---- Password generation and clipboard ----
function generatePassword(length = 20) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{};:,.?';
  const bytes = crypto.randomBytes(length);
  let out = '';

  for (let i = 0; i < length; i += 1) {
    out += chars[bytes[i] % chars.length];
  }

  return out;
}

function copyTextToClipboard(text) {
  const value = String(text || '');
  if (!value) return false;

  const attempts = [];

  if (process.platform === 'win32') {
    attempts.push(['clip', [], value]);
  } else if (process.platform === 'darwin') {
    attempts.push(['pbcopy', [], value]);
  } else {
    attempts.push(['wl-copy', [], value]);
    attempts.push(['xclip', ['-selection', 'clipboard'], value]);
    attempts.push(['xsel', ['--clipboard', '--input'], value]);
  }

  for (const [cmd, args, input] of attempts) {
    try {
      const result = spawnSync(cmd, args, {
        input,
        encoding: 'utf8',
        windowsHide: true
      });

      if (result.status === 0) return true;
    } catch {}
  }

  return false;
}


// ---- Have I Been Pwned k-anonymity breach check ----
function checkPasswordPwned(password) {
  const value = String(password || '');

  if (!value) {
    return Promise.resolve({ count: 0, checked: false });
  }

  const sha1 = crypto
    .createHash('sha1')
    .update(value, 'utf8')
    .digest('hex')
    .toUpperCase();

  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  return new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: 'api.pwnedpasswords.com',
        path: `/range/${prefix}`,
        method: 'GET',
        headers: {
          'User-Agent': 'ColdVault',
          'Add-Padding': 'true'
        },
        timeout: 10000
      },
      (res) => {
        let body = '';

        res.setEncoding('utf8');

        res.on('data', (chunk) => {
          body += chunk;
        });

        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`Breach check failed: HTTP ${res.statusCode}`));
            return;
          }

          const line = body
            .split(/\r?\n/)
            .find(row => row.toUpperCase().startsWith(`${suffix}:`));

          if (!line) {
            resolve({ count: 0, checked: true });
            return;
          }

          const count = Number.parseInt(line.split(':')[1], 10);
          resolve({
            count: Number.isFinite(count) ? count : 1,
            checked: true
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('Breach check timed out.'));
    });

    req.on('error', reject);
  });
}

// ---- Simple informational modal ----
function showInfoModal(label, content, options = {}) {
  modalOpen = true;

  const modal = blessed.box({
    parent: screen,
    width: options.width || '64%',
    height: options.height || 9,
    left: 'center',
    top: 'center',
    border: 'line',
    label,
    keys: true,
    mouse: true,
    tags: true,
    padding: { left: 2, right: 2 },
    content
  });

  const close = async () => {
    modalOpen = false;
    screen.removeListener('keypress', keyHandler);

    try { modal.destroy(); } catch {}

    list.focus();
    screen.render();
  };

  const keyHandler = (ch, key = {}) => {
    if (key.name === 'escape' || isEnterKey(ch, key) || ch === 'q') {
      close();
    }
  };

  screen.on('keypress', keyHandler);
  modal.setFront();
  modal.focus();
  screen.render();

  return {
    setContent(nextContent) {
      modal.setContent(nextContent);
      screen.render();
    },
    close
  };
}

async function checkSelectedAccountBreach() {
  if (modalOpen || isTyping() || currentView !== 'accounts') return;

  const info = getSelectedInfo();
  const e = info?.entry;

  if (!e) {
    showInfoModal(' Breach Check ', 'No account selected.\n\nPress Enter or Esc to close.');
    return;
  }

  if (!e.password) {
    showInfoModal(' Breach Check ', 'No password saved for this account.\n\nPress Enter or Esc to close.');
    return;
  }

  const modal = showInfoModal(
    ' Breach Check ',
    `Checking "${e.title}" against Have I Been Pwned k-anonymity data...\n\nOnly the first 5 characters of a SHA-1 hash are sent.\n\nPress Enter or Esc to close.`,
    { height: 10 }
  );

  try {
    const result = await checkPasswordPwned(e.password);

    if (result.count > 0) {
      modal.setContent(
        `{red-fg}⚠ Password found in breach data.{/red-fg}\n\n` +
        `Account: {bold}${e.title}{/bold}\n` +
        `Seen: ${result.count.toLocaleString()} time(s)\n\n` +
        'Recommendation: change this password and avoid reusing it elsewhere.\n\n' +
        'Press Enter or Esc to close.'
      );
    } else {
      modal.setContent(
        `{green-fg}✓ No breach match found for this password.{/green-fg}\n\n` +
        `Account: {bold}${e.title}{/bold}\n\n` +
        'This does not guarantee the password is safe, but it was not found in the checked breach corpus.\n\n' +
        'Press Enter or Esc to close.'
      );
    }
  } catch (err) {
    modal.setContent(
      `{red-fg}Breach check failed.{/red-fg}\n\n` +
      `${err?.message || err}\n\n` +
      'Check your internet connection and try again.\n\n' +
      'Press Enter or Esc to close.'
    );
  }
}


// ---- Key detection helpers ----
function isTabKey(ch, key = {}) {
  return key.name === 'tab' || key.full === 'tab' || ch === '\t';
}

function isShiftTabKey(ch, key = {}) {
  return key.name === 'S-tab' || key.full === 'S-tab';
}

function isEnterKey(ch, key = {}) {
  return key.name === 'enter' || ch === '\r' || ch === '\n';
}

function isBackspaceKey(ch, key = {}) {
  return key.name === 'backspace' || key.name === 'delete';
}

// ---- otpauth:// import/export helpers ----
function parseOtpauth(uri) {
  const u = new URL(uri);

  if (u.protocol !== 'otpauth:') {
    throw new Error('Not an otpauth URI');
  }

  const host = (u.hostname || u.host || '').toLowerCase();
  const type = sanitizeOtpType(host);

  if (!['totp', 'hotp'].includes(host)) {
    throw new Error('Only TOTP and HOTP types are supported');
  }

  const labelRaw = decodeURIComponent((u.pathname || '').replace(/^\//, '')).trim() || `New ${type.toUpperCase()}`;
  const issuerParam = String(u.searchParams.get('issuer') || '').trim();

  const secret = String(u.searchParams.get('secret') || '')
    .trim()
    .replace(/\s+/g, '')
    .toUpperCase();

  if (!secret) {
    throw new Error('Missing secret');
  }

  const algorithm = sanitizeAlgorithm(u.searchParams.get('algorithm'));
  const digits = sanitizeDigits(u.searchParams.get('digits'));
  const period = sanitizePeriod(u.searchParams.get('period'));
  const counter = sanitizeCounter(u.searchParams.get('counter'));

  if (type === 'hotp' && !u.searchParams.has('counter')) {
    throw new Error('HOTP URI is missing counter');
  }

  let name = labelRaw;

  if (issuerParam) {
    const prefix = `${issuerParam}:`;

    if (labelRaw.toLowerCase().startsWith(prefix.toLowerCase())) {
      const account = labelRaw.slice(prefix.length).trim();

      if (!account || account.toLowerCase() === issuerParam.toLowerCase()) {
        name = issuerParam;
      } else {
        name = `${issuerParam}:${account}`;
      }
    } else if (labelRaw.toLowerCase() === issuerParam.toLowerCase()) {
      name = issuerParam;
    } else {
      name = labelRaw;
    }
  }

  return { type, name, secret, digits, period, counter, algorithm };
}

function buildOtpauthUri(entry) {
  if (!entry || !entry.secret) {
    throw new Error('No OTP entry selected.');
  }

  const type = sanitizeOtpType(entry.type);
  const rawName = String(entry.name || 'OTP').trim() || 'OTP';

  const secret = String(entry.secret || '')
    .trim()
    .replace(/\s+/g, '')
    .toUpperCase();

  const digits = sanitizeDigits(entry.digits);
  const period = sanitizePeriod(entry.period);
  const counter = sanitizeCounter(entry.counter);
  const algorithm = sanitizeAlgorithm(entry.algorithm).toUpperCase();

  let issuer = rawName;
  let label = rawName;

  if (rawName.includes(':')) {
    const parts = rawName.split(':');
    issuer = parts.shift().trim() || 'OTP';
    const account = parts.join(':').trim();

    label = account ? `${issuer}:${account}` : issuer;
  }

  const params = new URLSearchParams();
  params.set('secret', secret);
  params.set('issuer', issuer);
  params.set('algorithm', algorithm);
  params.set('digits', String(digits));

  if (type === 'hotp') {
    params.set('counter', String(counter));
  } else {
    params.set('period', String(period));
  }

  return `otpauth://${type}/${encodeURIComponent(label)}?${params.toString()}`;
}

// ============================================================================
// 05. Runtime state and auto-lock helpers
// ============================================================================
let db = normaliseVault({});
let currentView = 'otp'; // otp | accounts | notes
let selectedIndex = 0;
let selectedByView = { otp: 0, accounts: 0, notes: 0 };
let searchByView = { otp: '', accounts: '', notes: '' };
let revealSecret = false;
let revealPassword = false;
let modalOpen = false;
let resizeTimer = null;

const AUTO_LOCK_MS = 5 * 60 * 1000;
let idleLockTimer = null;

function clearVisibleSensitiveData() {
  try {
    codeBig.setContent('------');
    codePlain.setContent('------');
    progress.setProgress(0);
    details.setContent('');
    accountDetails.setContent('');
  } catch {}
}

function resetIdleTimer() {
  if (idleLockTimer) clearTimeout(idleLockTimer);

  if (!MASTER_KEY) return;

  idleLockTimer = setTimeout(() => {
    if (MASTER_KEY) lockVault({ force: true });
  }, AUTO_LOCK_MS);
}

function stopIdleTimer() {
  if (idleLockTimer) clearTimeout(idleLockTimer);
  idleLockTimer = null;
}

function destroyTransientScreenChildren() {
  try {
    for (const child of [...(screen.children || [])]) {
      if (child !== grid) {
        try { child.destroy(); } catch {}
      }
    }
  } catch {}
}

// ============================================================================
// 06. Blessed screen layout
// ============================================================================
const screen = blessed.screen({
  smartCSR: true,
  fullUnicode: true,
  title: `ColdVault v${APP_VERSION}`
});

function isTyping() {
  const focused = screen.focused;

  return (
    focused &&
    (
      focused.type === 'textbox' ||
      focused.type === 'textarea' ||
      focused.inputOnFocus
    )
  );
}

screen.key(['C-c'], () => hardExit(0));

screen.key(['q'], () => {
  if (modalOpen || isTyping()) return;
  hardExit(0);
});

screen.on('keypress', () => resetIdleTimer());
screen.on('mouse', () => resetIdleTimer());

const grid = blessed.box({
  parent: screen,
  width: '100%',
  height: '100%',
  top: 0,
  left: 0
});

const list = blessed.list({
  parent: grid,
  label: ' Vault ',
  tags: true,
  keys: true,
  mouse: true,
  vi: true,
  width: '35%',
  height: '100%-4',
  border: 'line',
  scrollbar: { ch: ' ', track: { bg: 'gray' }, style: { inverse: true } },
  style: { selected: { inverse: true } }
});

const otpInfo = blessed.box({
  parent: grid,
  label: ' Current OTP Code ',
  width: '65%',
  height: '70%',
  left: '35%',
  border: 'line',
  hidden: false
});

const codeBig = blessed.bigtext({
  parent: otpInfo,
  content: '------',
  width: '100%-4',
  height: 15,
  top: 1,
  left: 'center',
  fch: ' ',
  shrink: true,
  style: { fg: 'green' },
  hidden: false
});

const codePlain = blessed.box({
  parent: otpInfo,
  content: '------',
  width: '100%-2',
  height: 1,
  top: 3,
  left: 'center',
  align: 'center',
  style: { fg: 'green', bold: true },
  hidden: true
});

const progress = blessed.progressbar({
  parent: otpInfo,
  top: 14,
  left: 2,
  height: 3,
  width: '100%-6',
  filled: 0,
  orientation: 'horizontal',
  pch: '█',
  style: {
    bar: { bg: 'green' },
    border: { fg: 'white' }
  },
  border: 'line'
});

const details = blessed.box({
  parent: grid,
  label: ' Details ',
  width: '65%',
  height: '30%-3',
  top: '70%',
  left: '35%',
  border: 'line',
  tags: true,
  scrollable: true,
  alwaysScroll: true,
  keys: true,
  mouse: true,
  padding: { left: 1, right: 1 }
});

const accountDetails = blessed.box({
  parent: grid,
  label: ' Account Details ',
  width: '65%',
  height: '100%-4',
  left: '35%',
  border: 'line',
  tags: true,
  scrollable: true,
  alwaysScroll: true,
  keys: true,
  mouse: true,
  padding: { left: 1, right: 1 },
  hidden: true
});

const help = blessed.box({
  parent: grid,
  bottom: 0,
  height: 4,
  width: '100%',
  tags: true,
  border: 'line'
});

function getHelpContent() {
  if (currentView === 'otp') {
    return (
      '{bold}1{/bold} OTP  {bold}2{/bold} accounts  {bold}3{/bold} notes  {bold}↑/↓{/bold} select  {bold}a{/bold} add  {bold}e{/bold} edit  {bold}d{/bold} delete  {bold}s{/bold} search  {bold}i{/bold} import\n' +
      '{bold}x{/bold} export  {bold}c{/bold} copy code  {bold}r{/bold} reveal secret  {bold}m{/bold} master password  {bold}l{/bold} lock  {bold}q{/bold} quit'
    );
  }

  if (currentView === 'notes') {
    return (
      '{bold}1{/bold} OTP  {bold}2{/bold} accounts  {bold}3{/bold} notes  {bold}↑/↓{/bold} select  {bold}a{/bold} add  {bold}e{/bold} edit  {bold}d{/bold} delete  {bold}s{/bold} search\n' +
      '{bold}m{/bold} master password  {bold}l{/bold} lock  {bold}q{/bold} quit'
    );
  }

  return (
    '{bold}1{/bold} OTP  {bold}2{/bold} accounts  {bold}3{/bold} notes  {bold}↑/↓{/bold} select  {bold}a{/bold} add  {bold}e{/bold} edit  {bold}d{/bold} delete  {bold}s{/bold} search  {bold}b{/bold} breach check\n' +
    '{bold}u{/bold} copy user  {bold}p{/bold} copy pass  {bold}o{/bold} copy url  {bold}r{/bold} show/hide pass  {bold}m{/bold} master password  {bold}l{/bold} lock  {bold}q{/bold} quit'
  );
}
function setHelp() {
  help.setContent(getHelpContent());
}

// ============================================================================
// 07. View/list rendering helpers
// ============================================================================
function activeCollectionName() {
  if (currentView === 'otp') return 'totps';
  if (currentView === 'notes') return 'notes';
  return 'accounts';
}

function activeCollection() {
  return db[activeCollectionName()] || [];
}

function getActiveSearch() {
  return searchByView[currentView] || '';
}

function setActiveSearch(value) {
  searchByView[currentView] = String(value || '').trim();
}

function getFilteredItems() {
  const q = getActiveSearch().trim().toLowerCase();
  const items = activeCollection();

  if (!q) {
    return items.map((entry, realIndex) => ({ entry, realIndex }));
  }

  return items
    .map((entry, realIndex) => ({ entry, realIndex }))
    .filter(({ entry }) => {
      if (currentView === 'otp') {
        return String(entry.name || '').toLowerCase().includes(q);
      }

      if (currentView === 'notes') {
        const noteHaystack = [entry.title, entry.body, formatTags(entry.tags)].join(' ').toLowerCase();
        return noteHaystack.includes(q);
      }

      const haystack = [
        entry.title,
        entry.username,
        entry.url,
        formatTags(entry.tags),
        entry.notes
      ].join(' ').toLowerCase();

      return haystack.includes(q);
    });
}

function getSelectedInfo() {
  const filtered = getFilteredItems();
  return filtered[selectedIndex] || null;
}

async function setSelected(idx) {
  resetIdleTimer();
  const filtered = getFilteredItems();

  if (idx < 0) idx = 0;
  if (idx >= filtered.length) idx = filtered.length - 1;

  selectedIndex = Math.max(0, idx);
  selectedByView[currentView] = selectedIndex;

  await refreshList();
  updateDetails();
}

async function switchView(view) {
  resetIdleTimer();
  if (modalOpen || isTyping()) return;
  if (!['otp', 'accounts', 'notes'].includes(view)) return;

  selectedByView[currentView] = selectedIndex;
  currentView = view;
  selectedIndex = selectedByView[currentView] || 0;

  if (currentView === 'otp') {
    otpInfo.show();
    details.show();
    accountDetails.hide();
    resumeCode();
  } else if (currentView === 'accounts') {
    suspendCode();
    otpInfo.hide();
    details.hide();
    accountDetails.show();
    accountDetails.setLabel(' Account Details ');
  } else {
    suspendCode();
    otpInfo.hide();
    details.hide();
    accountDetails.show();
    accountDetails.setLabel(' Secure Note ');
  }

  setHelp();
  await refreshList();
  updateDetails();

  list.focus();
  screen.render();
}

async function refreshList() {
  db = normaliseVault(db);

  const filtered = getFilteredItems();

  if (selectedIndex >= filtered.length) {
    selectedIndex = Math.max(0, filtered.length - 1);
  }

  list.setLabel(currentView === 'otp' ? ' OTP Codes ' : currentView === 'notes' ? ' Secure Notes ' : ' Accounts ');

  const items = filtered.map(({ entry }, idx) => {
    const prefix = idx === selectedIndex ? '» ' : '  ';

    if (currentView === 'otp') {
      return `${prefix}{bold}${entry.name}{/bold} {gray-fg}[${sanitizeOtpType(entry.type).toUpperCase()}]{/gray-fg}`;
    }

    const tags = formatTags(entry.tags);
    return `${prefix}{bold}${entry.title}{/bold}${tags ? ` {gray-fg}[${tags}]{/gray-fg}` : ''}`;
  });

  const emptyText = currentView === 'otp'
    ? '  {gray-fg}No OTP entries found{/gray-fg}'
    : currentView === 'notes'
      ? '  {gray-fg}No secure notes found{/gray-fg}'
      : '  {gray-fg}No accounts found{/gray-fg}';

  list.setItems(items.length ? items : [emptyText]);
  list.select(Math.min(selectedIndex, Math.max(0, items.length - 1)));
}

function updateDetails() {
  const selected = getSelectedInfo();
  const e = selected?.entry;

  if (currentView === 'otp') {
    if (!e) {
      codeBig.setContent('------');
      codePlain.setContent('------');
      details.setContent(
        `{bold}Search:{/bold} ${getActiveSearch() || '(none)'}\n\n` +
        'No OTP entry selected.'
      );
      screen.render();
      return;
    }

    const secretText = revealSecret
      ? (e.secret || '[no secret saved]')
      : '••••••••••••';

    details.setContent(
      `Name: {bold}${e.name}{/bold}\n` +
      `Digits: ${sanitizeDigits(e.digits)}   Period: ${sanitizePeriod(e.period)}s   Algo: ${sanitizeAlgorithm(e.algorithm).toUpperCase()}\n` +
      `Secret: ${secretText}\n` +
      `Reveal mode: ${revealSecret ? 'ON' : 'OFF'}\n` +
      `Search: ${getActiveSearch() || '(none)'}\n` +
      `File: ${DATA_FILE}`
    );

    screen.render();
    return;
  }

  if (currentView === 'notes') {
    if (!e) {
      accountDetails.setContent(
        `{bold}Search:{/bold} ${getActiveSearch() || '(none)'}\n\n` +
        'No secure note selected.'
      );
      screen.render();
      return;
    }

    accountDetails.setContent(
      `{bold}${e.title}{/bold}\n\n` +
      `Tags: ${formatTags(e.tags)}\n\n` +
      `{bold}Body:{/bold}\n${e.body || ''}\n\n` +
      `Search: ${getActiveSearch() || '(none)'}\n` +
      `File: ${DATA_FILE}\n` +
      `Updated: ${e.updatedAt || ''}`
    );

    screen.render();
    return;
  }

  if (!e) {
    accountDetails.setContent(
      `{bold}Search:{/bold} ${getActiveSearch() || '(none)'}\n\n` +
      'No account selected.'
    );
    screen.render();
    return;
  }

  const passwordText = revealPassword ? (e.password || '[empty]') : maskValue(e.password);

  accountDetails.setContent(
    `{bold}${e.title}{/bold}\n\n` +
    `Username: ${e.username || ''}\n` +
    `Password: ${passwordText}\n` +
    `URL: ${e.url || ''}\n` +
    `Tags: ${formatTags(e.tags)}\n\n` +
    `{bold}Notes:{/bold}\n${e.notes || ''}\n\n` +
    `Reveal mode: ${revealPassword ? 'ON' : 'OFF'}\n` +
    `Breach check: press b\n` +
    `Search: ${getActiveSearch() || '(none)'}\n` +
    `File: ${DATA_FILE}\n` +
    `Updated: ${e.updatedAt || ''}`
  );

  screen.render();
}

function showWelcomeMessageIfEmpty() {
  if (!db || (db.accounts.length || db.totps.length || db.notes.length)) return;

  const msg = blessed.message({
    parent: screen,
    width: '72%',
    height: 7,
    left: 'center',
    top: 'center',
    border: 'line',
    label: ' Welcome '
  });

  msg.display('Press "1" for OTPs, "2" for accounts, or "3" for notes. Use "a" to add.', 4, () => {
    list.focus();
    screen.render();
  });
}

// ============================================================================
// 08. Lock, unlock, and master-password flow
// ============================================================================
function showUnlockModal({ firstOpen = false } = {}) {
  if (modalOpen) return;

  modalOpen = true;

  db = normaliseVault({});
  MASTER_KEY = null;
  stopIdleTimer();
  clearVisibleSensitiveData();
  revealSecret = false;
  revealPassword = false;
  selectedIndex = 0;
  selectedByView = { otp: 0, accounts: 0, notes: 0 };

  suspendCode();

  list.hide();
  otpInfo.hide();
  details.hide();
  accountDetails.hide();
  help.hide();

  const modal = blessed.box({
    parent: screen,
    width: '60%',
    height: 9,
    left: 'center',
    top: 'center',
    border: 'line',
    label: firstOpen ? ' Unlock Vault ' : ' Vault Locked ',
    keys: true,
    mouse: true,
    tags: true
  });

let isNewVault = true;

try {
  if (fs.existsSync(DATA_FILE)) {
    const raw = fs.readFileSync(DATA_FILE, 'utf8').trim();

    if (raw) {
      const parsed = JSON.parse(raw);

      if (isEncryptedDb(parsed)) {
        isNewVault = false;
      }
    }
  }

  if (fs.existsSync(LEGACY_TOTP_FILE) || fs.existsSync(LEGACY_PASSWORD_FILE)) {
    isNewVault = false;
  }
} catch {
  isNewVault = true;
}

  blessed.text({
    parent: modal,
    top: 1,
    left: 3,
    content: isNewVault ? 'Create master password:' : 'Master password:'
  });

  const input = blessed.textbox({
    parent: modal,
    top: 3,
    left: 3,
    width: '90%',
    height: 1,
    inputOnFocus: true,
    keys: true,
    mouse: true,
    censor: true,
    style: {
      fg: 'white',
      bg: 'black',
      focus: { fg: 'white', bg: 'blue' },
      blur: { fg: 'white', bg: 'blue' }
    }
  });

  const status = blessed.text({
    parent: modal,
    top: 5,
    left: 3,
    width: '90%',
    tags: true,
    content: ''
  });

  const placePasswordCursor = () => {
    if (!modalOpen || !input) return;

    const width = Number(input.width) || 1;
    const valueLength = String(input.getValue() || '').length;
    const cursorX = input.aleft + Math.min(valueLength, Math.max(0, width - 1));
    const cursorY = input.atop;

    screen.program.showCursor();
    screen.program.move(cursorX, cursorY);
  };

  const closeModal = async () => {
    try { input.cancel(); } catch {}
    try { modal.destroy(); } catch {}

    screen.program.hideCursor();

    modalOpen = false;

    list.show();
    help.show();

    if (currentView === 'otp') {
      otpInfo.show();
      details.show();
      accountDetails.hide();
      resumeCode();
    } else if (currentView === 'accounts') {
      otpInfo.hide();
      details.hide();
      accountDetails.show();
      accountDetails.setLabel(' Account Details ');
      suspendCode();
    } else {
      otpInfo.hide();
      details.hide();
      accountDetails.show();
      accountDetails.setLabel(' Secure Note ');
      suspendCode();
    }

    setHelp();
    await refreshList();
    await setSelected(0);
    updateDetails();

    list.focus();
    screen.render();

    showWelcomeMessageIfEmpty();
    resetIdleTimer();
  };

  const tryUnlock = async () => {
    const password = String(input.getValue() || '');

    if (!password.trim()) {
      status.setContent('{red-fg}Password cannot be empty.{/red-fg}');
      input.clearValue();
      input.focus();
      input.readInput();
      screen.render();
      setTimeout(placePasswordCursor, 0);
      return;
    }

    try {
      db = await loadDbFromDisk(password);
      await closeModal();
} catch (err) {
  const message = String(err?.message || err || '');

  const isAuthFailure =
    message.includes('Unsupported state or unable to authenticate data') ||
    message.includes('bad decrypt') ||
    message.includes('authenticate data');

  // Wrong password is expected, not a crash.
  if (!isAuthFailure) {
    try {
      writeCrashLog(err);
    } catch {}
  }

  if (isNewVault) {
    status.setContent(
      '{red-fg}Failed to create vault. See ColdVault-crash.log if this continues.{/red-fg}'
    );
  } else {
    status.setContent(
      '{red-fg}Wrong password or corrupted vault/database.{/red-fg}'
    );
  }

  input.clearValue();
  input.focus();
  input.readInput();

  screen.render();
  setTimeout(placePasswordCursor, 0);
}
  };

  input.on('submit', tryUnlock);

  input.key('escape', () => {
    input.focus();
    input.readInput();
    screen.render();
    setTimeout(placePasswordCursor, 0);
  });

  input.on('keypress', () => setTimeout(placePasswordCursor, 0));

  modal.setFront();
  input.focus();
  input.readInput();
  screen.render();
  setTimeout(placePasswordCursor, 0);
}

function lockVault(options = {}) {
  const force = !!options.force;
  if (!force && (modalOpen || isTyping())) return;

  if (force && modalOpen) {
    destroyTransientScreenChildren();
    modalOpen = false;
  }

  stopIdleTimer();
  clearVisibleSensitiveData();
  showUnlockModal({ firstOpen: false });
}

// ============================================================================
// 09. Shared prompt/modal helpers
// ============================================================================
function promptSimple(label, message, placeholder, onSubmit, options = {}) {
  modalOpen = true;

  const form = blessed.box({
    parent: screen,
    width: options.width || '70%',
    height: options.height || 9,
    left: 'center',
    top: 'center',
    border: 'line',
    label,
    keys: true,
    mouse: true
  });

  blessed.text({
    parent: form,
    top: 1,
    left: 3,
    content: message
  });

  const input = blessed.box({
    parent: form,
    top: 3,
    left: 3,
    width: '92%',
    height: 1,
    content: placeholder || '',
    style: { fg: 'white', bg: 'black' }
  });

  input.value = placeholder || '';
  input.setValue = (v) => {
    input.value = String(v);
    input.setContent(input.value);
  };
  input.getValue = () => input.value;

  const buttonStyle = {
    fg: 'white',
    bg: 'black',
    focus: { inverse: true },
    hover: { inverse: true }
  };

  const btnOk = blessed.button({
    parent: form,
    content: ' OK ',
    shrink: true,
    top: 6,
    left: 3,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const btnClear = blessed.button({
    parent: form,
    content: ' Clear ',
    shrink: true,
    top: 6,
    left: 12,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const btnCancel = blessed.button({
    parent: form,
    content: ' Cancel ',
    shrink: true,
    top: 6,
    left: 23,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const marker = blessed.text({
    parent: form,
    top: 3,
    left: 0,
    width: 2,
    content: '▶',
    style: { fg: 'yellow' }
  });

  const fields = [
    { el: input, top: 3, left: 0, input: true },
    { el: btnOk, top: 6, left: 0, button: true },
    { el: btnClear, top: 6, left: 9, button: true },
    { el: btnCancel, top: 6, left: 20, button: true }
  ];

  let fieldIndex = 0;
  let closed = false;
  let submitting = false;

  const focusField = (idx) => {
    fieldIndex = idx;
    const current = fields[fieldIndex];

    marker.top = current.top;
    marker.left = current.left;

    form.focus();
    screen.render();
  };

  const close = async () => {
    if (closed) return;
    closed = true;

    modalOpen = false;
    screen.removeListener('keypress', handleKey);

    try { form.destroy(); } catch {}

    list.focus();
    screen.render();
  };

  const submit = (value = input.getValue()) => {
    close();
    onSubmit?.(value);
  };

  const handleKey = (ch, key = {}) => {
    const current = fields[fieldIndex];

    if (isTabKey(ch, key)) {
      focusField((fieldIndex + 1) % fields.length);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      focusField((fieldIndex - 1 + fields.length) % fields.length);
      return;
    }

    if (key.name === 'escape') {
      close();
      return;
    }

    if (isEnterKey(ch, key)) {
      if (current.el === btnOk) submit(input.getValue());
      else if (current.el === btnClear) submit('');
      else if (current.el === btnCancel) close();
      else submit(input.getValue());
      return;
    }

    if (!current.input) return;

    if (isBackspaceKey(ch, key)) {
      input.setValue(input.getValue().slice(0, -1));
      screen.render();
      return;
    }

    if (ch && ch.length === 1 && !key.ctrl && !key.meta) {
      input.setValue(input.getValue() + ch);
      screen.render();
    }
  };

  btnOk.on('press', () => submit(input.getValue()));
  btnClear.on('press', () => submit(''));
  btnCancel.on('press', close);
  screen.on('keypress', handleKey);

  form.setFront();
  form.focus();
  focusField(0);

  screen.render();
}

// ============================================================================
// 10. Account forms and account actions
// ============================================================================
function openAccountForm(initial = {}) {
  modalOpen = true;

  const form = blessed.box({
    parent: screen,
    width: '78%',
    height: 22,
    left: 'center',
    top: 'center',
    border: 'line',
    label: initial.id ? ' Edit Account ' : ' Add Account ',
    keys: true,
    mouse: true
  });

  blessed.text({
    parent: form,
    top: 0,
    left: 2,
    content: 'TAB switches fields. Enter activates buttons. Notes are single-line in this version.'
  });

  const marker = blessed.text({
    parent: form,
    top: 2,
    left: 0,
    width: 2,
    content: '▶',
    style: { fg: 'yellow' }
  });

  const makeInput = (top, label, left, width, value = '', hidden = false) => {
    blessed.text({ parent: form, top, left: 3, content: label });

    const box = blessed.box({
      parent: form,
      top,
      left,
      width,
      height: 1,
      content: hidden ? '*'.repeat(String(value).length) : String(value),
      style: { fg: 'white', bg: 'black' }
    });

    box.value = String(value);
    box.hiddenValue = hidden;

    box.setValue = (v) => {
      box.value = String(v);
      box.setContent(box.hiddenValue ? '*'.repeat(box.value.length) : box.value);
    };

    box.getValue = () => box.value;

    return box;
  };

  const inTitle = makeInput(2, 'Title:', 16, '76%', initial.title || '');
  const inUser = makeInput(4, 'Username:', 16, '76%', initial.username || '');
  const inPass = makeInput(6, 'Password:', 16, '76%', initial.password || '', true);
  const inUrl = makeInput(8, 'URL:', 16, '76%', initial.url || '');
  const inTags = makeInput(10, 'Tags:', 16, '76%', formatTags(initial.tags));
  const inNotes = makeInput(12, 'Notes:', 16, '76%', initial.notes || '');

  const buttonStyle = {
    fg: 'white',
    bg: 'black',
    focus: { inverse: true },
    hover: { inverse: true }
  };

  const btnSave = blessed.button({
    parent: form,
    content: ' Save ',
    mouse: true,
    keys: true,
    shrink: true,
    left: 16,
    top: 17,
    style: buttonStyle
  });

  const btnGenerate = blessed.button({
    parent: form,
    content: ' Generate Password ',
    mouse: true,
    keys: true,
    shrink: true,
    left: 27,
    top: 17,
    style: buttonStyle
  });

  const btnCancel = blessed.button({
    parent: form,
    content: ' Cancel ',
    mouse: true,
    keys: true,
    shrink: true,
    left: 49,
    top: 17,
    style: buttonStyle
  });

  const status = blessed.text({
    parent: form,
    top: 19,
    left: 3,
    width: '92%',
    tags: true,
    content: ''
  });

  const fields = [
    { el: inTitle, top: 2, left: 0, input: true },
    { el: inUser, top: 4, left: 0, input: true },
    { el: inPass, top: 6, left: 0, input: true },
    { el: inUrl, top: 8, left: 0, input: true },
    { el: inTags, top: 10, left: 0, input: true },
    { el: inNotes, top: 12, left: 0, input: true },
    { el: btnSave, top: 17, left: 13, button: true },
    { el: btnGenerate, top: 17, left: 24, button: true },
    { el: btnCancel, top: 17, left: 46, button: true }
  ];

  let fieldIndex = 0;
  let closed = false;

  const focusField = (idx) => {
    fieldIndex = idx;
    const current = fields[fieldIndex];

    marker.top = current.top;
    marker.left = current.left;

    form.focus();
    screen.render();
  };

  const close = async () => {
    if (closed) return;
    closed = true;

    modalOpen = false;
    screen.removeListener('keypress', handleKey);

    try {
      btnSave.removeListener('press', submit);
      btnGenerate.removeListener('press', generateIntoPassword);
      btnCancel.removeListener('press', close);
    } catch {}

    try { form.destroy(); } catch {}

    list.focus();
    screen.render();
  };

  const generateIntoPassword = () => {
    const pw = generatePassword(20);
    inPass.setValue(pw);
    status.setContent('{green-fg}Generated a password into the password field.{/green-fg}');
    focusField(2);
    screen.render();
  };

  const submit = async () => {
    const v = {
      title: inTitle.getValue().trim(),
      username: inUser.getValue().trim(),
      password: inPass.getValue(),
      url: inUrl.getValue().trim(),
      tags: sanitizeTags(inTags.getValue()),
      notes: inNotes.getValue().trim()
    };

    if (!v.title) {
      status.setContent('{red-fg}Title is required.{/red-fg}');
      focusField(0);
      return;
    }

    if (!v.password) {
      status.setContent('{red-fg}Password is required. Use Generate Password if needed.{/red-fg}');
      focusField(2);
      return;
    }

    form.emit('submit', v);
    close();
  };

  const handleKey = (ch, key = {}) => {
    const current = fields[fieldIndex];

    if (isTabKey(ch, key)) {
      focusField((fieldIndex + 1) % fields.length);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      focusField((fieldIndex - 1 + fields.length) % fields.length);
      return;
    }

    if (key.name === 'escape') {
      close();
      return;
    }

    if (isEnterKey(ch, key)) {
      if (current.el === btnSave) submit();
      else if (current.el === btnGenerate) generateIntoPassword();
      else if (current.el === btnCancel) close();
      else focusField((fieldIndex + 1) % fields.length);
      return;
    }

    if (!current.input) return;

    const box = current.el;

    if (isBackspaceKey(ch, key)) {
      box.setValue(box.getValue().slice(0, -1));
      screen.render();
      return;
    }

    if (ch && ch.length === 1 && !key.ctrl && !key.meta) {
      box.setValue(box.getValue() + ch);
      screen.render();
    }
  };

  screen.on('keypress', handleKey);

  btnSave.on('press', submit);
  btnGenerate.on('press', generateIntoPassword);
  btnCancel.on('press', close);

  form.setFront();
  form.focus();
  focusField(0);

  screen.render();

  return form;
}

function addAccount() {
  const form = openAccountForm();

  form.on('submit', async (v) => {
    const entry = normaliseAccount({
      id: nanoid(),
      ...v,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    db.accounts.push(entry);
    await saveDb(db);

    setActiveSearch('');
    selectedIndex = db.accounts.length - 1;
    selectedByView.accounts = selectedIndex;

    await refreshList();
    updateDetails();
  });
}

function editAccount() {
  const info = getSelectedInfo();
  if (!info) return;

  const form = openAccountForm(info.entry);

  form.on('submit', async (v) => {
    Object.assign(db.accounts[info.realIndex], v, {
      updatedAt: new Date().toISOString()
    });

    await saveDb(db);
    await refreshList();
    updateDetails();
  });
}

function copySelectedAccountField(fieldName, label) {
  if (modalOpen || isTyping() || currentView !== 'accounts') return;

  const info = getSelectedInfo();
  const value = info?.entry?.[fieldName];

  const msg = blessed.message({
    parent: screen,
    width: '50%',
    height: 5,
    left: 'center',
    top: 'center',
    border: 'line',
    label: ` Copy ${label} `
  });

  if (!value) {
    msg.display(`No ${label.toLowerCase()} saved for this entry.`, 2, () => {
      list.focus();
      screen.render();
    });
    return;
  }

  resetIdleTimer();
  const ok = copyTextToClipboard(value);

  msg.display(
    ok ? `${label} copied to clipboard.` : 'Clipboard copy failed.',
    2,
    () => {
      list.focus();
      screen.render();
    }
  );
}

// ============================================================================
// 11. OTP/TOTP/HOTP forms, import/export, and code actions
// ============================================================================
function openTotpForm(initial = {}) {
  modalOpen = true;
  suspendCode();

  const form = blessed.box({
    parent: screen,
    width: '74%',
    height: 21,
    left: 'center',
    top: 'center',
    border: 'line',
    label: initial.id ? ' Edit OTP Entry ' : ' Add OTP Entry ',
    keys: true,
    mouse: true
  });

  blessed.text({
    parent: form,
    top: 0,
    left: 2,
    content: 'Hint: TAB switches fields. On Type, press T for TOTP or H for HOTP.'
  });

  const marker = blessed.text({
    parent: form,
    top: 2,
    left: 0,
    width: 2,
    content: '▶',
    style: { fg: 'yellow' }
  });

  const makeInput = (top, label, left, width, value = '') => {
    if (label) {
  blessed.text({ parent: form, top, left: 3, content: label });
}
    const box = blessed.box({
      parent: form,
      top,
      left,
      width,
      height: 1,
      content: String(value),
      style: { fg: 'white', bg: 'black' }
    });

    box.value = String(value);
    box.setValue = (v) => {
      box.value = String(v);
      box.setContent(box.value);
    };
    box.getValue = () => box.value;

    return box;
  };

  let otpType = sanitizeOtpType(initial.type);

  const typeBox = blessed.box({
    parent: form,
    top: 2,
    left: 14,
    width: 26,
    height: 1,
    tags: true,
    style: { fg: 'white', bg: 'black' }
  });

  blessed.text({ parent: form, top: 2, left: 3, content: 'Type:' });

  const inName = makeInput(4, 'Name:', 14, '75%', initial.name || '');
  const inSec = makeInput(6, 'Secret (Base32):', 20, '69%', initial.secret || '');
  const inDigits = makeInput(8, 'Digits:', 15, 6, sanitizeDigits(initial.digits ?? 6));
  
const otpExtraLabel = blessed.text({
  parent: form,
  top: 10,
  left: 3,
  width: 12,
  content: 'Period (s):'
});

const inPeriod = makeInput(10, '', 16, 6, sanitizePeriod(initial.period ?? 30));
const inCounter = makeInput(10, '', 16, 12, sanitizeCounter(initial.counter ?? 0));
  
  const inAlg = makeInput(12, 'Algorithm:', 15, 12, sanitizeAlgorithm(initial.algorithm || 'sha1').toUpperCase());

  const setOtpType = (nextType) => {
    otpType = sanitizeOtpType(nextType);
    typeBox.setContent(otpType === 'hotp' ? '{bold}HOTP{/bold}  (T/H)' : '{bold}TOTP{/bold}  (T/H)');

if (otpType === 'hotp') {
  otpExtraLabel.setContent('Counter:');
  inPeriod.hide();
  inCounter.show();
} else {
  otpExtraLabel.setContent('Period (s):');
  inCounter.hide();
  inPeriod.show();
}

    screen.render();
  };

  const buttonStyle = {
    fg: 'white',
    bg: 'black',
    focus: { inverse: true },
    hover: { inverse: true }
  };

  const btnOk = blessed.button({
    parent: form,
    content: ' Save ',
    mouse: true,
    keys: true,
    shrink: true,
    left: 14,
    top: 17,
    style: buttonStyle
  });

  const btnCancel = blessed.button({
    parent: form,
    content: ' Cancel ',
    mouse: true,
    keys: true,
    shrink: true,
    left: 24,
    top: 17,
    style: buttonStyle
  });

  const fields = [
    { el: typeBox, top: 2, left: 0, typeToggle: true },
    { el: inName, top: 4, left: 0, input: true },
    { el: inSec, top: 6, left: 0, input: true },
    { el: inDigits, top: 8, left: 0, input: true },
    { el: inPeriod, top: 10, left: 0, input: true, onlyType: 'totp' },
    { el: inCounter, top: 10, left: 0, input: true, onlyType: 'hotp' },
    { el: inAlg, top: 12, left: 0, input: true },
    { el: btnOk, top: 17, left: 11, button: true },
    { el: btnCancel, top: 17, left: 21, button: true }
  ];

  const visibleFields = () => fields.filter(f => !f.onlyType || f.onlyType === otpType);

  let fieldIndex = 0;
  let closed = false;

  const focusField = (idx) => {
    const visible = visibleFields();
    fieldIndex = ((idx % visible.length) + visible.length) % visible.length;
    const current = visible[fieldIndex];

    marker.top = current.top;
    marker.left = current.left;

    form.focus();
    screen.render();
  };

  const close = async () => {
    if (closed) return;
    closed = true;

    modalOpen = false;
    screen.removeListener('keypress', handleKey);

    try {
      btnOk.removeListener('press', submit);
      btnCancel.removeListener('press', close);
    } catch {}

    try { form.destroy(); } catch {}

    if (currentView === 'otp') resumeCode();

    list.focus();
    screen.render();
  };

  const submit = async () => {
    const v = {
      type: otpType,
      name: inName.getValue().trim(),
      secret: inSec.getValue().trim().replace(/\s+/g, '').toUpperCase(),
      digits: sanitizeDigits(inDigits.getValue() || 6),
      period: sanitizePeriod(inPeriod.getValue() || 30),
      counter: sanitizeCounter(inCounter.getValue() || 0),
      algorithm: sanitizeAlgorithm(inAlg.getValue())
    };

    if (!v.name || !v.secret) return;

    form.emit('submit', v);
    close();
  };

  const handleKey = (ch, key = {}) => {
    const visible = visibleFields();
    const current = visible[fieldIndex];

    if (isTabKey(ch, key)) {
      focusField(fieldIndex + 1);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      focusField(fieldIndex - 1);
      return;
    }

    if (key.name === 'escape') {
      close();
      return;
    }

    if (current.typeToggle && (ch === 't' || ch === 'T')) {
      setOtpType('totp');
      focusField(fieldIndex);
      return;
    }

    if (current.typeToggle && (ch === 'h' || ch === 'H')) {
      setOtpType('hotp');
      focusField(fieldIndex);
      return;
    }

    if (isEnterKey(ch, key)) {
      if (current.typeToggle) setOtpType(otpType === 'totp' ? 'hotp' : 'totp');
      else if (current.el === btnOk) submit();
      else if (current.el === btnCancel) close();
      else focusField(fieldIndex + 1);
      return;
    }

    if (!current.input) return;

    const box = current.el;

    if (isBackspaceKey(ch, key)) {
      box.setValue(box.getValue().slice(0, -1));
      screen.render();
      return;
    }

    if (ch && ch.length === 1 && !key.ctrl && !key.meta) {
      box.setValue(box.getValue() + ch);
      screen.render();
    }
  };

  screen.on('keypress', handleKey);

  btnOk.on('press', submit);
  btnCancel.on('press', close);

  form.setFront();
  form.focus();
  setOtpType(otpType);
  focusField(0);

  screen.render();

  return form;
}

function addTotp() {
  const form = openTotpForm({ type: 'totp', digits: 6, period: 30, counter: 0, algorithm: 'sha1' });

  form.on('submit', async (v) => {
    const entry = normaliseTotp({
      id: nanoid(),
      ...v,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    db.totps.push(entry);
    await saveDb(db);

    setActiveSearch('');
    selectedIndex = db.totps.length - 1;
    selectedByView.otp = selectedIndex;

    await refreshList();
    updateDetails();
  });
}

function editTotp() {
  const info = getSelectedInfo();
  if (!info) return;

  const form = openTotpForm(info.entry);

  form.on('submit', async (v) => {
    Object.assign(db.totps[info.realIndex], v, {
      updatedAt: new Date().toISOString()
    });

    await saveDb(db);
    await refreshList();
    updateDetails();
  });
}

async function importOtpauth() {
  if (currentView !== 'otp') await switchView('otp');

  promptSimple(
    ' Import otpauth URL ',
    'Paste an otpauth:// URL and press Enter on OK.',
    'otpauth://totp/Issuer:Label?secret=BASE32...',
    async (txt) => {
      try {
        if (!txt) {
          list.focus();
          screen.render();
          return;
        }

        const v = parseOtpauth(txt.trim());
        const entry = normaliseTotp({ id: nanoid(), ...v });

        db.totps.push(entry);
        await saveDb(db);

        setActiveSearch('');
        selectedIndex = db.totps.length - 1;
        selectedByView.otp = selectedIndex;

        await refreshList();
        updateDetails();

        list.focus();
        screen.render();
      } catch (e) {
        const err = blessed.message({
          parent: screen,
          width: '55%',
          height: 5,
          left: 'center',
          top: 'center',
          border: 'line',
          label: ' Error '
        });

        err.display(`Invalid otpauth URI\n${e?.message || e}`, 3, () => {
          list.focus();
          screen.render();
        });
      }
    },
    { width: '80%' }
  );
}

function exportOtpauth() {
  if (currentView !== 'otp') return;

  const info = getSelectedInfo();
  const e = info?.entry;

  if (!e) return;

  let uri = '';

  try {
    uri = buildOtpauthUri(e);
  } catch (err) {
    const msg = blessed.message({
      parent: screen,
      width: '60%',
      height: 5,
      left: 'center',
      top: 'center',
      border: 'line',
      label: ' Export Error '
    });

    msg.display(String(err?.message || err), 3, () => {
      list.focus();
      screen.render();
    });
    return;
  }

  modalOpen = true;
  suspendCode();

  const modal = blessed.box({
    parent: screen,
    width: '76%',
    height: 10,
    left: 'center',
    top: 'center',
    border: 'line',
    label: ' Export otpauth URL ',
    keys: true,
    mouse: true,
    tags: true
  });

  blessed.text({
    parent: modal,
    top: 1,
    left: 3,
    width: '92%',
    tags: true,
    content: 'This will copy the full single-line otpauth URL for the selected account.'
  });

  blessed.box({
    parent: modal,
    top: 3,
    left: 3,
    width: '92%',
    height: 1,
    tags: false,
    style: { fg: 'white', bg: 'black' },
    content: uri.length > 90 ? `${uri.slice(0, 87)}...` : uri
  });

  const status = blessed.text({
    parent: modal,
    top: 7,
    left: 3,
    width: '92%',
    tags: true,
    content: ''
  });

  const buttonStyle = {
    fg: 'white',
    bg: 'black',
    focus: { inverse: true },
    hover: { inverse: true }
  };

  const btnCopy = blessed.button({
    parent: modal,
    content: ' Copy ',
    shrink: true,
    top: 5,
    left: 3,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const btnCancel = blessed.button({
    parent: modal,
    content: ' Cancel ',
    shrink: true,
    top: 5,
    left: 14,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const marker = blessed.text({
    parent: modal,
    content: '▶',
    top: 5,
    left: 1,
    width: 2,
    style: { fg: 'yellow' }
  });

  const buttons = [
    { el: btnCopy, markerLeft: 1 },
    { el: btnCancel, markerLeft: 12 }
  ];

  let buttonIndex = 0;
  let closed = false;
  let hotpConsumed = false;

  const focusButton = (idx) => {
    buttonIndex = idx;
    marker.left = buttons[buttonIndex].markerLeft;
    modal.focus();
    screen.render();
  };

  const close = async () => {
    if (closed) return;
    closed = true;

    screen.removeListener('keypress', keyHandler);

    try {
      btnCopy.removeListener('press', doCopy);
      btnCancel.removeListener('press', close);
    } catch {}

    try { modal.destroy(); } catch {}

    modalOpen = false;

    await refreshList();
    updateDetails();

    if (currentView === 'otp') resumeCode();

    list.setFront();
    otpInfo.setFront();
    details.setFront();
    accountDetails.setFront();
    help.setFront();

    list.focus();
    screen.render();
  };

  const doCopy = () => {
    const ok = copyTextToClipboard(uri);

    status.setContent(
      ok
        ? '{green-fg}Copied full otpauth URL to clipboard.{/green-fg}'
        : '{red-fg}Clipboard copy failed. On Linux, install wl-copy/xclip/xsel.{/red-fg}'
    );

    screen.render();
  };

  const keyHandler = (ch, key = {}) => {
    if (!modalOpen || closed) return;

    if (isTabKey(ch, key) || key.name === 'left' || key.name === 'right') {
      focusButton((buttonIndex + 1) % buttons.length);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      focusButton((buttonIndex - 1 + buttons.length) % buttons.length);
      return;
    }

    if (isEnterKey(ch, key)) {
      if (buttonIndex === 0) doCopy();
      else close();
      return;
    }

    if (key.name === 'escape' || ch === 'q') {
      close();
      return;
    }

    if (ch === 'c') doCopy();
  };

  btnCopy.on('press', doCopy);
  btnCancel.on('press', close);
  screen.on('keypress', keyHandler);

  modal.setFront();
  focusButton(0);
  screen.render();
}

function getCurrentTotpEntry() {
  if (currentView !== 'otp') return null;
  const info = getSelectedInfo();
  return info?.entry || null;
}

function generateOtpCodeForEntry(entry) {
  if (!entry || !entry.secret) {
    throw new Error('No OTP entry selected.');
  }

  const digits = sanitizeDigits(entry.digits);
  const algorithm = sanitizeAlgorithm(entry.algorithm);
  const secret = String(entry.secret || '').trim();

  if (sanitizeOtpType(entry.type) === 'hotp') {
    hotp.options = { digits, algorithm };
    return hotp.generate(secret, sanitizeCounter(entry.counter));
  }

  const period = sanitizePeriod(entry.period);
  authenticator.options = { digits, step: period, algorithm };
  return authenticator.generate(secret);
}

function getCurrentTotpCode() {
  const e = getCurrentTotpEntry();
  return generateOtpCodeForEntry(e);
}

async function incrementSelectedHotpCounter(entryId) {
  const idx = db.totps.findIndex(entry => entry.id === entryId);
  if (idx < 0) return false;

  db.totps[idx].counter = sanitizeCounter(db.totps[idx].counter) + 1;
  db.totps[idx].updatedAt = new Date().toISOString();
  await saveDb(db);
  return true;
}

function showHotpGenerateModal() {
  if (modalOpen || isTyping() || currentView !== 'otp') return;

  const info = getSelectedInfo();
  const e = info?.entry;

  if (!e || sanitizeOtpType(e.type) !== 'hotp') {
    copyCurrentTotpCode();
    return;
  }

  let code = '';

  try {
    code = generateOtpCodeForEntry(e);
  } catch (err) {
    const msg = blessed.message({
      parent: screen,
      width: '50%',
      height: 5,
      left: 'center',
      top: 'center',
      border: 'line',
      label: ' HOTP Error '
    });

    msg.display(String(err?.message || err), 3, () => {
      list.focus();
      screen.render();
    });
    return;
  }

  modalOpen = true;
  suspendCode();

  const modal = blessed.box({
    parent: screen,
    width: '62%',
    height: 12,
    left: 'center',
    top: 'center',
    border: 'line',
    label: ' Generate HOTP Code ',
    keys: true,
    mouse: true,
    tags: true,
    padding: { left: 2, right: 2 }
  });

  blessed.text({
    parent: modal,
    top: 1,
    left: 3,
    tags: true,
    content: `Account: {bold}${e.name}{/bold}   Counter: ${sanitizeCounter(e.counter)}`
  });

  blessed.text({
    parent: modal,
    top: 3,
    left: 3,
    tags: true,
    content: `Code: {bold}${code}{/bold}`
  });

  blessed.text({
    parent: modal,
    top: 5,
    left: 3,
    width: '90%',
    content: 'The counter will only increment when you confirm use.'
  });

  const buttonStyle = {
    fg: 'white',
    bg: 'black',
    focus: { inverse: true },
    hover: { inverse: true }
  };

  const btnUse = blessed.button({
    parent: modal,
    content: ' Copy + Increment ',
    shrink: true,
    top: 7,
    left: 3,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const btnCopyOnly = blessed.button({
    parent: modal,
    content: ' Copy Only ',
    shrink: true,
    top: 7,
    left: 24,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const btnCancel = blessed.button({
    parent: modal,
    content: ' Cancel ',
    shrink: true,
    top: 7,
    left: 39,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const marker = blessed.text({
    parent: modal,
    content: '▶',
    top: 7,
    left: 1,
    width: 2,
    style: { fg: 'yellow' }
  });

  const buttons = [
    { el: btnUse, markerLeft: 1 },
    { el: btnCopyOnly, markerLeft: 22 },
    { el: btnCancel, markerLeft: 37 }
  ];

  let buttonIndex = 0;
  let closed = false;
  let handled = false;

  const focusButton = (idx) => {
    if (closed) return;
    buttonIndex = ((idx % buttons.length) + buttons.length) % buttons.length;
    marker.left = buttons[buttonIndex].markerLeft;

    // Keep focus on the modal itself. Focusing a button that is later destroyed can
    // leave blessed pointing at a dead element until the terminal focus changes.
    try { modal.focus(); } catch {}
    screen.render();
  };

  const cleanup = () => {
    screen.removeListener('keypress', keyHandler);

    try {
      btnUse.removeListener('press', useAndIncrement);
      btnCopyOnly.removeListener('press', copyOnly);
      btnCancel.removeListener('press', close);
    } catch {}
  };

  const close = async () => {
    if (closed) return;
    closed = true;

    cleanup();

    try { modal.destroy(); } catch {}

    modalOpen = false;

    await refreshList();
    updateDetails();

    if (currentView === 'otp') resumeCode();

    list.setFront();
    otpInfo.setFront();
    details.setFront();
    accountDetails.setFront();
    help.setFront();

    list.focus();
    screen.render();
  };

  const flashResult = (label, text, seconds = 2) => {
    // Use a plain non-focus notification instead of blessed.message. blessed.message
    // can temporarily steal focus/key handling after a modal button is destroyed.
    const notice = blessed.box({
      parent: screen,
      width: '50%',
      height: 5,
      left: 'center',
      top: 'center',
      border: 'line',
      label,
      tags: true,
      content: `\n ${text}`
    });

    notice.setFront();
    try { list.focus(); } catch {}
    screen.render();

    setTimeout(() => {
      try { notice.destroy(); } catch {}
      try { list.setFront(); } catch {}
      try { otpInfo.setFront(); } catch {}
      try { details.setFront(); } catch {}
      try { accountDetails.setFront(); } catch {}
      try { help.setFront(); } catch {}
      try { list.focus(); } catch {}
      screen.render();
    }, Math.max(1, seconds) * 1000);
  };

  const copyOnly = () => {
    if (handled || closed) return;
    handled = true;

    resetIdleTimer();
    const ok = copyTextToClipboard(code);
    close();

    flashResult(' HOTP Code ', ok ? 'Copied. Counter not changed.' : 'Clipboard copy failed. Counter not changed.');
  };

  const useAndIncrement = async () => {
    if (handled || closed) return;
    handled = true;

    resetIdleTimer();
    const ok = copyTextToClipboard(code);
    await incrementSelectedHotpCounter(e.id);
    close();

    flashResult(
      ' HOTP Code ',
      ok ? 'Copied and counter incremented.' : 'Counter incremented, but clipboard copy failed.'
    );
  };

  const keyHandler = (ch, key = {}) => {
    if (!modalOpen || closed) return;

    if (isTabKey(ch, key) || key.name === 'left' || key.name === 'right') {
      focusButton(buttonIndex + 1);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      focusButton(buttonIndex - 1);
      return;
    }

    if (isEnterKey(ch, key)) {
      if (buttonIndex === 0) useAndIncrement();
      else if (buttonIndex === 1) copyOnly();
      else close();
      return;
    }

    if (key.name === 'escape' || ch === 'q') {
      close();
    }
  };

  btnUse.on('press', useAndIncrement);
  btnCopyOnly.on('press', copyOnly);
  btnCancel.on('press', close);
  screen.on('keypress', keyHandler);

  modal.setFront();
  focusButton(0);
  screen.render();
}

function copyCurrentTotpCode() {
  if (modalOpen || isTyping() || currentView !== 'otp') return;

  const e = getCurrentTotpEntry();

  if (e && sanitizeOtpType(e.type) === 'hotp') {
    showHotpGenerateModal();
    return;
  }

  let code = '';

  try {
    code = getCurrentTotpCode();
  } catch (err) {
    const msg = blessed.message({
      parent: screen,
      width: '50%',
      height: 5,
      left: 'center',
      top: 'center',
      border: 'line',
      label: ' Copy Error '
    });

    msg.display(String(err?.message || err), 3, () => {
      list.focus();
      screen.render();
    });
    return;
  }

  resetIdleTimer();
  const ok = copyTextToClipboard(code);

  const msg = blessed.message({
    parent: screen,
    width: '50%',
    height: 5,
    left: 'center',
    top: 'center',
    border: 'line',
    label: ' Copy Code '
  });

  msg.display(
    ok ? 'Current TOTP code copied to clipboard.' : 'Clipboard copy failed.',
    2,
    () => {
      list.focus();
      screen.render();
    }
  );
}

// ============================================================================
// 12. Secure-note forms and note actions
// ============================================================================
function openNoteForm(initial = {}) {
  modalOpen = true;

  const form = blessed.box({
    parent: screen,
    width: '82%',
    height: 24,
    left: 'center',
    top: 'center',
    border: 'line',
    label: initial.id ? ' Edit Secure Note ' : ' Add Secure Note ',
    keys: true,
    mouse: true
  });

  blessed.text({
    parent: form,
    top: 0,
    left: 2,
    content: 'Body supports multiple lines. In Body: Esc moves to Save. Tab inserts indentation.'
  });

  const marker = blessed.text({
    parent: form,
    top: 2,
    left: 0,
    width: 2,
    content: '▶',
    style: { fg: 'yellow' }
  });

  const makeInput = (top, label, left, width, value = '') => {
    blessed.text({ parent: form, top, left: 3, content: label });

    const box = blessed.box({
      parent: form,
      top,
      left,
      width,
      height: 1,
      content: String(value),
      style: { fg: 'white', bg: 'black' }
    });

    box.value = String(value);
    box.setValue = (v) => {
      box.value = String(v);
      box.setContent(box.value);
    };
    box.getValue = () => box.value;

    return box;
  };

  const inTitle = makeInput(2, 'Title:', 14, '78%', initial.title || '');
  const inTags = makeInput(4, 'Tags:', 14, '78%', formatTags(initial.tags));

  blessed.text({ parent: form, top: 6, left: 3, content: 'Body:' });

  const inBody = blessed.textarea({
    parent: form,
    top: 7,
    left: 14,
    width: '78%',
    height: 10,
    value: String(initial.body || ''),
    inputOnFocus: true,
    keys: true,
    mouse: true,
    scrollable: true,
    alwaysScroll: true,
    border: 'line',
    style: {
      fg: 'white',
      bg: 'black',
      focus: { fg: 'white', bg: 'blue' }
    }
  });

inBody.key(['escape'], () => {
  try { inBody.cancel(); } catch {}
  focusField(3); // Save button
});

  const buttonStyle = {
    fg: 'white',
    bg: 'black',
    focus: { inverse: true },
    hover: { inverse: true }
  };

  const btnSave = blessed.button({
    parent: form,
    content: ' Save ',
    mouse: true,
    keys: true,
    shrink: true,
    left: 14,
    top: 19,
    style: buttonStyle
  });

  const btnCancel = blessed.button({
    parent: form,
    content: ' Cancel ',
    mouse: true,
    keys: true,
    shrink: true,
    left: 25,
    top: 19,
    style: buttonStyle
  });

  const status = blessed.text({
    parent: form,
    top: 21,
    left: 3,
    width: '92%',
    tags: true,
    content: ''
  });

  const fields = [
    { el: inTitle, top: 2, left: 0, input: true },
    { el: inTags, top: 4, left: 0, input: true },
    { el: inBody, top: 7, left: 11, textarea: true },
    { el: btnSave, top: 19, left: 11, button: true },
    { el: btnCancel, top: 19, left: 22, button: true }
  ];

  let fieldIndex = 0;
  let closed = false;

  const focusField = (idx) => {
    fieldIndex = ((idx % fields.length) + fields.length) % fields.length;
    const current = fields[fieldIndex];

    marker.top = current.top;
    marker.left = current.left;

if (current.textarea) {
  current.el.focus();

  // Prevent textarea from eating TAB forever
  current.el.readInput((err, value) => {});
} else {
  form.focus();
}

    screen.render();
  };

  const close = async () => {
    if (closed) return;
    closed = true;

    modalOpen = false;
    screen.removeListener('keypress', handleKey);

    try {
      btnSave.removeListener('press', submit);
      btnCancel.removeListener('press', close);
    } catch {}

    try { form.destroy(); } catch {}

    list.focus();
    screen.render();
  };

  const submit = async () => {
    const v = {
      title: inTitle.getValue().trim(),
      tags: sanitizeTags(inTags.getValue()),
      body: String(inBody.getValue() || '').trim()
    };

    if (!v.title) {
      status.setContent('{red-fg}Title is required.{/red-fg}');
      focusField(0);
      return;
    }

    form.emit('submit', v);
    close();
  };

  const handleKey = (ch, key = {}) => {
    const current = fields[fieldIndex];

    if (isTabKey(ch, key)) {
      if (current.textarea) {
        try { current.el.cancel(); } catch {}
      }
      focusField(fieldIndex + 1);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      if (current.textarea) {
        try { current.el.cancel(); } catch {}
      }
      focusField(fieldIndex - 1);
      return;
    }

    if (key.name === 'escape') {
      close();
      return;
    }

    if (current.textarea) {
      return;
    }

    if (isEnterKey(ch, key)) {
      if (current.el === btnSave) submit();
      else if (current.el === btnCancel) close();
      else focusField(fieldIndex + 1);
      return;
    }

    if (!current.input) return;

    const box = current.el;

    if (isBackspaceKey(ch, key)) {
      box.setValue(box.getValue().slice(0, -1));
      screen.render();
      return;
    }

    if (ch && ch.length === 1 && !key.ctrl && !key.meta) {
      box.setValue(box.getValue() + ch);
      screen.render();
    }
  };

  screen.on('keypress', handleKey);

  btnSave.on('press', submit);
  btnCancel.on('press', close);

  form.setFront();
  focusField(0);
  screen.render();

  return form;
}


function addNote() {
  const form = openNoteForm();

  form.on('submit', async (v) => {
    const entry = normaliseNote({
      id: nanoid(),
      ...v,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    db.notes.push(entry);
    await saveDb(db);

    setActiveSearch('');
    selectedIndex = db.notes.length - 1;
    selectedByView.notes = selectedIndex;

    await refreshList();
    updateDetails();
  });
}

function editNote() {
  const info = getSelectedInfo();
  if (!info) return;

  const form = openNoteForm(info.entry);

  form.on('submit', async (v) => {
    Object.assign(db.notes[info.realIndex], v, {
      updatedAt: new Date().toISOString()
    });

    await saveDb(db);
    await refreshList();
    updateDetails();
  });
}

// ============================================================================
// 13. Shared entry actions
// ============================================================================
function addEntry() {
  if (currentView === 'otp') addTotp();
  else if (currentView === 'notes') addNote();
  else addAccount();
}

function editEntry() {
  if (currentView === 'otp') editTotp();
  else if (currentView === 'notes') editNote();
  else editAccount();
}

function deleteEntry() {
  const info = getSelectedInfo();
  if (!info) return;

  const label = currentView === 'otp'
    ? info.entry.name
    : info.entry.title;

  modalOpen = true;
  if (currentView === 'otp') suspendCode();

  const modal = blessed.box({
    parent: screen,
    width: '50%',
    height: 7,
    left: 'center',
    top: 'center',
    border: 'line',
    label: ' Confirm ',
    content: `\n Delete "${label}"?\n`,
    keys: true,
    mouse: true,
    tags: true
  });

  const marker = blessed.text({
    parent: modal,
    content: '▶',
    top: 4,
    left: 7,
    width: 2,
    style: { fg: 'yellow' }
  });

  const yes = blessed.button({
    parent: modal,
    content: ' Yes ',
    left: 10,
    top: 4,
    shrink: true,
    keys: true,
    mouse: true,
    style: { fg: 'white', bg: 'black', focus: { inverse: true } }
  });

  const no = blessed.button({
    parent: modal,
    content: ' No ',
    left: 20,
    top: 4,
    shrink: true,
    keys: true,
    mouse: true,
    style: { fg: 'white', bg: 'black', focus: { inverse: true } }
  });

  let closed = false;
  let confirmIndex = 0;

  const buttons = [
    { el: yes, markerLeft: 7 },
    { el: no, markerLeft: 17 }
  ];

  const focusConfirm = (idx) => {
    confirmIndex = idx;
    marker.left = buttons[confirmIndex].markerLeft;
    modal.focus();
    screen.render();
  };

  const closeModal = async () => {
    if (closed) return;
    closed = true;

    modalOpen = false;
    screen.removeListener('keypress', deleteKeyHandler);

    try { modal.destroy(); } catch {}

    if (currentView === 'otp') resumeCode();

    list.focus();
    screen.render();
  };

  const confirmDelete = async () => {
    if (currentView === 'otp') {
      db.totps.splice(info.realIndex, 1);
    } else if (currentView === 'notes') {
      db.notes.splice(info.realIndex, 1);
    } else {
      db.accounts.splice(info.realIndex, 1);
    }

    await saveDb(db);

    selectedIndex = Math.min(selectedIndex, getFilteredItems().length - 1);
    if (selectedIndex < 0) selectedIndex = 0;
    selectedByView[currentView] = selectedIndex;

    await refreshList();
    updateDetails();
    closeModal();
  };

  const deleteKeyHandler = (ch, key = {}) => {
    if (!modalOpen || closed) return;

    if (isTabKey(ch, key) || key.name === 'left' || key.name === 'right') {
      focusConfirm((confirmIndex + 1) % buttons.length);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      focusConfirm((confirmIndex - 1 + buttons.length) % buttons.length);
      return;
    }

    if (isEnterKey(ch, key)) {
      if (confirmIndex === 0) confirmDelete();
      else closeModal();
      return;
    }

    if (key.name === 'escape' || ch === 'n') {
      closeModal();
      return;
    }

    if (ch === 'y') {
      confirmDelete();
    }
  };

  screen.on('keypress', deleteKeyHandler);
  yes.on('press', confirmDelete);
  no.on('press', closeModal);

  modal.setFront();
  modal.focus();
  focusConfirm(0);
  screen.render();
}

function searchEntries() {
  if (modalOpen || isTyping()) return;

  const promptMessage = currentView === 'otp'
    ? 'Search OTP names:'
    : currentView === 'notes'
      ? 'Search note title, body, or tags:'
      : 'Search title, username, URL, tags, or notes:';

  promptSimple(' Search ', promptMessage, getActiveSearch(), async (value) => {
    setActiveSearch(value);
    selectedIndex = 0;
    selectedByView[currentView] = 0;

    await refreshList();
    updateDetails();

    list.focus();
    screen.render();
  });
}

function changeMasterPassword() {
  if (modalOpen || isTyping()) return;

  modalOpen = true;
  if (currentView === 'otp') suspendCode();

  const modal = blessed.box({
    parent: screen,
    width: '70%',
    height: 15,
    left: 'center',
    top: 'center',
    border: 'line',
    label: ' Change Master Password ',
    keys: true,
    mouse: true,
    tags: true
  });

  blessed.text({
    parent: modal,
    top: 1,
    left: 3,
    content: 'Enter current password, then the new master password twice.'
  });

  const marker = blessed.text({
    parent: modal,
    content: '▶',
    top: 3,
    left: 1,
    width: 2,
    style: { fg: 'yellow' }
  });

  const makePasswordBox = (top, label) => {
    blessed.text({
      parent: modal,
      top,
      left: 3,
      content: label
    });

    const box = blessed.box({
      parent: modal,
      top,
      left: 25,
      width: '65%',
      height: 1,
      content: '',
      style: { fg: 'white', bg: 'black' }
    });

    box.value = '';
    box.setValue = (v) => {
      box.value = String(v);
      box.setContent('*'.repeat(box.value.length));
    };
    box.getValue = () => box.value;

    return box;
  };

  const currentInput = makePasswordBox(3, 'Current password:');
  const newInput = makePasswordBox(5, 'New password:');
  const confirmInput = makePasswordBox(7, 'Confirm password:');

  const status = blessed.text({
    parent: modal,
    top: 12,
    left: 3,
    width: '92%',
    tags: true,
    content: ''
  });

  const buttonStyle = {
    fg: 'white',
    bg: 'black',
    focus: { inverse: true },
    hover: { inverse: true }
  };

  const btnSave = blessed.button({
    parent: modal,
    content: ' Save ',
    shrink: true,
    top: 10,
    left: 25,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const btnCancel = blessed.button({
    parent: modal,
    content: ' Cancel ',
    shrink: true,
    top: 10,
    left: 36,
    keys: true,
    mouse: true,
    style: buttonStyle
  });

  const fields = [
    { el: currentInput, top: 3, left: 23, input: true },
    { el: newInput, top: 5, left: 23, input: true },
    { el: confirmInput, top: 7, left: 23, input: true },
    { el: btnSave, top: 10, left: 23, button: true },
    { el: btnCancel, top: 10, left: 34, button: true }
  ];

  let fieldIndex = 0;
  let closed = false;
  let submitting = false;

  const focusField = (idx) => {
    fieldIndex = idx;
    const current = fields[fieldIndex];

    marker.top = current.top;
    marker.left = current.left;

    modal.focus();
    screen.render();
  };

  const close = async () => {
    if (closed) return;
    closed = true;

    screen.removeListener('keypress', keyHandler);

    try {
      btnSave.removeListener('press', submit);
      btnCancel.removeListener('press', close);
    } catch {}

    try { modal.destroy(); } catch {}

    modalOpen = false;

    await refreshList();
    updateDetails();

    if (currentView === 'otp') resumeCode();

    list.setFront();
    otpInfo.setFront();
    details.setFront();
    accountDetails.setFront();
    help.setFront();

    list.focus();
    screen.render();
  };

const submit = async () => {
    if (submitting) return;
    submitting = true;

    const currentPassword = currentInput.getValue();
    const newPassword = newInput.getValue();
    const confirmPassword = confirmInput.getValue();

    if (!currentPassword || !newPassword || !confirmPassword) {
      submitting = false;
      status.setContent('{red-fg}All password fields are required.{/red-fg}');
      screen.render();
      return;
    }

    if (newPassword !== confirmPassword) {
      submitting = false;
      status.setContent('{red-fg}New passwords do not match.{/red-fg}');
      newInput.setValue('');
      confirmInput.setValue('');
      focusField(1);
      screen.render();
      return;
    }

    if (newPassword.length < 8) {
      submitting = false;
      status.setContent('{red-fg}New password should be at least 8 characters.{/red-fg}');
      focusField(1);
      screen.render();
      return;
    }

    try {
      const verifiedDb = await loadDbFromDisk(currentPassword);

      db = verifiedDb;
      MASTER_KEY = newPassword;
      await saveEncryptedDb(db);

      status.setContent('{green-fg}✅ Master password changed successfully.{/green-fg}');
      screen.render();

      setTimeout(close, 900);
    } catch {
      submitting = false;
      status.setContent('{red-fg}❌ Current password is incorrect.{/red-fg}');
      currentInput.setValue('');
      focusField(0);
      screen.render();
    }
  };

  const keyHandler = (ch, key = {}) => {
    if (!modalOpen || closed) return;

    const current = fields[fieldIndex];

    if (isTabKey(ch, key)) {
      focusField((fieldIndex + 1) % fields.length);
      return;
    }

    if (isShiftTabKey(ch, key)) {
      focusField((fieldIndex - 1 + fields.length) % fields.length);
      return;
    }

    if (key.name === 'escape') {
      close();
      return;
    }

    if (isEnterKey(ch, key)) {
      if (current.el === btnSave) submit();
      else if (current.el === btnCancel) close();
      else focusField((fieldIndex + 1) % fields.length);
      return;
    }

    if (!current.input) return;

    const box = current.el;

    if (isBackspaceKey(ch, key)) {
      box.setValue(box.getValue().slice(0, -1));
      screen.render();
      return;
    }

    if (ch && ch.length === 1 && !key.ctrl && !key.meta) {
      box.setValue(box.getValue() + ch);
      screen.render();
    }
  };

  btnSave.on('press', submit);
  btnCancel.on('press', close);
  screen.on('keypress', keyHandler);

  modal.setFront();
  focusField(0);
  screen.render();
}

// ============================================================================
// 14. OTP render loop
// ============================================================================
function fitsBigText(digitCount, containerWidth) {
  const need = (digitCount * 8) + 10;
  const cols = Number(containerWidth) || 0;
  return cols >= need;
}

function suspendCode() {
  codeBig.hidden = true;
  codePlain.hidden = true;
  progress.setProgress(0);
  try { screen.render(); } catch {}
}

function resumeCode() {
  if (currentView !== 'otp') return;
  codeBig.hidden = false;
  codePlain.hidden = false;
  renderTotp();
  screen.render();
}

function renderTotp() {
  if (currentView !== 'otp' || modalOpen || !MASTER_KEY) return;

  const e = getCurrentTotpEntry();

  if (!e) {
    codeBig.setContent('------');
    codePlain.setContent('------');
    progress.setProgress(0);
    screen.render();
    return;
  }

  if (sanitizeOtpType(e.type) === 'hotp') {
    const text = 'HOTP';
    codeBig.hidden = true;
    codePlain.hidden = false;
    codePlain.setContent(`Press g/c to generate next HOTP code  |  Counter ${sanitizeCounter(e.counter)}`);
    progress.setProgress(0);
    screen.render();
    return;
  }

  const digits = sanitizeDigits(e.digits);
  const period = sanitizePeriod(e.period);
  const algorithm = sanitizeAlgorithm(e.algorithm);

  authenticator.options = { digits, step: period, algorithm };

  let code = '——';
  try { code = authenticator.generate((e.secret || '').trim()); } catch {}

  let rem = 0;
  try { rem = authenticator.timeRemaining(); } catch { rem = 0; }

  const elapsed = Math.max(0, period - rem);
  const pct = Math.max(0, Math.min(100, Math.round((elapsed / period) * 100)));

  const cols = (Number(otpInfo.width) || Number(screen.width) || 0) - 4;

  const showBig =
    !resizeTimer &&
    screen.width >= 80 &&
    screen.height >= 24 &&
    cols >= 60 &&
    fitsBigText(String(code).length, cols);

  if (showBig) {
    codeBig.setContent(code);
    codeBig.hidden = false;
    codePlain.hidden = true;
  } else {
    codePlain.setContent(code);
    codePlain.hidden = false;
    codeBig.hidden = true;
  }

  progress.setProgress(pct);
  screen.render();
}

// ============================================================================
// 15. Global keyboard shortcuts
// ============================================================================
list.on('select', (item, idx) => { void setSelected(idx); });

screen.key(['1'], () => { void switchView('otp'); });
screen.key(['2'], () => { void switchView('accounts'); });
screen.key(['3'], () => { void switchView('notes'); });

screen.key(['a'], () => {
  if (modalOpen) return;
  addEntry();
});

screen.key(['e'], () => {
  if (modalOpen) return;
  editEntry();
});

screen.key(['d'], () => {
  if (modalOpen) return;
  deleteEntry();
});

screen.key(['s'], () => {
  if (modalOpen) return;
  searchEntries();
});

screen.key(['i'], () => {
  if (modalOpen || currentView !== 'otp') return;
  void importOtpauth();
});

screen.key(['x'], () => {
  if (modalOpen || currentView !== 'otp') return;
  exportOtpauth();
});

screen.key(['c'], () => {
  copyCurrentTotpCode();
});

screen.key(['g'], () => {
  showHotpGenerateModal();
});

screen.key(['r'], () => {
  if (modalOpen) return;

  if (currentView === 'otp') {
    revealSecret = !revealSecret;
  } else if (currentView === 'accounts') {
    revealPassword = !revealPassword;
  }

  updateDetails();
  screen.render();
});

screen.key(['u'], () => {
  copySelectedAccountField('username', 'Username');
});

screen.key(['p'], () => {
  copySelectedAccountField('password', 'Password');
});

screen.key(['o'], () => {
  copySelectedAccountField('url', 'URL');
});

screen.key(['b'], () => {
  checkSelectedAccountBreach();
});

screen.key(['m'], () => {
  changeMasterPassword();
});

screen.key(['l'], () => {
  lockVault();
});

screen.key(['tab'], () => {
  if (modalOpen) return;
  list.focus();
  screen.render();
});

// ============================================================================
// 16. Boot/startup
// ============================================================================
function boot() {
  setHelp();
  showUnlockModal({ firstOpen: true });

setInterval(() => {
  if (modalOpen || !MASTER_KEY) return;
  renderTotp();
}, 250);

  screen.on('resize', () => {
    clearTimeout(resizeTimer);

    if (!modalOpen && currentView === 'otp') {
      codeBig.hidden = true;
      codePlain.hidden = false;
      codePlain.setContent('Resizing...');
      screen.render();
    }

    resizeTimer = setTimeout(async () => {
      try {
        screen.realloc();

        if (!modalOpen) {
          list.setFront();
          otpInfo.setFront();
          details.setFront();
          accountDetails.setFront();
          help.setFront();

          await refreshList();
          updateDetails();

          if (currentView === 'otp') renderTotp();
        }

        screen.render();
      } catch {
        codeBig.hidden = true;
        codePlain.hidden = false;
        codePlain.setContent('------');

        try { screen.render(); } catch {}
      }

      resizeTimer = null;
    }, 150);
  });
}

boot();