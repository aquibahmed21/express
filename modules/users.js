/**
 * Signaling users – phone + password registration and login.
 * Accounts are stored in <FAMILY_DIR>/signaling-users.json.
 *
 * Routes:
 *   POST /api/register  { phone, password, name }  → { token, name, phone }
 *   POST /api/login     { phone, password }         → { token, name, phone }
 *   GET  /api/me        Bearer token                → { phone, name }
 *
 * Tokens are signed HMAC-SHA256 JWTs (manual, no deps), 30-day expiry.
 * Set JWT_SECRET env var for stable tokens across restarts; random otherwise.
 */
const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { FAMILY_DIR, atomicWrite } = require('./storage');

const USERS_FILE = path.join(FAMILY_DIR, 'signaling-users.json');
const PHONE_RE = /^\+?[0-9]{7,15}$/;

// In-memory store: phone → { phone, name, salt, hash, createdAt }
let users = {};

// Stable across restarts only if JWT_SECRET is set as an env var.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ── Storage ───────────────────────────────────────────────────────────────────

async function loadUsers() {
  try {
    users = JSON.parse(await fs.readFile(USERS_FILE, 'utf-8'));
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    users = {};
  }
}

async function saveUsers() {
  await fs.mkdir(FAMILY_DIR, { recursive: true });
  await atomicWrite(USERS_FILE, JSON.stringify(users, null, 2));
}

// ── Password hashing (PBKDF2) ─────────────────────────────────────────────────

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(String(password), salt, 100_000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const derived = crypto.pbkdf2Sync(String(password), salt, 100_000, 64, 'sha512').toString('hex');
  if (derived.length !== hash.length) return false;
  return crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(hash, 'hex'));
}

// ── Tokens (manual JWT-like) ──────────────────────────────────────────────────

function makeToken(phone) {
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000;
  const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ phone, exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (!payload || payload.exp < Date.now()) return null;
  return payload; // { phone, exp }
}

// ── Brute-force limiter ───────────────────────────────────────────────────────

function Limiter(max, windowMs, lockMs) {
  const m = new Map();
  return {
    wait(key) { const s = m.get(key); return s?.lock > Date.now() ? Math.ceil((s.lock - Date.now()) / 1000) : 0; },
    fail(key) {
      const now = Date.now();
      let s = m.get(key);
      if (!s || now - s.first > windowMs) s = { n: 0, first: now, lock: 0 };
      if (++s.n >= max) { s.lock = now + lockMs; s.n = 0; s.first = now; }
      m.set(key, s);
    },
    ok(key) { m.delete(key); },
  };
}
const byIp = Limiter(10, 10 * 60_000, 5 * 60_000);
const byPhone = Limiter(15, 10 * 60_000, 2 * 60_000);
const clientIp = req => String(req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip || '?').split(',')[0].trim();

// ── Routes ────────────────────────────────────────────────────────────────────

const router = express.Router();
const ah = fn => (req, res, next) => fn(req, res, next).catch(next);
const fail = (status, msg) => Object.assign(new Error(msg), { status });

router.post('/api/register', ah(async (req, res) => {
  const phone = String(req.body?.phone ?? '').replace(/\s/g, '');
  const password = String(req.body?.password ?? '');
  const name = String(req.body?.name ?? '').replace(/\s+/g, ' ').trim().slice(0, 40);

  if (!PHONE_RE.test(phone)) throw fail(400, 'Invalid phone number (7–15 digits, optional leading +)');
  if (password.length < 6) throw fail(400, 'Password must be at least 6 characters');
  if (!name) throw fail(400, 'Name is required');
  if (users[phone]) throw fail(409, 'Phone number already registered');

  users[phone] = { phone, name, ...hashPassword(password), createdAt: Date.now() };
  await saveUsers();
  res.status(201).json({ token: makeToken(phone), name, phone });
}));

router.post('/api/login', ah(async (req, res) => {
  const phone = String(req.body?.phone ?? '').replace(/\s/g, '');
  const password = String(req.body?.password ?? '');
  const ip = clientIp(req);

  const wait = Math.max(byIp.wait(ip), byPhone.wait(phone));
  if (wait) { res.set('Retry-After', String(wait)); throw fail(429, `Too many attempts – try again in ${wait}s`); }

  const u = users[phone];
  if (!u || !verifyPassword(password, u.salt, u.hash)) {
    byIp.fail(ip);
    byPhone.fail(phone);
    throw fail(401, 'Wrong phone number or password');
  }
  byIp.ok(ip);
  byPhone.ok(phone);
  res.json({ token: makeToken(phone), name: u.name, phone });
}));

router.get('/api/me', (req, res) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'login required' });
  const payload = verifyToken(h.slice(7));
  if (!payload) return res.status(401).json({ error: 'invalid or expired token' });
  const u = users[payload.phone];
  if (!u) return res.status(401).json({ error: 'user not found' });
  res.json({ phone: u.phone, name: u.name });
});

module.exports = { usersRouter: router, loadUsers, verifyToken };
