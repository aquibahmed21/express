/**
 * Expense Studio backups – mobile-number accounts and .db uploads.
 *
 * Data lives next to family/ and voip/:  <DATA_DIR>/expense/
 *   expense/users.json                 accounts (PBKDF2 hashes, never plain passwords)
 *   expense/jwt-secret.txt             token secret (stable across restarts)
 *   expense/<mobile>/expense-YYYY-MM-DD.db   one file per day, newest upload of the day wins
 *
 * Only the last 7 days are kept; older files are deleted after each upload and once a day.
 * Accounts are separate from the MeshCall (voip) accounts. No native modules: works on the phone host (Node 18).
 *
 * Routes (all under /expense):
 *   POST /expense/register   { phone, password }  -> { token, phone }
 *   POST /expense/login      { phone, password }  -> { token, phone }
 *   POST /expense/upload     Bearer, raw .db body -> { name, size, kept }
 *   GET  /expense/backups    Bearer               -> { keepDays, files: [{ name, size, modified }] }
 *   GET  /expense/backups/:name  Bearer           -> the .db file
 */
const express = require('express');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { FAMILY_DIR, atomicWrite } = require('./storage');

const DATA_DIR = path.dirname(FAMILY_DIR);
const EXPENSE_DIR = path.join(DATA_DIR, 'expense');
const USERS_FILE = path.join(EXPENSE_DIR, 'users.json');
const PHONE_RE = /^[0-9]{7,15}$/;
const FILE_RE = /^expense-(\d{4})-(\d{2})-(\d{2})\.db$/;
const KEEP_DAYS = 7;
const MAX_UPLOAD = 100 * 1024 * 1024; // 100 MB
const SQLITE_MAGIC = 'SQLite format 3\0';

fs.mkdirSync(EXPENSE_DIR, { recursive: true });

// ── Secret + users ───────────────────────────────────────────────────────────

function loadSecret() {
  if (process.env.EXPENSE_JWT_SECRET) return process.env.EXPENSE_JWT_SECRET;
  const f = path.join(EXPENSE_DIR, 'jwt-secret.txt');
  try { const s = fs.readFileSync(f, 'utf8').trim(); if (s.length >= 32) return s; } catch (_) { /* first start */ }
  const s = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(f, s, { mode: 0o600 }); } catch (_) { /* keep in memory */ }
  return s;
}
const SECRET = loadSecret();

let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (_) { users = {}; }
const saveUsers = () => atomicWrite(USERS_FILE, JSON.stringify(users));

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.pbkdf2Sync(String(password), salt, 100_000, 64, 'sha512').toString('hex') };
}
function verifyPassword(password, salt, hash) {
  const d = crypto.pbkdf2Sync(String(password), salt, 100_000, 64, 'sha512');
  const h = Buffer.from(hash, 'hex');
  return d.length === h.length && crypto.timingSafeEqual(d, h);
}

// ── Tokens (HMAC-SHA256, 30 days, audience "expense" so MeshCall tokens never work here) ──

function makeToken(phone) {
  const head = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ phone, aud: 'expense', exp: Date.now() + 30 * 24 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${sig}`;
}
function verifyToken(token) {
  const p = String(token || '').split('.');
  if (p.length !== 3) return null;
  const want = crypto.createHmac('sha256', SECRET).update(`${p[0]}.${p[1]}`).digest('base64url');
  if (p[2].length !== want.length || !crypto.timingSafeEqual(Buffer.from(p[2]), Buffer.from(want))) return null;
  let o; try { o = JSON.parse(Buffer.from(p[1], 'base64url').toString()); } catch { return null; }
  return o && o.aud === 'expense' && o.exp > Date.now() && PHONE_RE.test(String(o.phone)) ? o : null;
}

// ── Brute-force limiter ──────────────────────────────────────────────────────

function Limiter(max, windowMs, lockMs) {
  const m = new Map();
  return {
    wait(k) { const s = m.get(k); return s?.lock > Date.now() ? Math.ceil((s.lock - Date.now()) / 1000) : 0; },
    fail(k) { const now = Date.now(); let s = m.get(k); if (!s || now - s.first > windowMs) s = { n: 0, first: now, lock: 0 }; if (++s.n >= max) { s.lock = now + lockMs; s.n = 0; s.first = now; } m.set(k, s); },
    ok(k) { m.delete(k); },
  };
}
const byIp = Limiter(10, 10 * 60_000, 5 * 60_000);
const byPhone = Limiter(15, 10 * 60_000, 2 * 60_000);
const clientIp = (req) => String(req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip || '?').split(',')[0].trim();

// ── Files ────────────────────────────────────────────────────────────────────

const pad = (n) => String(n).padStart(2, '0');
const dayKey = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const userDir = (phone) => path.join(EXPENSE_DIR, phone);

/** Deletes every backup older than the last KEEP_DAYS days (today counts as day 1). Returns the files left. */
async function prune(phone) {
  const dir = userDir(phone);
  const cutoff = new Date(); cutoff.setHours(0, 0, 0, 0); cutoff.setDate(cutoff.getDate() - (KEEP_DAYS - 1));
  const cut = dayKey(cutoff);
  let names = [];
  try { names = await fsp.readdir(dir); } catch (_) { return []; }
  const keep = [];
  for (const n of names) {
    const m = FILE_RE.exec(n);
    if (!m) continue; // never touch anything that isn't one of our files
    if (`${m[1]}-${m[2]}-${m[3]}` < cut) await fsp.rm(path.join(dir, n), { force: true });
    else keep.push(n);
  }
  return keep;
}
async function pruneAll() {
  try { for (const e of await fsp.readdir(EXPENSE_DIR, { withFileTypes: true })) if (e.isDirectory() && PHONE_RE.test(e.name)) await prune(e.name); }
  catch (e) { console.error('[expense] prune failed:', e.message); }
}
pruneAll();
setInterval(pruneAll, 6 * 3600 * 1000).unref();

// ── Routes ───────────────────────────────────────────────────────────────────

const router = express.Router();
const fail = (status, msg) => Object.assign(new Error(msg), { status });
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const json = express.json({ limit: '8kb' });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const p = h.startsWith('Bearer ') ? verifyToken(h.slice(7)) : null;
  if (!p) return res.status(401).json({ error: 'Please log in again' });
  if (!users[p.phone]) return res.status(401).json({ error: 'Account not found' });
  req.phone = p.phone;
  next();
}

router.post('/expense/register', json, ah(async (req, res) => {
  const phone = String(req.body?.phone ?? '').replace(/[\s\-()]/g, '');
  const password = String(req.body?.password ?? '');
  const ip = clientIp(req);
  const wait = byIp.wait(ip);
  if (wait) { res.set('Retry-After', String(wait)); throw fail(429, `Too many attempts. Try again in ${wait}s`); }
  if (!PHONE_RE.test(phone)) throw fail(400, 'Mobile number must be 7 to 15 digits');
  if (password.length < 6) throw fail(400, 'Password must be at least 6 characters');
  if (users[phone]) { byIp.fail(ip); throw fail(409, 'This mobile number is already registered'); }
  const { salt, hash } = hashPassword(password);
  users[phone] = { salt, hash, created_at: Date.now() };
  await saveUsers();
  await fsp.mkdir(userDir(phone), { recursive: true });
  res.status(201).json({ token: makeToken(phone), phone });
}));

router.post('/expense/login', json, ah(async (req, res) => {
  const phone = String(req.body?.phone ?? '').replace(/[\s\-()]/g, '');
  const password = String(req.body?.password ?? '');
  const ip = clientIp(req);
  const wait = Math.max(byIp.wait(ip), byPhone.wait(phone));
  if (wait) { res.set('Retry-After', String(wait)); throw fail(429, `Too many attempts. Try again in ${wait}s`); }
  const u = Object.prototype.hasOwnProperty.call(users, phone) ? users[phone] : null;
  if (!u || !verifyPassword(password, u.salt, u.hash)) { byIp.fail(ip); byPhone.fail(phone); throw fail(401, 'Wrong mobile number or password'); }
  byIp.ok(ip); byPhone.ok(phone);
  res.json({ token: makeToken(phone), phone });
}));

router.post('/expense/upload', auth, express.raw({ type: () => true, limit: MAX_UPLOAD }), ah(async (req, res) => {
  const body = req.body;
  if (!Buffer.isBuffer(body) || body.length < 100) throw fail(400, 'No file received');
  if (body.subarray(0, 16).toString('latin1') !== SQLITE_MAGIC) throw fail(400, 'That is not a .db (SQLite) file');
  const dir = userDir(req.phone);
  await fsp.mkdir(dir, { recursive: true });
  const name = `expense-${dayKey(new Date())}.db`;
  await atomicWrite(path.join(dir, name), body); // same day = replaced by the newest upload
  const kept = await prune(req.phone);
  res.status(201).json({ name, size: body.length, kept: kept.length });
}));

router.get('/expense/backups', auth, ah(async (req, res) => {
  const names = (await prune(req.phone)).sort().reverse();
  const files = [];
  for (const name of names) { const st = await fsp.stat(path.join(userDir(req.phone), name)); files.push({ name, size: st.size, modified: st.mtimeMs }); }
  res.json({ keepDays: KEEP_DAYS, files });
}));

router.get('/expense/backups/:name', auth, ah(async (req, res) => {
  const name = req.params.name;
  if (!FILE_RE.test(name)) throw fail(400, 'Bad file name');
  const file = path.join(userDir(req.phone), name);
  if (!fs.existsSync(file)) throw fail(404, 'No such backup');
  res.download(file, name);
}));

module.exports = { expenseRouter: router };
