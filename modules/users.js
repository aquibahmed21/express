/**
 * Signaling users – phone + password registration and login.
 * Accounts are stored in <DATA_DIR>/voip/users.db (SQLite via node:sqlite).
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
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
// node:sqlite needs Node >= 22.5. The Android host runs Node 18, so fall back to a JSON file there.
let DatabaseSync = null;
try { ({ DatabaseSync } = require('node:sqlite')); } catch (_) { /* fallback below */ }
const { FAMILY_DIR } = require('./storage');

// DATA_DIR is the parent that holds both family/ and voip/ as siblings.
const DATA_DIR = path.dirname(FAMILY_DIR);
const VOIP_DIR = path.join(DATA_DIR, 'voip');
const DB_PATH = path.join(VOIP_DIR, 'users.db');
const PHONE_RE = /^[0-9]{7,15}$/;

// In-memory reference to the open database handle.
let db = null;

// JWT_SECRET must survive server restarts so tokens don't become invalid when the
// Cloudflare tunnel URL changes. We load/create it from a file on disk.
function loadJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const secretFile = path.join(path.dirname(require('./storage').FAMILY_DIR), 'voip', 'jwt-secret.txt');
  try {
    const s = fs.readFileSync(secretFile, 'utf8').trim();
    if (s.length >= 32) return s;
  } catch (_) {}
  // First start: generate and persist.
  const s = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(secretFile), { recursive: true });
    fs.writeFileSync(secretFile, s, { mode: 0o600 });
  } catch (_) {}
  return s;
}
const JWT_SECRET = loadJwtSecret();

// Comma-separated phone numbers that are granted root/admin role automatically.
// e.g. ADMIN_PHONES=+919876543210,+919876543211
const ADMIN_PHONES = new Set(
  (process.env.ADMIN_PHONES || '').split(',').map(p => p.replace(/\s/g, '')).filter(Boolean)
);
const ROOT_PHONE = (process.env.ROOT_PHONE || '').replace(/\s/g, '') || null;

// ── Database ──────────────────────────────────────────────────────────────────

const JSON_PATH = path.join(VOIP_DIR, 'users.json');

// Minimal stand-in exposing the same prepare().get()/run() calls used below.
function openJsonDb() {
  let rows = {};
  try { rows = JSON.parse(fs.readFileSync(JSON_PATH, 'utf8')); } catch (_) {}
  const save = () => { fs.writeFileSync(JSON_PATH + '.tmp', JSON.stringify(rows)); fs.renameSync(JSON_PATH + '.tmp', JSON_PATH); };
  const allRows = () => Object.values(rows);
  return {
    exec() {},
    prepare(sql) {
      if (sql.startsWith('INSERT')) {
        // Handles both 5-arg (legacy register) and 6-arg (root auto-create with role) calls
        return { run(phone, name, salt, hash, created_at, role = 'user') { rows[phone] = { phone, name, salt, hash, created_at, role, blocked: 0 }; save(); } };
      }
      if (sql.includes('SELECT') && sql.includes('WHERE phone = ?')) {
        return { get(phone) { return rows[phone] || null; } };
      }
      if (sql.includes('UPDATE users SET blocked')) {
        return { run(blocked, phone) { if (rows[phone]) { rows[phone].blocked = blocked; save(); } } };
      }
      if (sql.includes('UPDATE users SET role')) {
        return { run(role, phone) { if (rows[phone]) { rows[phone].role = role; save(); } } };
      }
      if (sql.includes('UPDATE users SET name') || sql.includes('UPDATE users SET salt')) {
        // password reset: run(salt, hash, phone)
        return { run(salt, hash, phone) { if (rows[phone]) { Object.assign(rows[phone], { salt, hash }); save(); } } };
      }
      if (sql.includes('DELETE FROM users WHERE phone')) {
        return { run(phone) { delete rows[phone]; save(); } };
      }
      if (sql.includes('SELECT phone, name, role, blocked, created_at FROM users') && !sql.includes('WHERE')) {
        return { all() { return allRows(); } };
      }
      if (sql.includes('WHERE phone IN')) {
        const excludeAdminRoot = sql.includes("role NOT IN");
        return { all(...phones) { return phones.flat().map(p => rows[p]).filter(r => r && (!excludeAdminRoot || !['admin','root'].includes(r.role))); } };
      }
      if (sql.includes('LIKE')) {
        const excludeAdminRoot = sql.includes("role NOT IN");
        return {
          all(phoneQ, nameQ) {
            const pq = (phoneQ || '').replace(/%/g, '').toLowerCase();
            const nq = (nameQ || '').replace(/%/g, '').toLowerCase();
            return allRows().filter(r =>
              (!excludeAdminRoot || !['admin','root'].includes(r.role)) &&
              (r.phone.replace(/\s/g, '').toLowerCase().includes(pq) ||
              (r.name || '').toLowerCase().includes(nq))
            );
          },
        };
      }
      // single-row SELECT (login, /me, register duplicate check)
      return { get(phone) { return rows[phone] || null; } };
    },
  };
}

function openDb() {
  fs.mkdirSync(VOIP_DIR, { recursive: true });
  if (!DatabaseSync) { db = openJsonDb(); return; }
  db = new DatabaseSync(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      phone       TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      salt        TEXT NOT NULL,
      hash        TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      role        TEXT NOT NULL DEFAULT 'user',
      blocked     INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
  `);
  // Add columns to existing DBs that predate this schema (ALTER TABLE errors if column exists).
  for (const ddl of [
    "ALTER TABLE users ADD COLUMN role    TEXT NOT NULL DEFAULT 'user'",
    "ALTER TABLE users ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0",
  ]) {
    try { db.exec(ddl); } catch (_) { /* column already exists */ }
  }
  db.exec(`
  `);
}

async function loadUsers() {
  openDb();
  // Apply passwords set from the host app settings on every startup.
  // ROOT_PASSWORD sets the root phone's password.
  // ADMIN_PASSWORDS is a comma-separated list of phone:password pairs.
  const rootPw = process.env.ROOT_PASSWORD;
  if (rootPw && ROOT_PHONE) {
    const existing = db.prepare('SELECT phone FROM users WHERE phone = ?').get(ROOT_PHONE);
    if (existing) {
      const { salt, hash } = hashPassword(rootPw);
      db.prepare('UPDATE users SET salt = ?, hash = ? WHERE phone = ?').run(salt, hash, ROOT_PHONE);
      console.log(`[users] Root password updated for ${ROOT_PHONE}`);
    } else {
      // Root account doesn't exist yet — auto-create it with 'root' role so root
      // can log in and immediately have admin powers.
      const { salt, hash } = hashPassword(rootPw);
      db.prepare('INSERT INTO users (phone, name, salt, hash, created_at, role) VALUES (?, ?, ?, ?, ?, ?)').run(ROOT_PHONE, 'Root', salt, hash, Date.now(), 'root');
      console.log(`[users] Root account auto-created for ${ROOT_PHONE} with role 'root'`);
    }
  }
  const adminPwStr = process.env.ADMIN_PASSWORDS || '';
  for (const pair of adminPwStr.split(',').map(s => s.trim()).filter(Boolean)) {
    const colon = pair.indexOf(':');
    if (colon < 1) continue;
    const phone = pair.slice(0, colon).trim();
    const pw = pair.slice(colon + 1);
    if (!phone || !pw) continue;
    const existing = db.prepare('SELECT phone FROM users WHERE phone = ?').get(phone);
    if (existing) {
      const { salt, hash } = hashPassword(pw);
      db.prepare('UPDATE users SET salt = ?, hash = ? WHERE phone = ?').run(salt, hash, phone);
      console.log(`[users] Admin password updated for ${phone}`);
    }
  }
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

function roleFor(phone) {
  if (phone === ROOT_PHONE) return 'root';
  if (ADMIN_PHONES.has(phone)) return 'admin';
  return null; // use DB value
}

function makeToken(phone, role) {
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000;
  const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ phone, role: role || 'user', exp })).toString('base64url');
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

  const existing = db.prepare('SELECT phone FROM users WHERE phone = ?').get(phone);
  if (existing) throw fail(409, 'Phone number already registered');

  const { salt, hash } = hashPassword(password);
  db.prepare('INSERT INTO users (phone, name, salt, hash, created_at) VALUES (?, ?, ?, ?, ?)').run(phone, name, salt, hash, Date.now());
  const role = roleFor(phone) || 'user';
  res.status(201).json({ token: makeToken(phone, role), name, phone, role });
}));

router.post('/api/login', ah(async (req, res) => {
  const phone = String(req.body?.phone ?? '').replace(/\s/g, '');
  const password = String(req.body?.password ?? '');
  const ip = clientIp(req);

  const wait = Math.max(byIp.wait(ip), byPhone.wait(phone));
  if (wait) { res.set('Retry-After', String(wait)); throw fail(429, `Too many attempts – try again in ${wait}s`); }

  const u = db.prepare('SELECT phone, name, role, blocked, salt, hash FROM users WHERE phone = ?').get(phone);
  if (!u || !verifyPassword(password, u.salt, u.hash)) {
    byIp.fail(ip);
    byPhone.fail(phone);
    throw fail(401, 'Wrong phone number or password');
  }
  if (u.blocked) throw fail(403, 'This account has been blocked');
  byIp.ok(ip);
  byPhone.ok(phone);
  const role = roleFor(phone) || u.role || 'user';
  res.json({ token: makeToken(phone, role), name: u.name, phone, role });
}));

router.get('/api/me', (req, res) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'login required' });
  const payload = verifyToken(h.slice(7));
  if (!payload) return res.status(401).json({ error: 'invalid or expired token' });
  const u = db.prepare('SELECT phone, name, role, blocked FROM users WHERE phone = ?').get(payload.phone);
  if (!u) return res.status(401).json({ error: 'user not found' });
  const role = roleFor(u.phone) || u.role || 'user';
  res.json({ phone: u.phone, name: u.name, role });
});

// Mounted after signaling starts so onlinePhones is populated.
let _onlinePhones = null;
function setOnlinePhones(map) { _onlinePhones = map; }

/** GET /api/users/search?q=<query>  — search by phone prefix or name (case-insensitive, max 20) */
router.get('/api/users/search', (req, res) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ') || !verifyToken(h.slice(7))) return res.status(401).json({ error: 'login required' });
  const raw = String(req.query.q ?? '').trim();
  // Strip spaces/dashes so "+91 98765 43210" matches the stored "+919876543210".
  const q = raw.replace(/[\s\-().]/g, '').toLowerCase();
  if (!q) return res.json([]);
  const rows = db.prepare(
    "SELECT phone, name, role FROM users WHERE (lower(replace(phone,' ','')) LIKE ? OR lower(name) LIKE ?) LIMIT 40",
  ).all(`%${q}%`, `%${raw.toLowerCase()}%`);
  const filtered = rows
    .filter(r => { const role = roleFor(r.phone) || r.role || 'user'; return role !== 'admin' && role !== 'root'; })
    .slice(0, 20);
  res.json(filtered.map((r) => ({ phone: r.phone, name: r.name, online: !!(_onlinePhones?.has(r.phone)) })));
});

/** POST /api/users/lookup  body: { phones: string[] }  — batch registration + online status check */
router.post('/api/users/lookup', (req, res) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ') || !verifyToken(h.slice(7))) return res.status(401).json({ error: 'login required' });
  const phones = Array.isArray(req.body?.phones) ? req.body.phones.filter((p) => typeof p === 'string').slice(0, 2000) : [];
  if (!phones.length) return res.json([]);
  const placeholders = phones.map(() => '?').join(',');
  const rows = db.prepare(`SELECT phone, name, role FROM users WHERE phone IN (${placeholders})`).all(...phones);
  const found = new Map(
    rows
      .filter(r => { const role = roleFor(r.phone) || r.role || 'user'; return role !== 'admin' && role !== 'root'; })
      .map((r) => [r.phone, r.name]),
  );
  res.json(phones
    .filter((p) => found.has(p))
    .map((p) => ({ phone: p, name: found.get(p), online: !!(_onlinePhones?.has(p)) })));
});

// ── Admin middleware ──────────────────────────────────────────────────────────

function guardAdmin(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'login required' });
  const payload = verifyToken(h.slice(7));
  if (!payload) return res.status(401).json({ error: 'invalid or expired token' });
  const role = roleFor(payload.phone) || payload.role || 'user';
  if (role !== 'admin' && role !== 'root') return res.status(403).json({ error: 'admin only' });
  req.adminPhone = payload.phone;
  req.adminRole = role;
  next();
}

// ── Admin routes ──────────────────────────────────────────────────────────────

/** GET /api/admin/users — list all users */
router.get('/api/admin/users', guardAdmin, (req, res) => {
  const rows = db.prepare('SELECT phone, name, role, blocked, created_at FROM users ORDER BY created_at DESC').all();
  res.json(rows.map(r => ({
    phone: r.phone, name: r.name,
    role: roleFor(r.phone) || r.role || 'user',
    blocked: !!r.blocked,
    online: !!(_onlinePhones?.has(r.phone)),
    createdAt: r.created_at,
  })));
});

/** PATCH /api/admin/users/:phone — block/unblock, change role */
router.patch('/api/admin/users/:phone', guardAdmin, ah(async (req, res) => {
  const target = decodeURIComponent(req.params.phone);
  const u = db.prepare('SELECT phone, name, role, blocked FROM users WHERE phone = ?').get(target);
  if (!u) throw fail(404, 'User not found');
  if (target === ROOT_PHONE && req.adminRole !== 'root') throw fail(403, 'Cannot modify root user');

  const { blocked, role, password } = req.body || {};

  if (blocked !== undefined) {
    db.prepare('UPDATE users SET blocked = ? WHERE phone = ?').run(blocked ? 1 : 0, target);
  }
  if (role !== undefined) {
    if (!['user', 'admin'].includes(role)) throw fail(400, 'role must be user or admin');
    if (req.adminRole !== 'root') throw fail(403, 'Only root can change roles');
    db.prepare('UPDATE users SET role = ? WHERE phone = ?').run(role, target);
  }
  if (password !== undefined) {
    if (String(password).length < 6) throw fail(400, 'Password must be at least 6 characters');
    const { salt, hash } = hashPassword(String(password));
    db.prepare('UPDATE users SET salt = ?, hash = ? WHERE phone = ?').run(salt, hash, target);
  }
  res.json({ ok: true });
}));

/** DELETE /api/admin/users/:phone — delete a user */
router.delete('/api/admin/users/:phone', guardAdmin, (req, res) => {
  const target = decodeURIComponent(req.params.phone);
  if (target === ROOT_PHONE) return res.status(403).json({ error: 'Cannot delete root user' });
  db.prepare('DELETE FROM users WHERE phone = ?').run(target);
  res.json({ ok: true });
});

/** GET /api/ice-servers — returns TURN/STUN config for the MeshCall client.
 *  Priority: Cloudflare TURN (auto-credentials) → manual TURN → free public STUN only.
 *  Cloudflare credentials are cached for 23 h so we don't hammer the API.
 */
let _cfCache = null; // { expires: ms, iceServers: RTCIceServer[] }

async function fetchCloudflareTurn(keyId, apiToken) {
  if (_cfCache && _cfCache.expires > Date.now()) return _cfCache.iceServers;
  const url = `https://rtc.live.cloudflare.com/v1/turn/keys/${keyId}/credentials/generate`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ttl: 86400 }),
  });
  if (!res.ok) throw new Error(`Cloudflare TURN API ${res.status}`);
  const json = await res.json();
  // Cloudflare returns { iceServers: { urls, username, credential } } (singular object, not array)
  const srv = json.iceServers;
  const servers = [{ urls: srv.urls, username: srv.username, credential: srv.credential }];
  _cfCache = { expires: Date.now() + 23 * 60 * 60 * 1000, iceServers: servers };
  return servers;
}

// Well-known free public STUN servers returned when no TURN is configured.
const FREE_STUN = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
];

router.get('/api/ice-servers', async (req, res) => {
  const cfKeyId = process.env.CF_TURN_KEY_ID;
  const cfToken = process.env.CF_TURN_API_TOKEN;

  // 1. Cloudflare TURN (preferred — takes the whole response slot)
  if (cfKeyId && cfToken) {
    try {
      const iceServers = await fetchCloudflareTurn(cfKeyId, cfToken);
      return res.json({ iceServers });
    } catch (e) {
      console.error('[ice] Cloudflare TURN fetch failed:', e.message);
      // fall through
    }
  }

  // 2. JSON arrays (multi-server, ordered, set from VPS Manager)
  const stunJson = process.env.STUN_SERVERS_JSON;
  const turnJson = process.env.TURN_SERVERS_JSON;
  if (stunJson || turnJson) {
    const iceServers = [];
    try {
      if (stunJson) {
        const urls = JSON.parse(stunJson).filter(u => typeof u === 'string' && u);
        if (urls.length) iceServers.push({ urls });
      }
    } catch (e) { console.error('[ice] STUN_SERVERS_JSON parse error:', e.message); }
    try {
      if (turnJson) {
        const entries = JSON.parse(turnJson);
        for (const e of entries) {
          if (e && e.urls) iceServers.push({ urls: e.urls, username: e.username, credential: e.credential });
        }
      }
    } catch (e) { console.error('[ice] TURN_SERVERS_JSON parse error:', e.message); }
    if (iceServers.length) return res.json({ iceServers });
  }

  // 3. No TURN configured — return free public STUN as best-effort fallback.
  res.json({ iceServers: FREE_STUN });
});

module.exports = { usersRouter: router, loadUsers, verifyToken, setOnlinePhones };
