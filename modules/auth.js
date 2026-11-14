/**
 * Auth module - who may see and change which family.
 *
 * Accounts are PINs, stored only as scrypt hashes in <FAMILY_DIR>/auth.json:
 *   root                  one PIN, may list/create/delete families and manage everything
 *   family "sc_majid"     any number of PINs, each with a role:
 *                           admin   read + write + manage the family's PINs
 *                           writer  read + write the family tree and photos
 *                           viewer  read only
 *
 * Login: POST /auth/login { id, pin }  (id is a family id, or "root")  ->  { token, role, family, label }
 * Send the token as `Authorization: Bearer <token>` (photos may also use ?token= for <img> tags).
 * Tokens are signed (HMAC) and expire after 30 days; changing a PIN or role invalidates its tokens.
 *
 * Routes here:  POST /auth/login   GET /auth/me   POST /auth/change-pin
 *               GET|POST /family/:id/users   PATCH|DELETE /family/:id/users/:uid
 * The family-level routes (/families, /family/:id ...) are in family.js and use `guard()`.
 */
const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { FAMILY_DIR, exists, atomicWrite } = require('./storage');

const scrypt = promisify(crypto.scrypt);
const AUTH_FILE = path.join(FAMILY_DIR, 'auth.json');
const RANK = { viewer: 1, writer: 2, admin: 3, root: 4 };
const FAMILY_ROLES = ['viewer', 'writer', 'admin'];
const PIN_RE = /^[0-9]{4,12}$/;
const ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MAX_USERS = 20;
const TOKEN_DAYS = 30;

let db = null;

// ---- hashing --------------------------------------------------------------------------------
async function hashPin(pin, saltHex) {
  const salt = saltHex || crypto.randomBytes(16).toString('hex');
  const hash = (await scrypt(String(pin), Buffer.from(salt, 'hex'), 32)).toString('hex');
  return { salt, hash };
}
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
async function pinMatches(rec, pin) {
  return same((await hashPin(pin, rec.salt)).hash, rec.hash);
}

// ---- storage --------------------------------------------------------------------------------
const save = () => atomicWrite(AUTH_FILE, JSON.stringify(db, null, 2));

/** Build a fresh auth database (used by the seed script and the ROOT_PIN first-start path). */
async function buildDb(rootPin, families = []) {
  if (!PIN_RE.test(rootPin)) throw new Error('root PIN must be 4-12 digits');
  const out = { secret: crypto.randomBytes(32).toString('hex'), root: { ...(await hashPin(rootPin)), v: 1 }, families: {} };
  for (const f of families) {
    if (!ID_RE.test(f.id) || !PIN_RE.test(f.pin)) throw new Error(`bad family seed ${f.id}`);
    out.families[f.id] = { name: f.name || f.id, users: [{ id: crypto.randomBytes(3).toString('hex'), label: f.label || 'Admin', role: 'admin', v: 1, ...(await hashPin(f.pin)) }] };
  }
  return out;
}

async function initAuth() {
  await fs.mkdir(FAMILY_DIR, { recursive: true });
  try {
    db = JSON.parse(await fs.readFile(AUTH_FILE, 'utf-8'));
    db.families = db.families || {};
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    if (process.env.ROOT_PIN) {
      db = await buildDb(process.env.ROOT_PIN);
      await save();
      console.log('auth: created auth.json with the root PIN from ROOT_PIN');
    } else {
      console.error('auth: no auth.json - nobody can log in. Create one with scripts/seed-auth.js (or start once with ROOT_PIN=...).');
      db = null;
    }
  }
}

// ---- tokens ---------------------------------------------------------------------------------
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const sig = body => crypto.createHmac('sha256', db.secret).update(body).digest('base64url');

function makeToken(p) {
  const body = b64({ ...p, e: Date.now() + TOKEN_DAYS * 86400000 });
  return `${body}.${sig(body)}`;
}

/** Returns { role, family, userId, label } for a valid token, otherwise null. */
function readToken(token) {
  if (!db || typeof token !== 'string') return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const want = sig(body);
  if (mac.length !== want.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (!p || p.e < Date.now()) return null;
  if (p.r === 'root') return p.v === db.root.v ? { role: 'root', family: null, userId: null, label: 'Root' } : null;
  const user = db.families[p.f]?.users.find(u => u.id === p.u);
  if (!user || user.v !== p.v) return null;     // PIN or role changed, or user removed
  return { role: user.role, family: p.f, userId: user.id, label: user.label };
}

const tokenFor = (role, family, user) => role === 'root' ? makeToken({ r: 'root', v: db.root.v }) : makeToken({ r: 'u', f: family, u: user.id, v: user.v });

// ---- brute-force limits ---------------------------------------------------------------------
function Limiter(max, windowMs, lockMs) {
  const m = new Map();
  return {
    wait(key) { const s = m.get(key); return s && s.lock > Date.now() ? Math.ceil((s.lock - Date.now()) / 1000) : 0; },
    fail(key) {
      const now = Date.now(); let s = m.get(key);
      if (!s || now - s.first > windowMs) s = { n: 0, first: now, lock: 0 };
      if (++s.n >= max) { s.lock = now + lockMs; s.n = 0; s.first = now; }
      m.set(key, s);
      if (m.size > 5000) for (const [k, v] of m) if (v.lock < now && now - v.first > windowMs) m.delete(k);
    },
    ok(key) { m.delete(key); }
  };
}
const byIp = Limiter(10, 10 * 60000, 5 * 60000);
const byId = Limiter(25, 10 * 60000, 2 * 60000);
const clientIp = req => String(req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip || '?').split(',')[0].trim();

// ---- middleware -----------------------------------------------------------------------------
const bearer = (req, allowQuery) => {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return allowQuery && typeof req.query.token === 'string' ? req.query.token : null;
};

/**
 * guard('writer') lets in writers, admins and root. A non-root account may only touch its own
 * family (the :id in the URL).  guard('root') is root only.
 */
function guard(minRole, { allowQueryToken = false } = {}) {
  return (req, res, next) => {
    const a = readToken(bearer(req, allowQueryToken));
    if (!a) return void res.status(401).json({ error: 'login required' });
    if (RANK[a.role] < RANK[minRole]) return void res.status(403).json({ error: 'your role cannot do this' });
    if (req.params.id && a.role !== 'root' && a.family !== req.params.id) return void res.status(403).json({ error: 'not your family' });
    req.auth = a;
    next();
  };
}

// ---- family registry (used by family.js) ----------------------------------------------------
const hasFamily = id => !!db?.families[id];
const familyList = () => Object.entries(db?.families || {}).map(([id, f]) => ({ id, name: f.name || id, users: f.users.length }));

async function addFamily(id, name, adminPin, label) {
  if (!db) throw Object.assign(new Error('auth not set up'), { status: 503 });
  if (!ID_RE.test(id) || id === 'photos' || id === 'root') throw Object.assign(new Error('invalid family id (lowercase letters, digits, - and _)'), { status: 400 });
  if (db.families[id]) throw Object.assign(new Error('family already exists'), { status: 409 });
  if (!PIN_RE.test(adminPin)) throw Object.assign(new Error('PIN must be 4-12 digits'), { status: 400 });
  const h = await hashPin(adminPin);
  if (db.families[id]) throw Object.assign(new Error('family already exists'), { status: 409 });
  db.families[id] = { name: String(name || id).slice(0, 80), users: [{ id: crypto.randomBytes(3).toString('hex'), label: String(label || 'Admin').slice(0, 40), role: 'admin', v: 1, ...h }] };
  await save();
}
async function removeFamily(id) { delete db.families[id]; await save(); }

// ---- routes ---------------------------------------------------------------------------------
const router = express.Router();
const ah = fn => (req, res, next) => { fn(req, res, next).catch(next); };
const fail = (status, msg) => Object.assign(new Error(msg), { status });

router.post('/auth/login', ah(async (req, res) => {
  if (!db) throw fail(503, 'login is not set up on this server');
  const id = String(req.body?.id ?? '').trim().toLowerCase();
  const pin = String(req.body?.pin ?? '').trim();
  const ipKey = clientIp(req), idKey = id.slice(0, 64);
  const wait = Math.max(byIp.wait(ipKey), byId.wait(idKey));
  if (wait) { res.set('Retry-After', String(wait)); throw fail(429, `too many wrong attempts - try again in ${wait}s`); }

  let match = null;
  if (id === 'root') {
    if (await pinMatches(db.root, pin)) match = { role: 'root' };
  } else if (db.families[id]) {
    for (const u of db.families[id].users) if (await pinMatches(u, pin)) { match = { role: u.role, user: u }; break; }
  } else {
    await hashPin(pin, '00'.repeat(16));    // same cost as a real check, so unknown ids are not revealed by timing
  }
  if (!match) { byIp.fail(ipKey); byId.fail(idKey); throw fail(401, 'wrong family id or PIN'); }
  byIp.ok(ipKey); byId.ok(idKey);
  res.json({
    token: tokenFor(match.role, id, match.user), role: match.role,
    family: match.role === 'root' ? null : id, familyName: match.role === 'root' ? null : db.families[id].name,
    label: match.user?.label || 'Root'
  });
}));

router.get('/auth/me', guard('viewer'), (req, res) => {
  res.json({ ...req.auth, familyName: req.auth.family ? db.families[req.auth.family]?.name : null });
});

router.post('/auth/change-pin', guard('viewer'), ah(async (req, res) => {
  const { current, pin } = req.body || {};
  if (!PIN_RE.test(String(pin ?? ''))) throw fail(400, 'new PIN must be 4-12 digits');
  const a = req.auth;
  const rec = a.role === 'root' ? db.root : db.families[a.family].users.find(u => u.id === a.userId);
  if (!(await pinMatches(rec, String(current ?? '')))) throw fail(403, 'current PIN is wrong');
  if (a.role !== 'root') await assertPinFree(a.family, String(pin), a.userId);
  Object.assign(rec, await hashPin(String(pin)));
  rec.v += 1;
  await save();
  res.json({ message: 'PIN changed', token: tokenFor(a.role, a.family, rec) });
}));

/** Two accounts of one family may not share a PIN, or login could not tell them apart. */
async function assertPinFree(family, pin, exceptUserId) {
  for (const u of db.families[family].users) if (u.id !== exceptUserId && await pinMatches(u, pin)) throw fail(409, 'that PIN is already used in this family');
}

const publicUser = u => ({ id: u.id, label: u.label, role: u.role });

router.get('/family/:id/users', guard('admin'), (req, res) => {
  if (!hasFamily(req.params.id)) throw fail(404, 'family not found');
  res.json(db.families[req.params.id].users.map(publicUser));
});

router.post('/family/:id/users', guard('admin'), ah(async (req, res) => {
  const fam = db.families[req.params.id];
  if (!fam) throw fail(404, 'family not found');
  const { pin, label, role } = req.body || {};
  if (!FAMILY_ROLES.includes(role)) throw fail(400, 'role must be admin, writer or viewer');
  if (!PIN_RE.test(String(pin ?? ''))) throw fail(400, 'PIN must be 4-12 digits');
  if (fam.users.length >= MAX_USERS) throw fail(409, `at most ${MAX_USERS} PINs per family`);
  await assertPinFree(req.params.id, String(pin));
  const u = { id: crypto.randomBytes(3).toString('hex'), label: String(label || role).slice(0, 40), role, v: 1, ...(await hashPin(String(pin))) };
  fam.users.push(u);
  await save();
  res.status(201).json(publicUser(u));
}));

router.patch('/family/:id/users/:uid', guard('admin'), ah(async (req, res) => {
  const fam = db.families[req.params.id];
  const u = fam?.users.find(x => x.id === req.params.uid);
  if (!u) throw fail(404, 'user not found');
  const { pin, label, role } = req.body || {};
  if (role !== undefined) {
    if (!FAMILY_ROLES.includes(role)) throw fail(400, 'role must be admin, writer or viewer');
    if (u.role === 'admin' && role !== 'admin' && fam.users.filter(x => x.role === 'admin').length < 2) throw fail(409, 'a family needs at least one admin');
  }
  let h = null;
  if (pin !== undefined) {
    if (!PIN_RE.test(String(pin))) throw fail(400, 'PIN must be 4-12 digits');
    await assertPinFree(req.params.id, String(pin), u.id);
    h = await hashPin(String(pin));
  }
  if (label !== undefined) u.label = String(label).slice(0, 40);
  if (role !== undefined && role !== u.role) { u.role = role; u.v += 1; }
  if (h) { Object.assign(u, h); u.v += 1; }
  await save();
  res.json(publicUser(u));
}));

router.delete('/family/:id/users/:uid', guard('admin'), ah(async (req, res) => {
  const fam = db.families[req.params.id];
  const u = fam?.users.find(x => x.id === req.params.uid);
  if (!u) throw fail(404, 'user not found');
  if (u.role === 'admin' && fam.users.filter(x => x.role === 'admin').length < 2) throw fail(409, 'a family needs at least one admin');
  fam.users = fam.users.filter(x => x !== u);
  await save();
  res.json({ message: 'removed' });
}));

module.exports = { authRouter: router, initAuth, guard, hasFamily, familyList, addFamily, removeFamily, buildDb };
