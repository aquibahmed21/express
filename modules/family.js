/**
 * Family module - several families, each with its own JSON and its own photo folder.
 *
 *   family/<id>/family.json     that family's history (any JSON object)
 *   family/<id>/photos/<file>   that family's profile pictures
 *   family/auth.json            PIN hashes and roles (see auth.js)
 *
 * Every route needs a login token (see auth.js). Roles: viewer < writer < admin < root.
 *   GET    /families                       root    -> [{ id, name, users, photos, updated }]
 *   POST   /families                       root    { id, name?, adminPin, adminLabel? } create a family
 *   DELETE /family/:id                     root    delete the family, its pictures and its PINs
 *   GET    /family/:id                     viewer  -> that family's JSON
 *   POST   /family/:id                     writer  replace the JSON (the family must already exist)
 *   GET    /family/:id/photos              viewer  -> ["a1b2.jpg", ...]
 *   POST   /family/:id/photos[?name=<n>]   writer  upload one image (raw body, Content-Type image/*) -> 201 { file, url }
 *   GET    /family/:id/photos/:file        viewer  the image (token may be passed as ?token= for <img>)
 *   DELETE /family/:id/photos/:file        writer  remove it
 *
 * Only validated names ever reach the file system, so no path can escape its folder.
 * The image type comes from the file's magic bytes, never from what the client claims.
 */
const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { FAMILY_DIR, exists, atomicWrite } = require('./storage');
const auth = require('./auth');

const MAX_FAMILIES = Number(process.env.FAMILY_MAX_FAMILIES || 200);
const MAX_PHOTO_BYTES = Number(process.env.FAMILY_PHOTO_MAX_BYTES || 5 * 1024 * 1024);
const MAX_JSON_BYTES = Number(process.env.FAMILY_JSON_MAX_BYTES || 5 * 1024 * 1024);

const SAFE_FILE = /^[A-Za-z0-9_-]{1,64}\.(jpg|png|webp|gif)$/;
const SAFE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const SAFE_NAME = /^[A-Za-z0-9_-]{1,64}$/;

/** Detect the image type from its first bytes. */
function sniff(b) {
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpg';
  if (b.length >= 8 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (b.length >= 12 && b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  if (b.length >= 6 && /^GIF8[79]a$/.test(b.toString('ascii', 0, 6))) return 'gif';
  return null;
}
const MIME = { jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif' };

const ah = fn => (req, res, next) => { fn(req, res, next).catch(next); };

const jsonPath = (id) => path.join(FAMILY_DIR, id, 'family.json');
const photosDir = (id) => path.join(FAMILY_DIR, id, 'photos');

async function initFamilyStorage() {
  await fs.mkdir(FAMILY_DIR, { recursive: true });
  await auth.initAuth();
}

const familyRouter = express.Router();

/** Validates :id for every route that has one. */
familyRouter.param('id', (req, res, next, id) => {
  if (!SAFE_ID.test(id) || id === 'photos') return void res.status(400).json({ error: 'invalid family id (lowercase letters, digits, - and _)' });
  next();
});

const needFamily = (req, res, next) => auth.hasFamily(req.params.id) ? next() : res.status(404).json({ error: 'family not found' });

async function readDoc(id) {
  try { return await fs.readFile(jsonPath(id), 'utf-8'); }
  catch (e) { if (e?.code === 'ENOENT') return null; throw e; }
}

const jsonBody = express.json({ limit: MAX_JSON_BYTES });
const validDoc = (d) => !!d && typeof d === 'object';

familyRouter.get('/families', auth.guard('root'), ah(async (_req, res) => {
  const list = await Promise.all(auth.familyList().map(async f => ({
    ...f,
    photos: (await fs.readdir(photosDir(f.id)).catch(() => [])).filter(n => SAFE_FILE.test(n)).length,
    updated: await fs.stat(jsonPath(f.id)).then(s => s.mtime.toISOString(), () => null)
  })));
  res.json(list.sort((a, b) => a.id.localeCompare(b.id)));
}));

familyRouter.post('/families', auth.guard('root'), express.json({ limit: '10kb' }), ah(async (req, res) => {
  const { id, name, adminPin, adminLabel } = req.body || {};
  if (auth.familyList().length >= MAX_FAMILIES) return void res.status(409).json({ error: `family limit reached (${MAX_FAMILIES})` });
  const fid = String(id ?? '').toLowerCase();
  await auth.addFamily(fid, name, String(adminPin ?? ''), adminLabel);
  await fs.mkdir(photosDir(fid), { recursive: true });
  if (!(await exists(jsonPath(fid)))) await atomicWrite(jsonPath(fid), '{}');
  res.status(201).json({ message: 'family created', id: fid });
}));

familyRouter.get('/family/:id', auth.guard('viewer'), needFamily, ah(async (req, res) => {
  res.type('application/json').send((await readDoc(req.params.id)) ?? '{}');
}));

familyRouter.post('/family/:id', auth.guard('writer'), needFamily, jsonBody, ah(async (req, res) => {
  if (!validDoc(req.body)) return void res.status(400).json({ error: 'JSON object or array required' });
  await fs.mkdir(photosDir(req.params.id), { recursive: true });
  await atomicWrite(jsonPath(req.params.id), JSON.stringify(req.body, null, 2));
  res.json({ message: 'family updated', id: req.params.id });
}));

familyRouter.delete('/family/:id', auth.guard('root'), needFamily, ah(async (req, res) => {
  await auth.removeFamily(req.params.id);
  await fs.rm(path.join(FAMILY_DIR, req.params.id), { recursive: true, force: true });
  res.json({ message: 'family deleted', id: req.params.id });
}));

const photoRoute = '/family/:id/photos';

familyRouter.get(photoRoute, auth.guard('viewer'), needFamily, ah(async (req, res) => {
  const names = (await fs.readdir(photosDir(req.params.id)).catch(() => [])).filter(n => SAFE_FILE.test(n)).sort();
  res.json(names);
}));

familyRouter.post(photoRoute, auth.guard('writer'), needFamily,
  express.raw({ type: ['image/*', 'application/octet-stream'], limit: MAX_PHOTO_BYTES }),
  ah(async (req, res) => {
    const id = req.params.id;
    const body = req.body;
    if (!Buffer.isBuffer(body) || !body.length) {
      return void res.status(400).json({ error: 'send the image as the raw request body with an image/* Content-Type' });
    }
    const ext = sniff(body);
    if (!ext) return void res.status(415).json({ error: 'only jpg, png, webp and gif images are accepted' });

    const wanted = typeof req.query.name === 'string' ? req.query.name : '';
    if (wanted && !SAFE_NAME.test(wanted)) return void res.status(400).json({ error: 'name may use letters, digits, - and _ (max 64)' });
    const base = wanted || crypto.randomBytes(8).toString('hex');
    const file = `${base}.${ext}`;

    await fs.mkdir(photosDir(id), { recursive: true });
    // Re-uploading under the same name replaces the old picture, even when its type differs.
    if (wanted) {
      for (const other of ['jpg', 'png', 'webp', 'gif']) {
        if (other !== ext) await fs.rm(path.join(photosDir(id), `${base}.${other}`), { force: true });
      }
    }
    await atomicWrite(path.join(photosDir(id), file), body);
    res.status(201).json({ file, url: `/family/${id}/photos/${file}` });
  }));

familyRouter.get(`${photoRoute}/:file`, auth.guard('viewer', { allowQueryToken: true }), needFamily, ah(async (req, res) => {
  const file = String(req.params.file);
  if (!SAFE_FILE.test(file)) return void res.status(400).json({ error: 'invalid file name' });
  try {
    const data = await fs.readFile(path.join(photosDir(req.params.id), file));
    res.set({
      'Content-Type': MIME[path.extname(file).slice(1)],
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, max-age=300',
      // The app may show the picture from another origin (e.g. the GitHub Pages front end).
      'Cross-Origin-Resource-Policy': 'cross-origin'
    }).send(data);
  } catch (e) {
    if (e?.code === 'ENOENT') return void res.status(404).json({ error: 'photo not found' });
    throw e;
  }
}));

familyRouter.delete(`${photoRoute}/:file`, auth.guard('writer'), needFamily, ah(async (req, res) => {
  const file = String(req.params.file);
  if (!SAFE_FILE.test(file)) return void res.status(400).json({ error: 'invalid file name' });
  try {
    await fs.unlink(path.join(photosDir(req.params.id), file));
  } catch (e) {
    if (e?.code === 'ENOENT') return void res.status(404).json({ error: 'photo not found' });
    throw e;
  }
  res.json({ message: 'deleted' });
}));

module.exports = { familyRouter, initFamilyStorage };
