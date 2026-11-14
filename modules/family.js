/**
 * Family module - several families, each with its own JSON and its own photo folder.
 *
 *   family/<id>/family.json     that family's history (any JSON object)
 *   family/<id>/photos/<file>   that family's profile pictures
 *
 * Routes (mounted by server.ts with `app.use(familyRouter)`):
 *   GET    /families                       -> [{ id, members?, photos, updated }]
 *   GET    /family                         -> the "default" family's JSON (old single-family clients)
 *   POST   /family                         -> replace the "default" family's JSON
 *   GET    /family/:id                     -> that family's JSON (404 if it does not exist)
 *   POST   /family/:id                     -> create or replace it (JSON body)
 *   DELETE /family/:id                     -> delete the family with all its photos
 *   GET    /family/:id/photos              -> ["a1b2.jpg", ...]
 *   POST   /family/:id/photos[?name=<n>]   -> upload one image (raw body, Content-Type image/*) -> 201 { file, url }
 *   GET    /family/:id/photos/:file        -> the image
 *   DELETE /family/:id/photos/:file        -> remove it
 *
 * Family ids: lowercase letters, digits, - and _ (max 64). Only validated names ever reach the
 * file system, so no path can escape its folder. The image type comes from the file's magic bytes.
 */
const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const FAMILY_DIR = process.env.FAMILY_DIR || path.join(__dirname, '..', 'family');
const DEFAULT_ID = 'default';
const MAX_FAMILIES = Number(process.env.FAMILY_MAX_FAMILIES || 200);
const LEGACY_JSON = path.join(__dirname, '..', 'family.json');
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

/** One write at a time per file, and atomic (temp file + rename) so a crash never leaves half a file. */
let writeChain = Promise.resolve();
function atomicWrite(file, data) {
  const job = writeChain.then(async () => {
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    try {
      await fs.writeFile(tmp, data);
      await fs.rename(tmp, file);
    } catch (e) {
      await fs.rm(tmp, { force: true });
      throw e;
    }
  });
  writeChain = job.catch(() => undefined);
  return job;
}

const ah = fn => (req, res, next) => { fn(req, res, next).catch(next); };

const jsonPath = (id) => path.join(FAMILY_DIR, id, 'family.json');
const photosDir = (id) => path.join(FAMILY_DIR, id, 'photos');
const exists = (p) => fs.access(p).then(() => true, () => false);

/** Create the base folder and move earlier single-family layouts into family/default/. */
async function initFamilyStorage() {
  await fs.mkdir(FAMILY_DIR, { recursive: true });
  const def = path.join(FAMILY_DIR, DEFAULT_ID);
  if (await exists(def)) return;
  const oldJson = [path.join(FAMILY_DIR, 'family.json'), LEGACY_JSON];
  const oldPhotos = path.join(FAMILY_DIR, 'photos');
  const haveJson = (await Promise.all(oldJson.map(exists))).findIndex(Boolean);
  const havePhotos = await exists(oldPhotos);
  if (haveJson < 0 && !havePhotos) return;
  await fs.mkdir(def, { recursive: true });
  if (haveJson >= 0) await fs.copyFile(oldJson[haveJson], jsonPath(DEFAULT_ID));
  if (havePhotos) await fs.rename(oldPhotos, photosDir(DEFAULT_ID));
  await fs.rm(path.join(FAMILY_DIR, 'family.json'), { force: true });
}

const familyRouter = express.Router();

/** Validates :id for every route that has one. */
familyRouter.param('id', (req, res, next, id) => {
  if (!SAFE_ID.test(id) || id === 'photos') return void res.status(400).json({ error: 'invalid family id (lowercase letters, digits, - and _)' });
  next();
});

async function readDoc(id) {
  try { return await fs.readFile(jsonPath(id), 'utf-8'); }
  catch (e) { if (e?.code === 'ENOENT') return null; throw e; }
}

async function saveDoc(id, doc) {
  if (!(await exists(path.join(FAMILY_DIR, id)))) {
    const count = (await fs.readdir(FAMILY_DIR, { withFileTypes: true })).filter(d => d.isDirectory()).length;
    if (count >= MAX_FAMILIES) throw Object.assign(new Error(`family limit reached (${MAX_FAMILIES})`), { status: 409 });
  }
  await fs.mkdir(photosDir(id), { recursive: true });
  await atomicWrite(jsonPath(id), JSON.stringify(doc, null, 2));
}

const jsonBody = express.json({ limit: MAX_JSON_BYTES });
const validDoc = (d) => !!d && typeof d === 'object';

familyRouter.get('/families', ah(async (_req, res) => {
  const dirs = (await fs.readdir(FAMILY_DIR, { withFileTypes: true })).filter(d => d.isDirectory() && SAFE_ID.test(d.name));
  const list = await Promise.all(dirs.map(async d => {
    const photos = (await fs.readdir(photosDir(d.name)).catch(() => [])).filter(n => SAFE_FILE.test(n)).length;
    const updated = await fs.stat(jsonPath(d.name)).then(s => s.mtime.toISOString(), () => null);
    return { id: d.name, photos, updated };
  }));
  res.json(list.sort((a, b) => a.id.localeCompare(b.id)));
}));

// Old single-family clients: /family means the "default" family.
familyRouter.get('/family', ah(async (_req, res) => {
  res.type('application/json').send((await readDoc(DEFAULT_ID)) ?? '{}');
}));
familyRouter.post('/family', jsonBody, ah(async (req, res) => {
  if (!validDoc(req.body)) return void res.status(400).json({ error: 'JSON object or array required' });
  await saveDoc(DEFAULT_ID, req.body);
  res.json({ message: 'family.json updated successfully' });
}));

familyRouter.get('/family/:id', ah(async (req, res) => {
  const doc = await readDoc(req.params.id);
  if (doc === null) return void res.status(404).json({ error: 'family not found' });
  res.type('application/json').send(doc);
}));

familyRouter.post('/family/:id', jsonBody, ah(async (req, res) => {
  if (!validDoc(req.body)) return void res.status(400).json({ error: 'JSON object or array required' });
  const created = (await readDoc(req.params.id)) === null;
  await saveDoc(req.params.id, req.body);
  res.status(created ? 201 : 200).json({ message: created ? 'family created' : 'family updated', id: req.params.id });
}));

familyRouter.delete('/family/:id', ah(async (req, res) => {
  const dir = path.join(FAMILY_DIR, req.params.id);
  if (!(await exists(dir))) return void res.status(404).json({ error: 'family not found' });
  await fs.rm(dir, { recursive: true, force: true });
  res.json({ message: 'family deleted', id: req.params.id });
}));

const photoRoute = '/family/:id/photos';

familyRouter.get(photoRoute, ah(async (req, res) => {
  if (!(await exists(path.join(FAMILY_DIR, req.params.id)))) return void res.status(404).json({ error: 'family not found' });
  const names = (await fs.readdir(photosDir(req.params.id)).catch(() => [])).filter(n => SAFE_FILE.test(n)).sort();
  res.json(names);
}));

familyRouter.post(photoRoute,
  express.raw({ type: ['image/*', 'application/octet-stream'], limit: MAX_PHOTO_BYTES }),
  ah(async (req, res) => {
    const id = req.params.id;
    if (!(await exists(path.join(FAMILY_DIR, id)))) return void res.status(404).json({ error: 'family not found - create it first with POST /family/' + id });
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

familyRouter.get(`${photoRoute}/:file`, ah(async (req, res) => {
  const file = String(req.params.file);
  if (!SAFE_FILE.test(file)) return void res.status(400).json({ error: 'invalid file name' });
  try {
    const data = await fs.readFile(path.join(photosDir(req.params.id), file));
    res.set({
      'Content-Type': MIME[path.extname(file).slice(1)],
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'public, max-age=300',
      // The app may show the picture from another origin (e.g. the GitHub Pages front end).
      'Cross-Origin-Resource-Policy': 'cross-origin'
    }).send(data);
  } catch (e) {
    if (e?.code === 'ENOENT') return void res.status(404).json({ error: 'photo not found' });
    throw e;
  }
}));

familyRouter.delete(`${photoRoute}/:file`, ah(async (req, res) => {
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
