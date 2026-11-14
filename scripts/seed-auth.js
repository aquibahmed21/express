#!/usr/bin/env node
/**
 * Writes an auth.json (PIN hashes only - never the PINs) for a new server.
 *
 *   ROOT_PIN=1234567890 FAMILIES="sc_majid:822474,other:556677" node scripts/seed-auth.js <out/auth.json>
 *
 * Each FAMILIES entry is id:adminPin. Put the PINs in the environment, not on the command line,
 * so they stay out of the process list.
 */
const fs = require('fs');
const path = require('path');
const { buildDb } = require('../modules/auth');

(async () => {
  const out = process.argv[2];
  if (!out || !process.env.ROOT_PIN) { console.error('usage: ROOT_PIN=... [FAMILIES="id:pin,..."] node scripts/seed-auth.js <out/auth.json>'); process.exit(1); }
  const families = (process.env.FAMILIES || '').split(',').filter(Boolean).map(x => { const [id, pin] = x.split(':'); return { id, pin }; });
  const db = await buildDb(process.env.ROOT_PIN, families);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(db, null, 2), { mode: 0o600 });
  console.log(`wrote ${out}: root + ${families.length} family(ies)`);
})().catch(e => { console.error(e.message); process.exit(1); });
