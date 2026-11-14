/** Shared file-system helpers for the modules. */
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

// Everything that must survive an app/server update lives here (the host app points FAMILY_DIR
// outside the repo folder, because "Update server" replaces the whole repo folder).
const FAMILY_DIR = process.env.FAMILY_DIR || path.join(__dirname, '..', 'family');

const exists = p => fs.access(p).then(() => true, () => false);

/** One write at a time, and atomic (temp file + rename) so a crash never leaves half a file. */
let chain = Promise.resolve();
function atomicWrite(file, data) {
  const job = chain.then(async () => {
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    try {
      await fs.writeFile(tmp, data, { mode: 0o600 });
      await fs.rename(tmp, file);
    } catch (e) {
      await fs.rm(tmp, { force: true });
      throw e;
    }
  });
  chain = job.catch(() => undefined);
  return job;
}

module.exports = { FAMILY_DIR, exists, atomicWrite };
