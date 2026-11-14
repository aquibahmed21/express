# Express server

Simple Express server.

```bash
npm install
npm start        # http://localhost:3000
```

- `GET /` hello message
- `GET /health` health check

## Family history and logins (`modules/family.js`, `modules/auth.js`)

Several families, each with its own JSON and photo folder, under `family/` (override with `FAMILY_DIR`):

```
family/auth.json                PIN hashes + roles (scrypt, never plain PINs)
family/<id>/family.json
family/<id>/photos/<file>
```

**Login:** `POST /auth/login {id, pin}` where `id` is a family id or `root`. It returns a signed token
(30 days) to send as `Authorization: Bearer <token>`. 10 wrong tries from one address, or 25 for one id,
lock further tries for a few minutes. Changing a PIN or role ends that account's tokens.

**Roles:** `viewer` reads, `writer` also edits the tree and photos, `admin` also manages that family's PINs,
`root` creates and deletes families and sees all of them. Each family has any number of PINs, each with a role.

| Route | Who |
|---|---|
| `GET /families`, `POST /families {id,name,adminPin}`, `DELETE /family/:id` | root |
| `GET /family/:id`, `GET /family/:id/photos[/file]` | viewer+ |
| `POST /family/:id`, `POST /family/:id/photos[?name=]`, `DELETE /family/:id/photos/:file` | writer+ |
| `GET/POST /family/:id/users`, `PATCH/DELETE /family/:id/users/:uid` | admin+ |
| `GET /auth/me`, `POST /auth/change-pin {current,pin}` | any account |

PINs are 4-12 digits. A family always keeps at least one admin.

**First setup:** create `auth.json` once (PINs go in through the environment; only hashes are written):

```bash
ROOT_PIN=... FAMILIES="sc_majid:822474" node scripts/seed-auth.js family/auth.json
```

or start once with `ROOT_PIN=...` to create it with only the root account, then create families as root.
