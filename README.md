# Express server

Express + Socket.IO server — signaling backend for MeshCall and family-history app.

```bash
npm install
npm start        # http://localhost:3000

# Optional env vars:
JWT_SECRET=...   # stable tokens across restarts (random by default)
PORT=3000
FAMILY_DIR=...   # override data directory (default: ./family)
```

- `GET /` hello message
- `GET /health` health check

## MeshCall signaling (`modules/users.js`, `modules/signaling.js`)

Socket.IO pub/sub signaling for the MeshCall app. Users register once with a phone number and password; every Socket.IO connection is authenticated with a 30-day JWT.

### User accounts

| Route | Body | Returns |
|---|---|---|
| `POST /api/register` | `{ phone, password, name }` | `{ token, name, phone }` |
| `POST /api/login` | `{ phone, password }` | `{ token, name, phone }` |
| `GET /api/me` | — (Bearer token) | `{ phone, name }` |

Passwords are hashed with PBKDF2-SHA512 (100 000 iterations). Tokens are HMAC-SHA256, 30-day expiry. Set `JWT_SECRET` as an env var so tokens survive server restarts.

Accounts are stored in `<DATA_DIR>/voip/users.db` (SQLite, `node:sqlite`), where `DATA_DIR` is the parent of `FAMILY_DIR` — so `voip/` and `family/` sit side by side.

### Socket.IO rooms

The client passes `auth: { token }` on connect. After authentication:

| Event (client → server) | Payload |
|---|---|
| `join_room` | `{ room, clientData }` |
| `leave_room` | `{ room }` |
| `publish` | `{ room, message }` |

| Event (server → client) | Payload |
|---|---|
| `room_opened` | `{ room }` |
| `message` | `{ room, data, id, timestamp, clientId }` |
| `members` | `{ room, members }` (observable rooms on join) |
| `member_join` | `{ room, member }` |
| `member_leave` | `{ room, member }` |

Observable rooms (name starts with `observable-`) maintain a live member list. Every published message is echoed back to the publisher so the client's liveness watchdog works.

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
