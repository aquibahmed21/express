# Express server

Simple Express server.

```bash
npm install
npm start        # http://localhost:3000
```

- `GET /` hello message
- `GET /health` health check

## Family history (`modules/family.js`)

Several families, each with its own JSON and its own photo folder, stored under `family/` (override with `FAMILY_DIR`):

```
family/<id>/family.json
family/<id>/photos/<file>
```

- `GET /families` list families
- `GET|POST|DELETE /family/:id` read, create/replace, delete a family (ids: `a-z 0-9 - _`)
- `GET|POST /family/:id/photos[?name=<n>]` list, upload (raw body, `Content-Type: image/*`; jpg/png/webp/gif, 5 MB)
- `GET|DELETE /family/:id/photos/:file` fetch, delete one picture
- `GET|POST /family` old single-family form, maps to the `default` family

An older root-level `family.json` is moved into `family/default/` on first start.
