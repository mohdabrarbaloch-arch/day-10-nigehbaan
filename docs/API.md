# API Reference

Base URL: `http://localhost:8000` (or your deployed origin).
All JSON. Auth via `Authorization: Bearer <jwt>` unless noted.

## Auth

### POST /api/auth/register
Body: `{ "email": "you@example.com", "master_password": "..." }`
→ `201` `{ "access_token": "...", "token_type": "bearer" }`
Errors: `409` email exists.

### POST /api/auth/login
Body: `{ "email": "...", "master_password": "..." }`
→ `200` token response. `401` invalid credentials.

### GET /api/auth/salt?email=you@example.com
→ `200` `{ "email": "...", "kdf_salt": "<hex>" }` — public salt for client-side
MEK derivation. `404` unknown user.

### GET /api/auth/me
→ `200` `{ "id": 1, "email": "...", "created_at": "..." }`

### POST /api/auth/change-password
Body: `{ "current_password": "...", "new_password": "..." }`
→ `200` `{ "message": "Master password updated" }`

## Vault  *(requires `X-Master-Key: <base64 32-byte MEK>`)*

### GET /api/vault
Query: `category`, `q` (search). → `200` `[EntrySummary…]` (no plaintext).

### POST /api/vault
Body: `{ title, category?, username?, password, website?, notes?, favorite? }`
→ `201` `EntryOut` (includes decrypted `password`).

### GET /api/vault/{id}
→ `200` `EntryOut`. `404` not found / not yours.

### PUT /api/vault/{id}
Body: any subset of EntryUpdate. Password fields are re-encrypted.
→ `200` `EntryOut`.

### DELETE /api/vault/{id}
→ `200` `{ "message": "Entry deleted" }`.

`EntryOut`: `{ id, title, category, username, password, website, notes, favorite, created_at, updated_at }`

## Tools

### POST /api/generate
Body: `{ length?, uppercase?, lowercase?, digits?, symbols?, exclude_ambiguous? }`
→ `200` `{ "password": "...", "entropy_bits": 97.2 }`

### POST /api/strength/check
Body: `{ "password": "..." }` → `200` `{ score: 0-4, label, entropy_bits, suggestions[] }`

### POST /api/totp/setup
→ `200` `{ "secret": "BASE32", "otpauth_url": "otpauth://totp/..." }`

### POST /api/totp/check
Body: `{ "secret": "BASE32", "code": "123456" }` → `200` `{ "valid": true }`

### GET /api/audit?limit=20
→ `200` `[ { id, action, detail, created_at } ]`

### GET /api/health
→ `200` `{ "status": "ok", "service": "nigehbaan" }`

## Errors

Standard JSON shape: `{ "detail": "message" }`
- `401` bad/missing JWT or wrong master key
- `404` missing resource
- `409` duplicate email
- `422` validation
- `429` rate limited
