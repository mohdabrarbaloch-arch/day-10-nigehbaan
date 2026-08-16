# Nigehbaan — Architecture

## Overview

Nigehbaan is a zero-knowledge password & secret vault. The core idea: **the
server can never read your secrets**. All vault data is encrypted client-side
with a Master Encryption Key (MEK) derived from the user's master password, and
the server only stores ciphertext plus a key-verifier token.

## System diagram

```
┌──────────────────────────────┐          ┌──────────────────────────────┐
│         Browser (SPA)        │          │          FastAPI             │
│                              │  HTTPS   │                              │
│  ┌────────────────────────┐  │ ◄──────► │  /api/auth/*                 │
│  │ deriveClientKey(pass,  │  │   JWT +  │  /api/vault/*   (X-Master-Key)│
│  │   salt) → MEK (PBKDF2  │  │ X-Master-│  /api/generate               │
│  │   SHA-256, 310k iter)  │  │   Key    │  /api/strength/check         │
│  │                        │  │          │  /api/totp/*                 │
│  │ AES-256-GCM encrypt/   │  │          │  /api/audit                  │
│  │ decrypt (WebCrypto)    │  │          │                              │
│  └────────────────────────┘  │          │  rate-limit (slowapi)        │
│   · master password stays    │          │  CORS allowlist              │
│     here, always             │          └──────────────┬───────────────┘
└──────────────────────────────┘                         │ SQLAlchemy 2.0
                                                         ▼
                                            ┌────────────────────────────┐
                                            │  PostgreSQL 16 (prod)      │
                                            │  SQLite /tmp (serverless)  │
                                            │  users · vault_entries ·   │
                                            │  audit_logs                │
                                            └────────────────────────────┘
```

## Data flow

1. **Register** — client sends email + master password (over TLS). Server:
   - generates a random 16-byte KDF salt,
   - derives the MEK via PBKDF2-SHA256 (310,000 iterations),
   - encrypts a random verifier token with the MEK (AES-256-GCM),
   - stores `master_hash` (argon2id), `kdf_salt`, `vault_verifier` (+ nonce).
   - Returns a JWT (HS256, 60 min). The MEK itself is never stored.
2. **Login** — client sends email + master password. Server verifies the
   argon2id hash and returns a JWT. The client then fetches `GET /api/auth/salt`
   and derives the identical MEK on-device via WebCrypto.
3. **Vault operations** — every request carries `Authorization: Bearer <JWT>`
   and `X-Master-Key: <base64 MEK>`. The server:
   - verifies the JWT → user,
   - decrypts `vault_verifier` with the presented MEK (wrong key → 401),
   - encrypts/decrypts entry payloads with AES-256-GCM.
4. **Audit** — every sensitive action appends a row to `audit_logs`.

## Crypto model

| Component | Algorithm | Notes |
|---|---|---|
| MEK derivation | PBKDF2-HMAC-SHA256, 310k iter | WebCrypto-compatible so the browser reproduces the exact key |
| Vault encryption | AES-256-GCM, 12-byte nonce | Authenticated encryption; tampering → `InvalidTag` |
| Password hash | argon2id (t=3, m=64 MiB, p=4) | Brute-force resistant, server-side only |
| Session | JWT HS256, 60 min expiry | Signed with `SECRET_KEY` |
| TOTP | RFC 6238, HMAC-SHA1, 30 s, 6 digits | ±1 window tolerance |

## Security properties

- **Zero knowledge**: server holds no plaintext secrets and no MEK.
- **Key-check without key storage**: the verifier token proves key validity.
- **Forward secrecy of content**: a DB dump alone yields only ciphertext.
- **Rate limited**: default 30 req/min per client IP (slowapi).
- **CORS allowlist** + no credentials unless explicitly configured.
- Secrets only in `.env`; `.env.example` documents every variable.

## Scaling notes

- **SQLite → PostgreSQL**: swap `DATABASE_URL` (docker-compose includes
  Postgres 16). SQLAlchemy 2.0 keeps the code identical.
- **Serverless**: `api/index.py` sets `VERCEL=1`, which switches the DB to a
  writable `/tmp/nigehbaan.db` (Vercel's filesystem is read-only elsewhere).
  For multi-instance production use a hosted Postgres (Neon/Supabase).
- **Reads scale** horizontally; the API is stateless except for the DB.
- **Rate limiting** can be moved to a shared store (Redis) behind a load balancer.