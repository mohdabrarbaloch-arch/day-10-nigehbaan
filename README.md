# Nigehbaan — Guard your secrets.

**Nigehbaan (نگہبان — "The Guardian")** is a zero-knowledge, end-to-end encrypted
password & secret vault. Your master password never leaves your device; the
server only ever sees AES-256-GCM ciphertext.

Live demo: `https://day-10-nigehbaan.vercel.app` *(deployed after Vercel connect)*

---

## Why this exists

Password managers are black boxes. Most people in Pakistan — freelancers,
students, shop owners — either reuse the same password everywhere or store
passwords in notes apps that aren't encrypted at all. Nigehbaan is a self-hostable
vault where the crypto is transparent and the whole thing can run on your own
server (or Vercel's free tier).

## How the crypto works (the short version)

```
master password
      │  PBKDF2-SHA256 · 310,000 iterations · per-user salt (WebCrypto-compatible)
      ▼
Master Encryption Key (MEK, 256-bit)   ──  stays on YOUR device only
      │
      ▼  AES-256-GCM (authenticated encryption)
ciphertext  →  stored in the database. Server holds zero plaintext.
```

- **Envelope encryption**: each vault entry is encrypted with AES-256-GCM using
a fresh 96-bit nonce. Tampered data fails decryption (InvalidTag).
- **Master key verification**: the server stores a random token encrypted with
your MEK. Every vault request presents `X-Master-Key`; the server decrypts the
token to confirm the key — wrong key = 401, no data touched.
- **Password hashing**: argon2id (server-side only) for the login hash, so the
login path is brute-force resistant even with a leaked DB dump.
- **TOTP**: built-in RFC 6238 generator (for authenticator-app onboarding flows).

## Features

- 🔐 Zero-knowledge vault — server can never read your secrets
- 🎲 Strong password generator (8–64 chars, char-class control, ambiguous-char filter, entropy estimate)
- 📊 Password strength meter (0–4 score + suggestions)
- 🔍 Search, favourites, categories (login / card / wifi / note / other)
- 🕘 Audit log of every action (register, login, create/update/delete, generate)
- ⏱ Auto-lock after 5 minutes idle + session expiry
- 📱 Mobile-first, premium dark + gold UI, zero build step
- 🐳 Docker + PostgreSQL 16 ready, Vercel-ready serverless entry
- ✅ 45 unit tests, ruff-clean, CI via GitHub Actions

## Tech stack

| Layer | Choice |
|---|---|
| API | FastAPI (Python 3.11) |
| DB | SQLAlchemy 2.0 · SQLite (dev) / PostgreSQL 16 (prod) |
| Crypto | `cryptography` AES-256-GCM · PBKDF2-SHA256 (310k) · argon2id · PyJWT |
| Auth | JWT (HS256, 60 min) + argon2id password hash |
| Security | CORS allowlist · rate limiting (slowapi) · header-based master key · audit logging |
| Frontend | Vanilla JS SPA (Playfair Display + Inter, dark/gold) |
| Deploy | Docker Compose · Vercel (`vercel.json` + `api/index.py`) |

## Quick start

```bash
git clone https://github.com/mohdabrarbaloch-arch/day-10-nigehbaan
cd day-10-nigehbaan
cp .env.example .env        # set a strong SECRET_KEY
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000, create an account, and start your vault.

### Docker

```bash
docker compose up --build
# → http://localhost:8000  (Postgres 16 + API)
```

### Tests & lint

```bash
pytest -q            # 45 tests
ruff check .         # lint must pass clean
```

## API surface (highlights)

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Create account (returns JWT) |
| POST | `/api/auth/login` | Login (returns JWT) |
| GET | `/api/auth/salt?email=` | Fetch KDF salt for client-side key derivation |
| GET/POST | `/api/vault` | List / create entries (requires `X-Master-Key`) |
| GET/PUT/DELETE | `/api/vault/{id}` | Read / update / delete an entry |
| POST | `/api/generate` | Generate strong password |
| POST | `/api/strength/check` | Score a password 0–4 |
| POST | `/api/totp/setup` · `/api/totp/check` | TOTP secret + RFC 6238 verify |
| GET | `/api/audit` | Activity log |

Full reference in [`docs/API.md`](docs/API.md).

## Security notes

- Never commit `.env`; rotate `SECRET_KEY` in production.
- Production DB should be PostgreSQL 16 (see `docker-compose.yml`).
- The master password is never sent to the server after login — only the JWT
and the derived MEK (which is useless without the password).
- Rate limiting (30 req/min by default) protects auth endpoints.

## Screenshots

![Vault](docs/screenshots/vault.png)
![Generator](docs/screenshots/generator.png)

## License

MIT — see [LICENSE](LICENSE).