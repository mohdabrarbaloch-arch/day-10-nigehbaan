# Setup

## Requirements

- Python 3.11+
- (optional) Docker + Docker Compose for the Postgres 16 stack

## Local development

```bash
git clone https://github.com/mohdabrarbaloch-arch/day-10-nigehbaan
cd day-10-nigehbaan

python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

cp .env.example .env                 # then edit SECRET_KEY
uvicorn app.main:app --reload
```

Open http://localhost:8000 — the SPA is served at `/`.

## Docker (Postgres 16 + API)

```bash
cp .env.example .env
docker compose up --build
```

The API listens on http://localhost:8000 with `DATABASE_URL` pointing at the
compose-managed Postgres instance.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | `change-me…` | JWT signing secret — **must be changed** |
| `CORS_ORIGINS` | `http://localhost:8000` | Comma-separated allowed origins |
| `DATABASE_URL` | `sqlite:///./nigehbaan.db` | SQLAlchemy connection string |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT lifetime |
| `ARGON2_TIME_COST` | `3` | argon2id time cost |
| `ARGON2_MEMORY_COST` | `65536` | argon2id memory cost (KiB) |
| `ARGON2_PARALLELISM` | `4` | argon2id parallelism |
| `RATE_LIMIT_PER_MINUTE` | `30` | slowapi default limit |

## Production notes

- Use a strong random `SECRET_KEY`: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
- Use hosted PostgreSQL (e.g. Neon, Supabase) as `DATABASE_URL`.
- Vercel: import the repo, set env vars, deploy — `api/index.py` handles the
  serverless entry and switches to `/tmp` SQLite automatically.
