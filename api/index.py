"""Vercel serverless entrypoint."""
import os

# Force the /tmp SQLite path on serverless (read-only filesystem otherwise).
os.environ.setdefault("VERCEL", "1")

from app.main import app  # noqa: E402

# Vercel's Python runtime looks for a module-level ASGI app.
application = app
