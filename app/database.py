"""Database engine + session. SQLite for dev, PostgreSQL via DATABASE_URL in prod."""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings

settings = get_settings()

# On serverless (Vercel) the filesystem is read-only except /tmp.
if os.environ.get("VERCEL") or settings.is_vercel:
    db_url = "sqlite:////tmp/nigehbaan.db"
else:
    db_url = settings.database_url

connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}

engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
