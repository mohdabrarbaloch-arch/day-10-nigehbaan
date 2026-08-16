"""Shared test fixtures: isolated in-memory SQLite + TestClient."""
import os

os.environ["DATABASE_URL"] = "sqlite://"  # in-memory
os.environ["SECRET_KEY"] = "test-secret-key-not-for-prod"
os.environ["RATE_LIMIT_PER_MINUTE"] = "10000"

import base64
import hashlib

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402

engine.pool = StaticPool(creator=lambda: __import__("sqlite3").connect(":memory:", check_same_thread=False))


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def register(client, email="demo@nigehbaan.pk", password="VaultMaster2026!"):
    return client.post("/api/auth/register", json={"email": email, "master_password": password})


def login(client, email="demo@nigehbaan.pk", password="VaultMaster2026!"):
    return client.post("/api/auth/login", json={"email": email, "master_password": password})


def auth_headers(client, email="demo@nigehbaan.pk", password="VaultMaster2026!", master_key=None):
    token = login(client, email, password).json()["access_token"]
    salt = client.get(f"/api/auth/salt?email={email}").json()["kdf_salt"]
    if master_key is None:
        master_key = derive_test_key(password, salt)
    return {"Authorization": f"Bearer {token}", "X-Master-Key": master_key}


def derive_test_key(password, salt_hex):
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000, dklen=32)).decode()
