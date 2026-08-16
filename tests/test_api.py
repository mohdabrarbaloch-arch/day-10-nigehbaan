"""API tests: auth, vault CRUD with master key, tools."""
from tests.conftest import auth_headers, derive_test_key, login, register


# ── Auth ─────────────────────────────────────────────────────────────
def test_register_returns_token(client):
    r = register(client)
    assert r.status_code == 201
    assert r.json()["access_token"]


def test_register_duplicate_email_conflict(client):
    register(client)
    r = register(client)
    assert r.status_code == 409


def test_register_weak_password_rejected(client):
    r = client.post("/api/auth/register", json={"email": "weak@x.pk", "master_password": "short"})
    assert r.status_code == 422


def test_login_success(client):
    register(client)
    r = login(client)
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"


def test_login_wrong_password(client):
    register(client)
    r = login(client, password="WrongPassword99!")
    assert r.status_code == 401


def test_login_unknown_user(client):
    r = login(client, email="nobody@x.pk")
    assert r.status_code == 401


def test_salt_endpoint(client):
    register(client)
    r = client.get("/api/auth/salt?email=demo@nigehbaan.pk")
    assert r.status_code == 200
    assert len(r.json()["kdf_salt"]) == 32


def test_salt_unknown_user_404(client):
    r = client.get("/api/auth/salt?email=nope@x.pk")
    assert r.status_code == 404


def test_me_requires_token(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_returns_email(client):
    register(client)
    headers = auth_headers(client)
    r = client.get("/api/auth/me", headers={"Authorization": headers["Authorization"]})
    assert r.status_code == 200
    assert r.json()["email"] == "demo@nigehbaan.pk"


def test_change_password(client):
    register(client)
    headers = auth_headers(client)
    r = client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": "VaultMaster2026!", "new_password": "NewVaultMaster2027!"},
    )
    assert r.status_code == 200
    # old password no longer works
    assert login(client, password="VaultMaster2026!").status_code == 401
    assert login(client, password="NewVaultMaster2027!").status_code == 200


# ── Vault ────────────────────────────────────────────────────────────
def test_vault_empty_list(client):
    register(client)
    headers = auth_headers(client)
    r = client.get("/api/vault", headers=headers)
    assert r.status_code == 200
    assert r.json() == []


def test_vault_create_and_list(client):
    register(client)
    headers = auth_headers(client)
    r = client.post(
        "/api/vault", headers=headers, json={"title": "Gmail", "username": "me@x.pk", "password": "S3cret!"}
    )
    assert r.status_code == 201
    assert r.json()["password"] == "S3cret!"

    lst = client.get("/api/vault", headers=headers).json()
    assert len(lst) == 1 and lst[0]["title"] == "Gmail"


def test_vault_create_requires_master_key(client):
    register(client)
    token = login(client).json()["access_token"]
    r = client.post(
        "/api/vault",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "X", "password": "y"},
    )
    assert r.status_code == 401


def test_vault_create_wrong_master_key(client):
    register(client)
    headers = auth_headers(client)
    headers["X-Master-Key"] = derive_test_key("DifferentPassword!", "00" * 16)
    r = client.post("/api/vault", headers=headers, json={"title": "X", "password": "y"})
    assert r.status_code == 401


def test_vault_get_decrypts(client):
    register(client)
    headers = auth_headers(client)
    created = client.post("/api/vault", headers=headers, json={"title": "Bank", "password": "pin-4242"}).json()
    got = client.get(f"/api/vault/{created['id']}", headers=headers)
    assert got.status_code == 200
    assert got.json()["password"] == "pin-4242"


def test_vault_get_other_users_entry_404(client):
    register(client)
    h1 = auth_headers(client)
    created = client.post("/api/vault", headers=h1, json={"title": "Mine", "password": "pw"}).json()
    # second user
    register(client, email="other@x.pk", password="OtherUserPass2026!")
    h2 = auth_headers(client, email="other@x.pk", password="OtherUserPass2026!")
    r = client.get(f"/api/vault/{created['id']}", headers=h2)
    assert r.status_code == 404


def test_vault_update_password_rotates_ciphertext(client):
    register(client)
    headers = auth_headers(client)
    created = client.post("/api/vault", headers=headers, json={"title": "WiFi", "password": "old-pass"}).json()
    r = client.put(
        f"/api/vault/{created['id']}",
        headers=headers,
        json={"password": "new-pass", "favorite": True},
    )
    assert r.status_code == 200
    assert r.json()["password"] == "new-pass"
    assert r.json()["favorite"] is True


def test_vault_delete(client):
    register(client)
    headers = auth_headers(client)
    created = client.post("/api/vault", headers=headers, json={"title": "Temp", "password": "x"}).json()
    r = client.delete(f"/api/vault/{created['id']}", headers=headers)
    assert r.status_code == 200
    assert client.get(f"/api/vault/{created['id']}", headers=headers).status_code == 404


def test_vault_search(client):
    register(client)
    headers = auth_headers(client)
    client.post("/api/vault", headers=headers, json={"title": "Gmail", "username": "a@x.pk", "password": "1"})
    client.post("/api/vault", headers=headers, json={"title": "GitHub", "username": "b@x.pk", "password": "2"})
    r = client.get("/api/vault?q=git", headers=headers)
    assert len(r.json()) == 1 and r.json()[0]["title"] == "GitHub"


def test_vault_category_filter(client):
    register(client)
    headers = auth_headers(client)
    client.post("/api/vault", headers=headers, json={"title": "Wifi-Home", "category": "wifi", "password": "1"})
    client.post("/api/vault", headers=headers, json={"title": "Gmail", "category": "login", "password": "2"})
    r = client.get("/api/vault?category=wifi", headers=headers)
    assert len(r.json()) == 1 and r.json()[0]["category"] == "wifi"


# ── Tools ────────────────────────────────────────────────────────────
def test_generate_requires_auth(client):
    r = client.post("/api/generate", json={"length": 16})
    assert r.status_code == 401


def test_generate_password(client):
    register(client)
    headers = auth_headers(client)
    r = client.post("/api/generate", headers=headers, json={"length": 20, "symbols": True})
    assert r.status_code == 200
    assert len(r.json()["password"]) == 20
    assert r.json()["entropy_bits"] > 0


def test_strength_check(client):
    register(client)
    headers = auth_headers(client)
    r = client.post("/api/strength/check", headers=headers, json={"password": "weak"})
    assert r.status_code == 200
    assert r.json()["score"] <= 1


def test_totp_setup_and_check(client):
    register(client)
    headers = auth_headers(client)
    setup = client.post("/api/totp/setup", headers=headers).json()
    assert setup["secret"]
    from app.core.security import totp_code

    code = totp_code(setup["secret"])
    ok = client.post("/api/totp/check", headers=headers, json={"secret": setup["secret"], "code": code})
    assert ok.json()["valid"] is True
    bad = client.post("/api/totp/check", headers=headers, json={"secret": setup["secret"], "code": "000000"})
    assert bad.json()["valid"] is False


def test_audit_log_entries(client):
    register(client)
    headers = auth_headers(client)
    client.post("/api/vault", headers=headers, json={"title": "A", "password": "1"})
    r = client.get("/api/audit", headers=headers)
    assert r.status_code == 200
    actions = [a["action"] for a in r.json()]
    assert "create_entry" in actions
    assert "register" in actions


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_index_serves_spa(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Nigehbaan" in r.text
