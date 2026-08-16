"""Live smoke test against a running uvicorn instance."""
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8010"


def req(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "null")


def main():
    def ok(cond, msg):
        print(("PASS " if cond else "FAIL ") + msg)
        if not cond:
            sys.exit(1)

    s, _ = req("GET", "/api/health")
    ok(s == 200, "health 200")

    s, body = req("POST", "/api/auth/register", {"email": "demo@nigehbaan.pk", "master_password": "VaultMaster2026!"})
    ok(s == 201 and body["access_token"], "register 201 + token")

    s, salt_body = req("GET", "/api/auth/salt?email=demo@nigehbaan.pk")
    ok(s == 200 and len(salt_body["kdf_salt"]) == 32, "salt endpoint")

    s, login_body = req("POST", "/api/auth/login", {"email": "demo@nigehbaan.pk", "master_password": "VaultMaster2026!"})
    ok(s == 200, "login 200")
    token = login_body["access_token"]

    salt = salt_body["kdf_salt"]
    key = base64.b64encode(hashlib.pbkdf2_hmac("sha256", b"VaultMaster2026!", bytes.fromhex(salt), 310000, dklen=32)).decode()
    headers = {"Authorization": f"Bearer {token}", "X-Master-Key": key}

    s, entry = req("POST", "/api/vault", {"title": "Gmail", "username": "demo@nigehbaan.pk", "password": "S3cret!Pass"}, headers)
    ok(s == 201 and entry["password"] == "S3cret!Pass", "vault create + decrypt roundtrip")

    s, lst = req("GET", "/api/vault", headers=headers)
    ok(s == 200 and len(lst) == 1 and lst[0]["title"] == "Gmail", "vault list")

    s, _ = req("GET", "/api/vault", headers={"Authorization": f"Bearer {token}"})
    ok(s == 200, "vault list without master key → 200 (summaries only)")

    s, _ = req("GET", f"/api/vault/{entry['id']}", headers={"Authorization": f"Bearer {token}"})
    ok(s == 401, "entry decrypt without master key → 401")

    s, _ = req("POST", "/api/vault", {"title": "X", "password": "y"}, {"Authorization": f"Bearer {token}", "X-Master-Key": "AAAA"})
    ok(s == 401, "wrong master key → 401")

    s, gen = req("POST", "/api/generate", {"length": 20, "symbols": True}, {"Authorization": f"Bearer {token}"})
    ok(s == 200 and len(gen["password"]) == 20 and gen["entropy_bits"] > 0, "generator")

    s, audit = req("GET", "/api/audit?limit=10", headers={"Authorization": f"Bearer {token}"})
    ok(s == 200 and any(a["action"] == "create_entry" for a in audit), "audit log has create_entry")

    print("\nSMOKE TEST: ALL PASSED ✅")


if __name__ == "__main__":
    main()
