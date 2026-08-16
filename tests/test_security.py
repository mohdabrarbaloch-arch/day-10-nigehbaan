"""Crypto core tests: MEK derivation, AES-256-GCM, generator, strength, TOTP."""
import secrets

from app.core.security import (
    decrypt_secret,
    derive_mek,
    encrypt_secret,
    generate_password,
    hash_master_password,
    password_entropy_bits,
    random_hex,
    strength_score,
    totp_code,
    totp_secret,
    totp_uri,
    totp_verify,
    verify_master_password,
)


def test_mek_deterministic_same_salt():
    salt = secrets.token_hex(16)
    a = derive_mek("correct horse battery staple", salt)
    b = derive_mek("correct horse battery staple", salt)
    assert a == b and len(a) == 32


def test_mek_different_salt_different_key():
    salt_a, salt_b = secrets.token_hex(16), secrets.token_hex(16)
    assert derive_mek("same password", salt_a) != derive_mek("same password", salt_b)


def test_mek_different_password_different_key():
    salt = secrets.token_hex(16)
    assert derive_mek("password-one", salt) != derive_mek("password-two", salt)


def test_aes_gcm_roundtrip():
    mek = derive_mek("pw", secrets.token_hex(16))
    ct, nonce = encrypt_secret("my-secret-value", mek)
    assert ct != "my-secret-value"
    assert decrypt_secret(ct, nonce, mek) == "my-secret-value"


def test_aes_gcm_tamper_detected():
    import base64

    import pytest
    from cryptography.exceptions import InvalidTag

    from app.core.security import b64e

    mek = derive_mek("pw", secrets.token_hex(16))
    ct, nonce = encrypt_secret("secret", mek)
    tampered = list(base64.b64decode(ct))
    tampered[0] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_secret(b64e(bytes(tampered)), nonce, mek)


def test_aes_gcm_wrong_key_rejected():
    import pytest
    from cryptography.exceptions import InvalidTag

    salt = secrets.token_hex(16)
    ct, nonce = encrypt_secret("secret", derive_mek("right", salt))
    with pytest.raises(InvalidTag):
        decrypt_secret(ct, nonce, derive_mek("wrong", salt))


def test_argon2_hash_and_verify():
    h = hash_master_password("MasterPass123!")
    assert h.startswith("$argon2")
    assert verify_master_password("MasterPass123!", h)
    assert not verify_master_password("WrongPass!", h)


def test_generate_password_length_and_chars():
    pw = generate_password(length=24)
    assert len(pw) == 24
    assert any(c.isdigit() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)


def test_generate_password_minimum_one_per_pool():
    pw = generate_password(length=8, uppercase=True, lowercase=True, digits=True, symbols=True)
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_generate_password_excludes_ambiguous():
    pw = generate_password(length=32, exclude_ambiguous=True)
    for c in pw:
        assert c not in "Il1O0o"


def test_generate_password_uniqueness():
    a = generate_password(16)
    b = generate_password(16)
    assert a != b


def test_entropy_bits():
    assert password_entropy_bits("a") > 0
    assert password_entropy_bits("") == 0
    assert password_entropy_bits("A" * 12) > password_entropy_bits("A" * 8)


def test_strength_score_weak():
    r = strength_score("password")
    assert r["score"] <= 1


def test_strength_score_strong():
    r = strength_score("K7#vXp2!sQ9$LmWz")
    assert r["score"] == 4
    assert r["label"] == "Very strong"


def test_totp_code_and_verify():
    secret = totp_secret()
    code = totp_code(secret)
    assert len(code) == 6 and code.isdigit()
    assert totp_verify(secret, code)
    assert not totp_verify(secret, "000000")


def test_totp_uri_format():
    uri = totp_uri("ABCDEFGHIJKLMNOP", "user@example.com")
    assert uri.startswith("otpauth://totp/Nigehbaan:user@example.com?secret=")
    assert "issuer=Nigehbaan" in uri


def test_random_hex_format():
    assert len(random_hex(16)) == 32
    int(random_hex(16), 16)  # valid hex
