"""Security core: envelope encryption (AES-256-GCM), PBKDF2 MEK, TOTP, generator, strength."""
import base64
import hashlib
import hmac
import math
import re
import secrets
import struct
import time
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import get_settings

settings = get_settings()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def random_hex(n: int = 16) -> str:
    return secrets.token_hex(n)


# ── PBKDF2 KDF: master password -> Master Encryption Key (MEK) ──────
def derive_mek(master_password: str, salt_hex: str, key_len: int = 32) -> bytes:
    """Derive the 256-bit Master Encryption Key.

    Uses PBKDF2-HMAC-SHA256 with 310,000 iterations so the *same* derivation
    can run in the browser (WebCrypto) — the client needs to reproduce this
    key to encrypt/decrypt vault entries. argon2id is used separately for the
    master-password *hash* (verification), which stays server-side only.
    """
    return hashlib.pbkdf2_hmac("sha256", master_password.encode(), bytes.fromhex(salt_hex), 310_000, dklen=key_len)


# ── AES-256-GCM envelope encryption ─────────────────────────────────
def encrypt_secret(plaintext: str, mek: bytes) -> Tuple[str, str]:
    """Encrypt a secret with AES-256-GCM. Returns (ciphertext_b64, nonce_hex)."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(mek)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return b64e(ct), nonce.hex()


def decrypt_secret(ciphertext_b64: str, nonce_hex: str, mek: bytes) -> str:
    """Decrypt an AES-256-GCM payload. Raises on tampering."""
    aesgcm = AESGCM(mek)
    pt = aesgcm.decrypt(bytes.fromhex(nonce_hex), b64d(ciphertext_b64), None)
    return pt.decode("utf-8")


# ── Master password verification (argon2id) ─────────────────────────
def hash_master_password(password: str) -> str:
    from argon2 import PasswordHasher

    ph = PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost,
        parallelism=settings.argon2_parallelism,
    )
    return ph.hash(password)


def verify_master_password(password: str, master_hash: str) -> bool:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    ph = PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost,
        parallelism=settings.argon2_parallelism,
    )
    try:
        ph.verify(master_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        return False


# ── Password generator ──────────────────────────────────────────────
CHARS_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
CHARS_LOWER = "abcdefghijkmnopqrstuvwxyz"
CHARS_DIGITS = "23456789"
CHARS_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
AMBIGUOUS = set("Il1O0o|`'\"")


def generate_password(length: int = 16, uppercase: bool = True, lowercase: bool = True,
                      digits: bool = True, symbols: bool = True, exclude_ambiguous: bool = False) -> str:
    pools: list[str] = []
    if uppercase:
        pools.append(CHARS_UPPER)
    if lowercase:
        pools.append(CHARS_LOWER)
    if digits:
        pools.append(CHARS_DIGITS)
    if symbols:
        pools.append(CHARS_SYMBOLS)
    if not pools:
        pools = [CHARS_LOWER + CHARS_DIGITS]

    chars = "".join(pools)
    if exclude_ambiguous:
        chars = "".join(c for c in chars if c not in AMBIGUOUS)

    # Guarantee at least one char from each selected pool.
    result = [secrets.choice(p) for p in pools]
    for _ in range(length - len(result)):
        result.append(secrets.choice(chars))
    secrets.SystemRandom().shuffle(result)
    return "".join(result[:length])


def password_entropy_bits(password: str) -> float:
    """Rough entropy estimate: per-char pool size ^ length, in bits."""
    if not password:
        return 0.0
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    return round(len(password) * math.log2(max(pool, 2)), 1)


def strength_score(password: str) -> dict:
    """zxcbn-style 0-4 score + suggestions."""
    score = 0
    suggestions: list[str] = []
    n = len(password)

    if n >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")
    if n >= 12:
        score += 1
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Mix uppercase and lowercase letters.")
    if re.search(r"[0-9]", password) and re.search(r"[^a-zA-Z0-9]", password):
        score += 1
    else:
        suggestions.append("Add digits and symbols.")

    if password.lower() in {"password", "password123", "12345678", "qwerty123", "admin123", "letmein", "iloveyou"}:
        score = min(score, 1)
        suggestions.append("This is a very common password — avoid it.")

    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    return {
        "score": score,
        "label": labels[min(score, 4)],
        "entropy_bits": password_entropy_bits(password),
        "suggestions": suggestions[:3],
    }


# ── TOTP (RFC 6238) ─────────────────────────────────────────────────
def totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp_uri(secret_b32: str, account: str, issuer: str = "Nigehbaan") -> str:
    return f"otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def totp_code(secret_b32: str, at_time: int | None = None) -> str:
    """Compute the 6-digit TOTP code for a base32 secret (HMAC-SHA1, 30s period)."""
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    t = int(time.time() if at_time is None else at_time) // 30
    msg = struct.pack(">Q", t)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    now = int(time.time())
    for delta in range(-window, window + 1):
        candidate = totp_code(secret_b32, now + delta * 30)
        if hmac.compare_digest(candidate, code.strip()):
            return True
    return False
