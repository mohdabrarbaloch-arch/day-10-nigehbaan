"""Shared FastAPI dependencies, incl. the X-Master-Key verification."""
import base64

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from ..core.security import b64d, decrypt_secret
from ..database import get_db
from ..models import User



def get_master_key(x_master_key: str | None = Header(default=None, alias="X-Master-Key")) -> bytes:
    """Present the base64 MEK on every vault write/decrypt request.

    The server verifies it against the user's stored vault_verifier.
    """
    if not x_master_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="X-Master-Key header required")
    try:
        key = b64d(x_master_key)
        if len(key) != 32:
            raise ValueError("bad key length")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid master key encoding") from None
    return key



def verify_master_key(user: User, master_key: bytes, db: Session) -> None:
    """Decrypt the user's vault verifier with the presented key. Wrong key -> 401."""
    try:
        decrypt_secret(user.vault_verifier, user.vault_verifier_nonce, master_key)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong master key") from None
