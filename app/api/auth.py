"""Auth routes: register, login, me, change master password.

Registration derives the Master Encryption Key (PBKDF2) from the master
password and stores an MEK-encrypted verifier, so the server can verify a
client-presented key on later vault operations without storing the key.
"""
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.auth import create_access_token, get_current_user
from ..core.security import derive_mek, encrypt_secret, hash_master_password, random_hex, verify_master_password
from ..database import get_db
from ..models import AuditLog, User
from ..schemas import ChangePasswordRequest, LoginRequest, MessageResponse, RegisterRequest, TokenResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _log(db: Session, user_id: int, action: str, detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, detail=detail, ip=ip[:64]))
    db.commit()


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == body.email.lower()).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    kdf_salt = random_hex(16)
    master_key = derive_mek(body.master_password, kdf_salt)
    verifier_token = secrets.token_hex(16)
    verifier_ct, verifier_nonce = encrypt_secret(verifier_token, master_key)
    master_hash = hash_master_password(body.master_password)

    user = User(
        email=body.email.lower(),
        master_hash=master_hash,
        kdf_salt=kdf_salt,
        vault_verifier=verifier_ct,
        vault_verifier_nonce=verifier_nonce,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _log(db, user.id, "register", f"Account created for {user.email}", request.client.host if request.client else "")
    return TokenResponse(access_token=create_access_token(user.id, user.email))


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user is None or not verify_master_password(body.master_password, user.master_hash):
        raise HTTPException(status_code=401, detail="Invalid email or master password")
    _log(db, user.id, "login", "Successful login", request.client.host if request.client else "")
    return TokenResponse(access_token=create_access_token(user.id, user.email))


@router.get("/me", response_model=dict)
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "created_at": user.created_at.isoformat()}


@router.get("/salt")
def get_salt(email: str, db: Session = Depends(get_db)):
    """Return the user's KDF salt (public, not secret) for client-side MEK derivation."""
    user = db.query(User).filter(User.email == email.lower()).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"email": user.email, "kdf_salt": user.kdf_salt}


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_master_password(body.current_password, user.master_hash):
        raise HTTPException(status_code=401, detail="Current master password is incorrect")

    new_salt = random_hex(16)
    master_key = derive_mek(body.new_password, new_salt)
    verifier_token = secrets.token_hex(16)
    verifier_ct, verifier_nonce = encrypt_secret(verifier_token, master_key)

    user.master_hash = hash_master_password(body.new_password)
    user.kdf_salt = new_salt
    user.vault_verifier = verifier_ct
    user.vault_verifier_nonce = verifier_nonce
    db.commit()
    _log(db, user.id, "change_password", "Master password changed", request.client.host if request.client else "")
    return MessageResponse(message="Master password updated")
