"""Utility routes: password generator, strength meter, TOTP, audit log."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..core.auth import get_current_user
from ..core.security import (
    generate_password,
    password_entropy_bits,
    strength_score,
    totp_secret,
    totp_uri,
    totp_verify,
)
from ..database import get_db
from ..models import AuditLog, User
from ..schemas import (
    AuditEntryOut,
    PasswordGenerateRequest,
    PasswordGenerateResponse,
    StrengthResponse,
    TotpRequest,
    TotpSetupResponse,
    TotpVerifyResponse,
)

router = APIRouter(prefix="/api", tags=["tools"])


def _log(db: Session, user_id: int, action: str, detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, detail=detail, ip=ip[:64]))
    db.commit()


@router.post("/generate", response_model=PasswordGenerateResponse)
def generate(body: PasswordGenerateRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pw = generate_password(
        length=body.length,
        uppercase=body.uppercase,
        lowercase=body.lowercase,
        digits=body.digits,
        symbols=body.symbols,
        exclude_ambiguous=body.exclude_ambiguous,
    )
    _log(db, user.id, "generate", f"Generated {body.length}-char password")
    return PasswordGenerateResponse(password=pw, entropy_bits=password_entropy_bits(pw))


@router.post("/strength/check", response_model=StrengthResponse)
def strength_check(
    payload: dict,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    pw = payload.get("password", "")
    if not isinstance(pw, str) or len(pw) > 4096:
        raise HTTPException(status_code=422, detail="password must be a string")
    return StrengthResponse(**strength_score(pw))


@router.post("/totp/setup", response_model=TotpSetupResponse)
def totp_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = totp_secret()
    _log(db, user.id, "totp_setup", "Generated TOTP secret")
    return TotpSetupResponse(secret=secret, otpauth_url=totp_uri(secret, user.email))


@router.post("/totp/verify", response_model=TotpVerifyResponse)
def totp_verify_route(
    body: TotpRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # RFC 6238 stateless check: client supplies the secret it generated.
    raise HTTPException(status_code=400, detail="Use POST /api/totp/check with secret+code")


@router.post("/totp/check", response_model=TotpVerifyResponse)
def totp_check(
    payload: dict,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    secret = payload.get("secret", "")
    code = payload.get("code", "")
    if not secret or not code:
        raise HTTPException(status_code=422, detail="secret and code required")
    valid = totp_verify(secret, str(code))
    _log(db, user.id, "totp_check", "TOTP check " + ("OK" if valid else "FAIL"))
    return TotpVerifyResponse(valid=valid)


@router.get("/audit", response_model=list[AuditEntryOut])
def audit(
    limit: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.user_id == user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return rows
