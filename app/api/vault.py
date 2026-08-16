"""Vault routes: CRUD on AES-256-GCM encrypted secrets.

The client presents the Master Encryption Key (base64, 32 bytes) in the
X-Master-Key header on every vault operation. The server verifies it
against the user's stored vault_verifier before any encrypt/decrypt work,
so a wrong or missing key is rejected without ever touching the data.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.auth import get_current_user
from ..core.deps import get_master_key, verify_master_key
from ..core.security import decrypt_secret, encrypt_secret
from ..database import get_db
from ..models import AuditLog, User, VaultEntry
from ..schemas import EntryCreate, EntryOut, EntrySummary, EntryUpdate, MessageResponse

router = APIRouter(prefix="/api/vault", tags=["vault"])


def _log(db: Session, user_id: int, action: str, detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, detail=detail, ip=ip[:64]))
    db.commit()


def _get_entry_or_404(db: Session, user: User, entry_id: int) -> VaultEntry:
    entry = db.get(VaultEntry, entry_id)
    if entry is None or entry.user_id != user.id:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry


@router.get("", response_model=list[EntrySummary])
def list_entries(
    category: str | None = None,
    q: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(VaultEntry).filter(VaultEntry.user_id == user.id)
    if category:
        query = query.filter(VaultEntry.category == category)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            (VaultEntry.title.ilike(like)) | (VaultEntry.username.ilike(like)) | (VaultEntry.website.ilike(like))
        )
    return query.order_by(VaultEntry.favorite.desc(), VaultEntry.updated_at.desc()).all()


@router.post("", response_model=EntryOut, status_code=status.HTTP_201_CREATED)
def create_entry(
    body: EntryCreate,
    request: Request,
    user: User = Depends(get_current_user),
    master_key: bytes = Depends(get_master_key),
    db: Session = Depends(get_db),
):
    verify_master_key(user, master_key, db)
    ciphertext, nonce = encrypt_secret(body.password, master_key)
    entry = VaultEntry(
        user_id=user.id,
        title=body.title,
        category=body.category,
        username=body.username,
        ciphertext=ciphertext,
        nonce=nonce,
        website=body.website,
        notes=body.notes,
        favorite=1 if body.favorite else 0,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    _log(db, user.id, "create_entry", f"Created '{entry.title}'", request.client.host if request.client else "")
    return _to_out(entry, master_key)


@router.get("/{entry_id}", response_model=EntryOut)
def get_entry(
    entry_id: int,
    user: User = Depends(get_current_user),
    master_key: bytes = Depends(get_master_key),
    db: Session = Depends(get_db),
):
    entry = _get_entry_or_404(db, user, entry_id)
    verify_master_key(user, master_key, db)
    return _to_out(entry, master_key)


@router.put("/{entry_id}", response_model=EntryOut)
def update_entry(
    entry_id: int,
    body: EntryUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    master_key: bytes = Depends(get_master_key),
    db: Session = Depends(get_db),
):
    entry = _get_entry_or_404(db, user, entry_id)
    verify_master_key(user, master_key, db)
    data = body.model_dump(exclude_unset=True)
    if "password" in data:
        entry.ciphertext, entry.nonce = encrypt_secret(data.pop("password"), master_key)
    for field, value in data.items():
        if field == "favorite":
            value = 1 if value else 0
        setattr(entry, field, value)
    db.commit()
    db.refresh(entry)
    _log(db, user.id, "update_entry", f"Updated '{entry.title}'", request.client.host if request.client else "")
    return _to_out(entry, master_key)


@router.delete("/{entry_id}", response_model=MessageResponse)
def delete_entry(
    entry_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    entry = _get_entry_or_404(db, user, entry_id)
    title = entry.title
    db.delete(entry)
    db.commit()
    _log(db, user.id, "delete_entry", f"Deleted '{title}'", request.client.host if request.client else "")
    return MessageResponse(message="Entry deleted")


def _to_out(entry: VaultEntry, master_key: bytes) -> EntryOut:
    return EntryOut(
        id=entry.id,
        title=entry.title,
        category=entry.category,
        username=entry.username,
        password=decrypt_secret(entry.ciphertext, entry.nonce, master_key),
        website=entry.website,
        notes=entry.notes,
        favorite=bool(entry.favorite),
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )
