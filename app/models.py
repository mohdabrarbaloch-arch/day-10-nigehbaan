"""SQLAlchemy models."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    master_hash: Mapped[str] = mapped_column(Text, nullable=False)  # argon2id hash of master password
    kdf_salt: Mapped[str] = mapped_column(String(64), nullable=False)  # hex salt used for MEK derivation
    vault_verifier: Mapped[str] = mapped_column(Text, nullable=False)  # MEK-encrypted random token (key check)
    vault_verifier_nonce: Mapped[str] = mapped_column(String(48), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    entries: Mapped[list["VaultEntry"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(32), default="login", nullable=False)
    username: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)  # base64 (AES-256-GCM)
    nonce: Mapped[str] = mapped_column(String(48), nullable=False)
    website: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    favorite: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    user: Mapped[User] = relationship(back_populates="entries")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
