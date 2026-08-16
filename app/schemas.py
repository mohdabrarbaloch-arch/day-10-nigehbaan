"""Pydantic request/response schemas."""
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    master_password: str = Field(min_length=8, max_length=128)

    @field_validator("master_password")
    @classmethod
    def password_not_all_whitespace(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("password cannot be blank")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    master_password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class TotpRequest(BaseModel):
    token: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class EntryCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(default="login", max_length=32)
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=4096)
    website: str = Field(default="", max_length=512)
    notes: str = Field(default="", max_length=4000)
    favorite: bool = False


class EntryUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    category: str | None = Field(default=None, max_length=32)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=4096)
    website: str | None = Field(default=None, max_length=512)
    notes: str | None = Field(default=None, max_length=4000)
    favorite: bool | None = None


class EntryOut(BaseModel):
    id: int
    title: str
    category: str
    username: str
    password: str
    website: str
    notes: str
    favorite: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EntrySummary(BaseModel):
    id: int
    title: str
    category: str
    username: str
    website: str
    favorite: bool
    updated_at: datetime

    model_config = {"from_attributes": True}


class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=64)
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False


class PasswordGenerateResponse(BaseModel):
    password: str
    entropy_bits: float


class StrengthResponse(BaseModel):
    score: int
    label: str
    entropy_bits: float
    suggestions: list[str]


class TotpSetupResponse(BaseModel):
    otpauth_url: str
    secret: str


class TotpVerifyResponse(BaseModel):
    valid: bool


class AuditEntryOut(BaseModel):
    id: int
    action: str
    detail: str
    created_at: datetime

    model_config = {"from_attributes": True}


class MessageResponse(BaseModel):
    message: str
