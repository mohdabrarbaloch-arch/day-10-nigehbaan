"""Nigehbaan — secure password & secret vault.

FastAPI application entrypoint. Wires security middleware (rate limiting,
CORS), routers, and the DB bootstrap.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .api import auth as auth_router
from .api import tools as tools_router
from .api import vault as vault_router
from .config import get_settings
from .database import Base, engine

settings = get_settings()

limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.rate_limit_per_minute}/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Nigehbaan API",
    description="Zero-knowledge password & secret vault. AES-256-GCM envelope encryption, argon2id KDF, TOTP.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-Master-Key"],
)

app.include_router(auth_router.router)
app.include_router(vault_router.router)
app.include_router(tools_router.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "nigehbaan"}


@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded — slow down."})


# Static SPA (served at /)
app.mount("/", StaticFiles(directory="public", html=True), name="public")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse("public/index.html")
