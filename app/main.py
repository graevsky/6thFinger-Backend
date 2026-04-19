from fastapi import FastAPI, Request, HTTPException
import ipaddress
import os
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.routes import auth, avatar, device, app_settings
from app.middleware.client_gate import build_client_gate_middleware

"""
Backend API for authentication, account settings management, device settings management, and avatar storage.

Main routes:
- auth: SRP login, JWT tokens, email flows, password reset
- device: user-owned devices and device settings
- settings: app-level user preferences
- avatar: avatar upload, download, and deletion
"""


def _is_internal_client(request: Request) -> bool:
    host = request.client.host if request.client else ""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return host == "localhost"


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PROD = APP_ENV == "production"

ENABLE_DOCS = _env_flag("ENABLE_DOCS", default=not IS_PROD)

allowed_hosts_raw = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").strip()
ALLOWED_HOSTS = [x.strip() for x in allowed_hosts_raw.split(",") if x.strip()]

app = FastAPI(
    title="Finger Backend API",
    version="0.9",
    description="""
Backend API for authentication, account settings management, device settings management, and avatar storage.
""",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

app.middleware("http")(build_client_gate_middleware())

app.include_router(auth.router)
app.include_router(device.router)
app.include_router(app_settings.router)
app.include_router(avatar.router)


@app.get(
    "/",
    summary="Health check",
    description="Simple root endpoint to verify that the API is running.",
    include_in_schema=False,
)
def root():
    return {"status": "ok"}


@app.get("/healthz", include_in_schema=False)
def healthz(request: Request):
    if not _is_internal_client(request):
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "oki-doki"}
