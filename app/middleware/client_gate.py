import os

from fastapi import Request
from fastapi.responses import JSONResponse


_EXACT_EXEMPT_PATHS = {
    "/",
    "/healthz",
}

_PREFIX_EXEMPT_PATHS = (
    "/docs",
    "/redoc",
    "/openapi.json",
)


def build_client_gate_middleware():
    enabled = os.getenv("APP_CLIENT_TOKEN_ENABLED", "0").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    header_name = os.getenv("APP_CLIENT_HEADER_NAME", "X-App-Token").strip()
    token = (os.getenv("APP_CLIENT_TOKEN") or "").strip()

    async def client_gate(request: Request, call_next):
        path = request.url.path

        if path in _EXACT_EXEMPT_PATHS or any(
            path.startswith(prefix) for prefix in _PREFIX_EXEMPT_PATHS
        ):
            return await call_next(request)

        if enabled:
            if not token:
                return JSONResponse(
                    status_code=500,
                    content={"detail": "APP_CLIENT_TOKEN is not configured"},
                )

            if request.headers.get(header_name) != token:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid client token"},
                )

        return await call_next(request)

    return client_gate