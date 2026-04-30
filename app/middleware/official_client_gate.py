from app.db import SessionLocal
from app.security.android_attestation import is_client_attestation_enabled
from app.security.client_request_signature import verify_signed_client_request
from app.services.common import ServiceError
from fastapi import Request
from fastapi.responses import JSONResponse

_EXACT_EXEMPT_PATHS = {
    "/",
    "/healthz",
    "/client/challenge",
    "/client/attest",
}

_PREFIX_EXEMPT_PATHS = (
    "/docs",
    "/redoc",
    "/openapi.json",
)


def build_official_client_gate_middleware():
    async def official_client_gate(request: Request, call_next):
        path = request.url.path

        if path in _EXACT_EXEMPT_PATHS or any(
            path.startswith(prefix) for prefix in _PREFIX_EXEMPT_PATHS
        ):
            return await call_next(request)

        if not is_client_attestation_enabled():
            return await call_next(request)

        body = await request.body()
        path_with_query = request.url.path
        if request.url.query:
            path_with_query += f"?{request.url.query}"

        db = SessionLocal()
        try:
            client = verify_signed_client_request(
                db=db,
                method=request.method,
                path_with_query=path_with_query,
                body=body,
                headers=request.headers,
            )
        except ServiceError as exc:
            return JSONResponse(
                status_code=exc.status_code, content={"detail": exc.detail}
            )
        finally:
            db.close()

        request.state.client_instance = client

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive
        return await call_next(request)

    return official_client_gate
