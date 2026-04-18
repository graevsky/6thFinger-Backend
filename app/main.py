from fastapi import FastAPI
from app.routes import auth, avatar, device, app_settings

app = FastAPI(
    title="Finger Backend API",
    version="0.8",
    description="""

Backend API for authentication, account settings management, device settings management, and avatar storage.

Main routes:
- auth: SRP login, JWT tokens, email flows, password reset
- device: user-owned devices and device settings
- settings: app-level user preferences
- avatar: avatar upload, download, and deletion
""",
)

app.include_router(auth.router)
app.include_router(device.router)
app.include_router(app_settings.router)
app.include_router(avatar.router)


@app.get(
    "/",
    summary="Health check",
    description="Simple root endpoint to verify that the API is running.",
)
def root():
    """Health check endpoint."""
    return {"status": "aboba"}
