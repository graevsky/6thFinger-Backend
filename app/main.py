from fastapi import FastAPI
from app.routes import auth, device, app_settings

app = FastAPI(title="lmao somebody reading this?", version="0.1")

app.include_router(auth.router)
app.include_router(device.router)
app.include_router(app_settings.router)


@app.get("/")
def root():
    return {"status": "aboba"}
