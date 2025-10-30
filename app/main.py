from fastapi import FastAPI
from app.routes import auth

app = FastAPI(title="lmao somebody reading this?", version="0.1")

app.include_router(auth.router)


@app.get("/")
def root():
    return {"status": "aboba"}
