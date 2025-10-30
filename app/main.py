from fastapi import FastAPI

app = FastAPI(title="lmao somebody reading this?", version="0.1")

@app.get("/")
def root():
    return {"status": "aboba"}
