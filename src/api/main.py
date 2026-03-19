"""
Main for the fastapi web application
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from api.schemas import EncryptedPackage
from api.store import save, get, list_ids

app = FastAPI(title="Secure Messaging API")


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/messages/{msg_id}")
def upload(msg_id: str, package: EncryptedPackage):
    save(msg_id, package.model_dump())
    return {"status": "stored", "message_id": msg_id}


@app.get("/messages/{msg_id}")
def download(msg_id: str):
    pkg = get(msg_id)
    if not pkg:
        raise HTTPException(status_code=404, detail="Not found")

    return pkg


@app.get("/messages")
def all_messages():
    return {"messages": list_ids()}
