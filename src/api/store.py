"""
Very simple in-memory storage for encrypted message packages.
"""
from __future__ import annotations

_store: dict[str, dict] = {}


def save(msg_id: str, package: dict):
    _store[msg_id] = package


def get(msg_id: str):
    return _store.get(msg_id)


def list_ids():
    return list(_store.keys())
