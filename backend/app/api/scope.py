from __future__ import annotations

from fastapi import APIRouter

from ..config import Scope, load_scope, save_scope

router = APIRouter(prefix="/api/scope", tags=["scope"])


@router.get("", response_model=Scope)
def get_scope():
    return load_scope()


@router.put("", response_model=Scope)
def put_scope(scope: Scope):
    save_scope(scope)
    return load_scope()
