"""Per-router auth dependencies for all HTTP endpoints.

Instead of a centralized middleware with a route allowlist, auth mode is
implicit from which router an endpoint lives on:

- ``require_firebase``: Firebase token + BYOK validation + platform telemetry
- ``require_firebase_no_byok``: Firebase token only (BYOK activation/billing)
- No dependency: public or custom-auth routes (handler manages its own auth)

WebSocket endpoints are NOT handled here — they use explicit auth helpers
in ``endpoints.py`` and ``byok.py``.
"""

import logging
import os
from typing import AsyncGenerator, Dict, Optional

from fastapi import HTTPException, Request
from firebase_admin import auth as firebase_auth

import database.users as users_db
from utils.byok import (
    BYOK_HEADERS,
    _byok_ctx,
    validate_and_return_byok_keys,
)

logger = logging.getLogger('auth_middleware')


def _verify_token(token: str) -> str:
    """Verify a Firebase token or ADMIN_KEY and return the uid."""
    admin_key = os.getenv('ADMIN_KEY')
    if admin_key and token.startswith(admin_key):
        return token[len(admin_key) :]

    try:
        decoded_token = firebase_auth.verify_id_token(token)
        return decoded_token['uid']
    except firebase_auth.InvalidIdTokenError:
        if os.getenv('LOCAL_DEVELOPMENT') == 'true':
            return '123'
        raise


def _authenticate(request: Request) -> str:
    """Extract and verify Firebase token from Authorization header."""
    authorization = request.headers.get('authorization')
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header not found")

    parts = authorization.split(' ', 1)
    if len(parts) != 2 or not parts[1]:
        raise HTTPException(status_code=401, detail="Invalid authorization token")

    return _verify_token(parts[1])


def _extract_byok_headers(request: Request) -> Dict[str, str]:
    """Read BYOK headers from an HTTP request."""
    keys: Dict[str, str] = {}
    for provider, header in BYOK_HEADERS.items():
        value = request.headers.get(header)
        if value:
            keys[provider] = value
    return keys


async def require_firebase(request: Request) -> AsyncGenerator[str, None]:
    """Firebase auth + BYOK validation + platform telemetry.

    Sets ``request.state.uid`` and ``request.state.byok_keys``.
    Installs validated BYOK keys into ContextVar for deep LLM/STT access.
    """
    try:
        uid = _authenticate(request)
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid authorization token")

    request.state.uid = uid

    try:
        platform = request.headers.get('x-app-platform')
        if platform:
            users_db.record_user_platform(uid, platform)
    except Exception:
        pass

    byok_keys_raw = _extract_byok_headers(request)
    validated_keys = validate_and_return_byok_keys(uid, byok_keys_raw)
    request.state.byok_keys = validated_keys

    ctx_keys = validated_keys if validated_keys else None
    byok_token = _byok_ctx.set(ctx_keys)
    try:
        yield uid
    finally:
        _byok_ctx.reset(byok_token)


async def require_firebase_no_byok(request: Request) -> AsyncGenerator[str, None]:
    """Firebase auth without BYOK validation.

    For endpoints like BYOK activation/deactivation and billing that must work
    even when BYOK keys are rotated or broken.
    """
    try:
        uid = _authenticate(request)
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid authorization token")

    request.state.uid = uid
    request.state.byok_keys = {}

    try:
        platform = request.headers.get('x-app-platform')
        if platform:
            users_db.record_user_platform(uid, platform)
    except Exception:
        pass

    byok_keys_raw = _extract_byok_headers(request)
    ctx_keys = byok_keys_raw if byok_keys_raw else None
    byok_token = _byok_ctx.set(ctx_keys)
    try:
        yield uid
    finally:
        _byok_ctx.reset(byok_token)
