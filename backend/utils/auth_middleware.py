"""Unified Auth + BYOK middleware for all HTTP endpoints.

Replaces per-endpoint ``Depends(get_current_user_uid)`` with a single
middleware that runs on every HTTP request:

1. **Auth**: Verify Firebase ID token (or ADMIN_KEY), set ``request.state.uid``
2. **BYOK**: Extract + validate BYOK headers against Firestore fingerprints,
   set ``request.state.byok_keys`` and install into ContextVar
3. **Platform telemetry**: Record ``X-App-Platform`` (throttled)

Public routes (health, webhooks, firmware) and routes with custom auth
(integration API keys, admin secrets, MCP, OAuth) are allowlisted.

WebSocket endpoints are NOT handled here — ``BaseHTTPMiddleware`` only fires
for HTTP scope.  WS auth uses explicit helpers in ``endpoints.py``.
"""

import logging
import os
from enum import Enum
from typing import Dict, FrozenSet, List, Optional

from fastapi import HTTPException, Request
from firebase_admin import auth as firebase_auth
from firebase_admin.auth import InvalidIdTokenError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from database.users import record_user_platform
from utils.byok import (
    BYOK_HEADERS,
    _byok_ctx,
    set_byok_keys,
    validate_and_return_byok_keys,
)

logger = logging.getLogger('auth_middleware')


class AuthMode(str, Enum):
    """How a route should be authenticated."""

    FIREBASE = "firebase"  # Standard: Firebase + BYOK validation
    FIREBASE_SKIP_BYOK = "firebase_skip_byok"  # Firebase only, no BYOK validation
    CUSTOM = "custom"  # Route handles its own auth (API keys, admin secret, webhooks)
    PUBLIC = "public"  # No auth required


class RouteRule:
    """Match a request to an auth mode by method + path prefix."""

    __slots__ = ('methods', 'path', 'mode', '_is_prefix', '_has_middle_wild')

    def __init__(self, methods: FrozenSet[str], path: str, mode: AuthMode):
        self.methods = methods
        self.mode = mode
        self._has_middle_wild = False
        # Paths ending with * are prefix matches (e.g. "/v1/dev/*")
        if path.endswith('/*'):
            self._is_prefix = True
            self.path = path[:-1]  # keep trailing /
        elif '*' in path:
            # Middle wildcard (e.g. "/v1/conversations/*/shared")
            self._is_prefix = False
            self._has_middle_wild = True
            self.path = path
        else:
            self._is_prefix = False
            self.path = path

    def matches(self, method: str, path: str) -> bool:
        if self.methods and method not in self.methods:
            return False
        if self._is_prefix:
            return path.startswith(self.path)
        if self._has_middle_wild:
            # Simple glob: split on * and check prefix/suffix
            parts = self.path.split('*')
            return path.startswith(parts[0]) and path.endswith(parts[1]) and len(path) > len(parts[0]) + len(parts[1])
        # Exact match
        return path == self.path


_ALL = frozenset()  # empty = match all methods


def _verify_token(token: str) -> str:
    """Verify a Firebase token or ADMIN_KEY and return the uid."""
    admin_key = os.getenv('ADMIN_KEY')
    if admin_key and token.startswith(admin_key):
        return token[len(admin_key) :]

    try:
        decoded_token = firebase_auth.verify_id_token(token)
        return decoded_token['uid']
    except InvalidIdTokenError:
        if os.getenv('LOCAL_DEVELOPMENT') == 'true':
            return '123'
        raise


# ---------------------------------------------------------------------------
# Public / Custom route allowlist
#
# Routes NOT listed here default to AuthMode.FIREBASE (auth + BYOK).
# Order matters: first match wins.
# ---------------------------------------------------------------------------

AUTH_RULES: List[RouteRule] = [
    # --- Fully public (no auth) ---
    RouteRule(_ALL, "/v1/health", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/trends", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/announcements/changelogs", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/announcements/features", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/announcements/general", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/app-categories", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/app-capabilities", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/app/proactive-notification-scopes", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/action-items/shared/*", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v2/messages/shared/*", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/conversations/*/shared", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v2/firmware/latest", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v2/firmware/stable", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v2/desktop/appcast.xml", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v2/desktop/download/latest", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v2/desktop/download/beta", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/docs", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/openapi.json", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/redoc", AuthMode.PUBLIC),
    # Payment browser redirects / HTML pages (no auth)
    RouteRule(frozenset({"GET"}), "/v1/stripe/supported-countries", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/stripe/return/*", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/payments/success", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/payments/cancel", AuthMode.PUBLIC),
    RouteRule(frozenset({"GET"}), "/v1/payments/portal-return", AuthMode.PUBLIC),
    # --- Custom auth (own auth logic, not Firebase) ---
    # OAuth / auth flow
    RouteRule(_ALL, "/v1/auth/*", AuthMode.CUSTOM),
    RouteRule(_ALL, "/v1/oauth/*", AuthMode.CUSTOM),
    # Integration API key auth
    RouteRule(_ALL, "/v2/integrations/*", AuthMode.CUSTOM),
    # MCP SSE (API key auth)
    RouteRule(_ALL, "/v1/mcp/sse/*", AuthMode.CUSTOM),
    RouteRule(_ALL, "/v1/mcp/sse", AuthMode.CUSTOM),
    RouteRule(_ALL, "/authorize", AuthMode.CUSTOM),
    RouteRule(frozenset({"POST"}), "/token", AuthMode.CUSTOM),
    # Admin secret key
    RouteRule(_ALL, "/v1/admin/*", AuthMode.CUSTOM),
    # Announcements: user routes need Firebase, admin routes use secret-key header.
    # First-match-wins, so list Firebase user routes BEFORE admin wildcards.
    RouteRule(frozenset({"GET"}), "/v1/announcements/pending", AuthMode.FIREBASE),
    # POST /{id}/dismiss has extra segment — won't match PUT/DELETE /{id} wildcard
    # Admin CRUD (secret-key auth in handler)
    RouteRule(frozenset({"GET"}), "/v1/announcements/all", AuthMode.CUSTOM),
    RouteRule(frozenset({"POST"}), "/v1/announcements", AuthMode.CUSTOM),
    RouteRule(frozenset({"GET", "PUT", "DELETE"}), "/v1/announcements/*", AuthMode.CUSTOM),
    # Metrics (secret key)
    RouteRule(frozenset({"GET"}), "/metrics", AuthMode.CUSTOM),
    # Webhooks (signature validation)
    RouteRule(frozenset({"POST"}), "/v1/stripe/webhook", AuthMode.CUSTOM),
    RouteRule(frozenset({"POST"}), "/v1/stripe/connect/webhook", AuthMode.CUSTOM),
    RouteRule(frozenset({"POST"}), "/v2/desktop/clear-cache", AuthMode.CUSTOM),
    # External callbacks
    RouteRule(frozenset({"POST"}), "/v1/agents/hume/callback", AuthMode.CUSTOM),
    # Developer API (own key auth)
    RouteRule(_ALL, "/v1/dev/*", AuthMode.CUSTOM),
    # Notification webhooks
    RouteRule(frozenset({"POST"}), "/v1/notification", AuthMode.CUSTOM),
    RouteRule(frozenset({"POST"}), "/v1/integrations/notification", AuthMode.CUSTOM),
    # Agent tools (VM auth — /v1/agent-tools/ only, NOT /v1/tools/ which uses Firebase)
    RouteRule(_ALL, "/v1/agent-tools/*", AuthMode.CUSTOM),
    # Phone call webhooks
    RouteRule(frozenset({"POST"}), "/v1/phone-calls/webhook", AuthMode.CUSTOM),
    RouteRule(frozenset({"POST"}), "/v1/phone-calls/webhook/*", AuthMode.CUSTOM),
    # --- Firebase auth, skip BYOK validation ---
    # BYOK activation/deactivation endpoints (would deadlock on fingerprint check)
    RouteRule(frozenset({"POST", "DELETE"}), "/v1/users/me/byok-active", AuthMode.FIREBASE_SKIP_BYOK),
    # Payment/subscription (must work even if BYOK keys are rotated)
    RouteRule(frozenset({"GET"}), "/v1/payments/available-plans", AuthMode.FIREBASE_SKIP_BYOK),
    RouteRule(frozenset({"GET"}), "/v1/payments/overage-info", AuthMode.FIREBASE_SKIP_BYOK),
    RouteRule(frozenset({"GET"}), "/v1/users/me/subscription", AuthMode.FIREBASE_SKIP_BYOK),
]


def _resolve_auth_mode(method: str, path: str) -> AuthMode:
    """Determine how a request should be authenticated."""
    for rule in AUTH_RULES:
        if rule.matches(method, path):
            return rule.mode
    return AuthMode.FIREBASE


def _extract_byok_headers(request: Request) -> Dict[str, str]:
    """Read BYOK headers from an HTTP request."""
    keys: Dict[str, str] = {}
    for provider, header in BYOK_HEADERS.items():
        value = request.headers.get(header)
        if value:
            keys[provider] = value
    return keys


class AuthMiddleware(BaseHTTPMiddleware):
    """Unified authentication + BYOK middleware for all HTTP endpoints.

    Sets ``request.state.uid`` and ``request.state.byok_keys`` for downstream
    handlers.  Also installs BYOK keys into the ContextVar so that
    ``get_byok_keys()`` / ``has_byok_keys()`` work throughout the request.

    NOTE: ``BaseHTTPMiddleware`` does NOT fire for WebSocket connections.
    WebSocket auth is handled by explicit deps in ``endpoints.py``.
    """

    async def dispatch(self, request: Request, call_next):
        mode = _resolve_auth_mode(request.method, request.url.path)

        # Public or custom-auth routes — pass through without Firebase auth
        if mode in (AuthMode.PUBLIC, AuthMode.CUSTOM):
            # Still extract BYOK headers into ContextVar for has_byok_keys() checks
            byok_keys = _extract_byok_headers(request)
            byok_token = _byok_ctx.set(byok_keys if byok_keys else None)
            request.state.uid = None
            request.state.byok_keys = {}
            try:
                return await call_next(request)
            finally:
                _byok_ctx.reset(byok_token)

        # Firebase auth required
        try:
            uid = self._authenticate(request)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        except InvalidIdTokenError:
            return JSONResponse({"detail": "Invalid authorization token"}, status_code=401)

        request.state.uid = uid

        # Platform telemetry (fire-and-forget, never fails the request)
        try:
            platform = request.headers.get('x-app-platform')
            if platform:
                record_user_platform(uid, platform)
        except Exception:
            pass

        # BYOK validation
        byok_keys_raw = _extract_byok_headers(request)
        validated_keys: Dict[str, str] = {}

        if mode == AuthMode.FIREBASE:
            try:
                validated_keys = validate_and_return_byok_keys(uid, byok_keys_raw)
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        # FIREBASE_SKIP_BYOK: extract but don't validate (for BYOK activation endpoints)

        request.state.byok_keys = validated_keys

        # Install into ContextVar so get_byok_keys()/has_byok_keys() work
        # For FIREBASE mode: only install validated keys (never raw/unvalidated)
        # For FIREBASE_SKIP_BYOK: install raw keys (validation intentionally skipped)
        if mode == AuthMode.FIREBASE:
            ctx_keys = validated_keys if validated_keys else None
        else:
            ctx_keys = byok_keys_raw if byok_keys_raw else None
        byok_token = _byok_ctx.set(ctx_keys)
        try:
            return await call_next(request)
        finally:
            _byok_ctx.reset(byok_token)

    def _authenticate(self, request: Request) -> str:
        """Extract and verify Firebase token from Authorization header."""
        authorization = request.headers.get('authorization')
        if not authorization:
            raise HTTPException(status_code=401, detail="Authorization header not found")

        parts = authorization.split(' ', 1)
        if len(parts) != 2 or not parts[1]:
            raise HTTPException(status_code=401, detail="Invalid authorization token")

        token = parts[1]
        return _verify_token(token)
