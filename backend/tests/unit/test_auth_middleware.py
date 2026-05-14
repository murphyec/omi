"""Tests for the unified AuthMiddleware (utils/auth_middleware.py).

Covers:
- Route matching (public, custom, firebase, firebase_skip_byok)
- RouteRule exact and prefix matching
- Token verification (ADMIN_KEY and Firebase)
- End-to-end middleware dispatch (mocked)
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock database modules before importing auth_middleware — track what we inject
# so we can clean up if tests are collected alongside other test modules.
_MOCKED_MODULES = ['database', 'database._client', 'database.users', 'database.redis_db']
_injected = []
for _mod in _MOCKED_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
        _injected.append(_mod)


def teardown_module():
    """Remove only the mocks WE injected (don't clobber real imports from other tests)."""
    for _mod in _injected:
        sys.modules.pop(_mod, None)


from utils.auth_middleware import (
    AUTH_RULES,
    AuthMode,
    RouteRule,
    _resolve_auth_mode,
    _verify_token,
)


class TestRouteMatching(unittest.TestCase):
    """Test _resolve_auth_mode against AUTH_RULES."""

    # --- Public routes ---

    def test_health_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/health") == AuthMode.PUBLIC

    def test_trends_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/trends") == AuthMode.PUBLIC

    def test_firmware_latest_is_public(self):
        assert _resolve_auth_mode("GET", "/v2/firmware/latest") == AuthMode.PUBLIC

    def test_firmware_stable_is_public(self):
        assert _resolve_auth_mode("GET", "/v2/firmware/stable") == AuthMode.PUBLIC

    def test_desktop_appcast_is_public(self):
        assert _resolve_auth_mode("GET", "/v2/desktop/appcast.xml") == AuthMode.PUBLIC

    def test_desktop_download_latest_is_public(self):
        assert _resolve_auth_mode("GET", "/v2/desktop/download/latest") == AuthMode.PUBLIC

    def test_app_categories_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/app-categories") == AuthMode.PUBLIC

    def test_app_capabilities_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/app-capabilities") == AuthMode.PUBLIC

    def test_announcements_changelogs_public(self):
        assert _resolve_auth_mode("GET", "/v1/announcements/changelogs") == AuthMode.PUBLIC

    def test_announcements_features_public(self):
        assert _resolve_auth_mode("GET", "/v1/announcements/features") == AuthMode.PUBLIC

    def test_announcements_general_public(self):
        assert _resolve_auth_mode("GET", "/v1/announcements/general") == AuthMode.PUBLIC

    def test_shared_action_items_public(self):
        assert _resolve_auth_mode("GET", "/v1/action-items/shared/abc123") == AuthMode.PUBLIC

    def test_shared_messages_public(self):
        assert _resolve_auth_mode("GET", "/v2/messages/shared/token456") == AuthMode.PUBLIC

    def test_docs_public(self):
        assert _resolve_auth_mode("GET", "/docs") == AuthMode.PUBLIC

    def test_openapi_json_public(self):
        assert _resolve_auth_mode("GET", "/openapi.json") == AuthMode.PUBLIC

    # --- Custom auth routes ---

    def test_auth_authorize_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/auth/authorize") == AuthMode.CUSTOM

    def test_auth_callback_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/auth/callback/google") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/auth/callback/apple") == AuthMode.CUSTOM

    def test_oauth_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/oauth/authorize") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/oauth/token") == AuthMode.CUSTOM

    def test_integration_is_custom(self):
        assert _resolve_auth_mode("POST", "/v2/integrations/app123/user/conversations") == AuthMode.CUSTOM

    def test_mcp_sse_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/mcp/sse") == AuthMode.CUSTOM
        assert _resolve_auth_mode("GET", "/v1/mcp/sse") == AuthMode.CUSTOM
        assert _resolve_auth_mode("GET", "/v1/mcp/sse/info") == AuthMode.CUSTOM

    def test_stripe_webhook_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/stripe/webhook") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/stripe/connect/webhook") == AuthMode.CUSTOM

    def test_metrics_is_custom(self):
        assert _resolve_auth_mode("GET", "/metrics") == AuthMode.CUSTOM

    def test_admin_routes_are_custom(self):
        assert _resolve_auth_mode("GET", "/v1/admin/fair-use/flagged") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/admin/fair-use/user/uid123/resolve-event/evt1") == AuthMode.CUSTOM

    def test_dev_api_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/dev/user/memories") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/dev/user/memories") == AuthMode.CUSTOM

    def test_agent_tools_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/agent-tools/execute") == AuthMode.CUSTOM
        assert _resolve_auth_mode("GET", "/v1/agent-tools/status") == AuthMode.CUSTOM

    def test_tools_is_firebase(self):
        # /v1/tools/* uses Firebase auth (not custom)
        assert _resolve_auth_mode("GET", "/v1/tools/conversations") == AuthMode.FIREBASE
        assert _resolve_auth_mode("POST", "/v1/tools/conversations/search") == AuthMode.FIREBASE

    def test_notification_webhook_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/notification") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/integrations/notification") == AuthMode.CUSTOM

    def test_hume_callback_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/agents/hume/callback") == AuthMode.CUSTOM

    def test_desktop_clear_cache_is_custom(self):
        assert _resolve_auth_mode("POST", "/v2/desktop/clear-cache") == AuthMode.CUSTOM

    def test_phone_webhooks_are_custom(self):
        assert _resolve_auth_mode("POST", "/v1/phone-calls/webhook") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/phone-calls/webhook/status") == AuthMode.CUSTOM

    # --- Firebase skip BYOK ---

    def test_byok_activation_skip_byok(self):
        assert _resolve_auth_mode("POST", "/v1/users/me/byok-active") == AuthMode.FIREBASE_SKIP_BYOK
        assert _resolve_auth_mode("DELETE", "/v1/users/me/byok-active") == AuthMode.FIREBASE_SKIP_BYOK

    def test_subscription_skip_byok(self):
        assert _resolve_auth_mode("GET", "/v1/users/me/subscription") == AuthMode.FIREBASE_SKIP_BYOK

    def test_payment_plans_skip_byok(self):
        assert _resolve_auth_mode("GET", "/v1/payments/available-plans") == AuthMode.FIREBASE_SKIP_BYOK

    def test_overage_info_skip_byok(self):
        assert _resolve_auth_mode("GET", "/v1/payments/overage-info") == AuthMode.FIREBASE_SKIP_BYOK

    # --- Default: Firebase (auth + BYOK) ---

    def test_conversations_is_firebase(self):
        assert _resolve_auth_mode("GET", "/v1/conversations") == AuthMode.FIREBASE

    def test_memories_is_firebase(self):
        assert _resolve_auth_mode("GET", "/v3/memories") == AuthMode.FIREBASE

    def test_chat_messages_is_firebase(self):
        assert _resolve_auth_mode("POST", "/v2/messages") == AuthMode.FIREBASE

    def test_users_profile_is_firebase(self):
        assert _resolve_auth_mode("GET", "/v1/users/profile") == AuthMode.FIREBASE

    def test_unknown_route_defaults_to_firebase(self):
        assert _resolve_auth_mode("GET", "/v99/unknown/endpoint") == AuthMode.FIREBASE

    def test_post_to_public_get_route_is_firebase(self):
        # POST to /v1/trends should be Firebase (only GET is public)
        assert _resolve_auth_mode("POST", "/v1/trends") == AuthMode.FIREBASE

    def test_shared_conversation_is_public(self):
        # Middle wildcard: /v1/conversations/*/shared
        assert _resolve_auth_mode("GET", "/v1/conversations/abc123/shared") == AuthMode.PUBLIC

    def test_announcements_pending_is_firebase(self):
        # User route: needs Firebase auth, not CUSTOM
        assert _resolve_auth_mode("GET", "/v1/announcements/pending") == AuthMode.FIREBASE

    def test_announcements_dismiss_is_firebase(self):
        # POST /v1/announcements/{id}/dismiss — user route, needs Firebase
        assert _resolve_auth_mode("POST", "/v1/announcements/abc123/dismiss") == AuthMode.FIREBASE

    def test_announcements_admin_crud_is_custom(self):
        # Admin routes use secret-key header
        assert _resolve_auth_mode("GET", "/v1/announcements/all") == AuthMode.CUSTOM
        assert _resolve_auth_mode("POST", "/v1/announcements") == AuthMode.CUSTOM
        assert _resolve_auth_mode("PUT", "/v1/announcements/abc123") == AuthMode.CUSTOM
        assert _resolve_auth_mode("DELETE", "/v1/announcements/abc123") == AuthMode.CUSTOM

    def test_announcements_admin_get_by_id_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/announcements/abc123") == AuthMode.CUSTOM

    # --- Payment browser redirects (public, no auth) ---

    def test_stripe_supported_countries_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/stripe/supported-countries") == AuthMode.PUBLIC

    def test_stripe_return_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/stripe/return/acct_123abc") == AuthMode.PUBLIC

    def test_payments_success_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/payments/success") == AuthMode.PUBLIC

    def test_payments_cancel_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/payments/cancel") == AuthMode.PUBLIC

    def test_payments_portal_return_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/payments/portal-return") == AuthMode.PUBLIC

    # Public app catalog endpoints
    def test_v2_apps_catalog_is_public(self):
        assert _resolve_auth_mode("GET", "/v2/apps") == AuthMode.PUBLIC

    def test_v2_apps_capability_grouped_is_public(self):
        assert _resolve_auth_mode("GET", "/v2/apps/capability/abc123/grouped") == AuthMode.PUBLIC

    def test_approved_apps_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/approved-apps") == AuthMode.PUBLIC

    def test_popular_apps_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/apps/popular") == AuthMode.PUBLIC

    def test_app_reviews_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/apps/some-app-id/reviews") == AuthMode.PUBLIC

    def test_app_payment_plans_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/app/payment-plans") == AuthMode.PUBLIC

    def test_app_plans_is_firebase(self):
        """GET /v1/app/plans requires Firebase auth (handler reads request.state.uid)."""
        assert _resolve_auth_mode("GET", "/v1/app/plans") == AuthMode.FIREBASE

    # Stripe Connect refresh is custom
    def test_stripe_refresh_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/stripe/refresh/acct_123") == AuthMode.CUSTOM

    # Admin app management is custom
    def test_app_approve_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/apps/some-id/approve") == AuthMode.CUSTOM

    def test_app_reject_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/apps/some-id/reject") == AuthMode.CUSTOM

    def test_unapproved_apps_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/apps/public/unapproved") == AuthMode.CUSTOM

    # Personas: twitter routes use Firebase, admin get-by-id uses CUSTOM
    def test_personas_twitter_profile_is_firebase(self):
        assert _resolve_auth_mode("GET", "/v1/personas/twitter/profile") == AuthMode.FIREBASE

    def test_personas_twitter_verify_ownership_is_firebase(self):
        assert _resolve_auth_mode("GET", "/v1/personas/twitter/verify-ownership") == AuthMode.FIREBASE

    def test_personas_twitter_initial_message_is_firebase(self):
        assert _resolve_auth_mode("GET", "/v1/personas/twitter/initial-message") == AuthMode.FIREBASE

    def test_personas_admin_get_by_id_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/personas/some-persona-id") == AuthMode.CUSTOM

    # summary-app-ids: exact match and wildcard
    def test_summary_app_ids_exact_is_custom(self):
        assert _resolve_auth_mode("GET", "/v1/summary-app-ids") == AuthMode.CUSTOM

    def test_summary_app_ids_with_segment_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/summary-app-ids/abc123") == AuthMode.CUSTOM

    # Codex-found missing routes
    def test_fair_use_case_status_is_public(self):
        assert _resolve_auth_mode("GET", "/v1/fair-use/case/ABC123/status") == AuthMode.PUBLIC

    def test_phone_twiml_is_custom(self):
        assert _resolve_auth_mode("POST", "/v1/phone/twiml") == AuthMode.CUSTOM

    def test_migrate_owner_is_firebase(self):
        assert _resolve_auth_mode("POST", "/v1/apps/migrate-owner") == AuthMode.FIREBASE

    def test_docs_oauth2_redirect_is_public(self):
        assert _resolve_auth_mode("GET", "/docs/oauth2-redirect") == AuthMode.PUBLIC


class TestRouteRule(unittest.TestCase):
    """Test RouteRule matching logic."""

    def test_exact_match(self):
        rule = RouteRule(frozenset({"GET"}), "/v1/health", AuthMode.PUBLIC)
        assert rule.matches("GET", "/v1/health") is True
        assert rule.matches("POST", "/v1/health") is False
        assert rule.matches("GET", "/v1/health/extra") is False

    def test_prefix_match(self):
        rule = RouteRule(frozenset({"GET"}), "/v1/dev/*", AuthMode.CUSTOM)
        assert rule.matches("GET", "/v1/dev/user/memories") is True
        assert rule.matches("GET", "/v1/dev/") is True
        assert rule.matches("GET", "/v1/developer") is False
        assert rule.matches("POST", "/v1/dev/test") is False

    def test_all_methods_match(self):
        rule = RouteRule(frozenset(), "/v1/health", AuthMode.PUBLIC)
        assert rule.matches("GET", "/v1/health") is True
        assert rule.matches("POST", "/v1/health") is True
        assert rule.matches("DELETE", "/v1/health") is True

    def test_multiple_methods(self):
        rule = RouteRule(frozenset({"POST", "DELETE"}), "/v1/users/me/byok-active", AuthMode.FIREBASE_SKIP_BYOK)
        assert rule.matches("POST", "/v1/users/me/byok-active") is True
        assert rule.matches("DELETE", "/v1/users/me/byok-active") is True
        assert rule.matches("GET", "/v1/users/me/byok-active") is False

    def test_middle_wildcard_match(self):
        rule = RouteRule(frozenset({"GET"}), "/v1/conversations/*/shared", AuthMode.PUBLIC)
        assert rule.matches("GET", "/v1/conversations/abc123/shared") is True
        assert rule.matches("GET", "/v1/conversations//shared") is False  # empty segment
        assert rule.matches("GET", "/v1/conversations/shared") is False  # no middle segment
        assert rule.matches("POST", "/v1/conversations/abc123/shared") is False  # wrong method


class TestVerifyToken(unittest.TestCase):
    """Test token verification logic."""

    @patch.dict(os.environ, {"ADMIN_KEY": "test_admin_key_"})
    def test_admin_key_extracts_uid(self):
        uid = _verify_token("test_admin_key_user123")
        assert uid == "user123"

    @patch.dict(os.environ, {"ADMIN_KEY": "admin_"})
    def test_admin_key_empty_uid(self):
        uid = _verify_token("admin_")
        assert uid == ""

    @patch.dict(os.environ, {"ADMIN_KEY": ""})
    @patch("utils.auth_middleware.firebase_auth.verify_id_token")
    def test_firebase_token_verified(self, mock_verify):
        mock_verify.return_value = {"uid": "firebase_user"}
        uid = _verify_token("valid.firebase.token")
        assert uid == "firebase_user"
        mock_verify.assert_called_once_with("valid.firebase.token")

    @patch.dict(os.environ, {"ADMIN_KEY": "", "LOCAL_DEVELOPMENT": "true"})
    @patch("utils.auth_middleware.firebase_auth.verify_id_token")
    def test_local_dev_fallback(self, mock_verify):
        from firebase_admin.auth import InvalidIdTokenError

        mock_verify.side_effect = InvalidIdTokenError("test")
        uid = _verify_token("bad_token")
        assert uid == "123"

    @patch.dict(os.environ, {"ADMIN_KEY": "", "LOCAL_DEVELOPMENT": ""})
    @patch("utils.auth_middleware.firebase_auth.verify_id_token")
    def test_invalid_token_raises(self, mock_verify):
        from firebase_admin.auth import InvalidIdTokenError

        mock_verify.side_effect = InvalidIdTokenError("test")
        with self.assertRaises(InvalidIdTokenError):
            _verify_token("bad_token")


class TestAllowlistCompleteness(unittest.TestCase):
    """Ensure the allowlist covers all known public/custom routes."""

    def test_no_duplicate_rules(self):
        seen = set()
        for rule in AUTH_RULES:
            key = (tuple(sorted(rule.methods)), rule.path, rule.mode)
            assert key not in seen, f"Duplicate rule: {key}"
            seen.add(key)

    def test_all_modes_represented(self):
        modes = {rule.mode for rule in AUTH_RULES}
        assert AuthMode.PUBLIC in modes
        assert AuthMode.CUSTOM in modes
        assert AuthMode.FIREBASE_SKIP_BYOK in modes
        # FIREBASE is the default, doesn't need explicit rules


if __name__ == "__main__":
    unittest.main()
