import json
import logging
import re
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import RequestFactory, TestCase, override_settings

from api.middleware import AuthenticationPolicyMiddleware
from api.views_api import _validate_oidc_id_token, login
from api.views_front import user_login, user_register
from camellia_remote_management.observability import (
    StructuredEventFormatter,
    sanitize_log_attributes,
    sanitize_log_value,
)


class Batch82AuthPolicyAndLogHardeningTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_log_sanitization_secrets_redaction(self):
        """LOG-012: Secret keys are automatically redacted."""
        raw_attributes = {
            "username": "admin",
            "password": "SecretPasswordVal",
            "auth_token": "bearer-xyz-12345",
            "api_key": "sec_key_9999",
            "cookie": "sessionid=abcd1234efgh5678",
            "client_secret": "my-client-secret",
        }
        sanitized = sanitize_log_attributes(raw_attributes)
        self.assertEqual(sanitized["username"], "admin")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["auth_token"], "[REDACTED]")
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["cookie"], "[REDACTED]")
        self.assertEqual(sanitized["client_secret"], "[REDACTED]")

    def test_log_sanitization_pii_masking(self):
        """LOG-012: IP addresses and emails are masked in values."""
        raw_attributes = {
            "ip": "192.168.1.100",
            "client_ipv6": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "email": "developer@camellia-remote.org",
            "nested": {
                "user_email": "alice_test@example.com",
                "remote_addr": "10.0.0.1",
            },
        }
        sanitized = sanitize_log_attributes(raw_attributes)
        self.assertEqual(sanitized["ip"], "192.168.1.xxx")
        self.assertEqual(sanitized["client_ipv6"], "2001:0db8:85a3:xxxx")
        self.assertEqual(sanitized["email"], "d***@camellia-remote.org")
        self.assertEqual(sanitized["nested"]["user_email"], "a***@example.com")
        self.assertEqual(sanitized["nested"]["remote_addr"], "10.0.0.xxx")

    def test_log_sanitization_control_chars_and_length_bounding(self):
        """LOG-012: Control characters are stripped and long strings bounded."""
        malicious_input = "line1\r\nFake Log Line: 2026-01-01 [CRITICAL] Injected\0\x1b[31mRed"
        sanitized_str = sanitize_log_value(malicious_input)
        self.assertNotIn("\r", sanitized_str)
        self.assertNotIn("\n", sanitized_str)
        self.assertNotIn("\0", sanitized_str)
        self.assertNotIn("\x1b", sanitized_str)

        huge_string = "A" * 2000
        bounded_str = sanitize_log_value(huge_string, max_len=1024)
        self.assertLessEqual(len(bounded_str), 1040)
        self.assertTrue(bounded_str.endswith("...[TRUNCATED]"))

    def test_structured_event_formatter_sanitization(self):
        """LOG-012: Formatter sanitizes application log records."""
        formatter = StructuredEventFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.WARNING,
            pathname=__file__,
            lineno=50,
            msg="User bob@company.com with token 12345 login from 172.16.0.5",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        data = json.loads(formatted)
        self.assertEqual(data["service"], "remote-management")
        self.assertEqual(data["attributes"]["logger"], "test_logger")
        self.assertIn("b***@company.com", data["attributes"]["message"])
        self.assertIn("172.16.0.xxx", data["attributes"]["message"])

    @override_settings(CAMELLIA_REMOTE_AUTH_OIDC_ONLY=True)
    def test_auth014_api_login_rejected_when_oidc_only(self):
        """AUTH-014: API password login is rejected with HTTP 403 when OIDC-only is active."""
        request = self.factory.post(
            "/api/login",
            data=json.dumps({"username": "admin", "password": "password123"}),
            content_type="application/json",
        )
        response = login(request)
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertIn("OIDC", data.get("error", ""))

    @override_settings(CAMELLIA_REMOTE_AUTH_OIDC_ONLY=True)
    def test_auth014_front_login_rejected_when_oidc_only(self):
        """AUTH-014: Web front password login is rejected with HTTP 403 when OIDC-only is active."""
        request = self.factory.post(
            "/login",
            data={"account": "admin", "password": "password123"},
        )
        response = user_login(request)
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertEqual(data["code"], 0)
        self.assertIn("OIDC", data.get("msg", ""))

    @override_settings(CAMELLIA_REMOTE_AUTH_OIDC_ONLY=True)
    def test_auth014_front_register_rejected_when_oidc_only(self):
        """AUTH-014: Web front registration is rejected with HTTP 403 when OIDC-only is active."""
        request = self.factory.post(
            "/register",
            data={"account": "newuser", "password": "password123", "repassword": "password123"},
        )
        response = user_register(request)
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertEqual(data["code"], 0)
        self.assertIn("OIDC", data.get("msg", ""))

    @override_settings(CAMELLIA_REMOTE_AUTH_OIDC_ONLY=True)
    def test_auth014_admin_login_blocked_by_middleware(self):
        """AUTH-014: POST to admin login is blocked by AuthenticationPolicyMiddleware."""
        get_response = MagicMock()
        middleware = AuthenticationPolicyMiddleware(get_response)

        request = self.factory.post(
            "/admin/login/",
            data={"username": "admin", "password": "password123"},
        )
        response = middleware(request)
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Password login is disabled", response.content)
        self.assertFalse(get_response.called)

    def test_auth014_oidc_token_acr_policy_enforcement(self):
        """AUTH-014: _validate_oidc_id_token enforces required ACR values."""
        metadata = {"issuer": "https://auth.example.com", "id_token_signing_alg_values_supported": ["RS256"]}
        provider = {"client_id": "test-client-id"}

        with patch("api.views_api.validated_signing_algorithms", return_value=["RS256"]), \
             patch("api.views_api.validate_oidc_jwks", return_value={}), \
             patch("api.views_api._oidc_jwks", return_value={}), \
             patch("api.views_api._decode_oidc_id_token") as mock_decode, \
             patch("api.views_api.JWTClaimsRegistry") as mock_registry:

            mock_registry_instance = MagicMock()
            mock_registry.return_value = mock_registry_instance

            # Case 1: ACR policy configured and token satisfies it
            with override_settings(OIDC_REQUIRED_ACR_VALUES=("gold", "platinum")):
                mock_decode.return_value = MagicMock(
                    claims={
                        "iss": "https://auth.example.com",
                        "sub": "sub123",
                        "aud": "test-client-id",
                        "exp": 9999999999,
                        "iat": 1000000000,
                        "nonce": "nonce123",
                        "acr": "platinum",
                    }
                )
                claims = _validate_oidc_id_token({"id_token": "token123"}, metadata, provider, "nonce123")
                self.assertEqual(claims["acr"], "platinum")

            # Case 2: ACR policy configured and token does NOT satisfy it
            with override_settings(OIDC_REQUIRED_ACR_VALUES=("gold", "platinum")):
                mock_decode.return_value = MagicMock(
                    claims={
                        "iss": "https://auth.example.com",
                        "sub": "sub123",
                        "aud": "test-client-id",
                        "exp": 9999999999,
                        "iat": 1000000000,
                        "nonce": "nonce123",
                        "acr": "bronze",
                    }
                )
                with self.assertRaises(ValueError) as ctx:
                    _validate_oidc_id_token({"id_token": "token123"}, metadata, provider, "nonce123")
                self.assertIn("does not satisfy required ACR policy", str(ctx.exception))

    def test_auth014_oidc_token_mfa_policy_enforcement(self):
        """AUTH-014: _validate_oidc_id_token enforces MFA requirements."""
        metadata = {"issuer": "https://auth.example.com", "id_token_signing_alg_values_supported": ["RS256"]}
        provider = {"client_id": "test-client-id"}

        with patch("api.views_api.validated_signing_algorithms", return_value=["RS256"]), \
             patch("api.views_api.validate_oidc_jwks", return_value={}), \
             patch("api.views_api._oidc_jwks", return_value={}), \
             patch("api.views_api._decode_oidc_id_token") as mock_decode, \
             patch("api.views_api.JWTClaimsRegistry") as mock_registry:

            mock_registry_instance = MagicMock()
            mock_registry.return_value = mock_registry_instance

            # Case 1: MFA required, token has amr: ["pwd", "otp"]
            with override_settings(CAMELLIA_REMOTE_OIDC_REQUIRE_MFA=True, OIDC_REQUIRED_ACR_VALUES=()):
                mock_decode.return_value = MagicMock(
                    claims={
                        "iss": "https://auth.example.com",
                        "sub": "sub123",
                        "aud": "test-client-id",
                        "exp": 9999999999,
                        "iat": 1000000000,
                        "nonce": "nonce123",
                        "amr": ["pwd", "otp"],
                    }
                )
                claims = _validate_oidc_id_token({"id_token": "token123"}, metadata, provider, "nonce123")
                self.assertIn("otp", claims["amr"])

            # Case 2: MFA required, token only has password
            with override_settings(CAMELLIA_REMOTE_OIDC_REQUIRE_MFA=True, OIDC_REQUIRED_ACR_VALUES=()):
                mock_decode.return_value = MagicMock(
                    claims={
                        "iss": "https://auth.example.com",
                        "sub": "sub123",
                        "aud": "test-client-id",
                        "exp": 9999999999,
                        "iat": 1000000000,
                        "nonce": "nonce123",
                        "amr": ["pwd"],
                        "acr": "0",
                    }
                )
                with self.assertRaises(ValueError) as ctx:
                    _validate_oidc_id_token({"id_token": "token123"}, metadata, provider, "nonce123")
                self.assertIn("does not satisfy required MFA policy", str(ctx.exception))

    def test_log013_docker_compose_logging_contracts(self):
        """LOG-013: docker-compose.yaml defines bounded json-file logging for all services."""
        compose_path = settings.BASE_DIR / "docker-compose.yaml"
        compose_text = compose_path.read_text(encoding="utf-8")

        self.assertIn("x-logging: &default-logging", compose_text)
        self.assertIn('driver: "json-file"', compose_text)
        self.assertIn('max-size: "50m"', compose_text)
        self.assertIn('max-file: "5"', compose_text)
        self.assertIn('mode: "non-blocking"', compose_text)
        self.assertIn('max-buffer-size: "4m"', compose_text)

        # Verify default-logging is referenced across application and database blocks
        self.assertIn("logging: *default-logging", compose_text)
        for service_name in ["postgres-data-bootstrap", "postgres"]:
            pattern = rf"\n  {service_name}:(.*?)(?=\n  [a-zA-Z0-9_-]+:|\Z)"
            match = re.search(pattern, compose_text, re.DOTALL)
            self.assertIsNotNone(match, f"Service {service_name} not found in compose")
            block = match.group(1)
            self.assertIn("logging: *default-logging", block, f"Service {service_name} missing logging")
