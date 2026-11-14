"""Tests for Batch 75: VALID-003, LOG-009, and CONFIG-014."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch

from django.core.checks import run_checks
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from api.models import UserProfile
from api.plugin_signing_policy import (
    check_plugin_signing_key_policy,
    parse_and_validate_plugin_signing_key,
)
from api.views_api import _log_event, _validate_and_canonicalize_audit_info


class PluginSigningKeyPolicyTests(TestCase):
    def test_unconfigured_or_empty_key_is_allowed(self):
        self.assertIsNone(parse_and_validate_plugin_signing_key(None))
        self.assertIsNone(parse_and_validate_plugin_signing_key(""))
        self.assertIsNone(parse_and_validate_plugin_signing_key("   "))

    def test_valid_32_byte_hex_key_parses_and_derives_identity(self):
        raw_seed = b"A" * 32
        hex_key = raw_seed.hex()
        info = parse_and_validate_plugin_signing_key(hex_key)
        self.assertIsNotNone(info)
        self.assertEqual(info.seed, raw_seed)
        self.assertTrue(info.key_id.startswith("ed25519-key-"))
        self.assertTrue(info.public_key_fingerprint.startswith("sha256:"))

    def test_valid_32_byte_base64_key_parses_and_derives_identity(self):
        raw_seed = b"\x01\x02\x03\x04" * 8
        b64_key = base64.b64encode(raw_seed).decode("ascii")
        info = parse_and_validate_plugin_signing_key(b64_key)
        self.assertIsNotNone(info)
        self.assertEqual(info.seed, raw_seed)
        self.assertTrue(info.key_id.startswith("ed25519-key-"))
        self.assertTrue(info.public_key_fingerprint.startswith("sha256:"))

    def test_malformed_key_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            parse_and_validate_plugin_signing_key("not-valid-hex-or-base64!!!")

    def test_invalid_length_key_raises_validation_error(self):
        # 16 bytes hex (32 hex characters)
        with self.assertRaises(ValidationError):
            parse_and_validate_plugin_signing_key("00" * 16)

        # 64 bytes hex (128 hex characters)
        with self.assertRaises(ValidationError):
            parse_and_validate_plugin_signing_key("00" * 64)

    @override_settings(PLUGIN_SIGNING_KEY="invalid-key-seed")
    def test_system_check_flags_invalid_signing_key(self):
        errors = run_checks(tags=["security", "deployment"])
        key_errors = [e for e in errors if e.id == "api.E014_PLUGIN_SIGNING_KEY_INVALID"]
        self.assertEqual(len(key_errors), 1)

    @override_settings(PLUGIN_SIGNING_KEY="00" * 32)
    def test_system_check_passes_valid_signing_key(self):
        errors = run_checks(tags=["security", "deployment"])
        key_errors = [e for e in errors if e.id == "api.E014_PLUGIN_SIGNING_KEY_INVALID"]
        self.assertEqual(len(key_errors), 0)

    @override_settings(PLUGIN_SIGNING_KEY="corrupted-key-data")
    def test_health_ready_fails_when_signing_key_is_corrupted(self):
        with self.assertRaises(ValidationError):
            check_plugin_signing_key_policy()


class AuditInfoValidationTests(TestCase):
    def test_valid_string_and_dict_info_are_equivalent(self):
        payload_dict = {"message": "unauthorized attempt", "count": 3}
        payload_str = json.dumps(payload_dict)

        info1, err1 = _validate_and_canonicalize_audit_info(payload_dict)
        self.assertIsNone(err1)
        self.assertEqual(info1, payload_dict)

        info2, err2 = _validate_and_canonicalize_audit_info(payload_str)
        self.assertIsNone(err2)
        self.assertEqual(info2, payload_dict)

    def test_string_larger_than_16kib_returns_413(self):
        large_str = json.dumps({"blob": "X" * 17_000})
        _info, err = _validate_and_canonicalize_audit_info(large_str)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 413)

    def test_dict_larger_than_16kib_returns_413(self):
        large_dict = {"blob": "X" * 17_000}
        _info, err = _validate_and_canonicalize_audit_info(large_dict)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 413)

    def test_excessive_nesting_depth_rejected(self):
        deep = {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
        _info, err = _validate_and_canonicalize_audit_info(deep)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 400)

    def test_excessive_key_count_rejected(self):
        too_many_keys = {f"k{i}": i for i in range(50)}
        _info, err = _validate_and_canonicalize_audit_info(too_many_keys)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 400)

    def test_invalid_types_rejected(self):
        _info, err = _validate_and_canonicalize_audit_info(12345)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 400)

        _info, err = _validate_and_canonicalize_audit_info([1, 2, 3])
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 400)


class StatelessBearerLogAttributionTests(TestCase):
    def setUp(self):
        self.user_session = UserProfile.objects.create(
            username="session_alice",
            email="alice@example.com",
            is_active=True,
        )
        self.user_bearer = UserProfile.objects.create(
            username="bearer_bob",
            email="bob@example.com",
            is_active=True,
        )

    def test_stateless_api_logs_bearer_user_and_isolates_session_user(self):
        from unittest.mock import MagicMock

        request = MagicMock()
        request.is_stateless_api = True
        request.user = self.user_session
        request.META = {"REMOTE_ADDR": "192.0.2.1"}

        logged_attributes = None

        def fake_log_structured_event(_logger, _req, _event, level="info", attributes=None):
            nonlocal logged_attributes
            logged_attributes = attributes

        with patch("api.views_api.log_structured_event", side_effect=fake_log_structured_event):
            _log_event(request, "api_test_event", username=self.user_bearer.username, action="update")

        self.assertIsNotNone(logged_attributes)
        self.assertEqual(logged_attributes["user"], "bearer_bob")
        self.assertEqual(logged_attributes["ambient_session_user"], "session_alice")
        self.assertEqual(logged_attributes["action"], "update")

    def test_stateless_api_without_ambient_session_has_clean_attribution(self):
        from unittest.mock import MagicMock

        request = MagicMock()
        request.is_stateless_api = True
        request.user = None
        request.META = {"REMOTE_ADDR": "192.0.2.1"}

        logged_attributes = None

        def fake_log_structured_event(_logger, _req, _event, level="info", attributes=None):
            nonlocal logged_attributes
            logged_attributes = attributes

        with patch("api.views_api.log_structured_event", side_effect=fake_log_structured_event):
            _log_event(request, "api_test_event", username=self.user_bearer.username)

        self.assertIsNotNone(logged_attributes)
        self.assertEqual(logged_attributes["user"], "bearer_bob")
        self.assertNotIn("ambient_session_user", logged_attributes)

    def test_browser_view_logs_session_user(self):
        from unittest.mock import MagicMock

        request = MagicMock()
        request.is_stateless_api = False
        request.user = self.user_session
        request.META = {"REMOTE_ADDR": "192.0.2.1"}

        logged_attributes = None

        def fake_log_structured_event(_logger, _req, _event, level="info", attributes=None):
            nonlocal logged_attributes
            logged_attributes = attributes

        with patch("api.views_api.log_structured_event", side_effect=fake_log_structured_event):
            _log_event(request, "front_test_event")

        self.assertIsNotNone(logged_attributes)
        self.assertEqual(logged_attributes["user"], "session_alice")
        self.assertNotIn("ambient_session_user", logged_attributes)
