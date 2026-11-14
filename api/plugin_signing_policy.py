"""Validation and lifecycle contracts for plugin signing configuration."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import NamedTuple

from django.conf import settings
from django.core.exceptions import ValidationError


class PluginSigningKeyInfo(NamedTuple):
    seed: bytes
    key_id: str
    public_key_fingerprint: str


def parse_and_validate_plugin_signing_key(raw_key: str | bytes | None) -> PluginSigningKeyInfo | None:
    """
    Parse and validate a configured Ed25519 signing seed for plugin signing.

    Returns PluginSigningKeyInfo if non-empty and valid.
    Returns None if not configured or empty.
    Raises ValidationError if configured but malformed or invalid length.
    """
    if not raw_key:
        return None
    if isinstance(raw_key, bytes):
        candidate = raw_key
    else:
        text = str(raw_key).strip()
        if not text:
            return None
        candidate = None
        if len(text) == 64:
            try:
                candidate = bytes.fromhex(text)
            except ValueError:
                candidate = None
        if candidate is None:
            try:
                candidate = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError):
                raise ValidationError("PLUGIN_SIGNING_KEY must be a valid 32-byte hex or base64 encoded seed") from None

    if len(candidate) != 32:
        raise ValidationError(f"PLUGIN_SIGNING_KEY must be exactly 32 bytes, got {len(candidate)}")

    seed_digest = hashlib.sha256(candidate).hexdigest()
    key_id = f"ed25519-key-{seed_digest[:16]}"
    fingerprint = f"sha256:{seed_digest}"

    return PluginSigningKeyInfo(
        seed=candidate,
        key_id=key_id,
        public_key_fingerprint=fingerprint,
    )


def check_plugin_signing_key_policy() -> None:
    """Verify that configured PLUGIN_SIGNING_KEY satisfies production lifecycle contracts."""
    raw_key = getattr(settings, "PLUGIN_SIGNING_KEY", None)
    parse_and_validate_plugin_signing_key(raw_key)
