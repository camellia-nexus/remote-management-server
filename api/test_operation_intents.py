import copy
import json
import unittest
import uuid

from api.operation_intents import (
    SecretIntent,
    canonical_document,
    new_private_binding,
    partition_intent,
    private_binding_matches,
    public_intent_digest,
    serialize_canonical_json,
)


class OperationIntentPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.context = {"actor_id": 7, "operation_id": uuid.uuid4(), "operation": "privacy_test"}
        self.intent = {
            "target": "stable-target",
            "password": "SYNTHETIC-CREDENTIAL-A",
            "body": [{"note": "visible note", "rhash": "SYNTHETIC-CREDENTIAL-B"}],
        }

    def test_public_proof_has_no_secret_value_length_or_unkeyed_secret_verifier(self):
        public, private = partition_intent(self.intent)
        self.assertEqual(private, self.intent)
        self.assertEqual(public["password"], {"$secret_intent": "set"})
        self.assertEqual(public["body"][0]["rhash"], {"$secret_intent": "set"})
        self.assertNotIn("SYNTHETIC-CREDENTIAL", json.dumps(public))
        changed = copy.deepcopy(self.intent)
        changed["password"] = "SYNTHETIC-DIFFERENT-AND-MUCH-LONGER"  # noqa: S105 - isolated synthetic intent
        self.assertEqual(public_intent_digest(self.intent), public_intent_digest(changed))
        changed["target"] = "other-target"
        self.assertNotEqual(public_intent_digest(self.intent), public_intent_digest(changed))

    def test_private_binding_covers_every_secret_public_field_and_authority_context(self):
        binding = new_private_binding(self.intent, **self.context)
        self.assertTrue(private_binding_matches(binding, self.intent, **self.context))
        self.assertTrue(private_binding_matches(binding, dict(reversed(list(self.intent.items()))), **self.context))
        for changed in [
            {**self.intent, "password": "other"},
            {**self.intent, "target": "other"},
            {**self.intent, "body": [{"note": "visible note", "rhash": "other"}]},
        ]:
            with self.subTest(fields=tuple(changed)):
                self.assertFalse(private_binding_matches(binding, changed, **self.context))
        for key, value in [("actor_id", 8), ("operation_id", uuid.uuid4()), ("operation", "other")]:
            self.assertFalse(private_binding_matches(binding, self.intent, **{**self.context, key: value}))
        self.assertNotEqual(binding, new_private_binding(self.intent, **self.context))

    def test_personal_peer_wire_hash_is_secret_not_an_offline_public_verifier(self):
        first = {"body": {"id": "123", "hash": "SYNTHETIC-PERSONAL-HASH-A"}}
        changed = {"body": {"id": "123", "hash": "SYNTHETIC-PERSONAL-HASH-B"}}
        self.assertEqual(public_intent_digest(first), public_intent_digest(changed))
        binding = new_private_binding(first, **self.context)
        self.assertFalse(private_binding_matches(binding, changed, **self.context))

    def test_secret_actions_and_explicit_form_markers_are_unambiguous(self):
        for value, action in [(None, "keep"), ("", "clear"), ("nonempty", "set")]:
            with self.subTest(action=action):
                public, private = partition_intent({"default_password": value})
                self.assertEqual(public, {"default_password": {"$secret_intent": action}})
                self.assertEqual(private, {"default_password": value})
        public, private = partition_intent({"fields": {"opaque": SecretIntent(["private value"])}})
        self.assertNotIn("private value", json.dumps(public))
        self.assertEqual(private, {"fields": {"opaque": ["private value"]}})
        self.assertNotIn("private value", repr(SecretIntent("private value")))

    def test_malformed_binding_or_excess_depth_is_rejected_without_echoing_secrets(self):
        binding = new_private_binding(self.intent, **self.context)
        for field, value in [("version", True), ("key", "SYNTHETIC-CREDENTIAL"), ("mac", "F" * 64)]:
            with self.assertRaisesRegex(ValueError, "Stored private operation binding is invalid") as captured:
                private_binding_matches({**binding, field: value}, self.intent, **self.context)
            self.assertNotIn("SYNTHETIC-CREDENTIAL", str(captured.exception))
        recursive = []
        recursive.append(recursive)
        with self.assertRaisesRegex(ValueError, "too deeply nested"):
            partition_intent(recursive)

    def test_http_json_depth_budget_still_fits_after_metadata_and_secret_projection(self):
        nested = "SYNTHETIC-DEEP-INTENT"
        for _index in range(64):
            nested = {"password": nested}
        document = {"operation": "depth_budget", "body": nested}
        public, private = partition_intent(document)
        self.assertEqual(private, document)
        self.assertNotIn("SYNTHETIC-DEEP-INTENT", json.dumps(public))
        binding = new_private_binding(document, **self.context)
        self.assertTrue(private_binding_matches(binding, document, **self.context))


class CanonicalJsonSerializationTests(unittest.TestCase):
    def test_negative_zero_normalizes_to_zero(self):
        self.assertEqual(serialize_canonical_json(-0.0), "0")
        self.assertEqual(serialize_canonical_json(0.0), "0")
        self.assertEqual(serialize_canonical_json(0), "0")
        self.assertEqual(canonical_document({"zero": -0.0}), b'{"zero":0}')
        self.assertEqual(canonical_document([-0.0, 0.0, 0]), b"[0,0,0]")

    def test_integer_float_normalizes_to_integer(self):
        self.assertEqual(serialize_canonical_json(1.0), "1")
        self.assertEqual(serialize_canonical_json(-1.0), "-1")
        self.assertEqual(serialize_canonical_json(42.0), "42")
        self.assertEqual(serialize_canonical_json(9007199254740991.0), "9007199254740991")
        self.assertEqual(serialize_canonical_json(-9007199254740991.0), "-9007199254740991")
        self.assertEqual(canonical_document({"value": 1.0}), b'{"value":1}')

    def test_exponents_serialize_without_zero_padding(self):
        self.assertEqual(serialize_canonical_json(1e-7), "1e-7")
        self.assertEqual(serialize_canonical_json(-1e-7), "-1e-7")
        self.assertEqual(serialize_canonical_json(1e-5), "1e-5")
        self.assertEqual(serialize_canonical_json(2.5e-9), "2.5e-9")
        self.assertEqual(canonical_document({"rate": 1e-7}), b'{"rate":1e-7}')

    def test_non_finite_floats_raise_value_error(self):
        for non_finite in [float("nan"), float("inf"), float("-inf")]:
            with self.subTest(non_finite=str(non_finite)):
                with self.assertRaisesRegex(ValueError, "Non-finite float not permitted in canonical JSON"):
                    serialize_canonical_json(non_finite)
                with self.assertRaises(ValueError):
                    canonical_document({"bad": non_finite})
                with self.assertRaises(ValueError):
                    canonical_document([non_finite])

    def test_utf8_strings_and_sorted_dictionary_keys_serialize_deterministically(self):
        obj1 = {"b": "hello", "a": "world", "c": "你好"}
        obj2 = {"c": "你好", "b": "hello", "a": "world"}
        self.assertEqual(serialize_canonical_json(obj1), '{"a":"world","b":"hello","c":"你好"}')
        self.assertEqual(serialize_canonical_json(obj1), serialize_canonical_json(obj2))
        self.assertEqual(
            canonical_document(obj1),
            '{"a":"world","b":"hello","c":"你好"}'.encode(),
        )
        # Test UTF-16 code unit ordering vs UTF-32 code point ordering
        # \U0001f600 (surrogate pair high surrogate 0xD83D) sorts before \uffff (0xFFFF) in UTF-16
        utf16_keys = {"\uffff": "bmp_max", "\U0001f600": "supplementary"}
        self.assertEqual(
            serialize_canonical_json(utf16_keys),
            '{"\U0001f600":"supplementary","\uffff":"bmp_max"}',
        )

    def test_primitive_and_nested_structures(self):
        self.assertEqual(serialize_canonical_json(None), "null")
        self.assertEqual(serialize_canonical_json(True), "true")
        self.assertEqual(serialize_canonical_json(False), "false")
        self.assertEqual(serialize_canonical_json([]), "[]")
        self.assertEqual(serialize_canonical_json({}), "{}")
        nested = {
            "null": None,
            "bool": True,
            "list": [1, 2.0, -0.0, 1e-7, "item"],
            "dict": {"sub": "val"},
        }
        expected = '{"bool":true,"dict":{"sub":"val"},"list":[1,2,0,1e-7,"item"],"null":null}'
        self.assertEqual(serialize_canonical_json(nested), expected)
        self.assertEqual(canonical_document(nested), expected.encode())

    def test_invalid_types_and_keys_fail_closed(self):
        with self.assertRaises(TypeError):
            serialize_canonical_json({1: "invalid_key"})
        with self.assertRaises(ValueError):
            canonical_document({1: "invalid_key"})
        with self.assertRaises(ValueError):
            serialize_canonical_json({1, 2, 3})
        with self.assertRaises(ValueError):
            canonical_document({"set": {1, 2, 3}})
