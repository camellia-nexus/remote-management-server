import base64
import json
import uuid
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.db import connection
from django.test import Client, TestCase, override_settings

from api.models import (
    AddressBookProfile,
    AddressBookRule,
    AddressBookShare,
    RemoteDevice,
    RemotePeer,
    ShareLink,
    UserProfile,
)
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


@override_settings(
    STORAGES=TEST_STORAGES,
    REQUEST_RATE_LIMIT_ENABLED=False,
)
class AddressBookContractsBatch2Tests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "b2-admin",
            "b2-admin-password",  # noqa: S106 - isolated test credential
        )
        self.owner = UserProfile.objects.create_user(
            "b2-owner",
            "b2-owner-password",  # noqa: S106 - isolated test credential
        )
        self.manager = UserProfile.objects.create_user(
            "b2-manager",
            "b2-manager-password",  # noqa: S106 - isolated test credential
        )
        self.user1 = UserProfile.objects.create_user(
            "b2-user1",
            "b2-user1-password",  # noqa: S106 - isolated test credential
        )
        self.user2 = UserProfile.objects.create_user(
            "b2-user2",
            "b2-user2-password",  # noqa: S106 - isolated test credential
        )
        self.recipient = UserProfile.objects.create_user(
            "b2-recipient",
            "b2-recipient-password",  # noqa: S106 - isolated test credential
        )
        self.group = Group.objects.create(name="b2-managers")
        self.manager.groups.add(self.group)

        self.profile = AddressBookProfile.objects.create(
            guid=uuid.uuid4().hex,
            name="B2 Shared Profile",
            owner=self.owner,
            rule=1,
            default_password="DefaultProfilePassword123",  # noqa: S106 - isolated test credential
        )
        # Grant manager Rule 3 on profile
        self.manager_share = AddressBookShare.objects.create(
            profile=self.profile,
            user=self.manager,
            rule=3,
        )

        self.peer_with_pwd = RemotePeer.objects.create(
            profile=self.profile,
            rid="765000001",
            alias="Peer With Password",
            password="PeerSecretPassword456",  # noqa: S106 - isolated test credential
        )
        self.peer_with_default_pwd = RemotePeer.objects.create(
            profile=self.profile,
            rid="765000002",
            alias="Peer With Default Password",
            password="",
        )

        # Devices and tokens for API access
        self.owner_device = RemoteDevice.objects.create(
            rid="765999001",
            uuid=base64.b64encode(b"owner-device-b2").decode("ascii"),
            owner=self.owner,
            is_active=True,
            cpu="-",
            hostname="owner-dev",
            memory="-",
            os="Linux",
            username="b2-owner",
            version="test",
        )
        _t1, self.owner_bearer = _issue_access_token(self.owner, self.owner_device)

        self.manager_device = RemoteDevice.objects.create(
            rid="765999002",
            uuid=base64.b64encode(b"manager-device-b2").decode("ascii"),
            owner=self.manager,
            is_active=True,
            cpu="-",
            hostname="manager-dev",
            memory="-",
            os="Linux",
            username="b2-manager",
            version="test",
        )
        _t2, self.manager_bearer = _issue_access_token(self.manager, self.manager_device)

        self.user1_device = RemoteDevice.objects.create(
            rid="765999003",
            uuid=base64.b64encode(b"user1-device-b2").decode("ascii"),
            owner=self.user1,
            is_active=True,
            cpu="-",
            hostname="user1-dev",
            memory="-",
            os="Linux",
            username="b2-user1",
            version="test",
        )
        _t3, self.user1_bearer = _issue_access_token(self.user1, self.user1_device)

    def _auth(self, bearer):
        return {"HTTP_AUTHORIZATION": f"Bearer {bearer}"}

    # =========================================================================
    # VALID-001: Address book peer ID length & charset validation
    # =========================================================================

    def test_valid_001_peer_id_length_and_charset_api_add_and_update(self):
        client = Client()
        invalid_ids = [
            "12345",  # 5 chars (too short)
            "12345678901234567",  # 17 chars (too long, causes DataError on PostgreSQL without validation)
            "peer with space",  # space not allowed
            "peer@special!",  # special chars not allowed
            "peer\u4e2d\u6587",  # unicode not allowed
        ]
        for bad_id in invalid_ids:
            with self.subTest(bad_id=bad_id, action="add"):
                response = client.post(
                    f"/api/ab/peer/add/{self.profile.guid}",
                    data=json.dumps({"id": bad_id, "alias": "test"}),
                    content_type="application/json",
                    HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
                    HTTP_IF_MATCH='"0"',
                    **self._auth(self.owner_bearer),
                )
                self.assertEqual(response.status_code, 400, response.content)

            with self.subTest(bad_id=bad_id, action="update"):
                response = client.put(
                    f"/api/ab/peer/update/{self.profile.guid}",
                    data=json.dumps({"id": bad_id, "alias": "test"}),
                    content_type="application/json",
                    HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
                    HTTP_IF_MATCH='"0"',
                    **self._auth(self.owner_bearer),
                )
                self.assertEqual(response.status_code, 400, response.content)

        # Valid peer IDs at boundary lengths
        valid_ids = [
            "123456",  # 6 chars (min length)
            "1234567890123456",  # 16 chars (max length)
            "peer_01-test",  # alphanumeric with underscore and hyphen
        ]
        for good_id in valid_ids:
            with self.subTest(good_id=good_id):
                response = client.post(
                    f"/api/ab/peer/add/{self.profile.guid}",
                    data=json.dumps({"id": good_id, "alias": f"Alias {good_id}"}),
                    content_type="application/json",
                    HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
                    HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
                    **self._auth(self.owner_bearer),
                )
                self.assertEqual(response.status_code, 200, response.content)
                self.profile.refresh_from_db()
                self.assertTrue(RemotePeer.objects.filter(profile=self.profile, rid=good_id).exists())

    def test_valid_001_peer_id_api_delete_and_shared_credential(self):
        client = Client()
        # Delete with invalid ID in list (using DELETE /api/ab/peer/<guid>)
        response = client.delete(
            f"/api/ab/peer/{self.profile.guid}",
            data=json.dumps(["12345678901234567"]),  # 17 chars
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

        # Shared credential with invalid peer ID (17 chars)
        response = client.post(
            "/api/ab/shared/credential",
            data=json.dumps({"guid": self.profile.guid, "id": "12345678901234567"}),
            content_type="application/json",
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

    def test_valid_001_peer_id_web_ui_add_update_delete_bulk(self):
        client = Client()
        client.force_login(self.owner)

        # Web add peer with 17 chars
        response = client.post(
            f"/api/ab_book?guid={self.profile.guid}",
            {
                "action": "add_peer",
                "guid": self.profile.guid,
                "rid": "12345678901234567",
                "alias": "Too Long Peer",
                "note": "",
                "password": "",
                "tags": "",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(RemotePeer.objects.filter(profile=self.profile, rid="12345678901234567").exists())

        # Web update peer with invalid ID (5 chars)
        response = client.post(
            f"/api/ab_book?guid={self.profile.guid}",
            {
                "action": "update_peer",
                "guid": self.profile.guid,
                "rid": "12345",
                "alias": "Too Short Peer",
                "note": "",
                "password": "",
                "tags": "",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)

        # Web delete peer with invalid ID (17 chars)
        response = client.post(
            f"/api/ab_book?guid={self.profile.guid}",
            {
                "action": "delete_peer",
                "guid": self.profile.guid,
                "rid": "12345678901234567",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)

        # Web bulk delete with invalid ID in list
        response = client.post(
            f"/api/ab_book?guid={self.profile.guid}",
            {
                "action": "bulk",
                "subaction": "delete",
                "guid": self.profile.guid,
                "selected_ids": json.dumps(["12345678901234567"]),
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)

    # =========================================================================
    # VALID-002: Request schema & numerical bounds
    # =========================================================================

    def test_valid_002_profile_creation_and_update_rejects_non_string_names(self):
        client = Client()
        # Profile creation with integer name
        response = client.post(
            "/api/ab/shared/add",
            data=json.dumps({"name": 12345}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

        # Profile creation with dict name
        response = client.post(
            "/api/ab/shared/add",
            data=json.dumps({"name": {"foo": "bar"}}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

        # Profile update with list name via PUT /api/ab/shared/update/profile
        response = client.put(
            "/api/ab/shared/update/profile",
            data=json.dumps({"guid": self.profile.guid, "name": [1, 2, 3]}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

    def test_valid_002_rule_endpoints_guid_and_uuid_bounds_zero_500s(self):
        client = Client()

        # ab_rules with invalid guid
        response = client.get(
            "/api/ab/rules?guid=invalid@guid!",
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

        # ab_rule POST with non-string user
        response = client.post(
            "/api/ab/rule",
            data=json.dumps({"guid": self.profile.guid, "user": 12345, "rule": 1}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

        # ab_rule PATCH with non-UUID guid (caught by parse_uuid, zero 500s)
        response = client.patch(
            "/api/ab/rule",
            data=json.dumps({"guid": "not-a-valid-uuid", "rule": 2}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get("code"), "invalid_identifier")

        # ab_rules delete with malformed UUIDs
        response = client.delete(
            "/api/ab/rules",
            data=json.dumps(["not-a-uuid"]),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get("code"), "invalid_identifier")

        # ab_rules delete with non-list data (caught by parse_uuid_list, 400)
        response = client.delete(
            "/api/ab/rules",
            data=json.dumps({"not": "a-list"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 400, response.content)

        # ab_rules delete with empty list succeeds with 0 deleted
        response = client.delete(
            "/api/ab/rules",
            data=json.dumps([]),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json().get("deleted"), 0)

    def test_valid_002_sharelink_pk_numerical_bounds(self):
        client = Client()
        client.force_login(self.owner)

        # ShareLink create with BigInt out of range (> 2^63 - 1)
        huge_pk = 2**63 + 100
        response = client.post(
            "/api/share",
            {"data": json.dumps([{"value": str(huge_pk)}])},
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json().get("code"), "share_invalid_selection")

        # ShareLink create with negative pk
        response = client.post(
            "/api/share",
            {"data": json.dumps([{"value": "-1"}])},
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
        )
        self.assertEqual(response.status_code, 400, response.content)

    # =========================================================================
    # AUTH-018: Rule 3 Delegated Address Book Manager & Anti-Escalation
    # =========================================================================

    def test_auth_018_rule3_manager_can_update_metadata_and_manage_rules(self):
        client = Client()

        # Manager can update profile metadata via API (PUT /api/ab/shared/update/profile)
        response = client.put(
            "/api/ab/shared/update/profile",
            data=json.dumps({"guid": self.profile.guid, "name": "B2 Profile Updated by Manager"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.name, "B2 Profile Updated by Manager")

        # Manager can query rules via API
        response = client.get(
            f"/api/ab/rules?guid={self.profile.guid}",
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        rules_data = response.json()
        self.assertTrue(any(item["user"] == self.manager.username for item in rules_data.get("data", [])))

        # Manager can add Rule 1 to user1 via API
        response = client.post(
            "/api/ab/rule",
            data=json.dumps({"guid": self.profile.guid, "user": self.user1.username, "rule": 1}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        rule_guid = response.json().get("guid")
        self.assertTrue(AddressBookShare.objects.filter(profile=self.profile, user=self.user1, rule=1).exists())

        self.profile.refresh_from_db()
        # Manager can update user1's rule to Rule 2 via API
        response = client.patch(
            "/api/ab/rule",
            data=json.dumps({"guid": rule_guid, "rule": 2}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(AddressBookShare.objects.filter(profile=self.profile, user=self.user1, rule=2).exists())

        self.profile.refresh_from_db()
        # Manager can delete user1's rule via API (DELETE /api/ab/rules)
        response = client.delete(
            "/api/ab/rules",
            data=json.dumps([rule_guid]),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(AddressBookShare.objects.filter(profile=self.profile, user=self.user1).exists())

    def test_auth_018_rule3_manager_web_ui_management(self):
        client = Client()
        client.force_login(self.manager)

        # Manager can access ab_manage GET page
        response = client.get(f"/api/ab_manage?guid={self.profile.guid}")
        self.assertEqual(response.status_code, 200)

        # Manager can add user share (Rule 2) via Web UI
        response = client.post(
            "/api/ab_manage",
            {
                "action": "add_user_share",
                "profile_guid": self.profile.guid,
                "user": self.user2.username,
                "rule": "2",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AddressBookShare.objects.filter(profile=self.profile, user=self.user2, rule=2).exists())

        self.profile.refresh_from_db()
        # Manager can add group rule (Rule 1) via Web UI
        response = client.post(
            "/api/ab_manage",
            {
                "action": "add_group_rule",
                "profile_guid": self.profile.guid,
                "group": self.group.name,
                "rule": "1",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AddressBookRule.objects.filter(profile=self.profile, group=self.group, rule=1).exists())

        self.profile.refresh_from_db()
        # Manager can add everyone rule (Rule 1) via Web UI
        response = client.post(
            "/api/ab_manage",
            {
                "action": "add_everyone_rule",
                "profile_guid": self.profile.guid,
                "rule": "1",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AddressBookRule.objects.filter(profile=self.profile, is_everyone=True, rule=1).exists())

        # Manager can update book metadata via ab_books
        self.profile.refresh_from_db()
        response = client.post(
            "/api/ab_books",
            {
                "action": "update_book",
                "guid": self.profile.guid,
                "name": "Manager Renamed Book",
                "note": "Renamed by delegated manager",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.name, "Manager Renamed Book")

    def test_auth_018_rule3_anti_escalation_invariants(self):
        client = Client()

        # Invariant 1: Manager CANNOT grant Rule 3 via API POST /api/ab/rule
        response = client.post(
            "/api/ab/rule",
            data=json.dumps({"guid": self.profile.guid, "user": self.user1.username, "rule": 3}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 403, response.content)
        self.assertFalse(AddressBookShare.objects.filter(profile=self.profile, user=self.user1, rule=3).exists())

        # Invariant 2: Manager CANNOT grant Rule 3 via Web UI
        client_web = Client()
        client_web.force_login(self.manager)
        response = client_web.post(
            "/api/ab_manage",
            {
                "action": "add_user_share",
                "profile_guid": self.profile.guid,
                "user": self.user1.username,
                "rule": "3",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AddressBookShare.objects.filter(profile=self.profile, user=self.user1, rule=3).exists())

        # Invariant 3: Manager CANNOT modify existing Rule 3 rule via API PATCH
        response = client.patch(
            "/api/ab/rule",
            data=json.dumps({"guid": str(self.manager_share.guid), "rule": 1}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 403, response.content)
        self.manager_share.refresh_from_db()
        self.assertEqual(self.manager_share.rule, 3)

        # Invariant 4: Manager CANNOT modify existing Rule 3 rule via Web UI
        response = client_web.post(
            "/api/ab_manage",
            {
                "action": "update_rule",
                "rule_guid": str(self.manager_share.guid),
                "rule": "1",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.manager_share.refresh_from_db()
        self.assertEqual(self.manager_share.rule, 3)

        # Invariant 5: Manager CANNOT delete existing Rule 3 rule via API
        response = client.delete(
            "/api/ab/rules",
            data=json.dumps([str(self.manager_share.guid)]),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.manager_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json().get("deleted"), 0)  # Skipped
        self.assertTrue(AddressBookShare.objects.filter(pk=self.manager_share.pk).exists())

        # Invariant 6: Manager CANNOT delete existing Rule 3 rule via Web UI
        response = client_web.post(
            "/api/ab_manage",
            {
                "action": "delete_rule",
                "rule_guid": str(self.manager_share.guid),
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AddressBookShare.objects.filter(pk=self.manager_share.pk).exists())

        # Invariant 7: Manager CANNOT delete the address book profile via Web UI
        response = client_web.post(
            "/api/ab_books",
            {
                "action": "delete_book",
                "guid": self.profile.guid,
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AddressBookProfile.objects.filter(pk=self.profile.pk).exists())

        # Owner CAN delete/manage Rule 3 rules
        self.profile.refresh_from_db()
        response = client.patch(
            "/api/ab/rule",
            data=json.dumps({"guid": str(self.manager_share.guid), "rule": 2}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
            HTTP_IF_MATCH=f'"{self.profile.authorization_generation}"',
            **self._auth(self.owner_bearer),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.manager_share.refresh_from_db()
        self.assertEqual(self.manager_share.rule, 2)

    # =========================================================================
    # COMPAT-007: ShareLink credential normalization
    # =========================================================================

    def test_compat_007_sharelink_credential_normalization(self):
        client = Client()
        client.force_login(self.owner)

        # 1. Share peer with explicit password
        payload1 = json.dumps([{"value": str(self.peer_with_pwd.pk)}])
        res1 = client.post(
            "/api/share",
            {"data": payload1},
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
        )
        self.assertEqual(res1.status_code, 200, res1.content)
        token1 = res1.json().get("token")

        # Recipient accepts share link
        client.force_login(self.recipient)
        accept_res1 = client.post(
            f"/api/share/{token1}",
            {"idempotency_key": f"v2:{uuid.uuid4()}"},
        )
        self.assertEqual(accept_res1.status_code, 200, accept_res1.content)
        self.assertContains(accept_res1, "已获取 1 台设备")

        # Verify imported peer in recipient's personal address book
        personal_peer1 = RemotePeer.objects.get(
            profile__owner=self.recipient,
            rid=self.peer_with_pwd.rid,
        )
        expected_rhash1 = base64.b64encode(b"PeerSecretPassword456").decode("ascii")
        self.assertEqual(personal_peer1.rhash, expected_rhash1)
        self.assertEqual(personal_peer1.password, "")
        self.assertTrue(ShareLink.objects.filter(is_used=True).exists())

        # 2. Share peer with empty password (falls back to profile.default_password)
        client.force_login(self.owner)
        payload2 = json.dumps([{"value": str(self.peer_with_default_pwd.pk)}])
        res2 = client.post(
            "/api/share",
            {"data": payload2},
            HTTP_IDEMPOTENCY_KEY=f"v2:{uuid.uuid4()}",
        )
        self.assertEqual(res2.status_code, 200, res2.content)
        token2 = res2.json().get("token")

        client.force_login(self.recipient)
        accept_res2 = client.post(
            f"/api/share/{token2}",
            {"idempotency_key": f"v2:{uuid.uuid4()}"},
        )
        self.assertEqual(accept_res2.status_code, 200, accept_res2.content)
        self.assertContains(accept_res2, "已获取 1 台设备")

        personal_peer2 = RemotePeer.objects.get(
            profile__owner=self.recipient,
            rid=self.peer_with_default_pwd.rid,
        )
        expected_rhash2 = base64.b64encode(b"DefaultProfilePassword123").decode("ascii")
        self.assertEqual(personal_peer2.rhash, expected_rhash2)
        self.assertEqual(personal_peer2.password, "")

        # 3. Verify encrypted at rest: raw database column contains secretbox ciphertext, not plaintext
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT rhash FROM api_remotepeer WHERE id = %s",
                [personal_peer1.pk],
            )
            raw_rhash_db = cursor.fetchone()[0]
        self.assertTrue(raw_rhash_db.startswith("secretbox:v3:"))
        self.assertNotIn("PeerSecretPassword456", raw_rhash_db)

    # =========================================================================
    # LOG-010: Audit logging front_ab_rules_export
    # =========================================================================

    def test_log_010_front_ab_rules_export_audit_logging(self):
        client = Client()

        # 1. Admin CSV export triggers front_ab_rules_export
        client.force_login(self.admin)
        with patch("api.views_front._log_event") as mock_log:
            response = client.get("/api/ab_rules_export?format=csv")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.headers["Content-Type"].startswith("text/csv"))
            mock_log.assert_any_call(
                response.wsgi_request,
                "front_ab_rules_export",
                username=self.admin.username,
                count=mock_log.call_args_list[-1][1]["count"],
            )

        # 2. Admin XLSX export triggers front_ab_rules_export
        with patch("api.views_front._log_event") as mock_log:
            response = client.get("/api/ab_rules_export?format=xlsx")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(
                response.headers["Content-Type"].startswith(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
            )
            mock_log.assert_any_call(
                response.wsgi_request,
                "front_ab_rules_export",
                username=self.admin.username,
                count=mock_log.call_args_list[-1][1]["count"],
            )

        # 3. Non-admin export is denied and triggers front_ab_rules_export_denied
        client.force_login(self.owner)
        with patch("api.views_front._log_event") as mock_log:
            response = client.get("/api/ab_rules_export?format=csv")
            self.assertEqual(response.status_code, 302)
            mock_log.assert_any_call(
                response.wsgi_request,
                "front_ab_rules_export_denied",
                level="warning",
                username=self.owner.username,
            )
