import base64
import json
import uuid
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.db import IntegrityError
from django.test import Client, TestCase, override_settings

from api.models import UserProfile
from api.models_work import (
    AddressBookProfile,
    AddressBookRule,
    AddressBookShare,
    RemoteDevice,
    RemotePeer,
    RemoteTag,
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
class Batch77AddressBookConcurrencyTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = UserProfile.objects.create_user(
            username="owner_user",
            password="test-batch77-password",  # noqa: S106
            email="owner@example.com",
            is_active=True,
        )
        self.user2 = UserProfile.objects.create_user(
            username="user_two",
            password="test-batch77-password",  # noqa: S106
            email="user2@example.com",
            is_active=True,
        )
        self.group = Group.objects.create(name="ops_group")
        self.owner.groups.add(self.group)

        self.profile = AddressBookProfile.objects.create(
            guid=str(uuid.uuid4()),
            owner=self.owner,
            name="Team Book",
        )

        self.device = RemoteDevice.objects.create(
            rid="770001",
            uuid=base64.b64encode(b"b77-device-uuid-1").decode("ascii"),
            owner=self.owner,
            is_active=True,
            cpu="-",
            hostname="owner-dev",
            memory="-",
            os="Linux",
            username="owner_user",
            version="test",
        )
        _t, self.owner_token = _issue_access_token(self.owner, self.device)

        # Login as owner
        self.client.force_login(self.owner)

    def test_ab_manage_add_user_share_idempotent_on_conflict(self):
        self.profile.refresh_from_db()
        resp = self.client.post(
            "/api/ab_manage",
            {
                "action": "add_user_share",
                "profile_guid": self.profile.guid,
                "user": self.user2.username,
                "rule": "1",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=False,
        )
        self.assertEqual(resp.status_code, 302)
        share = AddressBookShare.objects.get(profile=self.profile, user=self.user2)
        self.assertEqual(share.rule, 1)

        self.profile.refresh_from_db()
        def uoc_mock(*args, **kwargs):
            raise IntegrityError("duplicate key value violates unique constraint")

        with patch.object(AddressBookShare.objects, "update_or_create", side_effect=uoc_mock):
            resp2 = self.client.post(
                "/api/ab_manage",
                {
                    "action": "add_user_share",
                    "profile_guid": self.profile.guid,
                    "user": self.user2.username,
                    "rule": "2",
                    "idempotency_key": f"v2:{uuid.uuid4()}",
                    "expected_generation": str(self.profile.authorization_generation),
                },
                follow=False,
            )
            self.assertEqual(resp2.status_code, 302)

        share.refresh_from_db()
        self.assertEqual(share.rule, 2)

    def test_ab_manage_add_group_rule_idempotent_on_conflict(self):
        self.profile.refresh_from_db()
        resp = self.client.post(
            "/api/ab_manage",
            {
                "action": "add_group_rule",
                "profile_guid": self.profile.guid,
                "group": self.group.name,
                "rule": "1",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=False,
        )
        self.assertEqual(resp.status_code, 302)
        rule = AddressBookRule.objects.get(profile=self.profile, group=self.group)
        self.assertEqual(rule.rule, 1)

        self.profile.refresh_from_db()
        def uoc_mock(*args, **kwargs):
            raise IntegrityError("duplicate key value violates unique constraint")

        with patch.object(AddressBookRule.objects, "update_or_create", side_effect=uoc_mock):
            resp2 = self.client.post(
                "/api/ab_manage",
                {
                    "action": "add_group_rule",
                    "profile_guid": self.profile.guid,
                    "group": self.group.name,
                    "rule": "2",
                    "idempotency_key": f"v2:{uuid.uuid4()}",
                    "expected_generation": str(self.profile.authorization_generation),
                },
                follow=False,
            )
            self.assertEqual(resp2.status_code, 302)

        rule.refresh_from_db()
        self.assertEqual(rule.rule, 2)

    def test_ab_manage_add_everyone_rule_idempotent_on_conflict(self):
        self.profile.refresh_from_db()
        resp = self.client.post(
            "/api/ab_manage",
            {
                "action": "add_everyone_rule",
                "profile_guid": self.profile.guid,
                "rule": "1",
                "idempotency_key": f"v2:{uuid.uuid4()}",
                "expected_generation": str(self.profile.authorization_generation),
            },
            follow=False,
        )
        self.assertEqual(resp.status_code, 302)
        rule = AddressBookRule.objects.get(profile=self.profile, is_everyone=True)
        self.assertEqual(rule.rule, 1)

        self.profile.refresh_from_db()
        def uoc_mock(*args, **kwargs):
            raise IntegrityError("duplicate key value violates unique constraint")

        with patch.object(AddressBookRule.objects, "update_or_create", side_effect=uoc_mock):
            resp2 = self.client.post(
                "/api/ab_manage",
                {
                    "action": "add_everyone_rule",
                    "profile_guid": self.profile.guid,
                    "rule": "2",
                    "idempotency_key": f"v2:{uuid.uuid4()}",
                    "expected_generation": str(self.profile.authorization_generation),
                },
                follow=False,
            )
            self.assertEqual(resp2.status_code, 302)

        rule.refresh_from_db()
        self.assertEqual(rule.rule, 2)

    def test_ab_tag_rename_merges_peers_when_target_tag_exists(self):
        tag_a = RemoteTag.objects.create(profile=self.profile, tag_name="TagA")
        tag_b = RemoteTag.objects.create(profile=self.profile, tag_name="TagB")
        peer1 = RemotePeer.objects.create(profile=self.profile, rid="1001", alias="Host1")
        peer2 = RemotePeer.objects.create(profile=self.profile, rid="1002", alias="Host2")
        tag_a.peers.add(peer1)
        tag_b.peers.add(peer2)

        self.profile.refresh_from_db()
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {self.owner_token}",
            "HTTP_IDEMPOTENCY_KEY": f"v2:{uuid.uuid4()}",
            "HTTP_IF_MATCH": f'"{self.profile.authorization_generation}"',
        }
        resp = self.client.put(
            f"/api/ab/tag/rename/{self.profile.guid}",
            data=json.dumps({"old": "TagA", "new": "TagB"}),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(resp.status_code, 200)

        self.assertFalse(RemoteTag.objects.filter(profile=self.profile, tag_name="TagA").exists())
        tag_b.refresh_from_db()
        peer_ids = set(tag_b.peers.values_list("rid", flat=True))
        self.assertEqual(peer_ids, {"1001", "1002"})

    def test_ab_tag_rename_handles_integrity_error_with_409_or_merge(self):
        RemoteTag.objects.create(profile=self.profile, tag_name="TagX")

        def raise_integrity(*args, **kwargs):
            raise IntegrityError("unique constraint failed")

        self.profile.refresh_from_db()
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {self.owner_token}",
            "HTTP_IDEMPOTENCY_KEY": f"v2:{uuid.uuid4()}",
            "HTTP_IF_MATCH": f'"{self.profile.authorization_generation}"',
        }
        with patch.object(RemoteTag, "save", side_effect=raise_integrity):
            resp = self.client.put(
                f"/api/ab/tag/rename/{self.profile.guid}",
                data=json.dumps({"old": "TagX", "new": "TagY"}),
                content_type="application/json",
                **headers,
            )
            self.assertEqual(resp.status_code, 409)

    def test_ab_shared_update_profile_handles_integrity_error_with_409(self):
        profile2 = AddressBookProfile.objects.create(
            guid=str(uuid.uuid4()),
            owner=self.owner,
            name="Second Book",
        )

        def raise_integrity(*args, **kwargs):
            raise IntegrityError("unique_address_book_profile_per_owner")

        profile2.refresh_from_db()
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {self.owner_token}",
            "HTTP_IDEMPOTENCY_KEY": f"v2:{uuid.uuid4()}",
            "HTTP_IF_MATCH": f'"{profile2.authorization_generation}"',
        }
        with patch.object(AddressBookProfile, "save", side_effect=raise_integrity):
            resp = self.client.put(
                "/api/ab/shared/update/profile",
                data=json.dumps({"guid": profile2.guid, "name": "Renamed Unique Book"}),
                content_type="application/json",
                **headers,
            )
            self.assertEqual(resp.status_code, 409)
            data = resp.json()
            self.assertIn("already has an address book", data.get("message", str(data)))
