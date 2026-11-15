"""Regression contracts for Batch 76: CONFIG-013.

- CONFIG-013: Device group allowed_incomings enforcement in device_group_accessible.
  Ensures non-admin users can discover groups where they own devices OR whose allowed_incomings
  explicitly includes the user's username or one of the user's Django groups, while
  enforcing strict fail-closed default-deny for unauthorized users.
"""

from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import Client, TestCase

from api.models import DeviceGroup, RemoteDevice, UserProfile


class DeviceGroupAllowedIncomingsTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Admin user
        self.admin_user = UserProfile.objects.create(
            username="admin_user",
            email="admin@example.com",
            is_admin=True,
            is_active=True,
        )

        # Alice: member of Django group 'operators'
        self.alice = UserProfile.objects.create(
            username="alice_user",
            email="alice@example.com",
            is_admin=False,
            is_active=True,
        )
        self.operators_group = Group.objects.create(name="operators")
        self.alice.groups.add(self.operators_group)

        # Bob: owner of group A and device A
        self.bob = UserProfile.objects.create(
            username="bob_user",
            email="bob@example.com",
            is_admin=False,
            is_active=True,
        )

        # Charlie: outsider with no device and not in operators
        self.charlie = UserProfile.objects.create(
            username="charlie_user",
            email="charlie@example.com",
            is_admin=False,
            is_active=True,
        )

        # Group 1: owned by Bob with device 1, allowed_incomings=['operators']
        self.group_ops = DeviceGroup.objects.create(
            name="Operations Fleet",
            note="Fleet for operators",
            allowed_incomings=["operators"],
        )
        self.device_bob = RemoteDevice.objects.create(
            rid="741000001",
            uuid="11111111-1111-4111-8111-111111111111",
            device_group=self.group_ops,
            owner=self.bob,
            is_active=True,
        )

        # Group 2: private group with no allowed_incomings and only Bob's device
        self.group_private = DeviceGroup.objects.create(
            name="Bob Secret Vault",
            note="Only Bob",
            allowed_incomings=[],
        )
        self.device_bob_private = RemoteDevice.objects.create(
            rid="741000002",
            uuid="22222222-2222-4222-8222-222222222222",
            device_group=self.group_private,
            owner=self.bob,
            is_active=True,
        )

    def test_alice_can_discover_group_allowed_to_her_django_group(self):
        """Alice owns 0 devices in group_ops, but group_ops allows 'operators'."""
        with patch("api.views_api._get_token_user", return_value=(None, self.alice)):
            resp = self.client.get(
                "/api/device-group/accessible",
                HTTP_AUTHORIZATION="Bearer valid-token",
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["data"][0]["name"], "Operations Fleet")
        self.assertEqual(data["data"][0]["allowed_incomings"], ["operators"])

    def test_charlie_cannot_discover_groups_without_ownership_or_allowed_incoming(self):
        """Charlie has no devices and is not in operators group; fail-closed default deny."""
        with patch("api.views_api._get_token_user", return_value=(None, self.charlie)):
            resp = self.client.get(
                "/api/device-group/accessible",
                HTTP_AUTHORIZATION="Bearer valid-token",
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["data"], [])

    def test_bob_discovers_groups_where_he_owns_devices(self):
        """Bob owns devices in both groups; both are accessible to Bob."""
        with patch("api.views_api._get_token_user", return_value=(None, self.bob)):
            resp = self.client.get(
                "/api/device-group/accessible",
                HTTP_AUTHORIZATION="Bearer valid-token",
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 2)
        names = {item["name"] for item in data["data"]}
        self.assertEqual(names, {"Operations Fleet", "Bob Secret Vault"})

    def test_admin_discovers_all_groups(self):
        """Admin has full discovery over all registered groups."""
        with patch("api.views_api._get_token_user", return_value=(None, self.admin_user)):
            resp = self.client.get(
                "/api/device-group/accessible",
                HTTP_AUTHORIZATION="Bearer valid-token",
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 2)

    def test_unauthorized_request_fails(self):
        with patch("api.views_api._get_token_user", return_value=(None, None)):
            resp = self.client.get("/api/device-group/accessible")
        self.assertEqual(resp.status_code, 401)
