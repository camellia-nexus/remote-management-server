from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase, override_settings

from api.views_front import get_safe_redirect_url

User = get_user_model()

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


@override_settings(STORAGES=TEST_STORAGES)
class Nav002OpenRedirectTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.client = Client()
        self.username = "nav002_testuser"
        self.password = "TestPassword123!"  # noqa: S105 - isolated test fixture password
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
            is_active=True,
        )

    def test_get_safe_redirect_url_valid_relative_routes(self):
        request = self.factory.get("/api/user_action?action=login", HTTP_HOST="testserver")
        valid_routes = [
            "/api/home",
            "/api/devices",
            "/admin",
            "/api/devices?page=2&filter=active",
            "/api/home#summary",
            "/settings/profile",
        ]
        for route in valid_routes:
            with self.subTest(route=route):
                result = get_safe_redirect_url(request, route)
                self.assertEqual(result, route)

    def test_get_safe_redirect_url_rejects_backslash_normalization_vectors(self):
        request = self.factory.get("/api/user_action?action=login", HTTP_HOST="testserver")
        backslash_attacks = [
            r"/\evil.example/path",
            r"/\\evil.example/path",
            r"\\evil.example",
            r"\evil.example/path",
            r"//\evil.example",
            r"/api/home\extra",
            r"/login\?next=evil.com",
            "/evil.example\\",
        ]
        for attack in backslash_attacks:
            with self.subTest(attack=attack):
                result = get_safe_redirect_url(request, attack, default="/api/home")
                self.assertEqual(result, "/api/home")

    def test_get_safe_redirect_url_rejects_scheme_relative_and_absolute_urls(self):
        request = self.factory.get("/api/user_action?action=login", HTTP_HOST="testserver")
        external_urls = [
            "//evil.example/path",
            "///evil.example/path",
            "https://evil.example/path",
            "http://evil.example/path",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "ftp://evil.example/resource",
            "https://management.example.evil.com/path",
        ]
        for url in external_urls:
            with self.subTest(url=url):
                result = get_safe_redirect_url(request, url, default="/api/home")
                self.assertEqual(result, "/api/home")

    def test_get_safe_redirect_url_rejects_control_characters_and_whitespace(self):
        request = self.factory.get("/api/user_action?action=login", HTTP_HOST="testserver")
        bad_inputs = [
            "/api/home\n",
            "/api/home\r",
            "/api/home\t",
            " /api/home",
            "/api/home ",
            "/api/home\x00",
            "/api/home\x1f",
            "/api/home\x7f",
        ]
        for bad_input in bad_inputs:
            with self.subTest(bad_input=bad_input):
                result = get_safe_redirect_url(request, bad_input, default="/api/home")
                self.assertEqual(result, "/api/home")

    def test_get_safe_redirect_url_rejects_non_string_and_empty(self):
        request = self.factory.get("/api/user_action?action=login", HTTP_HOST="testserver")
        for bad in [None, "", "   ", 123, [], {}, True]:
            with self.subTest(bad=bad):
                result = get_safe_redirect_url(request, bad, default="/api/home")
                self.assertEqual(result, "/api/home")

    def test_login_get_view_sanitizes_next_parameter(self):
        # 1. Malicious next parameter is stripped in template context
        response = self.client.get("/api/user_action?action=login&next=/\\evil.example/path")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context.get("next_url"), "")

        # 2. Safe next parameter is preserved in template context
        response = self.client.get("/api/user_action?action=login&next=/api/devices")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context.get("next_url"), "/api/devices")

    def test_login_post_redirects_safely(self):
        # 1. Attacker-controlled next URL is sanitized to /api/home on login success
        response = self.client.post(
            "/api/user_action?action=login",
            data={
                "account": self.username,
                "password": self.password,
                "next": r"/\evil.example/phishing",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("code"), 1)
        self.assertEqual(data.get("url"), "/api/home")

        # 2. Legitimate relative route next URL is honored on login success
        response = self.client.post(
            "/api/user_action?action=login",
            data={
                "account": self.username,
                "password": self.password,
                "next": "/api/devices?tab=groups",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("code"), 1)
        self.assertEqual(data.get("url"), "/api/devices?tab=groups")
