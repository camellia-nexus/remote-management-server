import ipaddress

from django.test import RequestFactory, SimpleTestCase, override_settings

from api.middleware import TrustedProxyMiddleware
from api.request_utils import is_trusted_proxy


class TrustedProxyMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = TrustedProxyMiddleware(lambda req: req)

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.1/32")),
    )
    def test_is_trusted_proxy_checks_remote_addr_against_networks(self):
        req_trusted_10 = self.factory.get("/", REMOTE_ADDR="10.20.30.40")
        self.assertTrue(is_trusted_proxy(req_trusted_10))

        req_trusted_loopback = self.factory.get("/", REMOTE_ADDR="127.0.0.1")
        self.assertTrue(is_trusted_proxy(req_trusted_loopback))

        req_untrusted = self.factory.get("/", REMOTE_ADDR="198.51.100.5")
        self.assertFalse(is_trusted_proxy(req_untrusted))

        req_invalid = self.factory.get("/", REMOTE_ADDR="not-an-ip")
        self.assertFalse(is_trusted_proxy(req_invalid))

        req_empty = self.factory.get("/", REMOTE_ADDR="")
        self.assertFalse(is_trusted_proxy(req_empty))

    @override_settings(
        TRUST_PROXY_HEADERS=False,
        TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"),),
    )
    def test_is_trusted_proxy_fails_closed_when_trust_proxy_headers_disabled(self):
        req = self.factory.get("/", REMOTE_ADDR="10.1.2.3")
        self.assertFalse(is_trusted_proxy(req))

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"),),
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    )
    def test_untrusted_remote_addr_has_proxy_ssl_header_stripped(self):
        # Plain HTTP request from untrusted IP attempting to spoof HTTPS
        req = self.factory.get(
            "/",
            REMOTE_ADDR="203.0.113.195",
            HTTP_X_FORWARDED_PROTO="https",
            HTTP_X_FORWARDED_PROTOCOL="https",
            HTTP_X_FORWARDED_SSL="on",
        )
        self.middleware(req)
        self.assertNotIn("HTTP_X_FORWARDED_PROTO", req.META)
        self.assertNotIn("HTTP_X_FORWARDED_PROTOCOL", req.META)
        self.assertNotIn("HTTP_X_FORWARDED_SSL", req.META)
        self.assertFalse(req.is_secure())
        self.assertEqual(req.scheme, "http")

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"),),
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    )
    def test_trusted_proxy_preserves_proxy_ssl_header(self):
        req = self.factory.get(
            "/",
            REMOTE_ADDR="10.50.60.70",
            HTTP_X_FORWARDED_PROTO="https",
        )
        self.middleware(req)
        self.assertEqual(req.META.get("HTTP_X_FORWARDED_PROTO"), "https")
        self.assertTrue(req.is_secure())
        self.assertEqual(req.scheme, "https")
