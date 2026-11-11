import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path

from django.conf import settings
from django.contrib.staticfiles import finders
from django.test import SimpleTestCase, TestCase, override_settings

from api.models import UserProfile
from webui2.views import (
    _normalize_relay_server,
    _normalize_rendezvous_server,
    _resolve_webui2_servers,
)


class _AccessibilityParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.label_targets = set()
        self.controls = []
        self.blank_links = []
        self.destructive_actions = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self._current_form = {"confirm": attributes.get("data-confirm"), "actions": []}
        if tag == "label" and attributes.get("for"):
            self.label_targets.add(attributes["for"])
        if tag in {"input", "select", "textarea"} and attributes.get("type", "").lower() != "hidden":
            self.controls.append(attributes)
        if (
            tag == "input"
            and self._current_form is not None
            and attributes.get("type", "").lower() == "hidden"
            and attributes.get("name") == "action"
        ):
            self._current_form["actions"].append((attributes.get("value"), self._current_form["confirm"]))
        if tag == "button" and attributes.get("name") == "action":
            self.destructive_actions.append((attributes.get("value"), attributes.get("data-confirm")))
        if tag == "a" and attributes.get("target", "").lower() == "_blank":
            self.blank_links.append(attributes)

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.destructive_actions.extend(self._current_form["actions"])
            self._current_form = None


class TemplateAccessibilityTests(SimpleTestCase):
    def test_form_controls_and_new_windows_have_accessible_names(self):
        template_roots = (
            Path(settings.BASE_DIR) / "api" / "templates",
            Path(settings.BASE_DIR) / "webui2" / "templates",
            Path(settings.BASE_DIR) / "templates",
        )
        for template_path in sorted(path for root in template_roots for path in root.rglob("*.html")):
            parser = _AccessibilityParser()
            parser.feed(template_path.read_text(encoding="utf-8"))
            for attributes in parser.controls:
                with self.subTest(template=template_path.name, control=attributes.get("name")):
                    self.assertTrue(
                        attributes.get("aria-label")
                        or attributes.get("aria-labelledby")
                        or attributes.get("id") in parser.label_targets,
                        f"{template_path}: visible form control has no accessible name",
                    )
            for attributes in parser.blank_links:
                with self.subTest(template=template_path.name, href=attributes.get("href")):
                    rel = set((attributes.get("rel") or "").split())
                    self.assertIn("noopener", rel, f"{template_path}: target=_blank must isolate opener")
                    self.assertIn("noreferrer", rel, f"{template_path}: target=_blank must suppress referrer")
            for action, confirmation in parser.destructive_actions:
                if action and (
                    action.startswith("delete_") or action in {"bulk_delete", "bulk_peer_delete", "transfer_book"}
                ):
                    with self.subTest(template=template_path.name, action=action):
                        self.assertTrue(
                            confirmation,
                            f"{template_path}: {action} must require explicit confirmation",
                        )


class WebClientServerConfigurationTests(SimpleTestCase):
    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="id.example.com",
        RELAY_SERVER="",
    )
    def test_native_endpoints_use_service_ports(self):
        raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(raw, ["id.example.com"])
        self.assertEqual(rendezvous, ["id.example.com:21116"])
        self.assertEqual(relay, ["id.example.com:21117"])

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="ws://id.example.com",
        RELAY_SERVER="",
    )
    def test_plain_websocket_endpoints_use_websocket_ports(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(rendezvous, ["ws://id.example.com:21118"])
        self.assertEqual(relay, ["ws://id.example.com:21119"])

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="wss://remote.example.com:443",
        RELAY_SERVER="",
    )
    def test_tls_reverse_proxy_uses_one_origin_and_distinct_paths(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(
            rendezvous,
            ["wss://remote.example.com:443/ws/id"],
        )
        self.assertEqual(
            relay,
            ["wss://remote.example.com:443/ws/relay"],
        )

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="wss://remote.example.com:8443/custom-id?tenant=one",
        RELAY_SERVER="wss://relay.example.com:9443/custom-relay?tenant=one",
    )
    def test_explicit_proxy_paths_and_queries_are_preserved(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(
            rendezvous,
            ["wss://remote.example.com:8443/custom-id?tenant=one"],
        )
        self.assertEqual(
            relay,
            ["wss://relay.example.com:9443/custom-relay?tenant=one"],
        )

    @override_settings(DEFAULT_ID_PORT=21116)
    def test_invalid_or_credentialed_endpoints_are_rejected(self):
        self.assertEqual(_normalize_rendezvous_server("https://id.example.com"), "")
        self.assertEqual(
            _normalize_rendezvous_server("wss://user:secret@id.example.com"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://user@id.example.com"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://@id.example.com"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com#fragment"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com#"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com/custom\x00id"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com/custom\x1fid"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com/custom\x7fid"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com/custom\x80id"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com/custom\x9fid"),
            "",
        )
        self.assertEqual(
            _normalize_rendezvous_server("wss://id.example.com/custom id"),
            "",
        )
        self.assertEqual(
            _normalize_relay_server("relay.example.com/path"),
            "",
        )
        self.assertEqual(
            _normalize_relay_server("user@relay.example.com"),
            "",
        )
        self.assertEqual(
            _normalize_relay_server("relay.example.com?query"),
            "",
        )
        self.assertEqual(
            _normalize_relay_server("relay.example.com#frag"),
            "",
        )


class WebClientRuntimeTests(TestCase):
    _created_runtime = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        runtime_dir = Path(settings.BASE_DIR) / "static" / "web_client"
        if not (runtime_dir / ".source_revision").is_file():
            cls._created_runtime = True
            revision_script = Path(settings.BASE_DIR) / "scripts" / "web_client_revision.sh"
            locked_rev = subprocess.check_output(["bash", str(revision_script)], text=True).strip()

            with tempfile.TemporaryDirectory() as tmp_src:
                src_path = Path(tmp_src)
                (src_path / ".source_revision").write_text(f"{locked_rev} clean\n", encoding="utf-8")

                files = {
                    "flutter_bootstrap.js": (
                        b'// flutter bootstrap mock\n'
                        b'_flutter.buildConfig = {"builds":[{"compileTarget":"dart2js","renderer":"canvaskit","mainJsPath":"main.dart.js"}]};\n'
                    ),
                    "flutter.js": b'// flutter engine mock\n',
                    "main.dart.js": b'// dart2js code\n',
                    "manifest.json": b'{"name":"Camellia"}\n',
                    "index.html": b'<!DOCTYPE html><html><head><base href="/"><script src="js/dist/web_bridge.js"></script></head><body></body></html>\n',
                    "canvaskit/canvaskit.wasm": b'\x00asm\x01\x00\x00\x00mock-canvaskit',
                    "js/dist/web_bridge.js": b'// web bridge mock\n',
                    "js/dist/assets/video_worker-mock.js": b'// worker mock\n',
                    "ogvjs-1.8.6/ogv-decoder-video-vp8-wasm.js": b'// vp8 mock\n',
                    "ogvjs-1.8.6/ogv-decoder-video-vp8-wasm.wasm": b'\x00asm\x01\x00\x00\x00mock-vp8',
                }
                manifest_files = {}
                for rel, data in files.items():
                    fp = src_path / rel
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    fp.write_bytes(data)
                    manifest_files[rel] = {
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }

                lines = [f"{k}:{manifest_files[k]['size']}:{manifest_files[k]['sha256']}" for k in sorted(manifest_files.keys())]
                root_digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
                build_manifest = {
                    "schema_version": 1,
                    "source_revision": locked_rev,
                    "source_state": "clean",
                    "base_href": "/",
                    "root_digest": root_digest,
                    "files": manifest_files,
                }
                (src_path / "build_manifest.json").write_text(json.dumps(build_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

                sync_script = Path(settings.BASE_DIR) / "sync_web_client.sh"
                subprocess.run(["bash", str(sync_script), "--source", str(src_path)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        if cls._created_runtime:
            runtime_dir = Path(settings.BASE_DIR) / "static" / "web_client"
            if runtime_dir.is_dir():
                shutil.rmtree(runtime_dir)
        super().tearDownClass()

    @property
    def runtime_root(self):
        return Path(settings.BASE_DIR) / "static" / "web_client"

    def test_runtime_bundle_excludes_build_tooling(self):
        required_files = (
            ".source_revision",
            "flutter_bootstrap.js",
            "main.dart.js",
            "manifest.json",
            "canvaskit/canvaskit.wasm",
            "js/dist/web_bridge.js",
            "web_client_manifest.json",
        )
        for relative_path in required_files:
            with self.subTest(relative_path=relative_path):
                self.assertTrue((self.runtime_root / relative_path).is_file())

        source_revision = (self.runtime_root / ".source_revision").read_text().strip()
        self.assertRegex(source_revision, r"^[0-9a-f]{40,64} clean$")

        forbidden_paths = (
            "js/node_modules",
            "js/src",
            "js/tools",
            "js/package.json",
            "js/package-lock.json",
            "js/tsconfig.json",
            "js/vite.config.ts",
        )
        for relative_path in forbidden_paths:
            with self.subTest(relative_path=relative_path):
                self.assertFalse((self.runtime_root / relative_path).exists())

    def test_web_client_manifest_and_deployment_hardening(self):
        manifest_file = self.runtime_root / "web_client_manifest.json"
        self.assertTrue(manifest_file.is_file())
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("schema_version"), 1)
        self.assertIn("root_digest", manifest)
        self.assertRegex(manifest["root_digest"], r"^[0-9a-f]{64}$")
        self.assertIsInstance(manifest.get("files"), dict)

        lines = []
        for rel_path, spec in sorted(manifest["files"].items()):
            file_path = self.runtime_root / rel_path
            self.assertTrue(file_path.is_file(), f"Manifest file missing: {rel_path}")
            data = file_path.read_bytes()
            self.assertEqual(len(data), spec["size"], f"Size mismatch for {rel_path}")
            self.assertEqual(
                hashlib.sha256(data).hexdigest().lower(),
                spec["sha256"].lower(),
                f"Hash mismatch for {rel_path}",
            )
            lines.append(f"{rel_path}:{spec['size']}:{spec['sha256']}")
        expected_root = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        self.assertEqual(expected_root, manifest["root_digest"])

        worker_matches = list((self.runtime_root / "js" / "dist" / "assets").glob("video_worker-*.js"))
        self.assertTrue(len(worker_matches) >= 1, "Expected video_worker-*.js chunk in js/dist/assets")

        web_bridge = (self.runtime_root / "js" / "dist" / "web_bridge.js").read_text(encoding="utf-8")
        self.assertNotRegex(web_bridge, r"""["']/js/dist/assets/video_worker""")
        self.assertNotIn("Object.assign({})[", web_bridge)

        index_html = (self.runtime_root / "index.html").read_text(encoding="utf-8")
        self.assertIn('<base href="/static/web_client/">', index_html)

    def test_bootstrap_has_one_complete_javascript_target(self):
        bootstrap = (self.runtime_root / "flutter_bootstrap.js").read_text()
        match = re.search(r"_flutter\.buildConfig = (\{[^\n]+\});", bootstrap)
        self.assertIsNotNone(match)
        config = json.loads(match.group(1))
        self.assertEqual(
            config["builds"],
            [
                {
                    "compileTarget": "dart2js",
                    "renderer": "canvaskit",
                    "mainJsPath": "main.dart.js",
                }
            ],
        )
        self.assertNotIn("sourceMappingURL=", bootstrap)
        self.assertNotIn(
            "sourceMappingURL=",
            (self.runtime_root / "flutter.js").read_text(),
        )

    def test_admin_assets_use_the_framework_version_without_shadowing(self):
        self.assertEqual(
            len(finders.find("admin/css/base.css", find_all=True)),
            1,
        )
        self.assertEqual(
            len(finders.find("camellia_admin/admin.css", find_all=True)),
            1,
        )

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_entrypoint_is_nonce_bound_without_unsafe_eval(self):
        user = UserProfile.objects.create_user(
            username="web-client-user",
            password="test-password",
        )
        self.client.force_login(user)

        response = self.client.get("/webui2/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/static/web_client/js/dist/web_bridge.js")
        self.assertContains(response, "/static/web_client/flutter_bootstrap.js")
        csp = response.headers.get("Content-Security-Policy", "")
        self.assertIn("script-src", csp)
        self.assertIn("'nonce-", csp)
        self.assertIn("'wasm-unsafe-eval'", csp)
        self.assertNotIn("'unsafe-eval'", csp)


class WebClientManifestHardeningTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        revision_script = Path(settings.BASE_DIR) / "scripts" / "web_client_revision.sh"
        self.locked_rev = subprocess.check_output(["bash", str(revision_script)], text=True).strip()
        self.sync_script = Path(settings.BASE_DIR) / "sync_web_client.sh"

    def _create_mock_source(self, tmp_path, files=None, manifest_override=None, include_manifest=True):
        src_path = Path(tmp_path)
        (src_path / ".source_revision").write_text(f"{self.locked_rev} clean\n", encoding="utf-8")
        if files is None:
            files = {
                "flutter_bootstrap.js": (
                    b'// flutter bootstrap mock\n'
                    b'_flutter.buildConfig = {"builds":[{"compileTarget":"dart2js","renderer":"canvaskit","mainJsPath":"main.dart.js"}]};\n'
                ),
                "flutter.js": b'// flutter engine mock\n',
                "main.dart.js": b'// dart2js code\n',
                "manifest.json": b'{"name":"Camellia"}\n',
                "index.html": b'<!DOCTYPE html><html><head><base href="/"><script src="js/dist/web_bridge.js"></script></head><body></body></html>\n',
                "canvaskit/canvaskit.wasm": b'\x00asm\x01\x00\x00\x00mock-canvaskit',
                "js/dist/web_bridge.js": b'// web bridge mock\n',
                "js/dist/assets/video_worker-mock.js": b'// worker mock\n',
                "ogvjs-1.8.6/ogv-decoder-video-vp8-wasm.js": b'// vp8 mock\n',
                "ogvjs-1.8.6/ogv-decoder-video-vp8-wasm.wasm": b'\x00asm\x01\x00\x00\x00mock-vp8',
            }

        manifest_files = {}
        for rel, data in files.items():
            fp = src_path / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(data)
            manifest_files[rel] = {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }

        if include_manifest:
            lines = [f"{k}:{manifest_files[k]['size']}:{manifest_files[k]['sha256']}" for k in sorted(manifest_files.keys())]
            root_digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
            build_manifest = {
                "schema_version": 1,
                "source_revision": self.locked_rev,
                "source_state": "clean",
                "base_href": "/",
                "root_digest": root_digest,
                "files": manifest_files,
            }
            if manifest_override:
                build_manifest.update(manifest_override)
            (src_path / "build_manifest.json").write_text(json.dumps(build_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        return src_path

    def test_missing_build_manifest_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._create_mock_source(tmp, include_manifest=False)
            res = subprocess.run(["bash", str(self.sync_script), "--source", str(src)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("missing build_manifest.json", res.stderr)

    def test_tampered_file_size_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._create_mock_source(tmp)
            (src / "main.dart.js").write_bytes(b'tampered-short')
            res = subprocess.run(["bash", str(self.sync_script), "--source", str(src)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Size mismatch for main.dart.js", res.stderr)

    def test_tampered_file_hash_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._create_mock_source(tmp)
            original_len = len(b'// dart2js code\n')
            (src / "main.dart.js").write_bytes(b'x' * original_len)
            res = subprocess.run(["bash", str(self.sync_script), "--source", str(src)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Hash mismatch for main.dart.js", res.stderr)

    def test_unmanifested_extra_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._create_mock_source(tmp)
            (src / "unexpected_file.txt").write_bytes(b'unmanifested')
            res = subprocess.run(["bash", str(self.sync_script), "--source", str(src)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Unmanifested file found in web client source: unexpected_file.txt", res.stderr)

    def test_tampered_root_digest_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._create_mock_source(tmp, manifest_override={"root_digest": "0" * 64})
            res = subprocess.run(["bash", str(self.sync_script), "--source", str(src)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("build_manifest root_digest mismatch", res.stderr)

    def test_tampered_source_revision_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = self._create_mock_source(tmp, manifest_override={"source_revision": "1" * 40})
            res = subprocess.run(["bash", str(self.sync_script), "--source", str(src)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("build_manifest source_revision mismatch", res.stderr)

