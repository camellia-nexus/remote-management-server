"""Contract tests for bounded operations diagnostics package and secret redaction (DIAG-002, LOG-014).

Verifies:
1. Archive creation, POSIX tar.gz format, manifest schema, 0600 file permissions, and 2 MiB compressed cap.
2. Multi-pass secret redaction (settings, environment, database passwords, SECRET_KEY replaced with [REDACTED]).
3. Case-insensitive substring matching for sensitive keys (password, secret, token, key, auth, credential, private).
4. Strict size bounds: rejection of payloads exceeding 10 MiB uncompressed, and bundles exceeding 2 MiB compressed.
5. Secondary Canary Scanner fail-closed abort and immediate archive unlinking on canary detection.
6. Directory creation with 0700 permissions and optional uncompressed tar export (--no-gzip).
7. Recent logs collection with IP/credential/token masking.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tarfile
import tempfile
import warnings
from pathlib import Path

import django
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, override_settings

from api.management.commands.export_ops_diagnostics import (
    CANARY_SECRET_PATTERNS,
    MAX_COMPRESSED_BYTES,
    MAX_UNCOMPRESSED_BYTES,
    export_ops_diagnostics,
)


class Batch86DiagnosticsContractTests(SimpleTestCase):
    """Contract test suite for export_ops_diagnostics management command."""

    databases = {"default"}

    def setUp(self):
        super().setUp()
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.temp_dir = Path(self.temp_dir_obj.name).resolve()

    def tearDown(self):
        self.temp_dir_obj.cleanup()
        super().tearDown()

    def test_archive_creation_tar_gz_format_permissions_and_manifest(self):
        """Test archive creation, tar.gz format, manifest schema, 0600 file permissions, and 2 MiB cap."""
        archive_path = self.temp_dir / "test_bundle.tar.gz"

        call_command("export_ops_diagnostics", output=str(archive_path))

        self.assertTrue(archive_path.exists(), "Archive file must be created on disk")

        # Verify Unix permissions: 0600
        mode = stat.S_IMODE(os.stat(archive_path).st_mode)
        self.assertEqual(mode, 0o600, f"Archive file permissions must be 0600, got {oct(mode)}")

        # Verify archive size is strictly bounded under 2 MiB
        compressed_size = archive_path.stat().st_size
        self.assertLessEqual(
            compressed_size,
            MAX_COMPRESSED_BYTES,
            f"Compressed bundle ({compressed_size} bytes) exceeded {MAX_COMPRESSED_BYTES} bytes limit",
        )

        # Verify tar.gz format and extract member files
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getmembers()
            member_names = [m.name for m in members]

            # Manifest and required diagnostic artifacts
            self.assertIn("manifest.json", member_names)
            self.assertIn("system_info.json", member_names)
            self.assertIn("config_audit.json", member_names)
            self.assertIn("recent_logs.jsonl", member_names)

            # Verify permissions on tar entries
            for m in members:
                self.assertEqual(
                    m.mode,
                    0o600,
                    f"Tar member {m.name} must have 0600 permissions, got {oct(m.mode)}",
                )
                self.assertEqual(m.uid, 0)
                self.assertEqual(m.gid, 0)

            # Read and validate manifest.json
            manifest_file = tar.extractfile("manifest.json")
            self.assertIsNotNone(manifest_file)
            manifest = json.loads(manifest_file.read().decode("utf-8"))

            self.assertEqual(manifest.get("manifest_version"), "1.0")
            self.assertEqual(manifest.get("management_version"), "1.0.0")
            self.assertEqual(manifest.get("django_version"), django.get_version())
            self.assertIn("collection_timestamp_utc", manifest)
            self.assertIsInstance(manifest.get("files"), list)

            # Validate file checksums and lengths in manifest against actual members
            manifest_file_map = {f["path"]: f for f in manifest["files"]}
            for file_name in ("system_info.json", "config_audit.json", "recent_logs.jsonl"):
                self.assertIn(file_name, manifest_file_map)
                entry = manifest_file_map[file_name]
                extracted = tar.extractfile(file_name).read()
                self.assertEqual(entry["size"], len(extracted))
                self.assertEqual(entry["sha256"], hashlib.sha256(extracted).hexdigest())

            # Read and validate system_info.json
            sys_info_file = tar.extractfile("system_info.json")
            sys_info = json.loads(sys_info_file.read().decode("utf-8"))
            self.assertIn("python_runtime", sys_info)
            self.assertIn("os_platform", sys_info)
            self.assertIn("django_version", sys_info)
            self.assertIn("installed_apps", sys_info)
            self.assertIn("database_connections", sys_info)
            self.assertIn("cache_connections", sys_info)
            self.assertIn("migration_status", sys_info)

    def test_no_gzip_uncompressed_tar_format(self):
        """Test archive creation with --no-gzip flag producing standard uncompressed tar."""
        archive_path = self.temp_dir / "test_bundle.tar"

        call_command("export_ops_diagnostics", output=str(archive_path), no_gzip=True)

        self.assertTrue(archive_path.exists())
        mode = stat.S_IMODE(os.stat(archive_path).st_mode)
        self.assertEqual(mode, 0o600)

        # Open uncompressed tar
        with tarfile.open(archive_path, "r:") as tar:
            names = tar.getnames()
            self.assertIn("manifest.json", names)
            self.assertIn("system_info.json", names)

    def test_multi_pass_secret_redaction(self):
        """Test multi-pass secret redaction: settings, environment, DB passwords, SECRET_KEY -> [REDACTED]."""
        test_secret_key = "super-confidential-secret-key-do-not-leak"  # noqa: S105
        test_db_password = "super-confidential-database-password-42"  # noqa: S105
        test_cache_password = "super-confidential-redis-password-77"  # noqa: S105
        test_oauth_secret = "super-confidential-oauth-client-secret"  # noqa: S105
        test_api_token = "super-confidential-api-bearer-token"  # noqa: S105
        test_webhook_key = "super-confidential-webhook-signing-key"  # noqa: S105
        test_admin_cred = "super-confidential-admin-credential"  # noqa: S105
        test_private_key = (  # noqa: S105
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Yh1...FAKE_KEY_FOR_TESTING...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        test_env_token = "super-confidential-env-token-xyz"  # noqa: S105

        databases_override = {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
                "PASSWORD": test_db_password,
            }
        }
        caches_override = {
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": f"redis://:user:{test_cache_password}@127.0.0.1:6379/0",
                "PASSWORD": test_cache_password,
            }
        }

        archive_path = self.temp_dir / "redacted_bundle.tar.gz"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=UserWarning)
            with (
                override_settings(
                    SECRET_KEY=test_secret_key,
                    DATABASES=databases_override,
                    CACHES=caches_override,
                    OAUTH_CLIENT_SECRET=test_oauth_secret,
                    API_AUTH_TOKEN=test_api_token,
                    WEBHOOK_SIGNING_KEY=test_webhook_key,
                    ADMIN_CREDENTIAL_STORAGE=test_admin_cred,
                    SIGNING_PRIVATE_KEY=test_private_key,
                ),
                tempfile.TemporaryDirectory(),
            ):
                # Set sensitive environment variable
                os.environ["CAMELLIA_OPS_AUTH_TOKEN"] = test_env_token

                try:
                    call_command("export_ops_diagnostics", output=str(archive_path))
                finally:
                    os.environ.pop("CAMELLIA_OPS_AUTH_TOKEN", None)

        self.assertTrue(archive_path.exists())

        # Inspect extracted config_audit.json
        with tarfile.open(archive_path, "r:gz") as tar:
            config_bytes = tar.extractfile("config_audit.json").read()
            config_text = config_bytes.decode("utf-8")
            config_audit = json.loads(config_text)

        # 1. Assert that none of the raw confidential strings appear anywhere in the payload
        forbidden_secrets = [
            test_secret_key,
            test_db_password,
            test_cache_password,
            test_oauth_secret,
            test_api_token,
            test_webhook_key,
            test_admin_cred,
            test_private_key,
            "BEGIN RSA PRIVATE KEY",
            test_env_token,
        ]
        for sec in forbidden_secrets:
            self.assertNotIn(
                sec,
                config_text,
                f"Secret '{sec}' was found in config_audit.json! Multi-pass redaction failed.",
            )

        # 2. Assert that sensitive settings keys were explicitly replaced with [REDACTED]
        django_settings = config_audit["django_settings"]
        self.assertEqual(django_settings.get("SECRET_KEY"), "[REDACTED]")
        self.assertEqual(django_settings.get("OAUTH_CLIENT_SECRET"), "[REDACTED]")
        self.assertEqual(django_settings.get("API_AUTH_TOKEN"), "[REDACTED]")
        self.assertEqual(django_settings.get("WEBHOOK_SIGNING_KEY"), "[REDACTED]")
        self.assertEqual(django_settings.get("ADMIN_CREDENTIAL_STORAGE"), "[REDACTED]")
        self.assertEqual(django_settings.get("SIGNING_PRIVATE_KEY"), "[REDACTED]")

        # Nested dictionary password redaction
        self.assertEqual(django_settings["DATABASES"]["default"]["PASSWORD"], "[REDACTED]")
        self.assertEqual(django_settings["CACHES"]["default"]["PASSWORD"], "[REDACTED]")

        # Environment variable redaction
        env_vars = config_audit["environment_variables"]
        self.assertEqual(env_vars.get("CAMELLIA_OPS_AUTH_TOKEN"), "[REDACTED]")

    def test_uncompressed_size_bounds_rejection(self):
        """Test strict fail-closed rejection when uncompressed payload exceeds 10 MiB cap."""
        archive_path = self.temp_dir / "overlong_uncompressed.tar.gz"

        # Construct payload exceeding 10 MiB limit (11 MiB)
        oversized_data = b"0" * (MAX_UNCOMPRESSED_BYTES + 1024 * 1024)

        with self.assertRaises(CommandError) as ctx:
            export_ops_diagnostics(
                output_path=archive_path,
                extra_files={"oversized_chunk.dat": oversized_data},
            )

        self.assertIn("exceeds maximum limit of 10485760 bytes", str(ctx.exception))
        self.assertFalse(archive_path.exists(), "Archive file must not exist on disk when bounds exceeded")

    def test_compressed_size_bounds_rejection(self):
        """Test strict fail-closed rejection when compressed bundle exceeds 2 MiB cap."""
        archive_path = self.temp_dir / "overlong_compressed.tar.gz"

        # Generate 2.5 MiB of uncompressible random bytes
        uncompressible_data = os.urandom(2_500_000)

        with self.assertRaises(CommandError) as ctx:
            export_ops_diagnostics(
                output_path=archive_path,
                max_uncompressed_bytes=20 * 1024 * 1024,  # allow uncompressed pass
                max_compressed_bytes=MAX_COMPRESSED_BYTES,
                extra_files={"random_entropy.bin": uncompressible_data},
            )

        self.assertIn("exceeds maximum bound of 2097152 bytes", str(ctx.exception))
        self.assertFalse(archive_path.exists(), "Archive must be unlinked and deleted on compression bound breach")

    def test_secondary_canary_scanner_fail_closed_abort_and_unlinking(self):
        """Test secondary canary scanner fail-closed abort and immediate archive unlinking on canary detection."""
        archive_path = self.temp_dir / "canary_leak.tar.gz"

        # 1. Test known private key canary pattern detection
        private_key_canary_payload = (
            b"sample header\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret_bytes\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        with self.assertRaises(CommandError) as ctx:
            export_ops_diagnostics(
                output_path=archive_path,
                extra_files={"leaked_key.pem": private_key_canary_payload},
            )

        self.assertIn("Secondary canary scanner detected sensitive secret pattern", str(ctx.exception))
        self.assertFalse(archive_path.exists(), "Archive file must be immediately deleted upon canary detection")

        # 2. Test custom canary detection via CLI flag and verify fail-closed unlinking
        custom_canary = "CANARY_TOKEN_ABCD_9876_XYZ"
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "export_ops_diagnostics",
                output=str(archive_path),
                canary=[custom_canary, "CPython"],  # CPython is guaranteed present in system_info
            )

        self.assertIn("Secondary canary scanner detected sensitive secret pattern", str(ctx.exception))
        self.assertFalse(archive_path.exists(), "Archive must be immediately unlinked from disk on canary hit")

    def test_directory_output_creation_with_0700_permissions(self):
        """Test output argument pointing to a new directory creates it with 0700 permissions."""
        target_dir = self.temp_dir / "diagnostics_target_subdir"
        self.assertFalse(target_dir.exists())

        call_command("export_ops_diagnostics", output=str(target_dir))

        self.assertTrue(target_dir.exists(), "Subdirectory must be created")
        mode = stat.S_IMODE(os.stat(target_dir).st_mode)
        self.assertEqual(mode, 0o700, f"Output directory permissions must be 0700, got {oct(mode)}")

        # Verify an archive was created inside the directory
        archives = list(target_dir.glob("camellia_remote_ops_diagnostics_*.tar.gz"))
        self.assertEqual(len(archives), 1)
        archive_mode = stat.S_IMODE(os.stat(archives[0]).st_mode)
        self.assertEqual(archive_mode, 0o600)

    def test_include_logs_collection_and_sanitization(self):
        """Test --include-logs flag collects logs with regex masking for tokens and sensitive credentials."""
        log_file = self.temp_dir / "test_application.log"
        log_lines = [
            "2026-11-16 12:00:01 INFO Connection from client 192.168.10.85 port 54321 established\n",
            "2026-11-16 12:00:02 DEBUG Authenticating operator admin_user@organization.corp with token\n",
            "2026-11-16 12:00:03 INFO Request headers Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.token\n",
            "2026-11-16 12:00:04 DEBUG Connecting to upstream redis://:secretpass12345@10.0.0.1:6379/0\n",
        ]
        with open(log_file, "w", encoding="utf-8") as f:
            f.writelines(log_lines)

        archive_path = self.temp_dir / "logs_bundle.tar.gz"

        logging_override = {
            "version": 1,
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": str(log_file),
                }
            },
        }

        with override_settings(LOGGING=logging_override):
            call_command(
                "export_ops_diagnostics",
                output=str(archive_path),
                include_logs=True,
            )

        self.assertTrue(archive_path.exists())

        with tarfile.open(archive_path, "r:gz") as tar:
            logs_content = tar.extractfile("recent_logs.jsonl").read().decode("utf-8")
            logs_report = json.loads(logs_content)

        self.assertEqual(logs_report.get("status"), "collected")
        self.assertEqual(logs_report.get("lines_collected"), 4)

        collected_text = "\n".join(logs_report["lines"])

        # Verify IPv4 masking
        self.assertNotIn("192.168.10.85", collected_text)
        self.assertIn("192.168.10.xxx", collected_text)

        # Verify email masking
        self.assertNotIn("admin_user@organization.corp", collected_text)
        self.assertIn("a***@organization.corp", collected_text)

        # Verify Bearer token masking
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9.test.token", collected_text)
        self.assertIn("Bearer [REDACTED]", collected_text)

        # Verify embedded URL password masking
        self.assertNotIn("secretpass12345", collected_text)
        self.assertIn("redis://:[REDACTED]@", collected_text)

    def test_canary_patterns_coverage(self):
        """Verify CANARY_SECRET_PATTERNS contains all required standard private key headers."""
        required_patterns = [
            "BEGIN PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
        ]
        for pat in required_patterns:
            self.assertIn(pat, CANARY_SECRET_PATTERNS)
