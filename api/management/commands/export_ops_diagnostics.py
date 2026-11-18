"""Bounded and redacted operations diagnostics support bundle exporter (DIAG-002, LOG-014).

Provides operational diagnostics collection for `python manage.py export_ops_diagnostics`:
- Read-only collection of system information, database/cache health, migration plan,
  configuration audit, and sanitized recent logs.
- Strict multi-pass secret redaction stripping SECRET_KEY, database passwords, cache passwords,
  JWT keys, OAuth secrets, API keys, webhook secrets, and bearer tokens.
- Bounded resource caps (max 10 MiB uncompressed payload, max 2 MiB compressed `.tar.gz`).
- Strict file security (0700 directory permissions, 0600 archive file permissions).
- In-process POSIX tar archive generation with gzip compression and manifest verification.
- Secondary Canary Scanner scanning in-memory files, uncompressed tar payload, and final archive;
  fails closed with immediate archive unlinking if any secret canary pattern matches.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import platform
import re
import sys
import tarfile
import tempfile
import uuid
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import django
from django.conf import settings
from django.core.cache import caches
from django.core.management.base import BaseCommand, CommandError
from django.db import DEFAULT_DB_ALIAS, connections
from django.db import Error as DatabaseError
from django.db.migrations.exceptions import MigrationSchemaMissing
from django.db.migrations.executor import MigrationExecutor

logger = logging.getLogger(__name__)

# Strict Size Bounds
MAX_UNCOMPRESSED_BYTES: int = 10 * 1024 * 1024  # 10 MiB
MAX_COMPRESSED_BYTES: int = 2 * 1024 * 1024  # 2 MiB

# Case-insensitive substring matching for sensitive keys
SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "key",
    "auth",
    "credential",
    "private",
)

# Known private key and secret canary patterns
CANARY_SECRET_PATTERNS: tuple[str, ...] = (
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
)

# Masking regular expressions
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9_\- ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_\- ]+PRIVATE KEY-----"
)
_BEARER_TOKEN_RE = re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE)
_BASIC_AUTH_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]+", re.IGNORECASE)
_URL_PASSWORD_RE = re.compile(r"://([^:@\s]*):([^@\s]+)@")
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:)[0-9a-fA-F:]+\b")
_EMAIL_RE = re.compile(r"\b([a-zA-Z0-9_.+-])[a-zA-Z0-9_.+-]*@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b")
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def sanitize_string(text: str, *, max_len: int = 4096) -> str:
    """Mask private keys, auth headers, URLs with passwords, IPs, emails, and control chars."""
    if not isinstance(text, str):
        text = str(text)

    cleaned = _PRIVATE_KEY_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY_BLOCK]", text)
    cleaned = _BEARER_TOKEN_RE.sub("Bearer [REDACTED]", cleaned)
    cleaned = _BASIC_AUTH_RE.sub("Basic [REDACTED]", cleaned)
    cleaned = _URL_PASSWORD_RE.sub(r"://\1:[REDACTED]@", cleaned)
    cleaned = _IPV4_RE.sub(r"\g<1>xxx", cleaned)
    cleaned = _IPV6_RE.sub(r"\g<1>xxxx", cleaned)
    cleaned = _EMAIL_RE.sub(r"\g<1>***@\g<2>", cleaned)
    cleaned = _CONTROL_CHAR_RE.sub(" ", cleaned)

    if len(cleaned) > max_len:
        return cleaned[:max_len] + "...[TRUNCATED]"
    return cleaned


def is_sensitive_key(key: str) -> bool:
    """Check if key contains any sensitive substrings (case-insensitive)."""
    key_lower = str(key).lower()
    return any(sub in key_lower for sub in SENSITIVE_KEY_SUBSTRINGS)


def redact_data(
    key: str,
    val: Any,
    *,
    active_secrets: set[str] | None = None,
    max_len: int = 4096,
) -> Any:
    """Recursively redact dictionary values, lists, and strings containing sensitive data."""
    if is_sensitive_key(key):
        return "[REDACTED]"

    if val is None or isinstance(val, (int, float, bool)):
        return val

    if isinstance(val, dict):
        return {
            str(k): redact_data(str(k), v, active_secrets=active_secrets, max_len=max_len)
            for k, v in val.items()
        }

    if isinstance(val, (list, tuple, set)):
        redacted_list = [
            redact_data(key, item, active_secrets=active_secrets, max_len=max_len)
            for item in val
        ]
        return type(val)(redacted_list) if isinstance(val, (list, tuple)) else redacted_list

    if active_secrets:
        val_str = str(val)
        for secret in active_secrets:
            if secret and secret in val_str:
                return "[REDACTED]"

    if isinstance(val, str):
        return sanitize_string(val, max_len=max_len)

    return sanitize_string(str(val), max_len=max_len)


def collect_active_secrets() -> set[str]:
    """Collect known active secrets from Django configuration to ensure canary detection."""
    secrets_set: set[str] = set()

    # Secret key
    secret_key = getattr(settings, "SECRET_KEY", None)
    if secret_key and isinstance(secret_key, str) and len(secret_key) >= 6:
        secrets_set.add(secret_key)

    # Database passwords
    for db_cfg in getattr(settings, "DATABASES", {}).values():
        if isinstance(db_cfg, dict):
            pw = db_cfg.get("PASSWORD")
            if pw and isinstance(pw, str) and len(pw) >= 4:
                secrets_set.add(pw)

    # Cache passwords
    for cache_cfg in getattr(settings, "CACHES", {}).values():
        if isinstance(cache_cfg, dict):
            pw = cache_cfg.get("PASSWORD")
            if pw and isinstance(pw, str) and len(pw) >= 4:
                secrets_set.add(pw)
            # Check LOCATION for embedded passwords
            loc = cache_cfg.get("LOCATION")
            if loc and isinstance(loc, str):
                match = _URL_PASSWORD_RE.search(loc)
                if match:
                    secrets_set.add(match.group(2))

    return secrets_set


def collect_system_info() -> dict[str, Any]:
    """Read-only collector: Python runtime, OS platform, Django version, apps, DB/cache health, migrations."""
    # 1. Database connection health
    db_status: dict[str, Any] = {}
    for alias in connections:
        conn = connections[alias]
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1;")
                cursor.fetchone()
            db_status[alias] = {
                "engine": conn.settings_dict.get("ENGINE", ""),
                "vendor": getattr(conn, "vendor", "unknown"),
                "status": "ok",
            }
        except (DatabaseError, OSError, RuntimeError) as exc:
            db_status[alias] = {
                "engine": conn.settings_dict.get("ENGINE", ""),
                "vendor": getattr(conn, "vendor", "unknown"),
                "status": "error",
                "error": sanitize_string(str(exc)),
            }

    # 2. Cache connection health
    cache_status: dict[str, Any] = {}
    for alias in getattr(settings, "CACHES", {"default": {}}):
        try:
            cache = caches[alias]
            test_key = f"_diag_ping_{uuid.uuid4().hex}"
            cache.set(test_key, "1", timeout=5)
            val = cache.get(test_key)
            cache.delete(test_key)
            cache_status[alias] = {
                "backend": settings.CACHES.get(alias, {}).get("BACKEND", ""),
                "status": "ok" if val == "1" else "degraded",
            }
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            cache_status[alias] = {
                "backend": settings.CACHES.get(alias, {}).get("BACKEND", ""),
                "status": "error",
                "error": sanitize_string(str(exc)),
            }

    # 3. Migration status
    try:
        connection = connections[DEFAULT_DB_ALIAS]
        executor = MigrationExecutor(connection)
        targets = executor.loader.graph.leaf_nodes()
        plan = executor.migration_plan(targets)
        applied = sorted(f"{m[0]}.{m[1]}" for m in executor.loader.applied_migrations)
        unapplied = [f"{m.app_label}.{m.name}" for m, backwards in plan]
        migration_status: dict[str, Any] = {
            "applied_count": len(applied),
            "unapplied_count": len(unapplied),
            "unapplied": unapplied,
            "status": "synchronized" if not unapplied else "pending_migrations",
        }
    except (DatabaseError, MigrationSchemaMissing, OSError, ValueError, RuntimeError) as exc:
        migration_status = {
            "status": "error",
            "error": sanitize_string(str(exc)),
        }

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "python_runtime": {
            "version": sys.version,
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "os_platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "django_version": django.get_version(),
        "installed_apps": list(getattr(settings, "INSTALLED_APPS", [])),
        "database_connections": db_status,
        "cache_connections": cache_status,
        "migration_status": migration_status,
    }


def collect_config_audit(*, active_secrets: set[str] | None = None) -> dict[str, Any]:
    """Collect active configuration settings and environment variables through strict multi-pass redaction."""
    if active_secrets is None:
        active_secrets = collect_active_secrets()

    # Redact settings
    redacted_settings: dict[str, Any] = {}
    for attr in dir(settings):
        if not attr.isupper() or attr.startswith("_"):
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                val = getattr(settings, attr)
            redacted_settings[attr] = redact_data(attr, val, active_secrets=active_secrets)
        except (AttributeError, ValueError, TypeError) as exc:
            redacted_settings[attr] = f"[UNREADABLE_SETTING: {exc}]"

    # Redact environment variables
    redacted_env: dict[str, Any] = {}
    for env_key, env_val in os.environ.items():
        redacted_env[env_key] = redact_data(env_key, env_val, active_secrets=active_secrets)

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "django_settings": redacted_settings,
        "environment_variables": redacted_env,
    }


def collect_recent_logs(*, include_logs: bool = False, max_lines: int = 500) -> dict[str, Any]:
    """Optionally collect the last 500 lines from configured log files with secret and PII masking."""
    if not include_logs:
        return {
            "status": "omitted",
            "reason": "--include-logs flag was not set",
        }

    candidate_log_files: list[Path] = []

    # 1. Search settings.LOGGING handlers
    logging_cfg = getattr(settings, "LOGGING", {})
    if isinstance(logging_cfg, dict):
        handlers = logging_cfg.get("handlers", {})
        if isinstance(handlers, dict):
            for h_cfg in handlers.values():
                if isinstance(h_cfg, dict) and "filename" in h_cfg:
                    candidate_log_files.append(Path(h_cfg["filename"]))

    # 2. Search common locations
    candidate_log_files.extend(
        [
            Path("logs/camellia-remote.log"),
            Path("camellia-remote.log"),
            Path("/var/log/camellia-remote/management.log"),
            Path(tempfile.gettempdir()) / "camellia-remote.log",
        ]
    )

    found_log: Path | None = None
    for cand in candidate_log_files:
        if cand.is_file():
            found_log = cand
            break

    if not found_log:
        return {
            "status": "no_logs_found",
            "reason": "No configured log file found on disk",
        }

    try:
        with open(found_log, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        tail_lines = lines[-max_lines:] if len(lines) > max_lines else lines
        sanitized_lines = [sanitize_string(line.rstrip("\r\n"), max_len=2048) for line in tail_lines]

        return {
            "status": "collected",
            "file": found_log.name,
            "total_lines_inspected": len(lines),
            "lines_collected": len(sanitized_lines),
            "lines": sanitized_lines,
        }
    except (OSError, UnicodeError) as exc:
        return {
            "status": "error",
            "file": found_log.name,
            "error": sanitize_string(str(exc)),
        }


def scan_for_canaries(
    data: bytes,
    *,
    custom_canaries: list[str] | None = None,
    active_secrets: set[str] | None = None,
) -> None:
    """Scan raw bytes for prohibited canary patterns and active secret leaks. Fail closed if matched."""
    canaries: list[str] = list(CANARY_SECRET_PATTERNS)

    if custom_canaries:
        canaries.extend(custom_canaries)

    if active_secrets:
        for s in active_secrets:
            if s and len(s) >= 4:
                canaries.append(s)

    text = data.decode("utf-8", errors="replace")

    for pat in canaries:
        if not pat:
            continue
        if pat in text:
            raise CommandError(
                f"Secondary canary scanner detected sensitive secret pattern: {pat[:16]}... (fail-closed abort)"
            )


def export_ops_diagnostics(
    *,
    output_path: Path | str | None = None,
    include_logs: bool = False,
    no_gzip: bool = False,
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES,
    max_compressed_bytes: int = MAX_COMPRESSED_BYTES,
    custom_canaries: list[str] | None = None,
    extra_files: dict[str, bytes] | None = None,
    active_secrets: set[str] | None = None,
) -> Path:
    """Generate bounded, redacted operations diagnostics package with fail-closed security guarantees."""
    if active_secrets is None:
        active_secrets = collect_active_secrets()

    # 1. Determine destination path
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    archive_ext = ".tar" if no_gzip else ".tar.gz"

    if output_path:
        target = Path(output_path).resolve()
        if target.suffix in (".tar", ".gz") or target.name.endswith(".tar.gz"):
            final_archive_path = target
            output_dir = target.parent
        else:
            output_dir = target
            final_archive_path = output_dir / f"camellia_remote_ops_diagnostics_{ts}{archive_ext}"
    else:
        output_dir = Path("diagnostics_export").resolve()
        final_archive_path = output_dir / f"camellia_remote_ops_diagnostics_{ts}{archive_ext}"

    # Ensure parent output directory exists with strict 0700 permissions
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(output_dir, 0o700)
    except OSError:
        pass

    # 2. Collect in-memory diagnostics components
    system_info = collect_system_info()
    config_audit = collect_config_audit(active_secrets=active_secrets)
    recent_logs = collect_recent_logs(include_logs=include_logs)

    sys_bytes = json.dumps(system_info, indent=2, sort_keys=True).encode("utf-8")
    cfg_bytes = json.dumps(config_audit, indent=2, sort_keys=True).encode("utf-8")
    logs_bytes = json.dumps(recent_logs, indent=2, sort_keys=True).encode("utf-8")

    files_to_pack: list[tuple[str, bytes]] = [
        ("system_info.json", sys_bytes),
        ("config_audit.json", cfg_bytes),
        ("recent_logs.jsonl", logs_bytes),
    ]

    if extra_files:
        for name, data in extra_files.items():
            files_to_pack.append((name, data))

    # 3. Check uncompressed size bound BEFORE archiving
    total_uncompressed = sum(len(content) for _, content in files_to_pack)
    if total_uncompressed > max_uncompressed_bytes:
        raise CommandError(
            f"Uncompressed diagnostics payload exceeds maximum limit of {max_uncompressed_bytes} bytes "
            f"(got {total_uncompressed})"
        )

    # 4. In-memory canary scan across all uncompressed file payloads
    for name, content in files_to_pack:
        try:
            scan_for_canaries(
                content,
                custom_canaries=custom_canaries,
                active_secrets=active_secrets,
            )
        except CommandError as exc:
            # If archive file exists, remove immediately
            if final_archive_path.exists():
                try:
                    final_archive_path.unlink()
                except OSError:
                    pass
            raise CommandError(f"In payload '{name}': {exc}") from exc

    # 5. Construct manifest
    file_manifest_entries = [
        {
            "path": name,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in files_to_pack
    ]

    manifest_data = {
        "manifest_version": "1.0",
        "collection_timestamp_utc": datetime.now(UTC).isoformat(),
        "management_version": "1.0.0",
        "django_version": django.get_version(),
        "files": file_manifest_entries,
    }
    manifest_bytes = json.dumps(manifest_data, indent=2, sort_keys=True).encode("utf-8")
    files_to_pack.insert(0, ("manifest.json", manifest_bytes))

    # 6. Build in-memory POSIX tar archive
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for entry_name, data in files_to_pack:
            ti = tarfile.TarInfo(name=entry_name)
            ti.size = len(data)
            ti.mtime = int(datetime.now(UTC).timestamp())
            ti.mode = 0o600
            ti.uname = ""
            ti.gname = ""
            ti.uid = 0
            ti.gid = 0
            tar.addfile(ti, io.BytesIO(data))

    tar_bytes = tar_buffer.getvalue()

    if len(tar_bytes) > max_uncompressed_bytes:
        raise CommandError(
            f"Uncompressed tar archive exceeds maximum limit of {max_uncompressed_bytes} bytes "
            f"(got {len(tar_bytes)})"
        )

    # Scan uncompressed tar bytes
    try:
        scan_for_canaries(
            tar_bytes,
            custom_canaries=custom_canaries,
            active_secrets=active_secrets,
        )
    except CommandError as exc:
        if final_archive_path.exists():
            try:
                final_archive_path.unlink()
            except OSError:
                pass
        raise CommandError(f"In uncompressed tar stream: {exc}") from exc

    # 7. Compress if gzip enabled
    if no_gzip:
        data_to_write = tar_bytes
    else:
        data_to_write = gzip.compress(tar_bytes, mtime=0)

    # Check compressed size bound
    if len(data_to_write) > max_compressed_bytes:
        if final_archive_path.exists():
            try:
                final_archive_path.unlink()
            except OSError:
                pass
        raise CommandError(
            f"Compressed support bundle exceeds maximum bound of {max_compressed_bytes} bytes "
            f"(got {len(data_to_write)})"
        )

    # 8. Write archive file with strict 0600 permissions
    try:
        with open(final_archive_path, "wb") as f:
            f.write(data_to_write)
        os.chmod(final_archive_path, 0o600)
    except OSError as exc:
        if final_archive_path.exists():
            try:
                final_archive_path.unlink()
            except OSError:
                pass
        raise CommandError(f"Failed to write diagnostic archive: {exc}") from exc

    # 9. Secondary Canary Scanner on disk artifact
    try:
        with open(final_archive_path, "rb") as f:
            disk_bytes = f.read()

        if no_gzip:
            scan_payload = disk_bytes
        else:
            scan_payload = gzip.decompress(disk_bytes)

        scan_for_canaries(
            scan_payload,
            custom_canaries=custom_canaries,
            active_secrets=active_secrets,
        )
    except CommandError as exc:
        if final_archive_path.exists():
            try:
                final_archive_path.unlink()
            except OSError:
                pass
        raise CommandError(f"Secondary canary scanner detected secret on disk: {exc}") from exc

    return final_archive_path


class Command(BaseCommand):
    help = "Export bounded and redacted operations diagnostics support bundle (DIAG-002, LOG-014)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--output",
            "-o",
            type=str,
            default=None,
            help="Destination directory or file path for the exported diagnostics archive.",
        )
        parser.add_argument(
            "--include-logs",
            action="store_true",
            default=False,
            help="Include sanitized recent logs in the diagnostic bundle.",
        )
        parser.add_argument(
            "--no-gzip",
            action="store_true",
            default=False,
            help="Do not gzip compress the tar archive.",
        )
        parser.add_argument(
            "--canary",
            action="append",
            default=[],
            help="Inject custom canary pattern for scanner verification.",
        )

    def handle(self, *args, **options):
        output_arg = options.get("output")
        include_logs = options.get("include_logs", False)
        no_gzip = options.get("no_gzip", False)
        canaries = options.get("canary") or []

        try:
            archive_path = export_ops_diagnostics(
                output_path=output_arg,
                include_logs=include_logs,
                no_gzip=no_gzip,
                custom_canaries=canaries,
            )
            self.stdout.write(
                self.style.SUCCESS(f"Diagnostics bundle successfully exported to: {archive_path}")
            )
        except CommandError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise CommandError(f"Export operations diagnostics failed: {exc}") from exc
