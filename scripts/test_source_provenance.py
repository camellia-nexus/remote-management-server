"""Unit tests for management source provenance semantic validation."""

from __future__ import annotations

import unittest
from pathlib import Path

from validate_source_provenance import (
    ProvenanceError,
    validate_document,
    validate_repository,
)

REPOSITORY = Path(__file__).resolve().parent.parent
COMMIT = "a" * 40


def canonical_document(commit: object = COMMIT) -> dict[str, object]:
    return {
        "schema_version": 1,
        "component": "camellia-remote-management-server",
        "source_repository": "https://github.com/XavierAlpha/camellia-api-server",
        "source_commit": commit,
        "history_policy": "fresh-root-snapshot",
        "production_database": "PostgreSQL 18",
        "license": "AGPL-3.0-only",
    }


class SourceProvenanceTests(unittest.TestCase):
    def test_repository_matches_provenance(self) -> None:
        validate_repository(REPOSITORY, expected_component="camellia-remote-management-server")

    def test_accepts_exact_canonical_source(self) -> None:
        validate_document(
            canonical_document(),
            expected_component="camellia-remote-management-server",
        )

    def test_rejects_missing_or_invalid_schema_version(self) -> None:
        for bad_schema in (2, 0, "1", None):
            doc = {**canonical_document(), "schema_version": bad_schema}
            with self.subTest(schema_version=bad_schema):
                with self.assertRaises(ProvenanceError):
                    validate_document(doc)

    def test_rejects_invalid_or_mismatched_component(self) -> None:
        doc = {**canonical_document(), "component": "unknown-component"}
        with self.assertRaises(ProvenanceError):
            validate_document(doc)

        with self.assertRaises(ProvenanceError):
            validate_document(
                canonical_document(),
                expected_component="camellia-remote-client",
            )

    def test_rejects_malformed_source_repository(self) -> None:
        bad_urls = (
            "http://github.com/user/repo",
            "git@github.com:user/repo.git",
            "https://gitlab.com/user/repo",
            "https://github.com/user",
            "https://github.com/user/repo/extra",
            "https://user:pass@github.com/user/repo",
            "https://github.com/user/../repo",
        )
        for bad_url in bad_urls:
            doc = {**canonical_document(), "source_repository": bad_url}
            with self.subTest(bad_url=bad_url):
                with self.assertRaises(ProvenanceError):
                    validate_document(doc)

    def test_rejects_malformed_source_commit(self) -> None:
        bad_commits = (
            "123456",
            "A" * 40,
            "g" * 40,
            COMMIT[:39],
            COMMIT + "a",
            12345,
        )
        for bad_commit in bad_commits:
            doc = {**canonical_document(), "source_commit": bad_commit}
            with self.subTest(bad_commit=bad_commit):
                with self.assertRaises(ProvenanceError):
                    validate_document(doc)

    def test_rejects_invalid_history_policy_or_license(self) -> None:
        doc_bad_policy = {**canonical_document(), "history_policy": "full-linear-import"}
        with self.assertRaises(ProvenanceError):
            validate_document(doc_bad_policy)

        doc_bad_license = {**canonical_document(), "license": "MIT"}
        with self.assertRaises(ProvenanceError):
            validate_document(doc_bad_license)

    def test_rejects_unknown_fields(self) -> None:
        doc = {**canonical_document(), "unexpected_extra_field": "injected"}
        with self.assertRaises(ProvenanceError):
            validate_document(doc)

    def test_production_database_constraints(self) -> None:
        doc_missing = canonical_document()
        del doc_missing["production_database"]
        with self.assertRaises(ProvenanceError):
            validate_document(doc_missing)

        doc_empty = {**canonical_document(), "production_database": ""}
        with self.assertRaises(ProvenanceError):
            validate_document(doc_empty)


if __name__ == "__main__":
    unittest.main()
