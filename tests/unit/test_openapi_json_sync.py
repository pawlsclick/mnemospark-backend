"""Ensure both OpenAPI JSON copies stay in sync."""

from __future__ import annotations

import unittest
from pathlib import Path


class OpenApiJsonSyncTests(unittest.TestCase):
    def test_repo_docs_and_service_docs_match(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        repo_docs = repo_root / "docs" / "openapi.json"
        service_docs = repo_root / "services" / "docs" / "openapi.json"

        self.assertEqual(
            repo_docs.read_text(encoding="utf-8"),
            service_docs.read_text(encoding="utf-8"),
            "docs/openapi.json and services/docs/openapi.json must stay identical.",
        )
