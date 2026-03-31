"""Unit tests for common.http_response_headers."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

_SERVICES = Path(__file__).resolve().parents[2] / "services"
if str(_SERVICES) not in sys.path:
    sys.path.insert(0, str(_SERVICES))

from common.http_response_headers import rest_api_json_headers  # noqa: E402


class RestApiJsonHeadersTests(unittest.TestCase):
    def tearDown(self) -> None:
        os.environ.pop("MNEMOSPARK_CORS_ALLOW_ORIGIN", None)

    def test_defaults_star_and_nosniff(self) -> None:
        h = rest_api_json_headers()
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["Access-Control-Allow-Origin"], "*")

    def test_explicit_origin(self) -> None:
        os.environ["MNEMOSPARK_CORS_ALLOW_ORIGIN"] = "https://app.example.com"
        h = rest_api_json_headers()
        self.assertEqual(h["Access-Control-Allow-Origin"], "https://app.example.com")

    def test_empty_origin_omits_cors(self) -> None:
        os.environ["MNEMOSPARK_CORS_ALLOW_ORIGIN"] = "   "
        h = rest_api_json_headers()
        self.assertNotIn("Access-Control-Allow-Origin", h)
