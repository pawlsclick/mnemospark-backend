"""Unit tests for dashboard GraphQL API key Lambda authorizer."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_SERVICES = Path(__file__).resolve().parents[2] / "services"
if str(_SERVICES) not in sys.path:
    sys.path.insert(0, str(_SERVICES))

from dashboard_graphql_authorizer import app as authorizer_app  # noqa: E402


class DashboardGraphqlAuthorizerTests(unittest.TestCase):
    def setUp(self) -> None:
        authorizer_app._cached_value = None  # noqa: SLF001
        authorizer_app._cache_expires_at = 0.0  # noqa: SLF001
        authorizer_app._secret_client = None  # noqa: SLF001

    def test_missing_header_denies(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x"}, clear=False):
            out = authorizer_app.lambda_handler({"headers": {}}, None)
        self.assertFalse(out["isAuthorized"])

    def test_wrong_key_denies(self):
        fake = mock.Mock()
        fake.get_secret_value.return_value = {"SecretString": "expected-secret"}
        with (
            mock.patch.dict(os.environ, {"DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x"}, clear=False),
            mock.patch.object(authorizer_app, "_client", return_value=fake),
        ):
            out = authorizer_app.lambda_handler(
                {"headers": {"x-api-key": "wrong"}},
                None,
            )
        self.assertFalse(out["isAuthorized"])

    def test_matching_key_allows(self):
        fake = mock.Mock()
        fake.get_secret_value.return_value = {"SecretString": "expected-secret"}
        with (
            mock.patch.dict(os.environ, {"DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x"}, clear=False),
            mock.patch.object(authorizer_app, "_client", return_value=fake),
        ):
            out = authorizer_app.lambda_handler(
                {"headers": {"x-api-key": "expected-secret"}},
                None,
            )
        self.assertTrue(out["isAuthorized"])

    def test_identity_source_only_allows(self):
        fake = mock.Mock()
        fake.get_secret_value.return_value = {"SecretString": "only-from-identity"}
        with (
            mock.patch.dict(os.environ, {"DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x"}, clear=False),
            mock.patch.object(authorizer_app, "_client", return_value=fake),
        ):
            out = authorizer_app.lambda_handler(
                {"headers": {}, "identitySource": ["only-from-identity"]},
                None,
            )
        self.assertTrue(out["isAuthorized"])

    def test_json_secret_with_api_key_dashboard_field(self):
        fake = mock.Mock()
        fake.get_secret_value.return_value = {
            "SecretString": json.dumps({"api_key_dashboard": "k-dashboard-field"}),
        }
        with (
            mock.patch.dict(os.environ, {"DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x"}, clear=False),
            mock.patch.object(authorizer_app, "_client", return_value=fake),
        ):
            out = authorizer_app.lambda_handler(
                {"headers": {"x-api-key": "k-dashboard-field"}},
                None,
            )
        self.assertTrue(out["isAuthorized"])

    def test_json_secret_with_api_key_field(self):
        fake = mock.Mock()
        fake.get_secret_value.return_value = {"SecretString": json.dumps({"api_key": "k-from-json"})}
        with (
            mock.patch.dict(os.environ, {"DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x"}, clear=False),
            mock.patch.object(authorizer_app, "_client", return_value=fake),
        ):
            out = authorizer_app.lambda_handler(
                {"headers": {"X-Api-Key": "k-from-json"}},
                None,
            )
        self.assertTrue(out["isAuthorized"])

    def test_no_secret_arn_denies(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN": ""}, clear=False):
            out = authorizer_app.lambda_handler(
                {"headers": {"x-api-key": "x"}},
                None,
            )
        self.assertFalse(out["isAuthorized"])
