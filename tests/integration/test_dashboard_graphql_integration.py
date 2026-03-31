"""Integration-style tests for dashboard GraphQL Lambda handler (no AWS)."""

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

from dashboard_graphql.app import lambda_handler  # noqa: E402


class DashboardGraphqlHandlerIntegrationTests(unittest.TestCase):
    def test_options_graphql_returns_204(self):
        event = {
            "version": "2.0",
            "routeKey": "OPTIONS /graphql",
            "rawPath": "/graphql",
            "requestContext": {"http": {"method": "OPTIONS", "path": "/graphql", "sourceIp": "127.0.0.1"}},
        }
        resp = lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 204)
        self.assertIn("Access-Control-Allow-Origin", resp["headers"])
        self.assertEqual(resp["headers"].get("X-Content-Type-Options"), "nosniff")

    def test_post_graphql_health(self):
        event = {
            "version": "2.0",
            "routeKey": "POST /graphql",
            "rawPath": "/graphql",
            "requestContext": {"http": {"method": "POST", "path": "/graphql", "sourceIp": "127.0.0.1"}},
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"query": "{ health { ok } }"}),
            "isBase64Encoded": False,
        }
        resp = lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(resp["headers"].get("X-Content-Type-Options"), "nosniff")
        body = json.loads(resp["body"])
        self.assertTrue(body["data"]["health"]["ok"])

    def test_post_graphql_health_without_source_ip(self):
        event = {
            "version": "2.0",
            "routeKey": "POST /graphql",
            "rawPath": "/graphql",
            "requestContext": {"http": {"method": "POST", "path": "/graphql"}},
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"query": "{ health { ok } }"}),
            "isBase64Encoded": False,
        }
        resp = lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["data"]["health"]["ok"])

    def test_post_revenue_summary_with_mocked_table(self):
        fake_table = mock.Mock()
        fake_table.name = "pay"
        fake_table.query.return_value = {"Items": [{"amount": "1"}]}
        fake_resource = mock.Mock()
        fake_resource.Table.return_value = fake_table

        event = {
            "version": "2.0",
            "routeKey": "POST /graphql",
            "rawPath": "/graphql",
            "requestContext": {"http": {"method": "POST", "path": "/graphql", "sourceIp": "127.0.0.1"}},
            "headers": {"content-type": "application/json"},
            "body": json.dumps(
                {
                    "query": """
                        query($w: String!) {
                          revenueSummary(walletAddress: $w) { totalAmount confirmedPaymentCount }
                        }
                    """,
                    "variables": {"w": "0xabc0000000000000000000000000000000000000"},
                }
            ),
            "isBase64Encoded": False,
        }
        with (
            mock.patch("dashboard_graphql.schema.boto3.resource", return_value=fake_resource),
            mock.patch.dict(os.environ, {"PAYMENT_LEDGER_TABLE_NAME": "pay"}, clear=False),
        ):
            resp = lambda_handler(event, None)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertIsNone(body.get("errors"))
        self.assertEqual(body["data"]["revenueSummary"]["totalAmount"], "1.000000")
        self.assertEqual(body["data"]["revenueSummary"]["confirmedPaymentCount"], 1)
