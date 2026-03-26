"""Unit tests for dashboard GraphQL (read-only)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

_SERVICES = Path(__file__).resolve().parents[2] / "services"
if str(_SERVICES) not in sys.path:
    sys.path.insert(0, str(_SERVICES))

from dashboard_graphql.domain.payment_ledger_read import revenue_summary_for_wallet  # noqa: E402
from dashboard_graphql.schema import schema  # noqa: E402


class _FakePaginator:
    def __init__(self, pages: list[dict]):
        self._pages = pages

    def paginate(self, **kwargs):
        yield from self._pages


class _FakeClient:
    def __init__(self, pages: list[dict]):
        self._pages = pages

    def get_paginator(self, name: str):
        assert name == "query"
        return _FakePaginator(self._pages)


class _FakeMeta:
    def __init__(self, pages: list[dict]):
        self.client = _FakeClient(pages)


class _FakeTable:
    def __init__(self, pages: list[dict]):
        self.name = "payments-test"
        self.meta = _FakeMeta(pages)


class DashboardGraphqlDomainTests(unittest.TestCase):
    def test_revenue_summary_sums_confirmed(self):
        table = _FakeTable(
            [
                {
                    "Items": [
                        {"amount": "1.5"},
                        {"amount": "2"},
                    ]
                },
                {"Items": [{"amount": "0.25"}]},
            ]
        )
        count, total = revenue_summary_for_wallet(table=table, wallet_address="0xAbC")
        self.assertEqual(count, 3)
        self.assertEqual(total, "3.750000")

    def test_revenue_summary_empty_partition(self):
        table = _FakeTable([{"Items": []}])
        count, total = revenue_summary_for_wallet(table=table, wallet_address="0xabc")
        self.assertEqual(count, 0)
        self.assertEqual(total, "0.000000")


class DashboardGraphqlSchemaTests(unittest.TestCase):
    def test_health_query(self):
        result = schema.execute_sync("{ health { ok } }")
        self.assertIsNone(result.errors)
        self.assertTrue(result.data["health"]["ok"])

    def test_revenue_summary_query(self):
        fake_table = _FakeTable(
            [{"Items": [{"amount": "10"}, {"amount": "0.5"}]}],
        )
        fake_resource = mock.Mock()
        fake_resource.Table.return_value = fake_table

        with (
            mock.patch("dashboard_graphql.schema.boto3.resource", return_value=fake_resource),
            mock.patch.dict("os.environ", {"PAYMENT_LEDGER_TABLE_NAME": "payments-test"}, clear=False),
        ):
            result = schema.execute_sync(
                """
                query Q($w: String!) {
                  revenueSummary(walletAddress: $w) {
                    walletAddress
                    confirmedPaymentCount
                    totalAmount
                  }
                }
                """,
                variable_values={"w": "0xabc"},
            )
        self.assertIsNone(result.errors)
        rs = result.data["revenueSummary"]
        self.assertEqual(rs["confirmedPaymentCount"], 2)
        self.assertEqual(rs["totalAmount"], "10.500000")
        self.assertEqual(rs["walletAddress"], "0xabc")
