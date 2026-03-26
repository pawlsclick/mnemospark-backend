"""Unit tests for dashboard GraphQL (read-only)."""

from __future__ import annotations

import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

_SERVICES = Path(__file__).resolve().parents[2] / "services"
if str(_SERVICES) not in sys.path:
    sys.path.insert(0, str(_SERVICES))

from dashboard_graphql.domain.event_fact_builder import (  # noqa: E402
    _json_safe_metadata,
    _str_or_number,
)
from dashboard_graphql.domain.normalize import normalize_status  # noqa: E402
from dashboard_graphql.domain.payment_ledger_read import revenue_summary_for_wallet  # noqa: E402
from dashboard_graphql.schema import schema  # noqa: E402


class _FakeTable:
    def __init__(self, pages: list[dict]):
        self._pages = pages
        self._idx = 0

    def query(self, **kwargs):
        if self._idx >= len(self._pages):
            return {"Items": []}
        page = self._pages[self._idx]
        self._idx += 1
        if self._idx < len(self._pages):
            page = {**page, "LastEvaluatedKey": {"wallet_address": "0xabc", "id": str(self._idx)}}
        return page


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
        count, total = revenue_summary_for_wallet(
            table=table,
            wallet_address="0xAbCd000000000000000000000000000000000000",
        )
        self.assertEqual(count, 3)
        self.assertEqual(total, "3.750000")

    def test_revenue_summary_empty_partition(self):
        table = _FakeTable([{"Items": []}])
        count, total = revenue_summary_for_wallet(
            table=table,
            wallet_address="0xabc0000000000000000000000000000000000000",
        )
        self.assertEqual(count, 0)
        self.assertEqual(total, "0.000000")

    def test_revenue_summary_skips_invalid_amounts_in_count(self):
        table = _FakeTable(
            [
                {
                    "Items": [
                        {"amount": "1.5"},
                        {"amount": None},
                        {"amount": "not-a-number"},
                    ]
                }
            ]
        )
        count, total = revenue_summary_for_wallet(
            table=table,
            wallet_address="0xabc0000000000000000000000000000000000000",
        )
        self.assertEqual(count, 1)
        self.assertEqual(total, "1.500000")


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
                variable_values={"w": "0xabc0000000000000000000000000000000000000"},
            )
        self.assertIsNone(result.errors)
        rs = result.data["revenueSummary"]
        self.assertEqual(rs["confirmedPaymentCount"], 2)
        self.assertEqual(rs["totalAmount"], "10.500000")
        self.assertEqual(rs["walletAddress"], "0xabc0000000000000000000000000000000000000")

    def test_revenue_summary_query_returns_normalized_wallet_address(self):
        fake_table = _FakeTable(
            [{"Items": [{"amount": "1"}]}],
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
                  }
                }
                """,
                variable_values={"w": "0xABC0000000000000000000000000000000000000"},
            )
        self.assertIsNone(result.errors)
        self.assertEqual(
            result.data["revenueSummary"]["walletAddress"],
            "0xabc0000000000000000000000000000000000000",
        )

    @mock.patch("dashboard_graphql.domain.dynamo_scan.scan_table", return_value=[])
    def test_quote_funnel_empty_with_context(self, _scan: object) -> None:
        from dashboard_graphql.request_context import DashboardRequestContext

        result = schema.execute_sync(
            """
            query Q {
              quoteFunnel {
                quoteCreated
                paymentSettled
                uploadStarted
                uploadConfirmed
                quoteToPaymentRate
              }
            }
            """,
            context_value={"dashboard": DashboardRequestContext()},
        )
        self.assertIsNone(result.errors)
        qf = result.data["quoteFunnel"]
        self.assertEqual(qf["quoteCreated"], 0)
        self.assertEqual(qf["paymentSettled"], 0)


class DashboardNormalizeAndMetadataTests(unittest.TestCase):
    def test_payment_settle_failures_not_classified_as_settled(self) -> None:
        self.assertEqual(normalize_status("payment_settle_failed", None), "failed")
        self.assertEqual(normalize_status("payment_settle_error", None), "failed")

    def test_payment_settle_success_still_settled(self) -> None:
        self.assertEqual(normalize_status("payment_settled", None), "payment_settled")

    def test_str_or_number_accepts_decimal(self) -> None:
        self.assertEqual(_str_or_number(Decimal("3.5")), 3.5)

    def test_json_safe_metadata_serializes(self) -> None:
        row = {"n": Decimal("2"), "nested": {"x": Decimal("1.25")}}
        safe = _json_safe_metadata(row)
        json.dumps(safe)
        self.assertEqual(safe, {"n": 2.0, "nested": {"x": 1.25}})
