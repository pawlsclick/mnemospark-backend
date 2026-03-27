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
    build_event_facts_uncached,
    _json_safe_metadata,
    _str_or_number,
)
from dashboard_graphql.domain.normalize import normalize_status  # noqa: E402
from dashboard_graphql.domain.payment_ledger_read import revenue_summary_for_wallet  # noqa: E402
from dashboard_graphql.domain.quote_fact_builder import build_quote_facts  # noqa: E402
from dashboard_graphql.request_context import DashboardRequestContext  # noqa: E402
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

    def test_trace_by_quote_id_uses_requested_time_range(self) -> None:
        class _TrackingDashboardContext(DashboardRequestContext):
            def __init__(self) -> None:
                super().__init__()
                self.calls: list[tuple[str | None, str | None]] = []

            def event_facts(
                self, *, time_from: str | None, time_to: str | None
            ) -> list[dict[str, object]]:
                self.calls.append((time_from, time_to))
                return []

        ctx = _TrackingDashboardContext()
        result = schema.execute_sync(
            """
            query Q($qid: String!, $tr: TimeRangeInput) {
              traceByQuoteId(quoteId: $qid, timeRange: $tr) {
                id
              }
            }
            """,
            variable_values={
                "qid": "q-123",
                "tr": {"from": "2024-01-01T00:00:00Z"},
            },
            context_value={"dashboard": ctx},
        )
        self.assertIsNone(result.errors)
        self.assertEqual(result.data["traceByQuoteId"], [])
        self.assertEqual(ctx.calls, [("2024-01-01T00:00:00Z", None)])


class DashboardNormalizeAndMetadataTests(unittest.TestCase):
    def test_payment_settle_failures_not_classified_as_settled(self) -> None:
        self.assertEqual(normalize_status("payment_settle_failed", None), "failed")
        self.assertEqual(normalize_status("payment_settle_error", None), "failed")

    def test_upload_confirm_failures_not_classified_as_confirmed(self) -> None:
        self.assertEqual(normalize_status("upload_confirm_failed", None), "failed")
        self.assertEqual(normalize_status("upload_confirmation_error", None), "failed")

    def test_quote_failures_not_classified_as_created(self) -> None:
        self.assertEqual(normalize_status("quote_failed", None), "failed")
        self.assertEqual(normalize_status("quote_error", None), "failed")

    def test_upload_started_failures_not_classified_as_started(self) -> None:
        self.assertEqual(normalize_status("upload_started_failed", None), "failed")
        self.assertEqual(normalize_status("upload_started", "internal error"), "failed")

    def test_payment_settle_success_still_settled(self) -> None:
        self.assertEqual(normalize_status("payment_settled", None), "payment_settled")

    def test_str_or_number_accepts_decimal(self) -> None:
        self.assertEqual(_str_or_number(Decimal("3.5")), 3.5)

    def test_json_safe_metadata_serializes(self) -> None:
        row = {"n": Decimal("2"), "nested": {"x": Decimal("1.25")}}
        safe = _json_safe_metadata(row)
        json.dumps(safe)
        self.assertEqual(safe, {"n": 2.0, "nested": {"x": 1.25}})

    def test_build_quote_facts_uses_event_facts_without_rescanning_api_calls(self) -> None:
        event_facts = [
            {
                "eventId": "api:r-123",
                "timestamp": "2024-01-01T00:00:00Z",
                "walletAddress": "0xabc",
                "quoteId": "q-123",
                "requestId": "r-123",
                "route": "/price-storage",
                "lambdaName": None,
                "normalizedStatus": "quote_created",
                "normalizedReason": None,
                "source": "api_calls",
                "eventType": "quote_created",
                "rawStatus": "ok",
                "rawReason": None,
                "isFailure": False,
                "transId": None,
                "idempotencyKey": None,
                "network": None,
                "amountNormalized": 0.0,
                "metadata": {
                    "object_id": "obj-1",
                    "object_id_hash": "hash-1",
                    "object_key": "key-1",
                },
            }
        ]
        with (
            mock.patch.dict("os.environ", {"API_CALLS_TABLE_NAME": "api-calls-test"}, clear=False),
            mock.patch(
                "dashboard_graphql.domain.dynamo_scan.boto3.resource",
                side_effect=AssertionError("build_quote_facts must not rescan api_calls"),
            ),
        ):
            rows = build_quote_facts(time_from=None, time_to=None, event_facts=event_facts)

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["quoteId"], "q-123")
        self.assertEqual(row["walletAddress"], "0xabc")
        self.assertEqual(row["finalStatus"], "quote_created")
        self.assertEqual(row["objectId"], "obj-1")
        self.assertEqual(row["objectIdHash"], "hash-1")
        self.assertEqual(row["objectKey"], "key-1")

    def test_build_event_facts_marks_price_storage_http_errors_as_failures(self) -> None:
        api_error_row = {
            "request_id": "r-500",
            "route": "/price-storage",
            "status_code": 500,
            "status": "ok",
            "error": "internal error",
            "event_ts": "2024-01-01T00:00:00Z",
        }
        with (
            mock.patch("dashboard_graphql.domain.event_fact_builder.quotes_table", return_value=object()),
            mock.patch(
                "dashboard_graphql.domain.event_fact_builder.upload_transaction_log_table",
                return_value=object(),
            ),
            mock.patch(
                "dashboard_graphql.domain.event_fact_builder.payment_ledger_table",
                return_value=object(),
            ),
            mock.patch(
                "dashboard_graphql.domain.event_fact_builder.wallet_auth_events_table",
                return_value=object(),
            ),
            mock.patch("dashboard_graphql.domain.event_fact_builder.api_calls_table", return_value=object()),
            mock.patch(
                "dashboard_graphql.domain.event_fact_builder.scan_table",
                side_effect=[[], [], [], [], [api_error_row]],
            ),
        ):
            facts = build_event_facts_uncached(time_from=None, time_to=None)

        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["normalizedStatus"], "failed")
        self.assertTrue(facts[0]["isFailure"])
        self.assertEqual(facts[0]["eventType"], "quote_create_failed")

    def test_build_quote_facts_does_not_mark_failed_price_storage_as_quote_created(self) -> None:
        event_facts = [
            {
                "eventId": "api:r-failed",
                "timestamp": "2024-01-01T00:00:00Z",
                "walletAddress": "0xabc",
                "quoteId": "q-failed",
                "requestId": "r-failed",
                "route": "/price-storage",
                "lambdaName": None,
                "normalizedStatus": "failed",
                "normalizedReason": "internal",
                "source": "api_calls",
                "eventType": "quote_create_failed",
                "rawStatus": "error",
                "rawReason": "internal error",
                "isFailure": True,
                "transId": None,
                "idempotencyKey": None,
                "network": None,
                "amountNormalized": 0.0,
                "metadata": {},
            }
        ]

        rows = build_quote_facts(time_from=None, time_to=None, event_facts=event_facts)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["quoteId"], "q-failed")
        self.assertFalse(row["hasQuoteCreated"])
        self.assertTrue(row["hasFailure"])
        self.assertEqual(row["finalStatus"], "failed")
