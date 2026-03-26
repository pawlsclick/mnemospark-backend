"""Strawberry GraphQL types for the dashboard API (camelCase field names)."""

from __future__ import annotations

from typing import Any

import strawberry
from strawberry.scalars import JSON


@strawberry.type
class Health:
    ok: bool


@strawberry.type
class RevenueSummary:
    wallet_address: str = strawberry.field(name="walletAddress")
    confirmed_payment_count: int = strawberry.field(name="confirmedPaymentCount")
    total_amount: str = strawberry.field(name="totalAmount")


@strawberry.type(name="DashboardEvent")
class DashboardEventGQL:
    id: str
    timestamp: str
    wallet_address: str | None = strawberry.field(name="walletAddress", default=None)
    event_type: str = strawberry.field(name="eventType")
    source: str
    route: str | None = None
    lambda_name: str | None = strawberry.field(name="lambdaName", default=None)
    status: str
    severity: str
    normalized_status: str | None = strawberry.field(name="normalizedStatus", default=None)
    normalized_reason: str | None = strawberry.field(name="normalizedReason", default=None)
    quote_id: str | None = strawberry.field(name="quoteId", default=None)
    object_id: str | None = strawberry.field(name="objectId", default=None)
    object_id_hash: str | None = strawberry.field(name="objectIdHash", default=None)
    object_key: str | None = strawberry.field(name="objectKey", default=None)
    trans_id: str | None = strawberry.field(name="transId", default=None)
    request_id: str | None = strawberry.field(name="requestId", default=None)
    idempotency_key: str | None = strawberry.field(name="idempotencyKey", default=None)
    network: str | None = None
    amount: float | None = None
    message: str
    metadata: JSON | None = None


@strawberry.type(name="WalletFacts")
class WalletFactsGQL:
    wallet_address: str = strawberry.field(name="walletAddress")
    first_seen_at: str | None = strawberry.field(name="firstSeenAt", default=None)
    last_seen_at: str | None = strawberry.field(name="lastSeenAt", default=None)
    total_quotes: int = strawberry.field(name="totalQuotes")
    total_uploads_started: int = strawberry.field(name="totalUploadsStarted")
    total_uploads_confirmed: int = strawberry.field(name="totalUploadsConfirmed")
    total_payments_settled: int = strawberry.field(name="totalPaymentsSettled")
    total_failures: int = strawberry.field(name="totalFailures")
    total_auth_failures: int = strawberry.field(name="totalAuthFailures")
    total_revenue: float = strawberry.field(name="totalRevenue")
    average_revenue_per_quote: float = strawberry.field(name="averageRevenuePerQuote")
    median_transaction_size: float = strawberry.field(name="medianTransactionSize")
    last_network: str | None = strawberry.field(name="lastNetwork", default=None)
    last_event_type: str | None = strawberry.field(name="lastEventType", default=None)


@strawberry.type(name="QuoteFact")
class QuoteFactGQL:
    quote_id: str = strawberry.field(name="quoteId")
    wallet_address: str | None = strawberry.field(name="walletAddress", default=None)
    network: str | None = None
    amount_normalized: float | None = strawberry.field(name="amountNormalized", default=None)
    has_quote_created: bool = strawberry.field(name="hasQuoteCreated")
    has_payment_settled: bool = strawberry.field(name="hasPaymentSettled")
    has_upload_started: bool = strawberry.field(name="hasUploadStarted")
    has_upload_confirmed: bool = strawberry.field(name="hasUploadConfirmed")
    has_failure: bool = strawberry.field(name="hasFailure")
    final_status: str = strawberry.field(name="finalStatus")
    first_seen_at: str | None = strawberry.field(name="firstSeenAt", default=None)
    last_seen_at: str | None = strawberry.field(name="lastSeenAt", default=None)
    object_id: str | None = strawberry.field(name="objectId", default=None)
    object_id_hash: str | None = strawberry.field(name="objectIdHash", default=None)
    object_key: str | None = strawberry.field(name="objectKey", default=None)
    failed_stage: str | None = strawberry.field(name="failedStage", default=None)


@strawberry.type
class FunnelMetricsGQL:
    quote_created: int = strawberry.field(name="quoteCreated")
    payment_settled: int = strawberry.field(name="paymentSettled")
    upload_started: int = strawberry.field(name="uploadStarted")
    upload_confirmed: int = strawberry.field(name="uploadConfirmed")
    quote_to_payment_rate: float = strawberry.field(name="quoteToPaymentRate")
    payment_to_upload_rate: float = strawberry.field(name="paymentToUploadRate")
    upload_to_confirm_rate: float = strawberry.field(name="uploadToConfirmRate")


@strawberry.type(name="SeriesPoint")
class SeriesPointGQL:
    label: str
    value: float


@strawberry.type(name="LatencyMetrics")
class LatencyMetricsGQL:
    quote_to_payment_p50: float = strawberry.field(name="quoteToPaymentP50")
    quote_to_payment_p95: float = strawberry.field(name="quoteToPaymentP95")
    payment_to_upload_p50: float = strawberry.field(name="paymentToUploadP50")
    payment_to_upload_p95: float = strawberry.field(name="paymentToUploadP95")
    upload_to_confirm_p50: float = strawberry.field(name="uploadToConfirmP50")
    upload_to_confirm_p95: float = strawberry.field(name="uploadToConfirmP95")


@strawberry.type(name="HealthScore")
class HealthScoreGQL:
    status: str
    success_rate: float = strawberry.field(name="successRate")
    error_rate: float = strawberry.field(name="errorRate")
    throughput: float
    latency_score: float = strawberry.field(name="latencyScore")


@strawberry.type(name="ObjectDuplicate")
class ObjectDuplicateGQL:
    object_id_hash: str = strawberry.field(name="objectIdHash")
    quote_count: int = strawberry.field(name="quoteCount")


@strawberry.type(name="WalletDetail")
class WalletDetailGQL:
    wallet: WalletFactsGQL | None
    quotes: list[QuoteFactGQL]
    events: list[DashboardEventGQL]


@strawberry.type(name="RootCausePanel")
class RootCausePanelGQL:
    latest_event: DashboardEventGQL | None = strawberry.field(name="latestEvent", default=None)
    first_failure_event: DashboardEventGQL | None = strawberry.field(name="firstFailureEvent", default=None)
    related_events: list[DashboardEventGQL] = strawberry.field(name="relatedEvents")
    likely_failure_category: str | None = strawberry.field(name="likelyFailureCategory", default=None)
    likely_failed_stage: str | None = strawberry.field(name="likelyFailedStage", default=None)


def dashboard_event_from_dict(d: dict[str, Any]) -> DashboardEventGQL:
    meta = d.get("metadata")
    if meta is not None and not isinstance(meta, dict):
        meta = None
    return DashboardEventGQL(
        id=str(d.get("id", "")),
        timestamp=str(d.get("timestamp", "")),
        wallet_address=d.get("walletAddress"),
        event_type=str(d.get("eventType", "")),
        source=str(d.get("source", "")),
        route=d.get("route"),
        lambda_name=d.get("lambdaName"),
        status=str(d.get("status", "")),
        severity=str(d.get("severity", "")),
        normalized_status=d.get("normalizedStatus"),
        normalized_reason=d.get("normalizedReason"),
        quote_id=d.get("quoteId"),
        object_id=d.get("objectId"),
        object_id_hash=d.get("objectIdHash"),
        object_key=d.get("objectKey"),
        trans_id=d.get("transId"),
        request_id=d.get("requestId"),
        idempotency_key=d.get("idempotencyKey"),
        network=d.get("network"),
        amount=d.get("amount"),
        message=str(d.get("message", "")),
        metadata=meta,
    )


def wallet_facts_from_dict(d: dict[str, Any]) -> WalletFactsGQL:
    return WalletFactsGQL(
        wallet_address=str(d.get("walletAddress", "")),
        first_seen_at=d.get("firstSeenAt"),
        last_seen_at=d.get("lastSeenAt"),
        total_quotes=int(d.get("totalQuotes", 0)),
        total_uploads_started=int(d.get("totalUploadsStarted", 0)),
        total_uploads_confirmed=int(d.get("totalUploadsConfirmed", 0)),
        total_payments_settled=int(d.get("totalPaymentsSettled", 0)),
        total_failures=int(d.get("totalFailures", 0)),
        total_auth_failures=int(d.get("totalAuthFailures", 0)),
        total_revenue=float(d.get("totalRevenue", 0)),
        average_revenue_per_quote=float(d.get("averageRevenuePerQuote", 0)),
        median_transaction_size=float(d.get("medianTransactionSize", 0)),
        last_network=d.get("lastNetwork"),
        last_event_type=d.get("lastEventType"),
    )


def quote_fact_from_dict(d: dict[str, Any]) -> QuoteFactGQL:
    return QuoteFactGQL(
        quote_id=str(d.get("quoteId", "")),
        wallet_address=d.get("walletAddress"),
        network=d.get("network"),
        amount_normalized=d.get("amountNormalized"),
        has_quote_created=bool(d.get("hasQuoteCreated")),
        has_payment_settled=bool(d.get("hasPaymentSettled")),
        has_upload_started=bool(d.get("hasUploadStarted")),
        has_upload_confirmed=bool(d.get("hasUploadConfirmed")),
        has_failure=bool(d.get("hasFailure")),
        final_status=str(d.get("finalStatus", "")),
        first_seen_at=d.get("firstSeenAt"),
        last_seen_at=d.get("lastSeenAt"),
        object_id=d.get("objectId"),
        object_id_hash=d.get("objectIdHash"),
        object_key=d.get("objectKey"),
        failed_stage=d.get("failedStage"),
    )
