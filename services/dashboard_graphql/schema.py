"""GraphQL schema for the internal dashboard API (read-only)."""

from __future__ import annotations

import os
from typing import Annotated, Any

import boto3
import strawberry
from strawberry.types import Info

try:
    from dashboard_graphql.dashboard_types import (
        DashboardEventGQL,
        FunnelMetricsGQL,
        Health,
        HealthScoreGQL,
        LatencyMetricsGQL,
        ObjectDuplicateGQL,
        QuoteFactGQL,
        RevenueSummary,
        RootCausePanelGQL,
        SeriesPointGQL,
        WalletDetailGQL,
        WalletFactsGQL,
        dashboard_event_from_dict,
        quote_fact_from_dict,
        wallet_facts_from_dict,
    )
    from dashboard_graphql.domain.event_fact_builder import event_facts_to_dashboard_events
    from dashboard_graphql.domain.metrics_builder import (
        failure_reason_breakdown,
        health_score,
        idempotency_conflicts,
        lambda_error_summary,
        object_duplicate_summary,
        event_rate_per_minute,
        quote_funnel,
        quote_latency_percentiles,
        status_distribution,
    )
    from dashboard_graphql.domain.payment_ledger_read import normalize_wallet_address, revenue_summary_for_wallet
    from dashboard_graphql.domain.quote_fact_builder import build_wallet_facts
    from dashboard_graphql.request_context import DashboardRequestContext
except ModuleNotFoundError as error:  # pragma: no cover
    if error.name not in ("dashboard_graphql", "dashboard_types"):
        raise
    from dashboard_types import (  # type: ignore[no-redef]
        DashboardEventGQL,
        FunnelMetricsGQL,
        Health,
        HealthScoreGQL,
        LatencyMetricsGQL,
        ObjectDuplicateGQL,
        QuoteFactGQL,
        RevenueSummary,
        RootCausePanelGQL,
        SeriesPointGQL,
        WalletDetailGQL,
        WalletFactsGQL,
        dashboard_event_from_dict,
        quote_fact_from_dict,
        wallet_facts_from_dict,
    )
    from domain.event_fact_builder import event_facts_to_dashboard_events  # type: ignore[no-redef]
    from domain.metrics_builder import (  # type: ignore[no-redef]
        failure_reason_breakdown,
        health_score,
        idempotency_conflicts,
        lambda_error_summary,
        object_duplicate_summary,
        event_rate_per_minute,
        quote_funnel,
        quote_latency_percentiles,
        status_distribution,
    )
    from domain.payment_ledger_read import normalize_wallet_address, revenue_summary_for_wallet  # type: ignore[no-redef]
    from domain.quote_fact_builder import build_wallet_facts  # type: ignore[no-redef]
    from request_context import DashboardRequestContext  # type: ignore[no-redef]


def _payment_ledger_table():
    name = os.environ.get("PAYMENT_LEDGER_TABLE_NAME", "").strip()
    if not name:
        raise RuntimeError("PAYMENT_LEDGER_TABLE_NAME is not set")
    return boto3.resource("dynamodb").Table(name)


def _dash(info: Info) -> DashboardRequestContext:
    ctx = info.context
    if isinstance(ctx, dict):
        dash = ctx.get("dashboard")
        if isinstance(dash, DashboardRequestContext):
            return dash
    raise RuntimeError("dashboard context missing")


def _time_range(tr: Any | None) -> tuple[str | None, str | None]:
    if tr is None:
        return (None, None)
    return (getattr(tr, "from_", None), getattr(tr, "to", None))


@strawberry.input
class TimeRangeInput:
    from_: str | None = strawberry.field(name="from", default=None)
    to: str | None = None


@strawberry.input
class DashboardEventFilterInput:
    wallet_address: str | None = strawberry.field(name="walletAddress", default=None)
    quote_id: str | None = strawberry.field(name="quoteId", default=None)
    request_id: str | None = strawberry.field(name="requestId", default=None)
    route: str | None = None
    lambda_name: str | None = strawberry.field(name="lambdaName", default=None)


def _trace_raw(
    info: Info,
    *,
    quote_id: str | None = None,
    request_id: str | None = None,
) -> list[dict[str, Any]]:
    ef = _dash(info).event_facts(time_from=None, time_to=None)
    mapped = event_facts_to_dashboard_events(ef)
    if quote_id:
        rows = [d for d in mapped if d.get("quoteId") == quote_id]
    elif request_id:
        rows = [d for d in mapped if d.get("requestId") == request_id]
    else:
        rows = []
    rows.sort(key=lambda x: x.get("timestamp") or "")
    return rows


def _filter_events(
    rows: list[dict[str, Any]],
    flt: DashboardEventFilterInput | None,
) -> list[dict[str, Any]]:
    if not flt:
        return rows
    out = []
    for d in rows:
        if flt.wallet_address and (d.get("walletAddress") or "").strip().lower() != flt.wallet_address.strip().lower():
            continue
        if flt.quote_id and d.get("quoteId") != flt.quote_id:
            continue
        if flt.request_id and d.get("requestId") != flt.request_id:
            continue
        if flt.route and d.get("route") != flt.route:
            continue
        if flt.lambda_name and d.get("lambdaName") != flt.lambda_name:
            continue
        out.append(d)
    return out


@strawberry.type
class Query:
    @strawberry.field
    def health(self) -> Health:
        return Health(ok=True)

    @strawberry.field(name="revenueSummary")
    def revenue_summary(
        self,
        wallet_address: Annotated[str, strawberry.argument(name="walletAddress")],
    ) -> RevenueSummary:
        w = normalize_wallet_address(wallet_address)
        if not w:
            raise ValueError("wallet_address is required")
        table = _payment_ledger_table()
        count, total = revenue_summary_for_wallet(table=table, wallet_address=w)
        return RevenueSummary(
            wallet_address=w,
            confirmed_payment_count=count,
            total_amount=total,
        )

    @strawberry.field(name="dashboardEvents")
    def dashboard_events(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
        limit: int = 2000,
        filters: DashboardEventFilterInput | None = None,
    ) -> list[DashboardEventGQL]:
        tf, tt = _time_range(time_range)
        ef = _dash(info).event_facts(time_from=tf, time_to=tt)
        mapped = event_facts_to_dashboard_events(ef)
        mapped = _filter_events(mapped, filters)
        if limit > 0:
            mapped = mapped[:limit]
        return [dashboard_event_from_dict(d) for d in mapped]

    @strawberry.field(name="walletFacts")
    def wallet_facts(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
        limit: int = 500,
    ) -> list[WalletFactsGQL]:
        tf, tt = _time_range(time_range)
        dash = _dash(info)
        ef = dash.event_facts(time_from=tf, time_to=tt)
        qf = dash.quote_facts(time_from=tf, time_to=tt)
        rows = build_wallet_facts(time_from=tf, time_to=tt, event_facts=ef, quote_facts=qf)
        if limit > 0:
            rows = rows[:limit]
        return [wallet_facts_from_dict(r) for r in rows]

    @strawberry.field(name="walletDetail")
    def wallet_detail(
        self,
        info: Info,
        wallet_address: Annotated[str, strawberry.argument(name="walletAddress")],
        time_range: TimeRangeInput | None = None,
    ) -> WalletDetailGQL:
        w = normalize_wallet_address(wallet_address)
        tf, tt = _time_range(time_range)
        dash = _dash(info)
        ef = dash.event_facts(time_from=tf, time_to=tt)
        qf = dash.quote_facts(time_from=tf, time_to=tt)
        wallets = build_wallet_facts(time_from=tf, time_to=tt, event_facts=ef, quote_facts=qf)
        wallet_row = next(
            (x for x in wallets if (x.get("walletAddress") or "").strip().lower() == w),
            None,
        )
        quotes = [q for q in qf if (q.get("walletAddress") or "").strip().lower() == w]
        dev = event_facts_to_dashboard_events(ef)
        ev_for_w = [
            d
            for d in dev
            if (d.get("walletAddress") or "").strip().lower() == w
        ]
        return WalletDetailGQL(
            wallet=wallet_facts_from_dict(wallet_row) if wallet_row else None,
            quotes=[quote_fact_from_dict(q) for q in quotes],
            events=[dashboard_event_from_dict(e) for e in ev_for_w[:500]],
        )

    @strawberry.field(name="quoteFacts")
    def quote_facts(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
        limit: int = 2000,
    ) -> list[QuoteFactGQL]:
        tf, tt = _time_range(time_range)
        rows = _dash(info).quote_facts(time_from=tf, time_to=tt)
        if limit > 0:
            rows = rows[:limit]
        return [quote_fact_from_dict(r) for r in rows]

    @strawberry.field(name="quoteFunnel")
    def quote_funnel_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> FunnelMetricsGQL:
        tf, tt = _time_range(time_range)
        qf = _dash(info).quote_facts(time_from=tf, time_to=tt)
        m = quote_funnel(qf)
        return FunnelMetricsGQL(**m)

    @strawberry.field(name="quoteLatencyPercentiles")
    def quote_latency_percentiles_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> LatencyMetricsGQL:
        tf, tt = _time_range(time_range)
        qf = _dash(info).quote_facts(time_from=tf, time_to=tt)
        m = quote_latency_percentiles(qf)
        return LatencyMetricsGQL(**m)

    @strawberry.field(name="failureReasonBreakdown")
    def failure_reason_breakdown_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> list[SeriesPointGQL]:
        tf, tt = _time_range(time_range)
        ef = _dash(info).event_facts(time_from=tf, time_to=tt)
        return [SeriesPointGQL(label=r["label"], value=r["value"]) for r in failure_reason_breakdown(ef)]

    @strawberry.field(name="lambdaErrorSummary")
    def lambda_error_summary_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
        limit: int = 50,
    ) -> list[SeriesPointGQL]:
        tf, tt = _time_range(time_range)
        ef = _dash(info).event_facts(time_from=tf, time_to=tt)
        return [
            SeriesPointGQL(label=r["label"], value=r["value"])
            for r in lambda_error_summary(ef, limit=limit)
        ]

    @strawberry.field(name="eventRatePerMinute")
    def event_rate_per_minute_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> list[SeriesPointGQL]:
        tf, tt = _time_range(time_range)
        ef = _dash(info).event_facts(time_from=tf, time_to=tt)
        return [SeriesPointGQL(label=r["label"], value=r["value"]) for r in event_rate_per_minute(ef)]

    @strawberry.field(name="healthScore")
    def health_score_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> HealthScoreGQL:
        tf, tt = _time_range(time_range)
        ef = _dash(info).event_facts(time_from=tf, time_to=tt)
        qf = _dash(info).quote_facts(time_from=tf, time_to=tt)
        lat = quote_latency_percentiles(qf)
        m = health_score(ef, lat)
        return HealthScoreGQL(**m)

    @strawberry.field(name="statusDistribution")
    def status_distribution_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> list[SeriesPointGQL]:
        tf, tt = _time_range(time_range)
        qf = _dash(info).quote_facts(time_from=tf, time_to=tt)
        return [SeriesPointGQL(label=r["label"], value=r["value"]) for r in status_distribution(qf)]

    @strawberry.field(name="objectDuplicateSummary")
    def object_duplicate_summary_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> list[ObjectDuplicateGQL]:
        tf, tt = _time_range(time_range)
        qf = _dash(info).quote_facts(time_from=tf, time_to=tt)
        return [
            ObjectDuplicateGQL(object_id_hash=r["object_id_hash"], quote_count=r["quote_count"])
            for r in object_duplicate_summary(qf)
        ]

    @strawberry.field(name="idempotencyConflicts")
    def idempotency_conflicts_field(
        self,
        info: Info,
        time_range: TimeRangeInput | None = None,
    ) -> list[SeriesPointGQL]:
        tf, tt = _time_range(time_range)
        ef = _dash(info).event_facts(time_from=tf, time_to=tt)
        return [SeriesPointGQL(label=r["label"], value=r["value"]) for r in idempotency_conflicts(ef)]

    @strawberry.field(name="traceByQuoteId")
    def trace_by_quote_id(
        self,
        info: Info,
        quote_id: Annotated[str, strawberry.argument(name="quoteId")],
    ) -> list[DashboardEventGQL]:
        rows = _trace_raw(info, quote_id=quote_id)
        return [dashboard_event_from_dict(d) for d in rows]

    @strawberry.field(name="traceByRequestId")
    def trace_by_request_id(
        self,
        info: Info,
        request_id: Annotated[str, strawberry.argument(name="requestId")],
    ) -> list[DashboardEventGQL]:
        rows = _trace_raw(info, request_id=request_id)
        return [dashboard_event_from_dict(d) for d in rows]

    @strawberry.field(name="rootCauseTrace")
    def root_cause_trace(
        self,
        info: Info,
        quote_id: str | None = None,
        request_id: str | None = None,
    ) -> RootCausePanelGQL:
        if quote_id:
            rel_dicts = _trace_raw(info, quote_id=quote_id)
        elif request_id:
            rel_dicts = _trace_raw(info, request_id=request_id)
        else:
            rel_dicts = []
        latest = max(rel_dicts, key=lambda x: x.get("timestamp") or "", default=None)
        first_fail = next((x for x in rel_dicts if x.get("status") == "error"), None)
        likely_cat = first_fail.get("normalizedReason") if first_fail else None
        et = (first_fail or {}).get("eventType") or ""
        likely_stage = (
            "payment"
            if "payment" in et
            else "confirm"
            if "confirm" in et
            else "upload"
            if "upload" in et
            else "quote"
            if "quote" in et
            else None
        )
        return RootCausePanelGQL(
            latest_event=dashboard_event_from_dict(latest) if latest else None,
            first_failure_event=dashboard_event_from_dict(first_fail) if first_fail else None,
            related_events=[dashboard_event_from_dict(d) for d in rel_dicts],
            likely_failure_category=str(likely_cat) if likely_cat else None,
            likely_failed_stage=likely_stage,
        )


schema = strawberry.Schema(query=Query)
