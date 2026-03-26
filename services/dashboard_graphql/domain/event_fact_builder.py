"""Build EventFacts from DynamoDB rows (port of v1 event-facts.ts)."""

from __future__ import annotations

from typing import Any

from .dynamo_scan import scan_table
from .env_tables import (
    api_calls_table,
    payment_ledger_table,
    quotes_table,
    upload_transaction_log_table,
    wallet_auth_events_table,
)
from .normalize import (
    coerce_iso_date,
    normalize_amount,
    normalize_failure_category,
    normalize_status,
)


def _str(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _str_or_number(value: Any) -> str | float | None:
    if isinstance(value, str):
        return value if value else None
    if isinstance(value, (int, float)) and value == value:
        return float(value)
    return None


def _classify_event_type(source: str, normalized_status: str, route: str | None) -> str:
    if route == "/price-storage":
        return "quote_created"
    if source == "wallet_auth":
        return "wallet_auth_failed" if normalized_status == "failed" else "wallet_auth_succeeded"
    if source == "quotes":
        return "quote_created"
    if source == "payments":
        return "payment_settle_failed" if normalized_status == "failed" else "payment_settled"
    if source == "upload_logs":
        if normalized_status == "upload_confirmed":
            return "upload_confirmed"
        if normalized_status == "failed":
            return "upload_failed"
        return "upload_started"
    if source == "api_calls":
        return "api_call_logged"
    return "lambda_invoked"


def build_event_facts_uncached(
    *,
    time_from: str | None,
    time_to: str | None,
) -> list[dict[str, Any]]:
    quotes = scan_table(quotes_table(), time_from=time_from, time_to=time_to)
    uploads = scan_table(upload_transaction_log_table(), time_from=time_from, time_to=time_to)
    payments = scan_table(payment_ledger_table(), time_from=time_from, time_to=time_to)
    auth_events = scan_table(wallet_auth_events_table(), time_from=time_from, time_to=time_to)
    api_calls = scan_table(api_calls_table(), time_from=time_from, time_to=time_to)

    events: list[dict[str, Any]] = []

    for row in quotes:
        status = normalize_status(_str(row.get("status")), _str(row.get("reason")))
        ts = (
            coerce_iso_date(row.get("created_at") or row.get("event_ts") or row.get("timestamp"))
            or ""
        )
        if not ts:
            from datetime import datetime, timezone

            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        events.append(
            {
                "eventId": f"quote:{row.get('quote_id')}:{row.get('created_at') or row.get('event_ts') or 'na'}",
                "timestamp": ts,
                "walletAddress": _str(row.get("wallet_address") or row.get("addr")),
                "quoteId": _str(row.get("quote_id")),
                "requestId": _str(row.get("request_id")),
                "network": _str(row.get("network")),
                "amountNormalized": normalize_amount(row.get("amount") or _str_or_number(row.get("storage_price"))),
                "normalizedStatus": status,
                "normalizedReason": normalize_failure_category(_str(row.get("reason")), _str(row.get("status")))
                if status == "failed"
                else None,
                "source": "quotes",
                "eventType": _classify_event_type("quotes", status, None),
                "rawStatus": _str(row.get("status")),
                "rawReason": _str(row.get("reason")),
                "isFailure": status == "failed",
                "route": None,
                "lambdaName": None,
                "transId": None,
                "idempotencyKey": None,
                "metadata": row,
            }
        )

    for row in uploads:
        ps = row.get("payment_status")
        status = (
            "upload_confirmed"
            if ps == "confirmed"
            else normalize_status(_str(row.get("status")), _str(row.get("reason")))
        )
        route = _str(row.get("route") or row.get("path"))
        lambda_name = _str(row.get("lambda_name"))
        if not lambda_name and route == "/storage/upload":
            lambda_name = "StorageUploadFunction"
        elif not lambda_name and route == "/storage/upload/confirm":
            lambda_name = "StorageUploadConfirmFunction"
        ts = (
            coerce_iso_date(row.get("event_ts") or row.get("created_at") or row.get("timestamp"))
            or ""
        )
        if not ts:
            from datetime import datetime, timezone

            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        events.append(
            {
                "eventId": f"upload:{row.get('quote_id')}:{row.get('trans_id')}",
                "timestamp": ts,
                "walletAddress": _str(row.get("wallet_address") or row.get("addr")),
                "quoteId": _str(row.get("quote_id")),
                "requestId": _str(row.get("request_id")),
                "transId": _str(row.get("trans_id")),
                "idempotencyKey": _str(row.get("idempotency_key")),
                "network": _str(row.get("network") or row.get("payment_network")),
                "amountNormalized": normalize_amount(row.get("amount") or _str_or_number(row.get("payment_amount"))),
                "normalizedStatus": status,
                "normalizedReason": normalize_failure_category(_str(row.get("reason")), _str(row.get("status")))
                if status == "failed"
                else None,
                "route": route,
                "lambdaName": lambda_name,
                "source": "upload_logs",
                "eventType": _classify_event_type("upload_logs", status, route),
                "rawStatus": _str(row.get("status")),
                "rawReason": _str(row.get("reason")),
                "isFailure": status == "failed",
                "metadata": row,
            }
        )

    for row in payments:
        status = normalize_status(
            _str(row.get("status") or row.get("payment_status")),
            _str(row.get("reason")),
        )
        ts = (
            coerce_iso_date(
                row.get("event_ts")
                or row.get("created_at")
                or row.get("payment_received_at")
                or row.get("timestamp")
            )
            or ""
        )
        if not ts:
            from datetime import datetime, timezone

            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        events.append(
            {
                "eventId": f"payment:{row.get('wallet_address')}:{row.get('quote_id')}",
                "timestamp": ts,
                "walletAddress": _str(row.get("wallet_address")),
                "quoteId": _str(row.get("quote_id")),
                "requestId": _str(row.get("request_id")),
                "network": _str(row.get("network")),
                "amountNormalized": normalize_amount(row.get("amount") or _str_or_number(row.get("storage_price"))),
                "normalizedStatus": status,
                "normalizedReason": normalize_failure_category(_str(row.get("reason")), _str(row.get("status")))
                if status == "failed"
                else None,
                "source": "payments",
                "eventType": _classify_event_type("payments", status, None),
                "rawStatus": _str(row.get("status")),
                "rawReason": _str(row.get("reason")),
                "isFailure": status == "failed",
                "route": None,
                "lambdaName": None,
                "transId": None,
                "idempotencyKey": None,
                "metadata": row,
            }
        )

    for row in auth_events:
        normalized_from_result = (
            "wallet_auth_succeeded"
            if str(row.get("result") or "").lower() == "allow"
            else "wallet_auth_failed"
        )
        status = normalize_status(normalized_from_result, _str(row.get("reason")))
        ts = (
            coerce_iso_date(row.get("event_ts") or row.get("created_at") or row.get("timestamp"))
            or ""
        )
        if not ts:
            from datetime import datetime, timezone

            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        events.append(
            {
                "eventId": f"auth:{row.get('event_id')}",
                "timestamp": ts,
                "walletAddress": _str(row.get("wallet_address")),
                "requestId": _str(row.get("request_id")),
                "normalizedStatus": status,
                "normalizedReason": normalize_failure_category(_str(row.get("reason")), _str(row.get("status")))
                if status == "failed"
                else None,
                "source": "wallet_auth",
                "eventType": _classify_event_type("wallet_auth", status, None),
                "rawStatus": _str(row.get("status")),
                "rawReason": _str(row.get("reason")),
                "isFailure": status == "failed",
                "quoteId": None,
                "route": None,
                "lambdaName": None,
                "transId": None,
                "idempotencyKey": None,
                "network": None,
                "amountNormalized": 0.0,
                "metadata": row,
            }
        )

    for row in api_calls:
        api_status_code = row.get("status_code")
        try:
            code = int(api_status_code) if api_status_code is not None else None
        except (TypeError, ValueError):
            code = None
        route = _str(row.get("route") or row.get("path"))
        is_api_failure = code is not None and code >= 400
        if route == "/price-storage":
            status = "quote_created"
        elif route == "/storage/upload":
            status = "upload_started"
        elif route == "/storage/upload/confirm":
            status = "upload_confirmed"
        elif is_api_failure:
            status = "failed"
        else:
            status = normalize_status(_str(row.get("status")), _str(row.get("reason") or row.get("error")))

        ts = (
            coerce_iso_date(row.get("event_ts") or row.get("created_at") or row.get("timestamp"))
            or ""
        )
        if not ts:
            from datetime import datetime, timezone

            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        lambda_name = row.get("lambda_name")
        lambda_str = str(lambda_name) if isinstance(lambda_name, str) else None
        events.append(
            {
                "eventId": f"api:{row.get('request_id')}",
                "timestamp": ts,
                "walletAddress": _str(row.get("wallet_address")),
                "quoteId": _str(row.get("quote_id")),
                "requestId": _str(row.get("request_id")),
                "route": route,
                "lambdaName": lambda_str,
                "normalizedStatus": status,
                "normalizedReason": normalize_failure_category(
                    _str(row.get("error") or row.get("reason")),
                    _str(row.get("status")),
                )
                if status == "failed"
                else None,
                "source": "api_calls",
                "eventType": _classify_event_type("api_calls", status, route),
                "rawStatus": _str(row.get("status")),
                "rawReason": _str(row.get("error") or row.get("reason")),
                "isFailure": status == "failed",
                "transId": None,
                "idempotencyKey": None,
                "network": None,
                "amountNormalized": 0.0,
                "metadata": row,
            }
        )

    events.sort(key=lambda e: e.get("timestamp") or "")
    return events


def event_facts_to_dashboard_events(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fact in facts:
        ns = fact.get("normalizedStatus") or "unknown"
        src = fact.get("source") or ""
        et = fact.get("eventType") or ""

        if src == "wallet_auth" and et == "wallet_auth_succeeded":
            ui_status = "success"
            severity = "info"
        else:
            if ns == "failed":
                ui_status = "error"
            elif ns == "unknown":
                ui_status = "pending"
            else:
                ui_status = "success"
            if ns == "failed":
                severity = "high"
            elif ns == "unknown":
                severity = "medium"
            else:
                severity = "info"

        meta = fact.get("metadata") or {}
        if isinstance(meta, dict):
            oid = meta.get("object_id")
            ohash = meta.get("object_id_hash")
            okey = meta.get("object_key")
        else:
            oid = ohash = okey = None

        out.append(
            {
                "id": fact.get("eventId"),
                "timestamp": fact.get("timestamp"),
                "walletAddress": fact.get("walletAddress"),
                "eventType": et,
                "source": src,
                "route": fact.get("route"),
                "lambdaName": fact.get("lambdaName"),
                "status": ui_status,
                "severity": severity,
                "normalizedStatus": ns,
                "normalizedReason": fact.get("normalizedReason"),
                "quoteId": fact.get("quoteId"),
                "objectId": str(oid) if oid else None,
                "objectIdHash": str(ohash) if ohash else None,
                "objectKey": str(okey) if okey else None,
                "transId": fact.get("transId"),
                "requestId": fact.get("requestId"),
                "idempotencyKey": fact.get("idempotencyKey"),
                "network": fact.get("network"),
                "amount": fact.get("amountNormalized"),
                "message": f"{et} from {src}",
                "metadata": meta if isinstance(meta, dict) else {},
            }
        )
    return out
