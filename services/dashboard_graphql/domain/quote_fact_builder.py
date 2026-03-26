"""Quote-centric facts (port of v1 quote-facts.ts)."""

from __future__ import annotations

from typing import Any

from .dynamo_scan import scan_table
from .env_tables import api_calls_table
from .event_fact_builder import build_event_facts_uncached
from .normalize import coerce_iso_date, max_iso, min_iso, normalize_failure_category


def _enrich_quote_facts_from_events(
    grouped: dict[str, dict[str, Any]], events: list[dict[str, Any]]
) -> None:
    for event in events:
        qid = event.get("quoteId")
        if not qid:
            continue
        existing = grouped.get(qid)
        if not existing:
            existing = {
                "quoteId": qid,
                "walletAddress": event.get("walletAddress"),
                "network": event.get("network"),
                "amountNormalized": event.get("amountNormalized"),
                "hasQuoteCreated": False,
                "hasPaymentSettled": False,
                "hasUploadStarted": False,
                "hasUploadConfirmed": False,
                "hasFailure": False,
                "finalStatus": "unknown",
                "requestIds": [],
                "transIds": [],
                "idempotencyKeys": [],
                "firstSeenAt": event.get("timestamp"),
                "lastSeenAt": event.get("timestamp"),
                "quoteCreatedAt": None,
                "paymentSettledAt": None,
                "uploadStartedAt": None,
                "uploadConfirmedAt": None,
                "normalizedReason": None,
                "failedStage": None,
                "objectId": None,
                "objectIdHash": None,
                "objectKey": None,
            }
            if event.get("requestId"):
                existing["requestIds"].append(event["requestId"])
            if event.get("transId"):
                existing["transIds"].append(event["transId"])
            if event.get("idempotencyKey"):
                existing["idempotencyKeys"].append(event["idempotencyKey"])
            grouped[qid] = existing

        existing = grouped[qid]
        existing["firstSeenAt"] = min_iso(existing.get("firstSeenAt"), event.get("timestamp"))
        existing["lastSeenAt"] = max_iso(existing.get("lastSeenAt"), event.get("timestamp"))
        rid = event.get("requestId")
        if rid and rid not in existing["requestIds"]:
            existing["requestIds"].append(rid)
        tid = event.get("transId")
        if tid and tid not in existing["transIds"]:
            existing["transIds"].append(tid)
        ikey = event.get("idempotencyKey")
        if ikey and ikey not in existing["idempotencyKeys"]:
            existing["idempotencyKeys"].append(ikey)

        if not existing.get("walletAddress") and event.get("walletAddress"):
            existing["walletAddress"] = event["walletAddress"]
        if not existing.get("amountNormalized") and event.get("amountNormalized"):
            existing["amountNormalized"] = event["amountNormalized"]
        if not existing.get("network") and event.get("network"):
            existing["network"] = event["network"]

        meta = event.get("metadata") or {}
        if isinstance(meta, dict):
            if not existing.get("objectIdHash") and isinstance(meta.get("object_id_hash"), str):
                existing["objectIdHash"] = meta["object_id_hash"]
            if not existing.get("objectId") and isinstance(meta.get("object_id"), str):
                existing["objectId"] = meta["object_id"]
            if not existing.get("objectKey") and isinstance(meta.get("object_key"), str):
                existing["objectKey"] = meta["object_key"]

        ns = event.get("normalizedStatus") or "unknown"
        et = event.get("eventType") or ""
        if ns == "quote_created":
            existing["hasQuoteCreated"] = True
            existing["quoteCreatedAt"] = min_iso(existing.get("quoteCreatedAt"), event.get("timestamp"))
        elif ns == "payment_settled":
            existing["hasPaymentSettled"] = True
            existing["paymentSettledAt"] = min_iso(existing.get("paymentSettledAt"), event.get("timestamp"))
        elif ns == "upload_started":
            existing["hasUploadStarted"] = True
            existing["uploadStartedAt"] = min_iso(existing.get("uploadStartedAt"), event.get("timestamp"))
        elif ns == "upload_confirmed":
            existing["hasUploadConfirmed"] = True
            existing["uploadConfirmedAt"] = min_iso(existing.get("uploadConfirmedAt"), event.get("timestamp"))
        elif ns == "failed":
            existing["hasFailure"] = True
            if not existing.get("normalizedReason"):
                existing["normalizedReason"] = event.get("normalizedReason") or normalize_failure_category(
                    event.get("rawReason"), event.get("rawStatus")
                )
                stage = (
                    "payment"
                    if "payment" in et
                    else "confirm"
                    if "confirm" in et
                    else "upload"
                    if "upload" in et
                    else "quote"
                    if "quote" in et
                    else "unknown"
                )
                if not existing.get("failedStage"):
                    existing["failedStage"] = stage

    for fact in grouped.values():
        if fact.get("hasUploadConfirmed"):
            fact["finalStatus"] = "upload_confirmed"
        elif fact.get("hasUploadStarted"):
            fact["finalStatus"] = "upload_started"
        elif fact.get("hasPaymentSettled"):
            fact["finalStatus"] = "payment_settled"
        elif fact.get("hasQuoteCreated"):
            fact["finalStatus"] = "quote_created"
        if fact.get("hasFailure") and not fact.get("hasUploadConfirmed"):
            fact["finalStatus"] = "failed"


def build_quote_facts(
    *,
    time_from: str | None,
    time_to: str | None,
    event_facts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    events = event_facts if event_facts is not None else build_event_facts_uncached(
        time_from=time_from, time_to=time_to
    )
    price_storage_calls = scan_table(
        api_calls_table(),
        time_from=time_from,
        time_to=time_to,
        route="/price-storage",
    )

    grouped: dict[str, dict[str, Any]] = {}

    for call in price_storage_calls:
        qid = call.get("quote_id")
        if not qid:
            continue
        qid_s = str(qid)
        call_ts = (
            coerce_iso_date(
                call.get("event_ts")
                or call.get("created_at")
                or call.get("timestamp")
            )
            or ""
        )
        if not call_ts:
            from datetime import datetime, timezone

            call_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        grouped[qid_s] = {
            "quoteId": qid_s,
            "walletAddress": call.get("wallet_address"),
            "hasQuoteCreated": True,
            "quoteCreatedAt": call_ts,
            "firstSeenAt": call_ts,
            "lastSeenAt": call_ts,
            "hasPaymentSettled": False,
            "hasUploadStarted": False,
            "hasUploadConfirmed": False,
            "hasFailure": False,
            "finalStatus": "quote_created",
            "requestIds": [call["request_id"]] if call.get("request_id") else [],
            "transIds": [],
            "idempotencyKeys": [],
            "objectId": call.get("object_id") if isinstance(call.get("object_id"), str) else None,
            "objectIdHash": call.get("object_id_hash") if isinstance(call.get("object_id_hash"), str) else None,
            "objectKey": call.get("object_key") if isinstance(call.get("object_key"), str) else None,
            "network": None,
            "amountNormalized": None,
            "normalizedReason": None,
            "failedStage": None,
            "paymentSettledAt": None,
            "uploadStartedAt": None,
            "uploadConfirmedAt": None,
        }

    _enrich_quote_facts_from_events(grouped, events)

    facts = list(grouped.values())
    facts.sort(key=lambda f: (f.get("lastSeenAt") or ""), reverse=True)
    return facts


def build_wallet_facts(
    *,
    time_from: str | None,
    time_to: str | None,
    event_facts: list[dict[str, Any]] | None = None,
    quote_facts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    from .event_fact_builder import event_facts_to_dashboard_events

    ef = event_facts if event_facts is not None else build_event_facts_uncached(
        time_from=time_from, time_to=time_to
    )
    quotes = (
        quote_facts
        if quote_facts is not None
        else build_quote_facts(time_from=time_from, time_to=time_to, event_facts=ef)
    )
    events = ef
    dashboard_events = event_facts_to_dashboard_events(events)

    grouped: dict[str, dict[str, Any]] = {}
    revenue_by_wallet: dict[str, list[float]] = {}

    for q in quotes:
        w = q.get("walletAddress")
        if not w or not isinstance(w, str):
            continue
        nw = w.strip().lower()
        if not nw:
            continue
        existing = grouped.get(nw) or {
            "walletAddress": w.strip(),
            "firstSeenAt": q.get("firstSeenAt"),
            "lastSeenAt": q.get("lastSeenAt"),
            "totalQuotes": 0,
            "totalUploadsStarted": 0,
            "totalUploadsConfirmed": 0,
            "totalPaymentsSettled": 0,
            "totalFailures": 0,
            "totalAuthFailures": 0,
            "totalRevenue": 0.0,
            "averageRevenuePerQuote": 0.0,
            "medianTransactionSize": 0.0,
            "lastNetwork": q.get("network"),
            "lastEventType": q.get("finalStatus"),
        }
        existing["totalQuotes"] += 1 if q.get("hasQuoteCreated") else 0
        existing["totalUploadsStarted"] += 1 if q.get("hasUploadStarted") else 0
        existing["totalUploadsConfirmed"] += 1 if q.get("hasUploadConfirmed") else 0
        existing["totalPaymentsSettled"] += 1 if q.get("hasPaymentSettled") else 0
        existing["totalFailures"] += 1 if q.get("hasFailure") else 0
        if q.get("hasPaymentSettled") and q.get("amountNormalized"):
            existing["totalRevenue"] = float(existing.get("totalRevenue", 0)) + float(
                q["amountNormalized"]
            )
            revenue_by_wallet.setdefault(nw, []).append(float(q["amountNormalized"]))
        existing["firstSeenAt"] = min_iso(existing.get("firstSeenAt"), q.get("firstSeenAt"))
        existing["lastSeenAt"] = max_iso(existing.get("lastSeenAt"), q.get("lastSeenAt"))
        if q.get("network"):
            existing["lastNetwork"] = q["network"]
        existing["lastEventType"] = q.get("finalStatus")
        grouped[nw] = existing

    for ev in dashboard_events:
        w = ev.get("walletAddress")
        if not w:
            continue
        nw = w.strip().lower()
        if not nw:
            continue
        if ev.get("eventType") == "wallet_auth_failed":
            existing = grouped.get(nw)
            if existing:
                existing["totalAuthFailures"] = int(existing.get("totalAuthFailures", 0)) + 1
                existing["lastSeenAt"] = max_iso(existing.get("lastSeenAt"), ev.get("timestamp"))
                if ev.get("network"):
                    existing["lastNetwork"] = ev["network"]
                existing["lastEventType"] = ev.get("eventType")
            else:
                grouped[nw] = {
                    "walletAddress": w.strip(),
                    "firstSeenAt": ev.get("timestamp"),
                    "lastSeenAt": ev.get("timestamp"),
                    "totalQuotes": 0,
                    "totalUploadsStarted": 0,
                    "totalUploadsConfirmed": 0,
                    "totalPaymentsSettled": 0,
                    "totalFailures": 0,
                    "totalAuthFailures": 1,
                    "totalRevenue": 0.0,
                    "averageRevenuePerQuote": 0.0,
                    "medianTransactionSize": 0.0,
                    "lastEventType": ev.get("eventType"),
                    "lastNetwork": ev.get("network"),
                }

    wallets = list(grouped.values())
    for wallet in wallets:
        tq = max(int(wallet.get("totalQuotes", 0)), 1)
        wallet["averageRevenuePerQuote"] = float(wallet.get("totalRevenue", 0)) / tq
        addr = wallet.get("walletAddress") or ""
        key = addr.strip().lower()
        amounts = revenue_by_wallet.get(key, [])
        if amounts:
            sorted_a = sorted(amounts)
            mid = len(sorted_a) // 2
            if len(sorted_a) % 2 == 0:
                wallet["medianTransactionSize"] = (sorted_a[mid - 1] + sorted_a[mid]) / 2
            else:
                wallet["medianTransactionSize"] = sorted_a[mid]
        else:
            wallet["medianTransactionSize"] = 0.0

    wallets.sort(key=lambda x: float(x.get("totalRevenue", 0)), reverse=True)
    return wallets
