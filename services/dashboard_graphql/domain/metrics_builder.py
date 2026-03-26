"""Aggregated metrics (port of v1 analytics/queries.ts helpers)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def safe_rate(num: float, den: float) -> float:
    if den <= 0:
        return 0.0
    return round(100.0 * num / den, 2)


def percentile(values: list[float], p: int) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[int(k)]
    return s[f] * (c - k) + s[c] * (k - f)


def quote_funnel(quote_facts: list[dict[str, Any]]) -> dict[str, Any]:
    qc = sum(1 for f in quote_facts if f.get("hasQuoteCreated"))
    ps = sum(1 for f in quote_facts if f.get("hasPaymentSettled"))
    us = sum(1 for f in quote_facts if f.get("hasUploadStarted"))
    uc = sum(1 for f in quote_facts if f.get("hasUploadConfirmed"))
    return {
        "quote_created": qc,
        "payment_settled": ps,
        "upload_started": us,
        "upload_confirmed": uc,
        "quote_to_payment_rate": safe_rate(ps, qc),
        "payment_to_upload_rate": safe_rate(us, ps),
        "upload_to_confirm_rate": safe_rate(uc, us),
    }


def quote_latency_percentiles(quote_facts: list[dict[str, Any]]) -> dict[str, float]:
    q2p: list[float] = []
    p2u: list[float] = []
    u2c: list[float] = []

    for fact in quote_facts:
        try:
            if fact.get("quoteCreatedAt") and fact.get("paymentSettledAt"):
                t0 = datetime.fromisoformat(
                    str(fact["quoteCreatedAt"]).replace("Z", "+00:00")
                ).timestamp()
                t1 = datetime.fromisoformat(
                    str(fact["paymentSettledAt"]).replace("Z", "+00:00")
                ).timestamp()
                q2p.append((t1 - t0) * 1000)
        except (TypeError, ValueError, KeyError):
            pass
        try:
            if fact.get("paymentSettledAt") and fact.get("uploadStartedAt"):
                t0 = datetime.fromisoformat(
                    str(fact["paymentSettledAt"]).replace("Z", "+00:00")
                ).timestamp()
                t1 = datetime.fromisoformat(
                    str(fact["uploadStartedAt"]).replace("Z", "+00:00")
                ).timestamp()
                p2u.append((t1 - t0) * 1000)
        except (TypeError, ValueError, KeyError):
            pass
        try:
            if fact.get("uploadStartedAt") and fact.get("uploadConfirmedAt"):
                t0 = datetime.fromisoformat(
                    str(fact["uploadStartedAt"]).replace("Z", "+00:00")
                ).timestamp()
                t1 = datetime.fromisoformat(
                    str(fact["uploadConfirmedAt"]).replace("Z", "+00:00")
                ).timestamp()
                u2c.append((t1 - t0) * 1000)
        except (TypeError, ValueError, KeyError):
            pass

    return {
        "quote_to_payment_p50": percentile(q2p, 50),
        "quote_to_payment_p95": percentile(q2p, 95),
        "payment_to_upload_p50": percentile(p2u, 50),
        "payment_to_upload_p95": percentile(p2u, 95),
        "upload_to_confirm_p50": percentile(u2c, 50),
        "upload_to_confirm_p95": percentile(u2c, 95),
    }


def failure_reason_breakdown(event_facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    m: dict[str, int] = {}
    for e in event_facts:
        if not e.get("isFailure"):
            continue
        key = str(e.get("normalizedReason") or "unknown")
        m[key] = m.get(key, 0) + 1
    return [{"label": k, "value": float(v)} for k, v in sorted(m.items(), key=lambda x: -x[1])]


def lambda_error_summary(event_facts: list[dict[str, Any]], limit: int = 50) -> list[dict[str, Any]]:
    m: dict[str, int] = {}
    for e in event_facts:
        if not e.get("isFailure"):
            continue
        ln = e.get("lambdaName")
        if not ln:
            continue
        m[str(ln)] = m.get(str(ln), 0) + 1
    items = sorted(m.items(), key=lambda x: -x[1])[:limit]
    return [{"label": k, "value": float(v)} for k, v in items]


def event_rate_per_minute(event_facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, int] = {}
    for e in event_facts:
        ts = e.get("timestamp") or ""
        if len(ts) >= 16:
            key = ts[:16]
            buckets[key] = buckets.get(key, 0) + 1
    return [{"label": k, "value": float(buckets[k])} for k in sorted(buckets.keys())]


def health_score(event_facts: list[dict[str, Any]], latency: dict[str, float]) -> dict[str, Any]:
    total = len(event_facts) or 1
    failures = sum(1 for e in event_facts if e.get("isFailure"))
    success_rate = safe_rate(total - failures, total)
    error_rate = safe_rate(failures, total)

    now = datetime.now(timezone.utc).timestamp()
    window = 60 * 60
    throughput = 0
    for e in event_facts:
        try:
            t = datetime.fromisoformat(
                str(e.get("timestamp", "")).replace("Z", "+00:00")
            ).timestamp()
            if t >= now - window:
                throughput += 1
        except (TypeError, ValueError):
            pass

    lat_ref = (
        latency.get("upload_to_confirm_p95")
        or latency.get("payment_to_upload_p95")
        or latency.get("quote_to_payment_p95")
        or 0.0
    )
    latency_score = 100.0 if lat_ref <= 0 else max(0.0, 100.0 - lat_ref / 1000.0)

    if error_rate > 20 or latency_score < 40:
        status = "red"
    elif error_rate > 8 or latency_score < 70:
        status = "yellow"
    else:
        status = "green"

    return {
        "status": status,
        "success_rate": success_rate,
        "error_rate": error_rate,
        "throughput": float(throughput),
        "latency_score": round(latency_score, 2),
    }


def status_distribution(quote_facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    m: dict[str, int] = {}
    for f in quote_facts:
        fs = str(f.get("finalStatus") or "unknown")
        m[fs] = m.get(fs, 0) + 1
    return [{"label": k, "value": float(v)} for k, v in sorted(m.items(), key=lambda x: -x[1])]


def object_duplicate_summary(quote_facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_hash: dict[str, set[str]] = {}
    for f in quote_facts:
        h = f.get("objectIdHash")
        qid = f.get("quoteId")
        if not h or not qid:
            continue
        hs = str(h)
        if hs not in by_hash:
            by_hash[hs] = set()
        by_hash[hs].add(str(qid))
    out = [
        {"object_id_hash": h, "quote_count": len(ids)}
        for h, ids in by_hash.items()
        if len(ids) > 1
    ]
    out.sort(key=lambda x: -x["quote_count"])
    return out


def idempotency_conflicts(event_facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for e in event_facts:
        k = e.get("idempotencyKey")
        if not k:
            continue
        ks = str(k)
        counts[ks] = counts.get(ks, 0) + 1
    conflicts = {k: v for k, v in counts.items() if v > 1}
    return [{"label": k, "value": float(v)} for k, v in sorted(conflicts.items(), key=lambda x: -x[1])]
