"""Port of v1 dashboard normalizers (analytics/normalizers.ts)."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

DEFAULT_AMOUNT_DECIMALS = 1_000_000


def normalize_amount(value: Any, decimals: int = DEFAULT_AMOUNT_DECIMALS) -> float:
    if value is None:
        return 0.0
    try:
        if isinstance(value, Decimal):
            parsed = float(value)
        elif isinstance(value, (int, float)):
            parsed = float(value)
        else:
            parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0
    if not (parsed == parsed):  # NaN
        return 0.0
    return parsed / decimals


def coerce_iso_date(value: Any) -> str | None:
    if value is None:
        return None
    as_string = str(value).strip()
    if not as_string:
        return None
    if re.match(r"^\d+(\.\d+)?$", as_string):
        try:
            raw = float(as_string)
        except ValueError:
            return None
        whole_part = as_string.split(".")[0]
        millis = raw * 1000 if len(whole_part) <= 10 else raw
        from datetime import datetime, timezone

        d = datetime.fromtimestamp(millis / 1000.0, tz=timezone.utc)
        return d.isoformat().replace("+00:00", "Z")
    from datetime import datetime

    try:
        d = datetime.fromisoformat(as_string.replace("Z", "+00:00"))
        return d.isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def normalize_status(raw_status: str | None, raw_reason: str | None) -> str:
    status = (raw_status or "").lower()
    reason = (raw_reason or "").lower()
    status_looks_failed = any(
        x in status for x in ("error", "fail", "revert", "denied")
    )

    if any(x in status for x in ("quote", "priced", "price_storage")) and not status_looks_failed:
        return "quote_created"

    if (
        "confirm_transaction_log_written" in status
        or "upload_confirmed" in status
        or ("upload" in status and "confirm" in status)
    ) and not status_looks_failed:
        return "upload_confirmed"

    # "payment_settle" alone matches failure strings like payment_settle_failed; require
    # no failure tokens before treating as a settled payment.
    payment_settle_positive = "payment_settle" in status and not any(
        x in status for x in ("fail", "error", "revert", "denied")
    )
    settled_looks_positive = (
        ("settled" in status and "unsettled" not in status)
        or payment_settle_positive
        or "payment_success" in status
        or "already_settled" in status
        or (
            "payment" in status
            and "confirm" in status
            and "upload" not in status
        )
        or status == "confirmed"
    )
    if settled_looks_positive:
        return "payment_settled"

    if (
        "transaction_log_written" in status
        or "upload_started" in status
        or "upload_initiated" in status
    ):
        return "upload_started"

    if status_looks_failed or any(
        x in reason for x in ("error", "fail", "revert", "denied")
    ):
        return "failed"

    return "unknown"


def normalize_failure_category(
    raw_reason: str | None, raw_status: str | None
) -> str:
    value = f"{raw_status or ''} {raw_reason or ''}".lower()
    if any(x in value for x in ("auth", "signature", "wallet_proof")):
        return "auth"
    if any(x in value for x in ("payment", "settle", "usdc")):
        return "payment"
    if any(x in value for x in ("upload", "transaction_log_written")):
        return "upload"
    if "confirm" in value:
        return "confirm"
    if any(x in value for x in ("storage", "s3", "object")):
        return "storage"
    if any(x in value for x in ("validation", "schema", "required")):
        return "validation"
    return "unknown"


def min_iso(a: str | None, b: str | None) -> str | None:
    if not a:
        return b
    if not b:
        return a
    return a if a < b else b


def max_iso(a: str | None, b: str | None) -> str | None:
    if not a:
        return b
    if not b:
        return a
    return a if a > b else b
