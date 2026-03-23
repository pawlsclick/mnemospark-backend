"""Deterministic keys for monthly storage renewal (DynamoDB + payment ledger)."""

from __future__ import annotations

import base64
from datetime import datetime, timezone


def object_key_to_url_safe_segment(object_key: str) -> str:
    raw = object_key.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def billing_period_utc(unix_ts: int) -> str:
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return f"{dt.year:04d}-{dt.month:02d}"


def billing_period_object_key(billing_period: str, object_key: str) -> str:
    return f"{billing_period}#{object_key_to_url_safe_segment(object_key)}"


def synthetic_renewal_quote_id(billing_period: str, object_key: str) -> str:
    return f"renewal#{billing_period}#{object_key_to_url_safe_segment(object_key)}"


def wallet_period_sk(wallet_address: str, object_key: str) -> str:
    """GSI sort key: unique per wallet and object within a billing_period partition."""
    return f"{wallet_address}#{object_key_to_url_safe_segment(object_key)}"


def active_inventory_sk(bucket_name: str, object_key: str) -> str:
    return f"{bucket_name}#{object_key_to_url_safe_segment(object_key)}"
