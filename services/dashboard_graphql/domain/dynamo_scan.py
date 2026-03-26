"""Full table scans with optional time range and route filter (v1 dynamodb.ts)."""

from __future__ import annotations

import logging
from typing import Any

import boto3

from .normalize import coerce_iso_date

logger = logging.getLogger(__name__)


def _comparable_timestamp(item: dict[str, Any]) -> str | None:
    for key in ("event_ts", "created_at", "timestamp", "updated_at", "ts"):
        val = item.get(key)
        if val is None:
            continue
        iso = coerce_iso_date(val)
        if iso:
            return iso
    return None


def _in_time_range(item: dict[str, Any], time_from: str | None, time_to: str | None) -> bool:
    if not time_from and not time_to:
        return True
    ts = _comparable_timestamp(item)
    if not ts:
        return True
    if time_from and ts < time_from:
        return False
    if time_to and ts > time_to:
        return False
    return True


def scan_table(
    table_name: str,
    *,
    time_from: str | None = None,
    time_to: str | None = None,
    route: str | None = None,
) -> list[dict[str, Any]]:
    if not table_name:
        return []
    table = boto3.resource("dynamodb").Table(table_name)
    rows: list[dict[str, Any]] = []
    last_key: dict[str, Any] | None = None

    filter_parts: list[str] = []
    expr_names: dict[str, str] = {}
    expr_vals: dict[str, Any] = {}

    if route:
        filter_parts.append("(#route = :route OR #path = :route)")
        expr_names["#route"] = "route"
        expr_names["#path"] = "path"
        expr_vals[":route"] = route

    while True:
        kwargs: dict[str, Any] = {}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        if filter_parts:
            kwargs["FilterExpression"] = " AND ".join(filter_parts)
        if expr_names:
            kwargs["ExpressionAttributeNames"] = expr_names
        if expr_vals:
            kwargs["ExpressionAttributeValues"] = expr_vals

        try:
            response = table.scan(**kwargs)
        except Exception:
            logger.warning("Unable to scan table %s", table_name, exc_info=True)
            break

        for item in response.get("Items", []):
            if _in_time_range(item, time_from, time_to):
                rows.append(item)
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break

    return rows
