"""
Scheduled Lambda: relayer wallet aggregates, health/runway, SNS alerts.

Triggered by EventBridge. See dev_docs/feature/base_relayer_monitoring_plan.md.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import ClientError
from web3 import Web3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

RELAYER_TX_TABLE_ENV = "RELAYER_TRANSACTIONS_TABLE_NAME"
RELAYER_STATS_TABLE_ENV = "RELAYER_STATS_TABLE_NAME"
RELAYER_HEALTH_TABLE_ENV = "RELAYER_HEALTH_TABLE_NAME"
WALLET_ENV = "MNEMOSPARK_RELAYER_WALLET_ADDRESS"
RPC_ENV = "MNEMOSPARK_BASE_RPC_URL"
TOPIC_ARN_ENV = "RELAYER_ALERTS_TOPIC_ARN"

HEALTH_SK = "HEALTH#LATEST"


@dataclass(frozen=True)
class ParsedTx:
    confirmed_at: datetime
    fee_wei: int
    gas_used: int


def normalize_wallet(address: str) -> str:
    raw = (address or "").strip()
    if not raw.startswith("0x") or len(raw) != 42:
        raise ValueError("invalid wallet address")
    return "0x" + raw[2:].lower()


def stats_partition_key(wallet_norm: str, period_type: str, period_value: str) -> str:
    return f"WALLET#{wallet_norm}#PERIOD#{period_type}#{period_value}"


def classify_runway_status(estimated_days: float | None) -> str:
    if estimated_days is None:
        return "ok"
    if estimated_days >= 3:
        return "ok"
    if estimated_days >= 1:
        return "warning"
    return "critical"


def parse_confirmed_at(raw: str | None) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def parse_tx_item(item: dict[str, Any]) -> ParsedTx | None:
    confirmed_raw = item.get("confirmedAt")
    if isinstance(confirmed_raw, str):
        dt = parse_confirmed_at(confirmed_raw)
    else:
        dt = None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        fee = int(str(item.get("feePaidWei", "0")))
        gas = int(str(item.get("gasUsed", "0")))
    except (TypeError, ValueError):
        return None
    return ParsedTx(confirmed_at=dt, fee_wei=fee, gas_used=gas)


def _period_labels(now: datetime) -> tuple[tuple[str, str], tuple[str, str], tuple[str, str]]:
    d = now.date()
    day_val = d.isoformat()
    iso = now.isocalendar()
    week_val = f"{iso.year}-W{iso.week:02d}"
    month_val = d.strftime("%Y-%m")
    return ("DAY", day_val), ("WEEK", week_val), ("MONTH", month_val)


def _in_day(tx_dt: datetime, day: datetime.date) -> bool:
    return tx_dt.astimezone(timezone.utc).date() == day


def _in_iso_week(tx_dt: datetime, year: int, week: int) -> bool:
    iso = tx_dt.astimezone(timezone.utc).isocalendar()
    return iso.year == year and iso.week == week


def _in_month(tx_dt: datetime, year: int, month: int) -> bool:
    t = tx_dt.astimezone(timezone.utc)
    return t.year == year and t.month == month


def _aggregate_for_period(
    txs: list[ParsedTx],
    now: datetime,
    period_type: str,
    period_value: str,
) -> dict[str, Any] | None:
    d = now.date()

    filtered: list[ParsedTx] = []
    for tx in txs:
        if period_type == "DAY" and _in_day(tx.confirmed_at, d):
            filtered.append(tx)
        elif period_type == "WEEK":
            py, pw = period_value.split("-W")
            if _in_iso_week(tx.confirmed_at, int(py), int(pw)):
                filtered.append(tx)
        elif period_type == "MONTH":
            py, pm = period_value.split("-")
            if _in_month(tx.confirmed_at, int(py), int(pm)):
                filtered.append(tx)

    if not filtered:
        return None
    n = len(filtered)
    total_fee = sum(t.fee_wei for t in filtered)
    total_gas = sum(t.gas_used for t in filtered)
    avg_fee = total_fee // n if n else 0
    updated = now.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    return {
        "txCount": n,
        "successCount": n,
        "revertCount": 0,
        "totalGasUsed": str(total_gas),
        "totalFeePaidWei": str(total_fee),
        "avgFeePaidWei": str(avg_fee),
        "updatedAt": updated,
    }


def _rolling_7d(txs: list[ParsedTx], now: datetime) -> tuple[int, int]:
    cutoff = now - timedelta(days=7)
    fees: list[ParsedTx] = [t for t in txs if t.confirmed_at >= cutoff]
    if not fees:
        return 0, 0
    return len(fees), sum(t.fee_wei for t in fees)


def _estimate_runway_days(balance_wei: int, tx_count_7d: int, fee_total_7d: int) -> float | None:
    if balance_wei <= 0:
        return 0.0
    if tx_count_7d <= 0 or fee_total_7d <= 0:
        return None
    avg_daily_tx = tx_count_7d / 7.0
    avg_fee_per_tx = fee_total_7d / tx_count_7d
    est_daily_spend = avg_daily_tx * avg_fee_per_tx
    if est_daily_spend <= 0:
        return None
    return balance_wei / est_daily_spend


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    wallet_raw = os.environ.get(WALLET_ENV, "").strip()
    rpc = os.environ.get(RPC_ENV, "").strip()
    tx_table = os.environ.get(RELAYER_TX_TABLE_ENV, "").strip()
    stats_table = os.environ.get(RELAYER_STATS_TABLE_ENV, "").strip()
    health_table = os.environ.get(RELAYER_HEALTH_TABLE_ENV, "").strip()
    topic_arn = os.environ.get(TOPIC_ARN_ENV, "").strip()

    if not wallet_raw or not rpc or not tx_table or not stats_table or not health_table:
        logger.warning(
            "base_relayer_monitor_skip_missing_env",
            extra={"message": "Missing wallet, RPC, or table env; exiting."},
        )
        return {"ok": True, "skipped": True}

    try:
        wallet = normalize_wallet(wallet_raw)
    except ValueError:
        logger.exception("base_relayer_monitor_invalid_wallet")
        return {"ok": False, "error": "invalid_wallet"}

    pk = f"WALLET#{wallet}"
    ddb = boto3.resource("dynamodb")
    tx_tbl = ddb.Table(tx_table)

    items: list[dict[str, Any]] = []
    try:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": "pk = :pk",
            "ExpressionAttributeValues": {":pk": pk},
        }
        while True:
            resp = tx_tbl.query(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
    except ClientError:
        logger.exception("base_relayer_monitor_query_failed")
        raise

    parsed = [p for p in (parse_tx_item(i) for i in items) if p is not None]
    now = datetime.now(timezone.utc)

    stats_tbl = ddb.Table(stats_table)
    for period_type, period_value in _period_labels(now):
        agg = _aggregate_for_period(parsed, now, period_type, period_value)
        if agg is None:
            continue
        spk = stats_partition_key(wallet, period_type, period_value)
        try:
            stats_tbl.put_item(Item={"pk": spk, **agg})
        except ClientError:
            logger.exception("base_relayer_monitor_stats_write_failed", extra={"pk": spk})
            raise

    count_7d, fee_7d = _rolling_7d(parsed, now)
    avg_fee_per_tx = fee_7d // count_7d if count_7d else 0
    avg_tx_per_day = count_7d / 7.0

    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 25}))
    if not w3.is_connected():
        logger.error("base_relayer_monitor_rpc_unreachable")
        raise RuntimeError("Unable to connect to Base RPC endpoint")

    balance_wei = int(w3.eth.get_balance(Web3.to_checksum_address(wallet)))
    est_days = _estimate_runway_days(balance_wei, count_7d, fee_7d)
    status = classify_runway_status(est_days)

    health_item: dict[str, Any] = {
        "pk": pk,
        "sk": HEALTH_SK,
        "ethBalanceWei": str(balance_wei),
        "avgFeePerTxWei_7d": str(avg_fee_per_tx),
        "avgTxPerDay_7d": Decimal(str(round(avg_tx_per_day, 6))),
        "status": status,
        "updatedAt": now.strftime("%Y-%m-%dT%H:%M:%S") + "Z",
    }
    if est_days is None:
        health_item["estimatedDaysRemaining"] = Decimal("-1")
    else:
        health_item["estimatedDaysRemaining"] = Decimal(str(round(est_days, 4)))

    health_tbl = ddb.Table(health_table)
    try:
        health_tbl.put_item(Item=health_item)
    except ClientError:
        logger.exception("base_relayer_monitor_health_write_failed")
        raise

    if topic_arn and status in ("warning", "critical"):
        sns = boto3.client("sns")
        payload = {
            "status": status,
            "wallet": wallet,
            "ethBalanceWei": str(balance_wei),
            "estimatedDaysRemaining": float(health_item["estimatedDaysRemaining"]),
            "avgTxPerDay_7d": avg_tx_per_day,
            "avgFeePerTxWei_7d": str(avg_fee_per_tx),
        }
        try:
            sns.publish(
                TopicArn=topic_arn,
                Subject=f"[mnemospark] Relayer {status.upper()}",
                Message=json.dumps(payload, indent=2),
            )
        except ClientError:
            logger.exception("base_relayer_monitor_sns_publish_failed")
            raise

    logger.info(
        "base_relayer_monitor_complete",
        extra={"status": status, "tx_count_7d": count_7d, "balance_wei": balance_wei},
    )
    return {"ok": True, "status": status, "tx_count_7d": count_7d}
