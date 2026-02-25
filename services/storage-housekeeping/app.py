"""
Scheduled housekeeping Lambda for storage billing enforcement.

This function scans the upload transaction ledger, determines the latest confirmed
payment timestamp for each stored object, and enforces a 32-day payment deadline
(30-day interval + 2-day grace by default). Overdue objects are deleted from S3;
if the bucket becomes empty, the bucket is deleted as well. Related transaction
rows are removed from DynamoDB after cleanup.

Payment confirmation logic:
- A row is considered a confirmed payment event when it has a non-empty trans_id.
- If the row contains recipient_wallet, it must match MNEMOSPARK_RECIPIENT_WALLET.
- The latest confirmed payment timestamp per object is used as the billing anchor.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_LOCATION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION
DEFAULT_BILLING_INTERVAL_DAYS = 30
DEFAULT_GRACE_PERIOD_DAYS = 2
DEFAULT_SCAN_LIMIT = 100

TRANSACTION_LOG_TABLE_ENV = "UPLOAD_TRANSACTION_LOG_TABLE_NAME"
RECIPIENT_WALLET_ENV = "MNEMOSPARK_RECIPIENT_WALLET"
BILLING_INTERVAL_DAYS_ENV = "HOUSEKEEPING_BILLING_INTERVAL_DAYS"
GRACE_PERIOD_DAYS_ENV = "HOUSEKEEPING_GRACE_PERIOD_DAYS"
SCAN_LIMIT_ENV = "HOUSEKEEPING_SCAN_LIMIT"
DRY_RUN_ENV = "HOUSEKEEPING_DRY_RUN"

ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
NOT_FOUND_S3_ERROR_CODES = {
    "403",
    "404",
    "AccessDenied",
    "AllAccessDisabled",
    "NoSuchBucket",
    "NoSuchKey",
    "NotFound",
}
PAYMENT_TIME_FIELDS = (
    "payment_received_at",
    "paid_at",
    "last_payment_at",
    "timestamp",
)
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


class BadRequestError(ValueError):
    """Raised when input/env validation fails."""


@dataclass(frozen=True)
class ObjectIdentity:
    wallet_address: str
    bucket_name: str
    object_key: str
    location: str


@dataclass
class ObjectLedger:
    identity: ObjectIdentity
    latest_payment_at: datetime
    transaction_keys: list[dict[str, Any]] = field(default_factory=list)


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }


def _error_response(status_code: int, error: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body)


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise BadRequestError(f"{name} environment variable is required")
    return value


def _read_int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        parsed = int(str(raw).strip())
    except ValueError as exc:
        raise BadRequestError(f"{name} must be an integer") from exc
    if parsed < minimum:
        raise BadRequestError(f"{name} must be >= {minimum}")
    return parsed


def _read_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    normalized = str(value).strip().lower()
    return normalized in {"1", "true", "yes", "y", "on"}


def _normalize_address(value: str, field_name: str) -> str:
    candidate = value.strip()
    if not ADDRESS_PATTERN.fullmatch(candidate):
        raise BadRequestError(f"{field_name} must be a 0x-prefixed 20-byte hex address")
    return f"0x{candidate[2:].lower()}"


def _optional_normalized_address(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not ADDRESS_PATTERN.fullmatch(candidate):
        return None
    return f"0x{candidate[2:].lower()}"


def _wallet_hash(wallet_address: str, length: int = 16) -> str:
    return hashlib.sha256(wallet_address.encode("utf-8")).hexdigest()[:length]


def _default_bucket_name(wallet_address: str) -> str:
    return f"mnemospark-{_wallet_hash(wallet_address)}"


def _parse_timestamp(raw: Any) -> datetime | None:
    if raw in (None, ""):
        return None

    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)

    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)

    if not isinstance(raw, str):
        return None

    candidate = raw.strip()
    if not candidate:
        return None

    iso_candidate = candidate.replace("Z", "+00:00")
    try:
        parsed_iso = datetime.fromisoformat(iso_candidate)
        return parsed_iso if parsed_iso.tzinfo else parsed_iso.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    try:
        parsed_ts = datetime.strptime(candidate, TIMESTAMP_FORMAT)
        return parsed_ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_event_now(event: dict[str, Any]) -> datetime:
    now_override = event.get("now")
    if now_override in (None, ""):
        return datetime.now(timezone.utc)
    parsed = _parse_timestamp(now_override)
    if not parsed:
        raise BadRequestError("event.now must be an ISO timestamp, epoch seconds, or YYYY-MM-DD HH:MM:SS")
    return parsed.astimezone(timezone.utc)


def _is_not_found_s3_error(exc: ClientError) -> bool:
    code = str(exc.response.get("Error", {}).get("Code", ""))
    return code in NOT_FOUND_S3_ERROR_CODES


def _scan_transaction_rows(transaction_log_table: Any, scan_limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    scan_kwargs: dict[str, Any] = {"Limit": scan_limit}
    while True:
        response = transaction_log_table.scan(**scan_kwargs)
        rows.extend(response.get("Items") or [])
        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_evaluated_key
    return rows


def _row_identity(item: dict[str, Any]) -> ObjectIdentity | None:
    wallet_address = _optional_normalized_address(item.get("addr") or item.get("wallet_address"))
    if not wallet_address:
        return None

    object_key_raw = item.get("object_key") or item.get("object_id")
    if not isinstance(object_key_raw, str) or not object_key_raw.strip():
        return None
    object_key = object_key_raw.strip()

    bucket_name_raw = item.get("bucket_name")
    bucket_name = str(bucket_name_raw).strip() if isinstance(bucket_name_raw, str) and bucket_name_raw.strip() else ""
    if not bucket_name:
        bucket_name = _default_bucket_name(wallet_address)

    location_raw = item.get("location") or item.get("region") or DEFAULT_LOCATION
    location = str(location_raw).strip() or DEFAULT_LOCATION

    return ObjectIdentity(
        wallet_address=wallet_address,
        bucket_name=bucket_name,
        object_key=object_key,
        location=location,
    )


def _row_timestamp(item: dict[str, Any]) -> datetime | None:
    for field_name in PAYMENT_TIME_FIELDS:
        parsed = _parse_timestamp(item.get(field_name))
        if parsed:
            return parsed.astimezone(timezone.utc)
    return None


def _row_is_confirmed_payment(item: dict[str, Any], expected_recipient_wallet: str) -> tuple[bool, str | None]:
    trans_id = str(item.get("trans_id") or "").strip()
    if not trans_id:
        return False, "missing_trans_id"

    row_recipient = _optional_normalized_address(item.get("recipient_wallet"))
    if row_recipient and row_recipient != expected_recipient_wallet:
        return False, "recipient_mismatch"

    if not _row_timestamp(item):
        return False, "missing_timestamp"

    return True, None


def _row_primary_key(item: dict[str, Any]) -> dict[str, Any] | None:
    quote_id = item.get("quote_id")
    trans_id = item.get("trans_id")
    if not isinstance(quote_id, str) or not quote_id.strip():
        return None
    if not isinstance(trans_id, str) or not trans_id.strip():
        return None
    return {"quote_id": quote_id.strip(), "trans_id": trans_id.strip()}


def _build_object_ledgers(
    rows: list[dict[str, Any]],
    expected_recipient_wallet: str,
) -> tuple[dict[ObjectIdentity, ObjectLedger], dict[str, int]]:
    ledgers: dict[ObjectIdentity, ObjectLedger] = {}
    counters = {
        "rows_scanned": 0,
        "rows_confirmed": 0,
        "rows_skipped_missing_identity": 0,
        "rows_skipped_missing_trans_id": 0,
        "rows_skipped_missing_timestamp": 0,
        "rows_skipped_recipient_mismatch": 0,
    }

    for row in rows:
        counters["rows_scanned"] += 1
        identity = _row_identity(row)
        if not identity:
            counters["rows_skipped_missing_identity"] += 1
            continue

        is_confirmed, reason = _row_is_confirmed_payment(row, expected_recipient_wallet)
        if not is_confirmed:
            if reason == "recipient_mismatch":
                counters["rows_skipped_recipient_mismatch"] += 1
            elif reason == "missing_timestamp":
                counters["rows_skipped_missing_timestamp"] += 1
            else:
                counters["rows_skipped_missing_trans_id"] += 1
            continue

        payment_time = _row_timestamp(row)
        if not payment_time:
            counters["rows_skipped_missing_timestamp"] += 1
            continue

        counters["rows_confirmed"] += 1
        ledger = ledgers.get(identity)
        if ledger is None:
            ledger = ObjectLedger(identity=identity, latest_payment_at=payment_time)
            ledgers[identity] = ledger
        elif payment_time > ledger.latest_payment_at:
            ledger.latest_payment_at = payment_time

        primary_key = _row_primary_key(row)
        if primary_key and primary_key not in ledger.transaction_keys:
            ledger.transaction_keys.append(primary_key)

    return ledgers, counters


def _delete_object_if_exists(s3_client: Any, bucket_name: str, object_key: str) -> bool:
    try:
        s3_client.head_object(Bucket=bucket_name, Key=object_key)
    except ClientError as exc:
        if _is_not_found_s3_error(exc):
            return False
        raise
    s3_client.delete_object(Bucket=bucket_name, Key=object_key)
    return True


def _delete_bucket_if_empty(s3_client: Any, bucket_name: str) -> bool:
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
    except ClientError as exc:
        if _is_not_found_s3_error(exc):
            return False
        raise

    key_count = response.get("KeyCount")
    is_empty = key_count == 0 if isinstance(key_count, int) else len(response.get("Contents") or []) == 0
    if not is_empty:
        return False

    s3_client.delete_bucket(Bucket=bucket_name)
    return True


def _cleanup_s3_for_object(s3_client: Any, identity: ObjectIdentity) -> tuple[bool, bool]:
    try:
        s3_client.head_bucket(Bucket=identity.bucket_name)
    except ClientError as exc:
        if _is_not_found_s3_error(exc):
            return False, False
        raise

    object_deleted = _delete_object_if_exists(
        s3_client=s3_client,
        bucket_name=identity.bucket_name,
        object_key=identity.object_key,
    )
    bucket_deleted = _delete_bucket_if_empty(
        s3_client=s3_client,
        bucket_name=identity.bucket_name,
    )
    return object_deleted, bucket_deleted


def _delete_transaction_rows(transaction_log_table: Any, keys: list[dict[str, Any]]) -> int:
    deleted = 0
    for key in keys:
        transaction_log_table.delete_item(Key=key)
        deleted += 1
    return deleted


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    try:
        event = event or {}
        table_name = _require_env(TRANSACTION_LOG_TABLE_ENV)
        recipient_wallet = _normalize_address(_require_env(RECIPIENT_WALLET_ENV), RECIPIENT_WALLET_ENV)
        billing_interval_days = _read_int_env(BILLING_INTERVAL_DAYS_ENV, DEFAULT_BILLING_INTERVAL_DAYS)
        grace_period_days = _read_int_env(GRACE_PERIOD_DAYS_ENV, DEFAULT_GRACE_PERIOD_DAYS, minimum=0)
        scan_limit = _read_int_env(SCAN_LIMIT_ENV, DEFAULT_SCAN_LIMIT)
        dry_run = _read_bool(os.environ.get(DRY_RUN_ENV)) or _read_bool(event.get("dry_run"))

        now = _parse_event_now(event)
        deadline_days = billing_interval_days + grace_period_days
        deadline_delta = timedelta(days=deadline_days)

        dynamodb = boto3.resource("dynamodb")
        transaction_log_table = dynamodb.Table(table_name)
        rows = _scan_transaction_rows(transaction_log_table, scan_limit=scan_limit)
        ledgers, counters = _build_object_ledgers(rows, expected_recipient_wallet=recipient_wallet)

        s3_clients: dict[str, Any] = {}
        objects_due = 0
        objects_deleted = 0
        buckets_deleted = 0
        transaction_rows_deleted = 0
        objects_due_details: list[dict[str, Any]] = []

        for ledger in ledgers.values():
            deadline_at = ledger.latest_payment_at + deadline_delta
            is_due = now > deadline_at
            if not is_due:
                continue
            objects_due += 1

            detail = {
                "wallet_address": ledger.identity.wallet_address,
                "bucket_name": ledger.identity.bucket_name,
                "object_key": ledger.identity.object_key,
                "location": ledger.identity.location,
                "latest_payment_at": ledger.latest_payment_at.isoformat(),
                "deadline_at": deadline_at.isoformat(),
            }
            objects_due_details.append(detail)

            if dry_run:
                continue

            s3_client = s3_clients.get(ledger.identity.location)
            if s3_client is None:
                s3_client = boto3.client("s3", region_name=ledger.identity.location)
                s3_clients[ledger.identity.location] = s3_client

            object_deleted, bucket_deleted = _cleanup_s3_for_object(
                s3_client=s3_client,
                identity=ledger.identity,
            )
            if object_deleted:
                objects_deleted += 1
            if bucket_deleted:
                buckets_deleted += 1

            transaction_rows_deleted += _delete_transaction_rows(transaction_log_table, ledger.transaction_keys)

        body = {
            "success": True,
            "dry_run": dry_run,
            "recipient_wallet": recipient_wallet,
            "billing_interval_days": billing_interval_days,
            "grace_period_days": grace_period_days,
            "deadline_days": deadline_days,
            "now": now.isoformat(),
            "objects_evaluated": len(ledgers),
            "objects_due": objects_due,
            "objects_deleted": objects_deleted,
            "buckets_deleted": buckets_deleted,
            "transaction_rows_deleted": transaction_rows_deleted,
            "objects_due_details": objects_due_details,
            **counters,
        }
        return _response(200, body)
    except BadRequestError as exc:
        return _error_response(400, "Bad request", str(exc))
    except Exception as exc:
        return _error_response(500, "Internal error", str(exc))
