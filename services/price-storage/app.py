"""
Lambda handler for mnemospark /price-storage.

POST /price-storage orchestrates:
  1) /estimate/storage
  2) /estimate/transfer
  3) configurable markup
  4) quote persistence in DynamoDB with TTL
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import botocore.exceptions

DEFAULT_QUOTE_TTL_SECONDS = 3600
DEFAULT_TRANSFER_DIRECTION = "out"
DEFAULT_RATE_TYPE = "BEFORE_DISCOUNTS"
DEFAULT_MARKUP_PERCENT = "0"
VALID_PROVIDERS = {"aws"}


class BadRequestError(ValueError):
    """Raised when request validation fails."""


def _load_service_module(module_name: str, service_dir: str) -> Any:
    module_path = Path(__file__).resolve().parents[1] / service_dir / "app.py"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError(f"Unable to load service module: {service_dir}")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


_ESTIMATE_STORAGE_MODULE = _load_service_module("price_storage_estimate_storage", "estimate-storage")
_ESTIMATE_TRANSFER_MODULE = _load_service_module("price_storage_estimate_transfer", "estimate-transfer")


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def _decode_event_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if body in (None, ""):
        raise BadRequestError("body is required and must be a JSON object")

    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body).decode("utf-8")
        except Exception as exc:  # pragma: no cover - defensive
            raise BadRequestError("body must be valid base64-encoded JSON") from exc

    try:
        parsed_body = json.loads(body)
    except json.JSONDecodeError as exc:
        raise BadRequestError("body must be valid JSON") from exc

    if not isinstance(parsed_body, dict):
        raise BadRequestError("body must be a JSON object")

    return parsed_body


def _required_string(payload: dict[str, Any], key: str) -> str:
    raw_value = payload.get(key)
    value = str(raw_value).strip() if raw_value is not None else ""
    if not value:
        raise BadRequestError(f"{key} is required")
    return value


def parse_input(event: dict[str, Any]) -> dict[str, Any]:
    payload = _decode_event_body(event)

    wallet_address = _required_string(payload, "wallet_address")
    object_id = _required_string(payload, "object_id")
    object_id_hash = _required_string(payload, "object_id_hash")
    provider = _required_string(payload, "provider").lower()
    region = _required_string(payload, "region")

    if provider not in VALID_PROVIDERS:
        raise BadRequestError("provider must be aws")

    try:
        gb = float(payload.get("gb"))
    except (TypeError, ValueError) as exc:
        raise BadRequestError("gb is required and must be a number") from exc

    if gb <= 0:
        raise BadRequestError("gb must be greater than 0")

    return {
        "wallet_address": wallet_address,
        "object_id": object_id,
        "object_id_hash": object_id_hash,
        "gb": gb,
        "provider": provider,
        "region": region,
    }


def _get_quotes_table_name() -> str:
    table_name = (os.getenv("QUOTES_TABLE_NAME") or os.getenv("DYNAMODB_QUOTES_TABLE") or "").strip()
    if not table_name:
        raise RuntimeError("QUOTES_TABLE_NAME environment variable is required")
    return table_name


def _get_quote_ttl_seconds() -> int:
    raw_ttl = (os.getenv("QUOTE_TTL_SECONDS") or str(DEFAULT_QUOTE_TTL_SECONDS)).strip()
    try:
        ttl_seconds = int(raw_ttl)
    except ValueError as exc:
        raise RuntimeError("QUOTE_TTL_SECONDS must be an integer") from exc

    if ttl_seconds <= 0:
        raise RuntimeError("QUOTE_TTL_SECONDS must be greater than 0")
    return ttl_seconds


def _get_rate_type() -> str:
    rate_type = (os.getenv("PRICE_STORAGE_RATE_TYPE") or DEFAULT_RATE_TYPE).strip().upper()
    valid_rate_types = getattr(_ESTIMATE_STORAGE_MODULE, "VALID_RATE_TYPES", ())
    if rate_type not in valid_rate_types:
        raise RuntimeError(
            "PRICE_STORAGE_RATE_TYPE must be one of "
            "BEFORE_DISCOUNTS, AFTER_DISCOUNTS, AFTER_DISCOUNTS_AND_COMMITMENTS"
        )
    return rate_type


def _get_transfer_direction() -> str:
    direction = (os.getenv("PRICE_STORAGE_TRANSFER_DIRECTION") or DEFAULT_TRANSFER_DIRECTION).strip().lower()
    if direction not in {"in", "out"}:
        raise RuntimeError("PRICE_STORAGE_TRANSFER_DIRECTION must be in or out")
    return direction


def _get_markup_multiplier() -> float:
    raw_markup = os.getenv(
        "PRICE_STORAGE_MARKUP_PERCENT",
        os.getenv("PRICE_MARKUP_PERCENT", DEFAULT_MARKUP_PERCENT),
    )
    try:
        markup = float(raw_markup)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("PRICE_STORAGE_MARKUP_PERCENT must be numeric") from exc

    if markup < 0:
        raise RuntimeError("PRICE_STORAGE_MARKUP_PERCENT must be non-negative")

    # Allow "0.15" (15%) or "15" (15%).
    return markup / 100.0 if markup > 1 else markup


def estimate_storage_cost(gb: float, region: str, rate_type: str) -> float:
    result = _ESTIMATE_STORAGE_MODULE.estimate_s3_storage_cost(
        storage_gb_month=gb,
        region=region,
        rate_type=rate_type,
    )
    return float(result["totalCost"])


def estimate_transfer_cost(gb: float, region: str, direction: str, rate_type: str) -> float:
    result = _ESTIMATE_TRANSFER_MODULE.estimate_data_transfer_cost(
        data_gb=gb,
        direction=direction,
        region=region,
        rate_type=rate_type,
    )
    return float(result["totalCost"])


def _build_quote_response(request: dict[str, Any], storage_price: float, now: datetime | None = None) -> dict[str, Any]:
    resolved_now = now or datetime.now(timezone.utc)
    return {
        "timestamp": resolved_now.strftime("%Y-%m-%d %H:%M:%S"),
        "quote_id": str(uuid.uuid4()),
        "storage_price": storage_price,
        "addr": request["wallet_address"],
        "object_id": request["object_id"],
        "object_id_hash": request["object_id_hash"],
        "object_size_gb": request["gb"],
        "provider": request["provider"],
        "location": request["region"],
    }


def get_dynamodb_client() -> Any:
    return boto3.client("dynamodb")


def write_quote(
    quote: dict[str, Any],
    storage_cost: float,
    transfer_cost: float,
    markup_multiplier: float,
    dynamodb_client: Any | None = None,
    table_name: str | None = None,
    ttl_seconds: int | None = None,
    now: datetime | None = None,
) -> None:
    resolved_now = now or datetime.now(timezone.utc)
    resolved_table_name = table_name or _get_quotes_table_name()
    resolved_ttl_seconds = ttl_seconds if ttl_seconds is not None else _get_quote_ttl_seconds()
    expires_at = int(resolved_now.timestamp()) + resolved_ttl_seconds

    item = {
        "quote_id": {"S": quote["quote_id"]},
        "timestamp": {"S": quote["timestamp"]},
        "storage_price": {"N": f"{quote['storage_price']:.2f}"},
        "addr": {"S": quote["addr"]},
        "object_id": {"S": quote["object_id"]},
        "object_id_hash": {"S": quote["object_id_hash"]},
        "object_size_gb": {"N": str(quote["object_size_gb"])},
        "provider": {"S": quote["provider"]},
        "location": {"S": quote["location"]},
        "expires_at": {"N": str(expires_at)},
        "storage_cost": {"N": f"{storage_cost:.6f}"},
        "transfer_cost": {"N": f"{transfer_cost:.6f}"},
        "markup_multiplier": {"N": f"{markup_multiplier:.6f}"},
    }

    client = dynamodb_client or get_dynamodb_client()
    client.put_item(
        TableName=resolved_table_name,
        Item=item,
        ConditionExpression="attribute_not_exists(quote_id)",
    )


def _error_response(status_code: int, error: str, message: str, details: Any | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    try:
        request = parse_input(event)
        rate_type = _get_rate_type()
        direction = _get_transfer_direction()
        markup_multiplier = _get_markup_multiplier()

        storage_cost = estimate_storage_cost(
            gb=request["gb"],
            region=request["region"],
            rate_type=rate_type,
        )
        transfer_cost = estimate_transfer_cost(
            gb=request["gb"],
            region=request["region"],
            direction=direction,
            rate_type=rate_type,
        )
        storage_price = round((storage_cost + transfer_cost) * (1 + markup_multiplier), 2)

        quote = _build_quote_response(request=request, storage_price=storage_price)
        write_quote(
            quote=quote,
            storage_cost=storage_cost,
            transfer_cost=transfer_cost,
            markup_multiplier=markup_multiplier,
        )
        return _response(200, quote)
    except BadRequestError as exc:
        return _error_response(400, "Bad request", str(exc))
    except botocore.exceptions.ClientError as exc:
        error_message = exc.response.get("Error", {}).get("Message", str(exc))
        return _error_response(500, "Internal error", "Failed to process price-storage request", error_message)
    except Exception as exc:
        return _error_response(500, "Internal error", str(exc))
