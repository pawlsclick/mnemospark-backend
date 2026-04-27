"""
Lambda handler for mnemospark /price-storage.

POST /price-storage calculates storage + transfer costs from the AWS Price
List Query API, applies configurable markup, and persists quotes in DynamoDB
with TTL.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
import botocore.exceptions

try:
    from common.http_response_headers import rest_api_json_headers
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.pricing_storage_quote import (
        DATA_TRANSFER_PRICING_SERVICE_CODE as SHARED_DATA_TRANSFER_PRICING_SERVICE_CODE,
        DEFAULT_RATE_TYPE as SHARED_DEFAULT_RATE_TYPE,
        DEFAULT_TRANSFER_DIRECTION as SHARED_DEFAULT_TRANSFER_DIRECTION,
        PRICING_API_REGION as SHARED_PRICING_API_REGION,
        PRICING_PAGE_SIZE as SHARED_PRICING_PAGE_SIZE,
        REGION_TO_S3_LOCATION as SHARED_REGION_TO_S3_LOCATION,
        STORAGE_USAGE_TYPE_TOKEN as SHARED_STORAGE_USAGE_TYPE_TOKEN,
        TRANSFER_IN_USAGE_TYPE_TOKEN as SHARED_TRANSFER_IN_USAGE_TYPE_TOKEN,
        TRANSFER_OUT_USAGE_TYPE_TOKEN as SHARED_TRANSFER_OUT_USAGE_TYPE_TOKEN,
        VALID_RATE_TYPES as SHARED_VALID_RATE_TYPES,
        _build_data_transfer_primary_filters as shared_build_data_transfer_primary_filters,
        _build_s3_storage_filters as shared_build_s3_storage_filters,
        _extract_ondemand_gb_price_dimensions as shared_extract_ondemand_gb_price_dimensions,
        _get_products as shared_get_products,
        _is_data_transfer_product as shared_is_data_transfer_product,
        _is_s3_storage_product as shared_is_s3_storage_product,
        _iter_ondemand_gb_dimensions as shared_iter_ondemand_gb_dimensions,
        _pick_tier_rate as shared_pick_tier_rate,
        estimate_storage_cost as shared_estimate_storage_cost,
        estimate_transfer_cost as shared_estimate_transfer_cost,
        get_markup_multiplier_from_env,
        get_price_floor_from_env,
        get_pricing_client as shared_get_pricing_client,
        get_rate_type_from_env,
        get_transfer_direction_from_env,
    )
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.http_response_headers import rest_api_json_headers
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.pricing_storage_quote import (
        DATA_TRANSFER_PRICING_SERVICE_CODE as SHARED_DATA_TRANSFER_PRICING_SERVICE_CODE,
        DEFAULT_RATE_TYPE as SHARED_DEFAULT_RATE_TYPE,
        DEFAULT_TRANSFER_DIRECTION as SHARED_DEFAULT_TRANSFER_DIRECTION,
        PRICING_API_REGION as SHARED_PRICING_API_REGION,
        PRICING_PAGE_SIZE as SHARED_PRICING_PAGE_SIZE,
        REGION_TO_S3_LOCATION as SHARED_REGION_TO_S3_LOCATION,
        STORAGE_USAGE_TYPE_TOKEN as SHARED_STORAGE_USAGE_TYPE_TOKEN,
        TRANSFER_IN_USAGE_TYPE_TOKEN as SHARED_TRANSFER_IN_USAGE_TYPE_TOKEN,
        TRANSFER_OUT_USAGE_TYPE_TOKEN as SHARED_TRANSFER_OUT_USAGE_TYPE_TOKEN,
        VALID_RATE_TYPES as SHARED_VALID_RATE_TYPES,
        _build_data_transfer_primary_filters as shared_build_data_transfer_primary_filters,
        _build_s3_storage_filters as shared_build_s3_storage_filters,
        _extract_ondemand_gb_price_dimensions as shared_extract_ondemand_gb_price_dimensions,
        _get_products as shared_get_products,
        _is_data_transfer_product as shared_is_data_transfer_product,
        _is_s3_storage_product as shared_is_s3_storage_product,
        _iter_ondemand_gb_dimensions as shared_iter_ondemand_gb_dimensions,
        _pick_tier_rate as shared_pick_tier_rate,
        estimate_storage_cost as shared_estimate_storage_cost,
        estimate_transfer_cost as shared_estimate_transfer_cost,
        get_markup_multiplier_from_env,
        get_price_floor_from_env,
        get_pricing_client as shared_get_pricing_client,
        get_rate_type_from_env,
        get_transfer_direction_from_env,
    )


log_api_call = load_log_api_call()
_log_api_call_result = load_log_api_call_result("/price-storage", log_api_call_getter=lambda: log_api_call)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DEFAULT_QUOTE_TTL_SECONDS = 3600
VALID_PROVIDERS = {"aws"}

# Keep local names for backwards compatibility while sourcing values from shared logic.
DEFAULT_TRANSFER_DIRECTION = SHARED_DEFAULT_TRANSFER_DIRECTION
DEFAULT_RATE_TYPE = SHARED_DEFAULT_RATE_TYPE
VALID_RATE_TYPES = SHARED_VALID_RATE_TYPES
DATA_TRANSFER_PRICING_SERVICE_CODE = SHARED_DATA_TRANSFER_PRICING_SERVICE_CODE
PRICING_API_REGION = SHARED_PRICING_API_REGION
PRICING_PAGE_SIZE = SHARED_PRICING_PAGE_SIZE
STORAGE_USAGE_TYPE_TOKEN = SHARED_STORAGE_USAGE_TYPE_TOKEN
TRANSFER_OUT_USAGE_TYPE_TOKEN = SHARED_TRANSFER_OUT_USAGE_TYPE_TOKEN
TRANSFER_IN_USAGE_TYPE_TOKEN = SHARED_TRANSFER_IN_USAGE_TYPE_TOKEN
REGION_TO_S3_LOCATION = SHARED_REGION_TO_S3_LOCATION


class BadRequestError(ValueError):
    """Raised when request validation fails."""


def _log_event(level: int, event_name: str, **fields: Any) -> None:
    payload: dict[str, Any] = {"event": event_name}
    payload.update({key: value for key, value in fields.items() if value is not None})
    logger.log(level, json.dumps(payload, default=str, separators=(",", ":")))


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": rest_api_json_headers(),
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


def _extract_authorizer_wallet(event: dict[str, Any]) -> str | None:
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        return None
    authorizer = request_context.get("authorizer")
    if not isinstance(authorizer, dict):
        return None

    candidates: list[Any] = [
        authorizer.get("walletAddress"),
        authorizer.get("wallet_address"),
    ]
    lambda_authorizer_context = authorizer.get("lambda")
    if isinstance(lambda_authorizer_context, dict):
        candidates.extend(
            [
                lambda_authorizer_context.get("walletAddress"),
                lambda_authorizer_context.get("wallet_address"),
            ]
        )

    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


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
    return get_rate_type_from_env()


def _get_transfer_direction() -> str:
    return get_transfer_direction_from_env()


def _get_markup_multiplier() -> float:
    return get_markup_multiplier_from_env()


def _get_price_floor() -> float:
    return get_price_floor_from_env()


def get_pricing_client() -> Any:
    return shared_get_pricing_client()


def _extract_positive_ondemand_gb_rates(product: dict[str, Any]) -> list[float]:
    return [
        amount
        for _dimension, amount in shared_iter_ondemand_gb_dimensions(product, include_zero=False)
    ]


def _pick_lowest_positive_rate(
    products: list[dict[str, Any]],
    product_matcher: Any,
    usage_gb: float,
    error_message: str,
) -> float:
    candidate_rates: list[float] = []
    for product in products:
        if not product_matcher(product):
            continue
        dimensions = shared_extract_ondemand_gb_price_dimensions(product)
        if dimensions:
            try:
                candidate_rates.append(shared_pick_tier_rate(dimensions=dimensions, usage_gb=usage_gb))
                continue
            except RuntimeError:
                pass
        candidate_rates.extend(_extract_positive_ondemand_gb_rates(product))

    if not candidate_rates:
        raise RuntimeError(error_message)
    return min(candidate_rates)


def get_s3_storage_price_per_gb_month(region: str, usage_gb: float = 1.0, client: Any | None = None) -> float:
    products = shared_get_products(service_code="AmazonS3", filters=shared_build_s3_storage_filters(region), client=client)
    if not products:
        products = shared_get_products(
            service_code="AmazonS3",
            filters=[{"Type": "TERM_MATCH", "Field": "regionCode", "Value": region}],
            client=client,
        )
    return _pick_lowest_positive_rate(
        products=products,
        product_matcher=shared_is_s3_storage_product,
        usage_gb=usage_gb,
        error_message=f"No S3 Standard storage SKU found for region {region}",
    )


def get_data_transfer_out_price_per_gb(
    region: str,
    usage_gb: float = 1.0,
    client: Any | None = None,
    direction: str = "out",
) -> float:
    if direction == "in":
        return 0.0

    products = shared_get_products(
        service_code=DATA_TRANSFER_PRICING_SERVICE_CODE,
        filters=shared_build_data_transfer_primary_filters(region),
        client=client,
    )
    return _pick_lowest_positive_rate(
        products=products,
        product_matcher=lambda product: shared_is_data_transfer_product(product, direction=direction),
        usage_gb=usage_gb,
        error_message=f"No data transfer SKU found for region {region} and direction {direction}",
    )


def estimate_storage_cost(gb: float, region: str, rate_type: str) -> float:
    return shared_estimate_storage_cost(
        gb=gb,
        region=region,
        rate_type=rate_type,
        client=get_pricing_client(),
    )


def estimate_transfer_cost(gb: float, region: str, direction: str, rate_type: str) -> float:
    if direction == "in":
        return 0.0
    return shared_estimate_transfer_cost(
        gb=gb,
        region=region,
        direction=direction,
        rate_type=rate_type,
        client=get_pricing_client(),
    )


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
    price_floor: float,
    dynamodb_client: Any | None = None,
    table_name: str | None = None,
    ttl_seconds: int | None = None,
    now: datetime | None = None,
) -> None:
    resolved_now = now or datetime.now(timezone.utc)
    resolved_table_name = table_name or _get_quotes_table_name()
    resolved_ttl_seconds = ttl_seconds if ttl_seconds is not None else _get_quote_ttl_seconds()
    expires_at = int(resolved_now.timestamp()) + resolved_ttl_seconds
    pre_markup_subtotal = max(storage_cost + transfer_cost, price_floor)

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
        "pre_markup_subtotal": {"N": f"{pre_markup_subtotal:.6f}"},
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
    try:
        request = parse_input(event)
        _log_event(
            logging.INFO,
            "price_request_parsed",
            wallet_address=request["wallet_address"],
            object_id=request["object_id"],
            object_id_hash=request["object_id_hash"],
            gb=request["gb"],
            provider=request["provider"],
            region=request["region"],
        )
        authorizer_wallet = _extract_authorizer_wallet(event)
        if authorizer_wallet:
            _log_event(
                logging.INFO,
                "price_authorizer_wallet_context",
                wallet_address=authorizer_wallet,
                request_wallet_address=request["wallet_address"],
            )
        rate_type = _get_rate_type()
        direction = _get_transfer_direction()
        markup_multiplier = _get_markup_multiplier()
        price_floor = _get_price_floor()

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
        pre_markup_subtotal = max(storage_cost + transfer_cost, price_floor)
        storage_price = round(pre_markup_subtotal * (1 + markup_multiplier), 2)
        _log_event(
            logging.INFO,
            "price_costs_computed",
            object_id=request["object_id"],
            region=request["region"],
            rate_type=rate_type,
            transfer_direction=direction,
            storage_cost=storage_cost,
            transfer_cost=transfer_cost,
            pre_markup_subtotal=pre_markup_subtotal,
            price_floor=price_floor,
            markup_multiplier=markup_multiplier,
            storage_price=storage_price,
        )

        quote = _build_quote_response(request=request, storage_price=storage_price)
        write_quote(
            quote=quote,
            storage_cost=storage_cost,
            transfer_cost=transfer_cost,
            markup_multiplier=markup_multiplier,
            price_floor=price_floor,
        )
        _log_event(
            logging.INFO,
            "price_quote_written",
            quote_id=quote["quote_id"],
            object_id=quote["object_id"],
            wallet_address=quote["addr"],
            storage_price=quote["storage_price"],
            provider=quote["provider"],
            location=quote["location"],
        )
        _log_api_call_result(
            event,
            context,
            status_code=200,
            result="success",
            quote_id=quote["quote_id"],
            object_id=quote["object_id"],
        )
        return _response(200, quote)
    except BadRequestError as exc:
        _log_event(
            logging.WARNING,
            "price_bad_request",
            error_type=type(exc).__name__,
            error_message=str(exc),
        )
        _log_api_call_result(
            event,
            context,
            status_code=400,
            result="bad_request",
            error_code="bad_request",
            error_message=str(exc),
        )
        return _error_response(400, "Bad request", str(exc))
    except botocore.exceptions.ClientError as exc:
        error_message = exc.response.get("Error", {}).get("Message", str(exc))
        _log_event(
            logging.ERROR,
            "price_client_error",
            error_type=type(exc).__name__,
            error_message=error_message,
        )
        _log_api_call_result(
            event,
            context,
            status_code=500,
            result="internal_error",
            error_code="dynamodb_client_error",
            error_message=error_message,
        )
        return _error_response(500, "Internal error", "Failed to process price-storage request", error_message)
    except Exception as exc:
        _log_event(
            logging.ERROR,
            "price_internal_error",
            error_type=type(exc).__name__,
            error_message=str(exc),
        )
        _log_api_call_result(
            event,
            context,
            status_code=500,
            result="internal_error",
            error_code="internal_error",
            error_message=str(exc),
        )
        return _error_response(500, "Internal error", str(exc))
