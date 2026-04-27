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
        get_markup_multiplier_from_env as _get_markup_multiplier,
        get_price_floor_from_env as _get_price_floor,
        get_rate_type_from_env as _get_rate_type,
        get_transfer_direction_from_env as _get_transfer_direction,
        estimate_storage_cost,
        estimate_transfer_cost,
    )
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.http_response_headers import rest_api_json_headers
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.pricing_storage_quote import (
        get_markup_multiplier_from_env as _get_markup_multiplier,
        get_price_floor_from_env as _get_price_floor,
        get_rate_type_from_env as _get_rate_type,
        get_transfer_direction_from_env as _get_transfer_direction,
        estimate_storage_cost,
        estimate_transfer_cost,
    )


log_api_call = load_log_api_call()
_log_api_call_result = load_log_api_call_result("/price-storage", log_api_call_getter=lambda: log_api_call)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DEFAULT_QUOTE_TTL_SECONDS = 3600
DEFAULT_TRANSFER_DIRECTION = "out"
DEFAULT_RATE_TYPE = "BEFORE_DISCOUNTS"
VALID_PROVIDERS = {"aws"}
# Internet egress rates for DataTransfer-Out-Bytes live under AWSDataTransfer in the Price List.
# Querying AmazonS3 can return a $0/GB SKU that wins min() and understates egress vs the calculator.
DATA_TRANSFER_PRICING_SERVICE_CODE = "AWSDataTransfer"
VALID_RATE_TYPES = (
    "BEFORE_DISCOUNTS",
    "AFTER_DISCOUNTS",
    "AFTER_DISCOUNTS_AND_COMMITMENTS",
)
PRICING_API_REGION = os.getenv("PRICE_STORAGE_PRICING_API_REGION") or ("us-" + "east-1")
PRICING_PAGE_SIZE = 100
STORAGE_USAGE_TYPE_TOKEN = "TimedStorage-ByteHrs"
TRANSFER_OUT_USAGE_TYPE_TOKEN = "DataTransfer-Out-Bytes"
TRANSFER_IN_USAGE_TYPE_TOKEN = "DataTransfer-Regional-Bytes"
REGION_TO_S3_LOCATION: dict[str, str] = {
    # Americas
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ca-central-1": "Canada (Central)",
    "sa-east-1": "South America (Sao Paulo)",
    # Europe
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-central-2": "EU (Zurich)",
    "eu-north-1": "EU (Stockholm)",
    "eu-south-1": "EU (Milan)",
    "eu-south-2": "EU (Spain)",
    "il-central-1": "Israel (Tel Aviv)",
    # Asia Pacific
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "ap-southeast-4": "Asia Pacific (Melbourne)",
    "ap-east-1": "Asia Pacific (Hong Kong)",
    # Middle East and Africa
    "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)",
    "af-south-1": "Africa (Cape Town)",
}


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
    rate_type = (os.getenv("PRICE_STORAGE_RATE_TYPE") or DEFAULT_RATE_TYPE).strip().upper()
    if rate_type not in VALID_RATE_TYPES:
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
    raw_markup_percent = (os.getenv("PRICE_STORAGE_MARKUP") or "").strip()
    if not raw_markup_percent:
        return 0.0

    try:
        markup_percent = float(raw_markup_percent)
    except ValueError as exc:
        raise RuntimeError("PRICE_STORAGE_MARKUP must be a number") from exc

    if markup_percent < 0:
        raise RuntimeError("PRICE_STORAGE_MARKUP must be greater than or equal to 0")

    return markup_percent / 100.0


def _get_price_floor() -> float:
    """Minimum USD for storage+transfer before markup; defaults to 1 cent."""
    raw = (os.getenv("PRICE_STORAGE_FLOOR") or "").strip()
    if not raw:
        return 0.01
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError("PRICE_STORAGE_FLOOR must be a number") from exc
    if value < 0:
        raise RuntimeError("PRICE_STORAGE_FLOOR must be greater than or equal to 0")
    return value


def get_pricing_client() -> Any:
    return boto3.client("pricing", region_name=PRICING_API_REGION)


def _parse_price_list_entries(raw_price_list: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw_entry in raw_price_list:
        if not isinstance(raw_entry, str):
            continue
        entries.append(json.loads(raw_entry))
    return entries


def _get_products(service_code: str, filters: list[dict[str, str]], client: Any | None = None) -> list[dict[str, Any]]:
    pricing_client = client or get_pricing_client()
    all_products: list[dict[str, Any]] = []
    next_token: str | None = None

    while True:
        request_kwargs: dict[str, Any] = {
            "ServiceCode": service_code,
            "Filters": filters,
            "FormatVersion": "aws_v1",
            "MaxResults": PRICING_PAGE_SIZE,
        }
        if next_token:
            request_kwargs["NextToken"] = next_token

        response = pricing_client.get_products(**request_kwargs)
        all_products.extend(_parse_price_list_entries(response.get("PriceList", [])))
        next_token = response.get("NextToken")
        if not next_token:
            return all_products


def _extract_positive_ondemand_gb_rates(product: dict[str, Any]) -> list[float]:
    return [amount for _, amount in _iter_positive_ondemand_gb_dimensions(product)]


def _iter_ondemand_gb_dimensions(
    product: dict[str, Any], *, include_zero: bool
) -> list[tuple[dict[str, Any], float]]:
    terms = product.get("terms", {})
    on_demand = terms.get("OnDemand", {})
    if not isinstance(on_demand, dict):
        return []

    dimensions_with_prices: list[tuple[dict[str, Any], float]] = []
    for term in on_demand.values():
        if not isinstance(term, dict):
            continue
        dimensions = term.get("priceDimensions", {})
        if not isinstance(dimensions, dict):
            continue
        for dimension in dimensions.values():
            if not isinstance(dimension, dict):
                continue
            unit = str(dimension.get("unit", "")).upper()
            if "GB" not in unit:
                continue
            usd = (dimension.get("pricePerUnit") or {}).get("USD")
            try:
                amount = float(usd)
            except (TypeError, ValueError):
                continue
            if amount > 0 or (include_zero and amount == 0):
                dimensions_with_prices.append((dimension, amount))
    return dimensions_with_prices


def _iter_positive_ondemand_gb_dimensions(product: dict[str, Any]) -> list[tuple[dict[str, Any], float]]:
    return _iter_ondemand_gb_dimensions(product, include_zero=False)


def _iter_all_ondemand_gb_dimensions(product: dict[str, Any]) -> list[tuple[dict[str, Any], float]]:
    return _iter_ondemand_gb_dimensions(product, include_zero=True)


def _extract_ondemand_gb_price_dimensions(
    product: dict[str, Any], *, include_zero: bool = False
) -> list[dict[str, float]]:
    dimensions: list[dict[str, float]] = []
    iterator = _iter_all_ondemand_gb_dimensions if include_zero else _iter_positive_ondemand_gb_dimensions
    for dimension, amount in iterator(product):
        begin_raw = str(dimension.get("beginRange", "0")).strip()
        end_raw = str(dimension.get("endRange", "Inf")).strip()
        try:
            begin = float(begin_raw)
        except ValueError:
            begin = 0.0
        if end_raw.lower() == "inf":
            end = float("inf")
        else:
            try:
                end = float(end_raw)
            except ValueError:
                end = float("inf")
        dimensions.append({"price": amount, "begin": begin, "end": end})
    return dimensions


def _pick_tier_rate(dimensions: list[dict[str, float]], usage_gb: float) -> float:
    for dimension in sorted(dimensions, key=lambda item: (item["begin"], item["end"])):
        if usage_gb >= dimension["begin"] and usage_gb < dimension["end"]:
            return dimension["price"]
    raise RuntimeError(f"No matching price tier found for usage={usage_gb}")


def _calculate_tiered_cost(dimensions: list[dict[str, float]], usage_gb: float) -> float:
    sorted_dimensions = sorted(dimensions, key=lambda item: (item["begin"], item["end"]))
    total_cost = 0.0
    covered_usage = 0.0

    for dimension in sorted_dimensions:
        tier_begin = max(dimension["begin"], 0.0)
        tier_end = dimension["end"]
        if usage_gb <= tier_begin:
            break

        billable_start = max(tier_begin, covered_usage)
        billable_end = min(usage_gb, tier_end)
        if billable_end <= billable_start:
            continue

        total_cost += (billable_end - billable_start) * dimension["price"]
        covered_usage = max(covered_usage, billable_end)
        if covered_usage >= usage_gb:
            return total_cost

    raise RuntimeError(f"No matching cumulative price tiers found for usage={usage_gb}")


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
        dimensions = _extract_ondemand_gb_price_dimensions(product)
        if dimensions:
            try:
                candidate_rates.append(_pick_tier_rate(dimensions=dimensions, usage_gb=usage_gb))
                continue
            except RuntimeError:
                pass
        candidate_rates.extend(_extract_positive_ondemand_gb_rates(product))

    if not candidate_rates:
        raise RuntimeError(error_message)

    return min(candidate_rates)


def _pick_lowest_tiered_cost(
    products: list[dict[str, Any]],
    product_matcher: Any,
    usage_gb: float,
    error_message: str,
) -> float:
    candidate_costs: list[float] = []
    for product in products:
        if not product_matcher(product):
            continue
        dimensions = _extract_ondemand_gb_price_dimensions(product, include_zero=True)
        if dimensions:
            try:
                candidate_costs.append(_calculate_tiered_cost(dimensions=dimensions, usage_gb=usage_gb))
                continue
            except RuntimeError:
                pass

        rates = _extract_positive_ondemand_gb_rates(product)
        if rates:
            candidate_costs.append(min(rates) * usage_gb)

    if not candidate_costs:
        raise RuntimeError(error_message)

    positive_costs = [cost for cost in candidate_costs if cost > 0]
    if positive_costs:
        return min(positive_costs)
    return min(candidate_costs)


def _is_s3_standard_storage_product(product: dict[str, Any]) -> bool:
    product_data = product.get("product", {})
    if not isinstance(product_data, dict):
        return False

    if str(product_data.get("productFamily", "")).lower() != "storage":
        return False

    attributes = product_data.get("attributes", {})
    if not isinstance(attributes, dict):
        return False

    usage_type = str(attributes.get("usagetype", ""))
    if STORAGE_USAGE_TYPE_TOKEN not in usage_type:
        return False

    searchable = " ".join(
        str(attributes.get(key, "")).lower()
        for key in ("volumeType", "storageClass", "group", "groupDescription", "operation")
    )
    exclusions = (
        "infrequent",
        "one zone",
        "onezone",
        "glacier",
        "deep archive",
        "intelligent-tiering",
        "outposts",
        "express",
    )
    return not any(excluded in searchable for excluded in exclusions)


def _is_data_transfer_product(product: dict[str, Any], *, direction: str) -> bool:
    product_data = product.get("product", {})
    if not isinstance(product_data, dict):
        return False

    if str(product_data.get("productFamily", "")).lower() != "data transfer":
        return False

    attributes = product_data.get("attributes", {})
    if not isinstance(attributes, dict):
        return False

    transfer_type = str(attributes.get("transferType", "")).lower()
    to_location_type = str(attributes.get("toLocationType", "")).lower()

    if direction == "out":
        # Accept any outbound-to-internet style transfer, not just an exact match.
        if "outbound" not in transfer_type and "internet" not in to_location_type:
            return False

    usage_type = str(attributes.get("usagetype", ""))
    expected_token = TRANSFER_OUT_USAGE_TYPE_TOKEN if direction == "out" else TRANSFER_IN_USAGE_TYPE_TOKEN
    if expected_token not in usage_type:
        return False

    searchable = " ".join(
        str(attributes.get(key, "")).lower()
        for key in ("transferType", "group", "groupDescription", "toLocationType")
    )
    return "cloudfront" not in searchable


def _build_data_transfer_primary_filters(region: str) -> list[dict[str, str]]:
    """Build GetProducts filters for regional internet egress (DataTransfer-Out-Bytes)."""
    location = REGION_TO_S3_LOCATION.get(region)
    if location:
        return [
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Data Transfer"},
            {"Type": "TERM_MATCH", "Field": "fromLocation", "Value": location},
            {"Type": "TERM_MATCH", "Field": "transferType", "Value": "AWS Outbound"},
        ]
    return [
        {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Data Transfer"},
        {"Type": "TERM_MATCH", "Field": "regionCode", "Value": region},
        {"Type": "TERM_MATCH", "Field": "locationType", "Value": "AWS Region"},
        {"Type": "TERM_MATCH", "Field": "transferType", "Value": "AWS Outbound"},
    ]


def get_s3_storage_price_per_gb_month(region: str, usage_gb: float = 1.0, client: Any | None = None) -> float:
    primary_filters = [
        {"Type": "TERM_MATCH", "Field": "regionCode", "Value": region},
        {"Type": "TERM_MATCH", "Field": "locationType", "Value": "AWS Region"},
    ]
    products = _get_products(service_code="AmazonS3", filters=primary_filters, client=client)
    if not products:
        products = _get_products(
            service_code="AmazonS3",
            filters=[{"Type": "TERM_MATCH", "Field": "regionCode", "Value": region}],
            client=client,
        )
    return _pick_lowest_positive_rate(
        products=products,
        product_matcher=_is_s3_standard_storage_product,
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

    primary_filters = _build_data_transfer_primary_filters(region)
    products = _get_products(
        service_code=DATA_TRANSFER_PRICING_SERVICE_CODE,
        filters=primary_filters,
        client=client,
    )
    return _pick_lowest_positive_rate(
        products=products,
        product_matcher=lambda product: _is_data_transfer_product(product, direction=direction),
        usage_gb=usage_gb,
        error_message=f"No data transfer SKU found for region {region} and direction {direction}",
    )


def estimate_storage_cost(gb: float, region: str, rate_type: str) -> float:
    del rate_type
    primary_filters = [
        {"Type": "TERM_MATCH", "Field": "regionCode", "Value": region},
        {"Type": "TERM_MATCH", "Field": "locationType", "Value": "AWS Region"},
    ]
    products = _get_products(service_code="AmazonS3", filters=primary_filters)
    if not products:
        products = _get_products(
            service_code="AmazonS3",
            filters=[{"Type": "TERM_MATCH", "Field": "regionCode", "Value": region}],
        )
    return _pick_lowest_tiered_cost(
        products=products,
        product_matcher=_is_s3_standard_storage_product,
        usage_gb=gb,
        error_message=f"No S3 Standard storage SKU found for region {region}",
    )


def estimate_transfer_cost(gb: float, region: str, direction: str, rate_type: str) -> float:
    del rate_type
    if direction == "in":
        return 0.0

    primary_filters = _build_data_transfer_primary_filters(region)
    products = _get_products(service_code=DATA_TRANSFER_PRICING_SERVICE_CODE, filters=primary_filters)
    return _pick_lowest_tiered_cost(
        products=products,
        product_matcher=lambda product: _is_data_transfer_product(product, direction=direction),
        usage_gb=gb,
        error_message=f"No data transfer SKU found for region {region} and direction {direction}",
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
