from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable

import boto3

DEFAULT_TRANSFER_DIRECTION = "out"
DEFAULT_RATE_TYPE = "BEFORE_DISCOUNTS"
VALID_RATE_TYPES = (
    "BEFORE_DISCOUNTS",
    "AFTER_DISCOUNTS",
    "AFTER_DISCOUNTS_AND_COMMITMENTS",
)

# Internet egress rates for DataTransfer-Out-Bytes live under AWSDataTransfer in the Price List.
# Querying AmazonS3 can return a $0/GB SKU that wins min() and understates egress vs the calculator.
DATA_TRANSFER_PRICING_SERVICE_CODE = "AWSDataTransfer"
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


def get_pricing_client() -> Any:
    return boto3.client("pricing", region_name=PRICING_API_REGION)


def get_rate_type_from_env() -> str:
    rate_type = (os.getenv("PRICE_STORAGE_RATE_TYPE") or DEFAULT_RATE_TYPE).strip().upper()
    if rate_type not in VALID_RATE_TYPES:
        raise RuntimeError(
            "PRICE_STORAGE_RATE_TYPE must be one of "
            "BEFORE_DISCOUNTS, AFTER_DISCOUNTS, AFTER_DISCOUNTS_AND_COMMITMENTS"
        )
    return rate_type


def get_transfer_direction_from_env() -> str:
    direction = (os.getenv("PRICE_STORAGE_TRANSFER_DIRECTION") or DEFAULT_TRANSFER_DIRECTION).strip().lower()
    if direction not in {"in", "out"}:
        raise RuntimeError("PRICE_STORAGE_TRANSFER_DIRECTION must be in or out")
    return direction


def get_markup_multiplier_from_env() -> float:
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


def get_price_floor_from_env() -> float:
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


def _extract_ondemand_gb_price_dimensions(
    product: dict[str, Any], *, include_zero: bool = False
) -> list[dict[str, float]]:
    dimensions: list[dict[str, float]] = []
    for dimension, amount in _iter_ondemand_gb_dimensions(product, include_zero=include_zero):
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


def _extract_positive_ondemand_gb_rates(product: dict[str, Any]) -> list[float]:
    rates: list[float] = []
    for _dimension, amount in _iter_ondemand_gb_dimensions(product, include_zero=False):
        rates.append(amount)
    return rates


def _pick_lowest_tiered_cost(
    products: list[dict[str, Any]],
    product_matcher: Callable[[dict[str, Any]], bool],
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
    return min(candidate_costs)


def _is_s3_storage_product(product: dict[str, Any], *, region: str) -> bool:
    product_data = product.get("product", {})
    if not isinstance(product_data, dict):
        return False
    attributes = product_data.get("attributes", {})
    if not isinstance(attributes, dict):
        return False
    if str(product_data.get("productFamily", "")).lower() != "storage":
        return False
    if str(attributes.get("location", "")) != REGION_TO_S3_LOCATION.get(region):
        return False
    if str(attributes.get("servicecode", "")).lower() != "amazons3":
        return False
    usage_type = str(attributes.get("usagetype", ""))
    if STORAGE_USAGE_TYPE_TOKEN not in usage_type:
        return False
    return True


def _is_data_transfer_product(product: dict[str, Any], *, direction: str) -> bool:
    product_data = product.get("product", {})
    if not isinstance(product_data, dict):
        return False
    attributes = product_data.get("attributes", {})
    if not isinstance(attributes, dict):
        return False
    if str(product_data.get("productFamily", "")).lower() != "data transfer":
        return False
    usage_type = str(attributes.get("usagetype", ""))
    if direction == "out" and TRANSFER_OUT_USAGE_TYPE_TOKEN not in usage_type:
        return False
    if direction == "in" and TRANSFER_IN_USAGE_TYPE_TOKEN not in usage_type:
        return False
    transfer_type = str(attributes.get("transferType", "")).lower()
    to_location_type = str(attributes.get("toLocationType", "")).lower()
    if direction == "out":
        # Accept any outbound-to-internet style transfer, not just an exact match.
        if "outbound" not in transfer_type and "internet" not in to_location_type:
            return False
    return True


def _build_s3_storage_filters(region: str) -> list[dict[str, str]]:
    location = REGION_TO_S3_LOCATION.get(region)
    if not location:
        raise RuntimeError(f"Unsupported region: {region}")
    return [
        {"Type": "TERM_MATCH", "Field": "servicecode", "Value": "AmazonS3"},
        {"Type": "TERM_MATCH", "Field": "location", "Value": location},
    ]


def _build_data_transfer_primary_filters(region: str) -> list[dict[str, str]]:
    location = REGION_TO_S3_LOCATION.get(region)
    if not location:
        raise RuntimeError(f"Unsupported region: {region}")
    return [
        {"Type": "TERM_MATCH", "Field": "location", "Value": location},
        {"Type": "TERM_MATCH", "Field": "transferType", "Value": "AWS Outbound"},
    ]


def estimate_storage_cost(*, gb: float, region: str, rate_type: str, client: Any | None = None) -> float:
    products = _get_products("AmazonS3", _build_s3_storage_filters(region), client=client)
    return _pick_lowest_tiered_cost(
        products=products,
        product_matcher=lambda product: _is_s3_storage_product(product, region=region),
        usage_gb=gb,
        error_message=f"No S3 storage SKU found for region {region}",
    )


def estimate_transfer_cost(*, gb: float, region: str, direction: str, rate_type: str, client: Any | None = None) -> float:
    # rate_type is currently unused in this cost selection but kept to match callers.
    del rate_type
    products = _get_products(DATA_TRANSFER_PRICING_SERVICE_CODE, _build_data_transfer_primary_filters(region), client=client)
    return _pick_lowest_tiered_cost(
        products=products,
        product_matcher=lambda product: _is_data_transfer_product(product, direction=direction),
        usage_gb=gb,
        error_message=f"No data transfer SKU found for region {region} and direction {direction}",
    )


@dataclass(frozen=True)
class StorageQuoteUsd:
    usd: float
    storage_cost: float
    transfer_cost: float
    pre_markup_subtotal: float
    markup_multiplier: float
    price_floor: float
    rate_type: str
    transfer_direction: str


def calculate_storage_quote_usd(*, gb: float, region: str, pricing_client: Any | None = None) -> StorageQuoteUsd:
    rate_type = get_rate_type_from_env()
    direction = get_transfer_direction_from_env()
    markup_multiplier = get_markup_multiplier_from_env()
    price_floor = get_price_floor_from_env()

    storage_cost = estimate_storage_cost(gb=gb, region=region, rate_type=rate_type, client=pricing_client)
    transfer_cost = estimate_transfer_cost(gb=gb, region=region, direction=direction, rate_type=rate_type, client=pricing_client)

    pre_markup_subtotal = max(storage_cost + transfer_cost, price_floor)
    usd = round(pre_markup_subtotal * (1 + markup_multiplier), 2)
    return StorageQuoteUsd(
        usd=usd,
        storage_cost=storage_cost,
        transfer_cost=transfer_cost,
        pre_markup_subtotal=pre_markup_subtotal,
        markup_multiplier=markup_multiplier,
        price_floor=price_floor,
        rate_type=rate_type,
        transfer_direction=direction,
    )
