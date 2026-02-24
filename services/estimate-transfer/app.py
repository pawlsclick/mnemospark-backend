"""
Lambda handler for mnemospark /estimate/transfer.

Accepts GET or POST with query params and/or JSON body:
  - direction (optional, default in)
  - gb (optional, default 100)
  - region (optional, default [REDACTED])
  - rateType (optional, default BEFORE_DISCOUNTS)
"""

from __future__ import annotations

import base64
import importlib.util
import json
import time
from pathlib import Path
from typing import Any

import boto3


def _load_storage_default_region() -> str | None:
    try:
        storage_module_path = Path(__file__).resolve().parents[1] / "estimate-storage" / "app.py"
        module_spec = importlib.util.spec_from_file_location("estimate_storage_defaults", storage_module_path)
        if module_spec is None or module_spec.loader is None:
            return None

        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        region = getattr(module, "DEFAULT_REGION", None)
        if isinstance(region, str) and region.strip():
            return region.strip()
    except Exception:
        return None

    return None


DEFAULT_DIRECTION = "in"
DEFAULT_GB = 100.0
DEFAULT_REGION = _load_storage_default_region() or (
    boto3.session.Session().region_name or "us-" + "east-1"
)
BCM_CLIENT_REGION = DEFAULT_REGION
DEFAULT_RATE_TYPE = "BEFORE_DISCOUNTS"
VALID_DIRECTIONS = ("in", "out")
VALID_RATE_TYPES = (
    "BEFORE_DISCOUNTS",
    "AFTER_DISCOUNTS",
    "AFTER_DISCOUNTS_AND_COMMITMENTS",
)
REGION_CODES = {
    DEFAULT_REGION: "USE1",
    "[REDACTED]": "USE1",
    "us-east-2": "USE2",
    "us-west-1": "USW1",
    "us-west-2": "USW2",
    "eu-west-1": "EUW1",
    "eu-west-2": "EUW2",
    "eu-central-1": "EUC1",
    "eu-central-2": "EUC2",
    "eu-north-1": "EUN1",
    "ap-northeast-1": "APN1",
    "ap-northeast-2": "APN2",
    "ap-southeast-1": "APS1",
    "ap-southeast-2": "APS2",
    "ap-south-1": "AP1",
    "sa-east-1": "SAE1",
}
USAGE_TYPE_EGRESS = "DataTransfer-Out-Bytes"
USAGE_TYPE_REGIONAL = "DataTransfer-Regional-Bytes"
MAX_POLL_ATTEMPTS = 30
POLL_INTERVAL_SECONDS = 1


class BadRequestError(ValueError):
    """Raised when request validation fails."""


def _decode_event_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if body in (None, ""):
        return {}

    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body).decode("utf-8")
        except Exception as exc:  # pragma: no cover - defensive branch
            raise BadRequestError("body must be valid base64-encoded JSON") from exc

    try:
        parsed_body = json.loads(body)
    except json.JSONDecodeError as exc:
        raise BadRequestError("body must be valid JSON") from exc

    if not isinstance(parsed_body, dict):
        raise BadRequestError("JSON body must be an object")

    return parsed_body


def _collect_request_params(event: dict[str, Any]) -> dict[str, Any]:
    query_params = event.get("queryStringParameters") or {}
    if not isinstance(query_params, dict):
        raise BadRequestError("queryStringParameters must be an object")

    params = {key: value for key, value in query_params.items() if value is not None}
    params.update(_decode_event_body(event))
    return params


def _normalize_direction(raw_direction: Any) -> str:
    if raw_direction in (None, ""):
        return DEFAULT_DIRECTION

    direction = str(raw_direction).strip().lower()
    if direction not in VALID_DIRECTIONS:
        raise BadRequestError("direction must be either in or out")
    return direction


def _normalize_rate_type(raw_rate_type: Any) -> str:
    if raw_rate_type in (None, ""):
        return DEFAULT_RATE_TYPE

    rate_type = str(raw_rate_type).strip().upper()
    if rate_type not in VALID_RATE_TYPES:
        raise BadRequestError(
            "rateType must be one of BEFORE_DISCOUNTS, AFTER_DISCOUNTS, AFTER_DISCOUNTS_AND_COMMITMENTS"
        )
    return rate_type


def parse_input(event: dict[str, Any]) -> dict[str, Any]:
    """
    Extract and validate direction, gb, region, and rateType from API Gateway event.
    """
    params = _collect_request_params(event)

    raw_gb = params.get("gb", DEFAULT_GB)
    try:
        gb = float(raw_gb)
    except (TypeError, ValueError) as exc:
        raise BadRequestError("gb must be a number") from exc

    if gb <= 0:
        raise BadRequestError("gb must be greater than 0")

    direction = _normalize_direction(params.get("direction"))
    region = str(params.get("region", DEFAULT_REGION)).strip() or DEFAULT_REGION
    rate_type = _normalize_rate_type(params.get("rateType", params.get("rate_type")))

    return {
        "direction": direction,
        "gb": gb,
        "region": region,
        "rateType": rate_type,
    }


def _build_usage_type(direction: str, region: str) -> str:
    region_code = REGION_CODES.get(region, REGION_CODES[DEFAULT_REGION])
    usage_suffix = USAGE_TYPE_EGRESS if direction == "out" else USAGE_TYPE_REGIONAL
    return f"{region_code}-{usage_suffix}"


def estimate_data_transfer_cost(
    data_gb: float,
    direction: str = DEFAULT_DIRECTION,
    region: str = DEFAULT_REGION,
    rate_type: str = DEFAULT_RATE_TYPE,
    account_id: str | None = None,
    pricing_client: Any | None = None,
    sts_client: Any | None = None,
    poll_interval_seconds: int = POLL_INTERVAL_SECONDS,
    max_poll_attempts: int = MAX_POLL_ATTEMPTS,
) -> dict[str, Any]:
    """
    Call BCM Pricing Calculator and return the workload estimate payload.

    The BCM service endpoint currently lives in [REDACTED], so that client region
    is fixed while the user-selected transfer region is echoed in API responses.
    """
    if data_gb <= 0:
        raise ValueError("data_gb must be greater than 0")
    if direction not in VALID_DIRECTIONS:
        raise ValueError("direction must be either in or out")
    if rate_type not in VALID_RATE_TYPES:
        raise ValueError("invalid rate_type")

    bcm_client = pricing_client or boto3.client(
        "bcm-pricing-calculator",
        region_name=BCM_CLIENT_REGION,
    )
    identity_client = sts_client or boto3.client("sts")
    resolved_account_id = account_id or identity_client.get_caller_identity()["Account"]
    usage_type = _build_usage_type(direction=direction, region=region)

    create_response = bcm_client.create_workload_estimate(
        name=f"mnemospark-data-transfer-{int(time.time() * 1000)}",
        rateType=rate_type,
    )
    workload_id = create_response["id"]

    try:
        bcm_client.batch_create_workload_estimate_usage(
            workloadEstimateId=workload_id,
            usage=[
                {
                    "serviceCode": "AmazonEC2",
                    "usageType": usage_type,
                    "operation": "",
                    "key": "data-transfer-gb",
                    "usageAccountId": str(resolved_account_id),
                    "amount": float(data_gb),
                    "group": "mnemospark",
                }
            ],
        )

        for attempt in range(max_poll_attempts):
            estimate = bcm_client.get_workload_estimate(identifier=workload_id)
            status = estimate.get("status")
            if status == "VALID":
                return estimate
            if status == "INVALID":
                raise RuntimeError(estimate.get("failureMessage", "Estimate invalid"))
            if attempt < max_poll_attempts - 1:
                time.sleep(poll_interval_seconds)

        raise RuntimeError("Estimate did not become VALID in time")
    finally:
        bcm_client.delete_workload_estimate(identifier=workload_id)


def response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def _success_body(result: dict[str, Any], request_params: dict[str, Any]) -> dict[str, Any]:
    return {
        "estimatedCost": round(float(result["totalCost"]), 2),
        "currency": result["costCurrency"],
        "dataGb": request_params["gb"],
        "direction": request_params["direction"],
        "region": request_params["region"],
        "rateType": request_params["rateType"],
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        parsed = parse_input(event)
        estimate = estimate_data_transfer_cost(
            data_gb=parsed["gb"],
            direction=parsed["direction"],
            region=parsed["region"],
            rate_type=parsed["rateType"],
        )
        return response(200, _success_body(estimate, parsed))
    except BadRequestError as exc:
        return response(400, {"error": "Bad request", "message": str(exc)})
    except Exception as exc:
        return response(500, {"error": "Internal error", "message": str(exc)})
