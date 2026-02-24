"""
Lambda handler for mnemospark /estimate/storage.

Accepts GET or POST with query params and/or JSON body:
  - gb (required)
  - region (optional, default us-east-1)
  - rateType (optional, default BEFORE_DISCOUNTS)
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import boto3

DEFAULT_REGION = "us-east-1"
DEFAULT_RATE_TYPE = "BEFORE_DISCOUNTS"
VALID_RATE_TYPES = (
    "BEFORE_DISCOUNTS",
    "AFTER_DISCOUNTS",
    "AFTER_DISCOUNTS_AND_COMMITMENTS",
)
S3_STANDARD_STORAGE_USAGE_TYPE = "TimedStorage-ByteHrs"
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
    Extract and validate gb, region, and rateType from API Gateway event.
    """
    params = _collect_request_params(event)

    if "gb" not in params and "storageGbMonth" not in params:
        raise BadRequestError("gb is required")

    raw_gb = params.get("gb", params.get("storageGbMonth"))
    try:
        gb = float(raw_gb)
    except (TypeError, ValueError) as exc:
        raise BadRequestError("gb must be a number") from exc

    if gb <= 0:
        raise BadRequestError("gb must be greater than 0")

    region = str(params.get("region", DEFAULT_REGION)).strip() or DEFAULT_REGION
    rate_type = _normalize_rate_type(params.get("rateType", params.get("rate_type")))

    return {
        "gb": gb,
        "region": region,
        "rateType": rate_type,
    }


def estimate_s3_storage_cost(
    storage_gb_month: float,
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

    The BCM service endpoint currently lives in us-east-1, so that client region
    is fixed while the user-selected storage region is echoed in API responses.
    """
    if storage_gb_month <= 0:
        raise ValueError("storage_gb_month must be greater than 0")
    if rate_type not in VALID_RATE_TYPES:
        raise ValueError("invalid rate_type")

    bcm_client = pricing_client or boto3.client("bcm-pricing-calculator", region_name="us-east-1")
    identity_client = sts_client or boto3.client("sts")
    resolved_account_id = account_id or identity_client.get_caller_identity()["Account"]

    create_response = bcm_client.create_workload_estimate(
        name=f"mnemospark-s3-storage-{int(time.time() * 1000)}",
        rateType=rate_type,
    )
    workload_id = create_response["id"]

    try:
        bcm_client.batch_create_workload_estimate_usage(
            workloadEstimateId=workload_id,
            usage=[
                {
                    "serviceCode": "AmazonS3",
                    "usageType": S3_STANDARD_STORAGE_USAGE_TYPE,
                    "operation": "",
                    "key": "s3-storage-gb-month",
                    "usageAccountId": str(resolved_account_id),
                    "amount": float(storage_gb_month),
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
        "storageGbMonth": request_params["gb"],
        "region": request_params["region"],
        "rateType": request_params["rateType"],
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        parsed = parse_input(event)
        estimate = estimate_s3_storage_cost(
            storage_gb_month=parsed["gb"],
            region=parsed["region"],
            rate_type=parsed["rateType"],
        )
        return response(200, _success_body(estimate, parsed))
    except BadRequestError as exc:
        return response(400, {"error": "Bad request", "message": str(exc)})
    except Exception as exc:
        return response(500, {"error": "Internal error", "message": str(exc)})
