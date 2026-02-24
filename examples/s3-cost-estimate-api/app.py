"""
Lambda handler for S3 storage cost estimate REST API.

Accepts GET or POST with query params or JSON body: gb, region, rate_type.
Returns JSON: { estimatedCost, currency, storageGbMonth, region, rateType }.
"""

import json
import time
from typing import Any

import boto3

S3_STANDARD_STORAGE_USAGE_TYPE = "TimedStorage-ByteHrs"
VALID_RATE_TYPES = ("BEFORE_DISCOUNTS", "AFTER_DISCOUNTS", "AFTER_DISCOUNTS_AND_COMMITMENTS")


def estimate_s3_storage_cost(
    storage_gb_month: float,
    region: str = "us-east-1",
    rate_type: str = "BEFORE_DISCOUNTS",
    account_id: str | None = None,
) -> dict[str, Any]:
    client = boto3.client("bcm-pricing-calculator", region_name="us-east-1")
    if not account_id:
        account_id = boto3.client("sts").get_caller_identity()["Account"]

    create = client.create_workload_estimate(
        name="S3-storage-cost-estimate",
        rateType=rate_type,
    )
    workload_id = create["id"]

    try:
        client.batch_create_workload_estimate_usage(
            workloadEstimateId=workload_id,
            usage=[
                {
                    "serviceCode": "AmazonS3",
                    "usageType": S3_STANDARD_STORAGE_USAGE_TYPE,
                    "operation": "",
                    "key": "s3storage",
                    "usageAccountId": str(account_id),
                    "amount": float(storage_gb_month),
                    "group": "mnemospark",
                }
            ],
        )
        for _ in range(30):
            est = client.get_workload_estimate(identifier=workload_id)
            if est["status"] == "VALID":
                return est
            if est["status"] == "INVALID":
                raise RuntimeError(est.get("failureMessage", "Estimate invalid"))
            time.sleep(1)
        raise RuntimeError("Estimate did not become VALID in time")
    finally:
        client.delete_workload_estimate(identifier=workload_id)


def parse_input(event: dict[str, Any]) -> dict[str, Any]:
    """Extract gb, region, rate_type from API Gateway event (query or body)."""
    params = event.get("queryStringParameters") or {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
            params = {**params, **body}
        except json.JSONDecodeError:
            pass
    gb = float(params.get("gb", params.get("storageGbMonth", 100)))
    region = params.get("region", "us-east-1")
    rate_type = params.get("rate_type", params.get("rateType", "BEFORE_DISCOUNTS"))
    if rate_type not in VALID_RATE_TYPES:
        rate_type = "BEFORE_DISCOUNTS"
    return {"gb": gb, "region": region, "rate_type": rate_type}


def response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body),
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        inp = parse_input(event)
        result = estimate_s3_storage_cost(
            storage_gb_month=inp["gb"],
            region=inp["region"],
            rate_type=inp["rate_type"],
        )
        return response(200, {
            "estimatedCost": round(result["totalCost"], 2),
            "currency": result["costCurrency"],
            "storageGbMonth": inp["gb"],
            "region": inp["region"],
            "rateType": inp["rate_type"],
        })
    except (ValueError, KeyError) as e:
        return response(400, {"error": "Bad request", "message": str(e)})
    except Exception as e:
        return response(500, {"error": "Internal error", "message": str(e)})
