"""
Lambda handler for data transfer cost estimate REST API.

Accepts GET or POST with query params or JSON body: direction, gb, region, rate_type.
Returns JSON: { estimatedCost, currency, dataGb, direction, region, rateType }.
"""

import json
import time
from typing import Any

import boto3

REGION_CODES = {
    "us-east-1": "USE1",
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
VALID_RATE_TYPES = ("BEFORE_DISCOUNTS", "AFTER_DISCOUNTS", "AFTER_DISCOUNTS_AND_COMMITMENTS")


def estimate_data_transfer_cost(
    data_gb: float,
    direction: str,
    region: str = "us-east-1",
    rate_type: str = "BEFORE_DISCOUNTS",
    account_id: str | None = None,
) -> dict[str, Any]:
    client = boto3.client("bcm-pricing-calculator", region_name="us-east-1")
    if not account_id:
        account_id = boto3.client("sts").get_caller_identity()["Account"]

    region_code = REGION_CODES.get(region, "USE1")
    usage_type = f"{region_code}-{USAGE_TYPE_EGRESS}" if direction == "out" else f"{region_code}-{USAGE_TYPE_REGIONAL}"

    create = client.create_workload_estimate(
        name="DataTransfer-cost-est",
        rateType=rate_type,
    )
    workload_id = create["id"]

    try:
        client.batch_create_workload_estimate_usage(
            workloadEstimateId=workload_id,
            usage=[
                {
                    "serviceCode": "AmazonEC2",
                    "usageType": usage_type,
                    "operation": "",
                    "key": "dtxfer01",
                    "usageAccountId": str(account_id),
                    "amount": float(data_gb),
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
    """Extract direction, gb, region, rate_type from API Gateway event (query or body)."""
    params = event.get("queryStringParameters") or {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
            params = {**params, **body}
        except json.JSONDecodeError:
            pass
    direction = (params.get("direction") or "in").lower()
    if direction not in ("in", "out"):
        direction = "in"
    gb = float(params.get("gb", 100))
    region = params.get("region", "us-east-1")
    rate_type = params.get("rate_type", params.get("rateType", "BEFORE_DISCOUNTS"))
    if rate_type not in VALID_RATE_TYPES:
        rate_type = "BEFORE_DISCOUNTS"
    return {"direction": direction, "gb": gb, "region": region, "rate_type": rate_type}


def response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body),
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        inp = parse_input(event)
        result = estimate_data_transfer_cost(
            data_gb=inp["gb"],
            direction=inp["direction"],
            region=inp["region"],
            rate_type=inp["rate_type"],
        )
        return response(200, {
            "estimatedCost": round(result["totalCost"], 2),
            "currency": result["costCurrency"],
            "dataGb": inp["gb"],
            "direction": inp["direction"],
            "region": inp["region"],
            "rateType": inp["rate_type"],
        })
    except (ValueError, KeyError) as e:
        return response(400, {"error": "Bad request", "message": str(e)})
    except Exception as e:
        return response(500, {"error": "Internal error", "message": str(e)})
