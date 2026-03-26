"""Lambda handler: HTTP API (v2) + GraphQL via Strawberry."""

from __future__ import annotations

import json
import logging
from typing import Any

from mangum import Mangum
from strawberry.asgi import GraphQL

try:
    from dashboard_graphql.schema import schema
except ModuleNotFoundError as error:  # pragma: no cover - runtime path when CodeUri is services/dashboard_graphql
    if error.name != "dashboard_graphql":
        raise
    from schema import schema

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_graphql_app = Mangum(GraphQL(schema), lifespan="off")


def _ensure_http_context_for_mangum(event: dict[str, Any]) -> None:
    """Mangum's API Gateway adapter expects requestContext.http.sourceIp; direct invokes omit it."""
    if event.get("version") != "2.0":
        return
    try:
        http = event["requestContext"]["http"]
        if isinstance(http, dict) and "sourceIp" not in http:
            http["sourceIp"] = "127.0.0.1"
    except (KeyError, TypeError):
        return


def _cors_headers() -> dict[str, str]:
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Headers": "content-type,x-api-key,authorization,x-amz-date,x-amz-security-token",
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    _ensure_http_context_for_mangum(event)
    method = (
        event.get("requestContext", {})
        .get("http", {})
        .get("method", event.get("httpMethod") or "")
        .upper()
    )
    path = event.get("rawPath") or event.get("path") or ""

    if method == "OPTIONS" and path.rstrip("/").endswith("/graphql"):
        return {
            "statusCode": 204,
            "headers": _cors_headers(),
            "body": "",
        }

    try:
        response = _graphql_app(event, context)
    except Exception:
        logger.exception("dashboard_graphql unhandled error")
        return {
            "statusCode": 500,
            "headers": {**_cors_headers(), "Content-Type": "application/json"},
            "body": json.dumps({"errors": [{"message": "Internal server error"}]}),
        }

    headers = dict(response.get("headers") or {})
    for k, v in _cors_headers().items():
        headers.setdefault(k, v)
    response["headers"] = headers
    return response
