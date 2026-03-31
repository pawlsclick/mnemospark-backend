"""Lambda handler: HTTP API (v2) + GraphQL via Strawberry."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from mangum import Mangum
from strawberry.asgi import GraphQL

try:
    from dashboard_graphql.request_context import DashboardRequestContext
    from dashboard_graphql.schema import schema
except ModuleNotFoundError as error:  # pragma: no cover - runtime path when CodeUri is services/dashboard_graphql
    if error.name != "dashboard_graphql":
        raise
    from request_context import DashboardRequestContext  # type: ignore[no-redef]
    from schema import schema  # type: ignore[no-redef]

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class DashboardGraphQL(GraphQL):
    """Adds per-request cache for expensive DynamoDB scans (see request_context)."""

    async def get_context(self, request, response):  # type: ignore[no-untyped-def]
        ctx = await super().get_context(request, response)
        if isinstance(ctx, dict):
            ctx = dict(ctx)
            ctx["dashboard"] = DashboardRequestContext()
        return ctx


_graphql_app = Mangum(DashboardGraphQL(schema, graphql_ide=None), lifespan="off")


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


def _cors_allow_origin() -> str | None:
    """Echo deploy-time origin; omit header if explicitly empty (CodeUri has no common/ package)."""
    raw = os.environ.get("DASHBOARD_GRAPHQL_CORS_ALLOW_ORIGIN")
    if raw is None:
        return "*"
    stripped = raw.strip()
    return stripped if stripped else None


def _cors_headers() -> dict[str, str]:
    origin = _cors_allow_origin()
    h: dict[str, str] = {
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Headers": "content-type,x-api-key,authorization,x-amz-date,x-amz-security-token",
        "X-Content-Type-Options": "nosniff",
    }
    if origin:
        h["Access-Control-Allow-Origin"] = origin
    return h


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
            "headers": {
                "Content-Type": "application/json",
                "X-Content-Type-Options": "nosniff",
            },
            "body": json.dumps({"errors": [{"message": "Internal server error"}]}),
        }

    headers = dict(response.get("headers") or {})
    headers.setdefault("X-Content-Type-Options", "nosniff")
    response["headers"] = headers
    return response
