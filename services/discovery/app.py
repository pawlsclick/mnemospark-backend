from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from common.http_response_headers import rest_api_json_headers


def _method(event: dict[str, Any]) -> str:
    raw = event.get("httpMethod")
    if isinstance(raw, str) and raw:
        return raw.upper()
    request_context = event.get("requestContext") or {}
    if isinstance(request_context, dict):
        http = request_context.get("http") or {}
        if isinstance(http, dict):
            method = http.get("method")
            if isinstance(method, str) and method:
                return method.upper()
    return ""


def _path(event: dict[str, Any]) -> str:
    raw = event.get("path")
    if isinstance(raw, str) and raw:
        return raw
    request_context = event.get("requestContext") or {}
    if isinstance(request_context, dict):
        http = request_context.get("http") or {}
        if isinstance(http, dict):
            path = http.get("path")
            if isinstance(path, str) and path:
                return path
    return ""


def _response(status_code: int, body_obj: dict[str, Any]) -> dict[str, Any]:
    headers = dict(rest_api_json_headers())
    return {
        "statusCode": int(status_code),
        "headers": headers,
        "body": json.dumps(body_obj),
    }


def _read_repo_file_text(rel_path: str) -> str:
    base = Path(__file__).resolve().parents[1]  # .../discovery/app.py -> Lambda package root
    target = (base / rel_path).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise RuntimeError("Invalid path traversal")
    return target.read_text(encoding="utf-8")


def _handle_openapi() -> dict[str, Any]:
    try:
        raw = _read_repo_file_text("docs/openapi.json")
    except FileNotFoundError:
        return _response(500, {"error": "openapi_missing", "message": "docs/openapi.json not found"})
    return {
        "statusCode": 200,
        "headers": {
            **rest_api_json_headers(),
            "Content-Type": "application/json",
        },
        "body": raw,
    }


def _handle_well_known_x402() -> dict[str, Any]:
    # NOTE: must be exactly this shape for the fallback discovery protocol.
    return _response(200, {"version": 1, "resources": ["POST /api/mnemospark-lite/upload"]})


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    method = _method(event)
    path = _path(event)

    if method == "GET" and path == "/openapi.json":
        return _handle_openapi()
    if method == "GET" and path == "/.well-known/x402":
        return _handle_well_known_x402()

    return _response(404, {"error": "not_found", "message": "Route not found"})

