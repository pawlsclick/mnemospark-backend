"""Shared HTTP response headers for API Gateway Lambda proxy integrations."""

from __future__ import annotations

import os


def _cors_allow_origin(env_var: str) -> str | None:
    """Return origin string, or None to omit Access-Control-Allow-Origin (explicit empty env)."""
    raw = os.environ.get(env_var)
    if raw is None:
        return "*"
    stripped = raw.strip()
    return stripped if stripped else None


def rest_api_json_headers() -> dict[str, str]:
    """JSON Content-Type, nosniff, and optional CORS origin for wallet REST Lambdas."""
    origin = _cors_allow_origin("MNEMOSPARK_CORS_ALLOW_ORIGIN")
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
    }
    if origin:
        headers["Access-Control-Allow-Origin"] = origin
    return headers
