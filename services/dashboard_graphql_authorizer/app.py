"""HTTP API Lambda authorizer: validates x-api-key against Secrets Manager."""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_secret_client = None
_cached_value: str | None = None
_cache_expires_at: float = 0.0
_CACHE_TTL_SEC = 300.0


def _client():
    global _secret_client
    if _secret_client is None:
        _secret_client = boto3.client("secretsmanager")
    return _secret_client


def _parse_secret_string(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith("{") and raw.endswith("}"):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                for key in ("api_key", "apiKey", "api_key_dashboard", "value", "key"):
                    v = obj.get(key)
                    if isinstance(v, str) and v:
                        return v.strip()
        except json.JSONDecodeError:
            pass
    return raw


def _expected_key() -> str | None:
    global _cached_value, _cache_expires_at
    secret_id = os.environ.get("DASHBOARD_GRAPHQL_API_KEY_SECRET_ID", "").strip()
    if not secret_id:
        logger.error("DASHBOARD_GRAPHQL_API_KEY_SECRET_ID is not set")
        return None
    now = time.monotonic()
    if _cached_value and now < _cache_expires_at:
        return _cached_value
    try:
        resp = _client().get_secret_value(SecretId=secret_id)
    except Exception:
        logger.exception("GetSecretValue failed")
        return None
    raw = resp.get("SecretString")
    if raw is None:
        logger.error("Secret has no SecretString")
        return None
    parsed = _parse_secret_string(raw)
    if not parsed:
        logger.error("SecretString parsed to an empty API key")
        return None
    _cached_value = parsed
    _cache_expires_at = now + _CACHE_TTL_SEC
    return _cached_value


def _keys_equal(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _extract_x_api_key(event: dict[str, Any]) -> str | None:
    """Resolve x-api-key from headers and/or identitySource (HTTP API REQUEST authorizer)."""
    headers = event.get("headers") or {}
    if isinstance(headers, dict):
        for hk, hv in headers.items():
            if hk.lower() != "x-api-key":
                continue
            if isinstance(hv, str):
                s = hv.strip()
                if s:
                    return s
            if isinstance(hv, list) and hv and isinstance(hv[0], str):
                s = hv[0].strip()
                if s:
                    return s

    # API Gateway fills identitySource with resolved $request.header.x-api-key values.
    sources = event.get("identitySource")
    if isinstance(sources, list):
        for item in sources:
            if not isinstance(item, str):
                continue
            s = item.strip()
            if not s or s.startswith("$"):
                continue
            return s
    return None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    provided = _extract_x_api_key(event)
    if not provided:
        logger.info("Authorizer deny: missing x-api-key (check headers and identitySource)")
        return {"isAuthorized": False}

    expected = _expected_key()
    if not expected:
        logger.info("Authorizer deny: expected key unavailable (secret id or Secrets Manager)")
        return {"isAuthorized": False}

    if not _keys_equal(provided, expected):
        logger.info(
            "Authorizer deny: key mismatch (length provided=%s expected=%s)",
            len(provided),
            len(expected),
        )
        return {"isAuthorized": False}

    return {"isAuthorized": True, "context": {"principalId": "dashboard-graphql"}}
