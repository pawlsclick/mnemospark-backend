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
                for key in ("api_key", "apiKey", "value", "key"):
                    v = obj.get(key)
                    if isinstance(v, str) and v:
                        return v.strip()
        except json.JSONDecodeError:
            pass
    return raw


def _expected_key() -> str | None:
    global _cached_value, _cache_expires_at
    arn = os.environ.get("DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN", "").strip()
    if not arn:
        logger.error("DASHBOARD_GRAPHQL_API_KEY_SECRET_ARN is not set")
        return None
    now = time.monotonic()
    if _cached_value is not None and now < _cache_expires_at:
        return _cached_value
    try:
        resp = _client().get_secret_value(SecretId=arn)
    except Exception:
        logger.exception("GetSecretValue failed")
        return None
    raw = resp.get("SecretString")
    if raw is None:
        logger.error("Secret has no SecretString")
        return None
    _cached_value = _parse_secret_string(raw)
    _cache_expires_at = now + _CACHE_TTL_SEC
    return _cached_value


def _keys_equal(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    headers = event.get("headers") or {}
    provided = None
    for hk, hv in headers.items():
        if hk.lower() == "x-api-key":
            provided = hv
            break
    if not provided:
        return {"isAuthorized": False}

    expected = _expected_key()
    if not expected:
        return {"isAuthorized": False}

    if not _keys_equal(provided, expected):
        return {"isAuthorized": False}

    return {"isAuthorized": True, "context": {"principalId": "dashboard-graphql"}}
