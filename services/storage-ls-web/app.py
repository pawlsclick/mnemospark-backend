"""
Lambda handler for ls-web BFF: session mint (wallet proof), exchange (code → cookie),
list (session cookie), batch presigned download.

Routes (dispatch by API Gateway path):
  POST /storage/ls-web/session   — wallet authorizer; returns one-time code + app URL
  POST /storage/ls-web/exchange — JSON { code }; Set-Cookie session
  POST /storage/ls-web/list      — cookie session; S3 list same semantics as /storage/ls list mode
  POST /storage/ls-web/download — cookie session; JSON { object_keys } (max 25)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, cast
from urllib.parse import quote

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

try:
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        NOT_FOUND_S3_ERROR_CODES,
        S3ListBucketAccessError,
        S3ListContinuationError,
        bucket_name_from_wallet,
        coerce_presigned_ttl_seconds,
        decode_json_event_body,
        get_required_authorizer_wallet,
        list_objects_v2_page,
        normalize_wallet_address,
        parse_list_max_keys_field,
        parse_optional_string_param,
        s3_error_code,
        s3_not_found_for_download,
        s3_last_modified_iso_utc,
        validate_bucket_naming_rules,
        validate_object_key_single_segment,
    )
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        NOT_FOUND_S3_ERROR_CODES,
        S3ListBucketAccessError,
        S3ListContinuationError,
        bucket_name_from_wallet,
        coerce_presigned_ttl_seconds,
        decode_json_event_body,
        get_required_authorizer_wallet,
        list_objects_v2_page,
        normalize_wallet_address,
        parse_list_max_keys_field,
        parse_optional_string_param,
        s3_error_code,
        s3_not_found_for_download,
        s3_last_modified_iso_utc,
        validate_bucket_naming_rules,
        validate_object_key_single_segment,
    )

log_api_call = load_log_api_call()
_log_api_call_result = load_log_api_call_result(
    "/storage/ls-web",
    log_api_call_getter=lambda: log_api_call,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_LOCATION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION
SESSION_TTL_SECONDS = 21600
COOKIE_NAME = "mnemospark_ls_web"
DOWNLOAD_MAX_KEYS = 25
DEFAULT_LIST_MAX_KEYS = 1000
LIST_MAX_KEYS_CAP = 1000
DEFAULT_PRESIGNED_TTL_SECONDS = int(os.environ.get("STORAGE_DOWNLOAD_URL_TTL_SECONDS", "300"))


def _ls_web_cookie_domain() -> str | None:
    """Return Domain= value, or None to omit (host-only cookie).

    Staging uses literal **host-only** in CloudFormation because empty Lambda env
    values are often dropped, which would otherwise fall back to .mnemospark.ai and
    break Set-Cookie from execute-api hosts.
    """
    if "LS_WEB_COOKIE_DOMAIN" not in os.environ:
        return ".mnemospark.ai"
    raw = os.environ["LS_WEB_COOKIE_DOMAIN"].strip()
    if not raw or raw.lower() == "host-only":
        return None
    return raw


def _ls_web_cookie_same_site() -> str:
    raw = (os.environ.get("LS_WEB_COOKIE_SAMESITE") or "Lax").strip() or "Lax"
    if raw not in ("Lax", "Strict", "None"):
        return "Lax"
    return raw


def _ls_web_set_cookie_header(session_id: str, max_age: int) -> str:
    parts = [
        f"{COOKIE_NAME}={session_id}",
        "HttpOnly",
        "Secure",
    ]
    domain = _ls_web_cookie_domain()
    if domain:
        parts.append(f"Domain={domain}")
    parts.extend(["Path=/", f"SameSite={_ls_web_cookie_same_site()}", f"Max-Age={max_age}"])
    return "; ".join(parts)


class UnauthorizedError(ValueError):
    pass


class MethodNotAllowedError(ValueError):
    pass


@dataclass(frozen=True)
class NotFoundError(Exception):
    error: str
    message: str


def _ls_web_cors_origin() -> str:
    raw = os.environ.get("MNEMOSPARK_LS_WEB_CORS_ORIGIN", "https://app.mnemospark.ai").strip()
    return raw or "https://app.mnemospark.ai"


def _ls_web_cors_headers() -> dict[str, str]:
    return {
        "Access-Control-Allow-Origin": _ls_web_cors_origin(),
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": (
            "Content-Type,Cookie,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token"
        ),
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Vary": "Origin",
    }


def _json_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    h: dict[str, str] = {
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
    }
    h.update(_ls_web_cors_headers())
    if extra:
        h.update(extra)
    return h


def _response(status_code: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    merged = _json_headers()
    if headers:
        merged.update(headers)
    return {"statusCode": status_code, "headers": merged, "body": json.dumps(body, default=str)}


def _error_response(status_code: int, error: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body)


def _exchange_invalid_response(
    event: dict[str, Any],
    context: Any,
    *,
    message: str = "Invalid or expired exchange code.",
) -> dict[str, Any]:
    _log_api_call_result(
        event,
        context,
        status_code=401,
        result="unauthorized",
        error_code="invalid_or_expired_code",
        error_message=message,
        wallet_address=None,
        object_key=None,
    )
    return _error_response(401, "invalid_or_expired_code", message)


def _s3_storage_head_not_found(exc: ClientError) -> bool:
    return s3_error_code(exc) in NOT_FOUND_S3_ERROR_CODES


def _api_path(event: dict[str, Any]) -> str:
    ctx = event.get("requestContext") or {}
    rp = ctx.get("resourcePath")
    if isinstance(rp, str) and rp:
        return rp
    p = event.get("path") or ""
    if not isinstance(p, str):
        return "/"
    stage = ctx.get("stage")
    if isinstance(stage, str) and stage and p.startswith(f"/{stage}/"):
        return "/" + p.split("/", 2)[-1]
    return p


def _parse_cookies(event: dict[str, Any]) -> dict[str, str]:
    headers = event.get("headers") or {}
    raw = ""
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "cookie" and v is not None:
                raw = str(v)
                break
    out: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _session_table() -> Any:
    name = os.environ.get("LS_WEB_SESSION_TABLE_NAME", "").strip()
    if not name:
        raise RuntimeError("LS_WEB_SESSION_TABLE_NAME is not configured")
    return boto3.resource("dynamodb").Table(name)


def _num_to_int(v: Any) -> int:
    if isinstance(v, Decimal):
        return int(v)
    if isinstance(v, bool):
        return int(v)
    return int(v)


def _hash_exchange_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _iso_from_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _list_objects_ls_web(
    s3_client: Any,
    bucket_name: str,
    *,
    max_keys: int,
    continuation_token: str | None,
    prefix: str | None,
) -> dict[str, Any]:
    try:
        return list_objects_v2_page(
            s3_client,
            bucket_name,
            max_keys=max_keys,
            continuation_token=continuation_token,
            prefix=prefix,
        )
    except S3ListBucketAccessError as exc:
        raise NotFoundError("bucket_not_found", "Bucket not found for this wallet") from exc
    except S3ListContinuationError as exc:
        raise BadRequestError(str(exc)) from exc


def handle_options(_event: dict[str, Any], _context: Any) -> dict[str, Any]:
    return {"statusCode": 204, "headers": _ls_web_cors_headers(), "body": ""}


def handle_mint(event: dict[str, Any], context: Any) -> dict[str, Any]:
    wallet = get_required_authorizer_wallet(event)
    body = decode_json_event_body(event)
    location = str(body.get("location") or body.get("region") or DEFAULT_LOCATION).strip() or DEFAULT_LOCATION
    now = int(time.time())
    expires_at = now + SESSION_TTL_SECONDS
    session_id = secrets.token_urlsafe(32)
    code = secrets.token_urlsafe(32)
    code_hash = _hash_exchange_code(code)
    table = _session_table()
    table.put_item(
        Item={
            "session_id": session_id,
            "wallet_address": wallet,
            "location": location,
            "exchange_code_hash": code_hash,
            "exchanged": False,
            "session_expires_at": expires_at,
            "expires_at": expires_at,
        },
        ConditionExpression="attribute_not_exists(session_id)",
    )
    app_base = os.environ.get("MNEMOSPARK_LS_WEB_APP_URL", "https://app.mnemospark.ai").strip().rstrip("/")
    prefix_query = os.environ.get("MNEMOSPARK_LS_WEB_APP_PREFIX_QUERY", "").strip()
    enc = quote(code, safe="")
    if prefix_query:
        app = f"{app_base}/?{prefix_query}&code={enc}"
    else:
        app = f"{app_base}/?code={enc}"
    body_out = {
        "success": True,
        "code": code,
        "app": app,
        "expires_at": _iso_from_epoch(expires_at),
    }
    _log_api_call_result(
        event,
        context,
        status_code=200,
        result="success",
        wallet_address=wallet,
        object_key=None,
    )
    return _response(200, body_out)


def handle_exchange(event: dict[str, Any], context: Any) -> dict[str, Any]:
    body = decode_json_event_body(event)
    code_raw = body.get("code")
    if not isinstance(code_raw, str) or not code_raw.strip():
        raise BadRequestError("code is required")
    code = code_raw.strip()
    code_hash = _hash_exchange_code(code)
    table = _session_table()
    resp = table.query(
        IndexName="GsiExchangeCode",
        KeyConditionExpression=Key("exchange_code_hash").eq(code_hash),
        Limit=1,
    )
    items = resp.get("Items") or []
    if not items:
        return _exchange_invalid_response(event, context)
    row = items[0]
    session_id = row.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return _exchange_invalid_response(event, context)
    now = int(time.time())
    try:
        table.update_item(
            Key={"session_id": session_id},
            UpdateExpression="SET exchanged = :t REMOVE exchange_code_hash",
            ConditionExpression=(
                "exchanged = :f AND session_expires_at > :now AND exchange_code_hash = :h"
            ),
            ExpressionAttributeValues={
                ":t": True,
                ":f": False,
                ":now": now,
                ":h": code_hash,
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return _exchange_invalid_response(event, context)
        raise
    exp = _num_to_int(row.get("session_expires_at", 0))
    max_age = max(0, exp - now)
    set_cookie = _ls_web_set_cookie_header(session_id, max_age)
    _log_api_call_result(
        event,
        context,
        status_code=200,
        result="success",
        wallet_address=str(row.get("wallet_address") or ""),
        object_key=None,
    )
    return _response(200, {"success": True}, headers={"Set-Cookie": set_cookie})


def _load_session_from_cookie(event: dict[str, Any]) -> dict[str, Any]:
    cookies = _parse_cookies(event)
    sid = cookies.get(COOKIE_NAME, "").strip()
    if not sid:
        raise UnauthorizedError("session cookie is required")
    table = _session_table()
    row = table.get_item(Key={"session_id": sid}).get("Item")
    if not row:
        raise UnauthorizedError("session not found or expired")
    now = int(time.time())
    exp = _num_to_int(row.get("session_expires_at", 0))
    if exp <= now:
        raise UnauthorizedError("session has expired")
    if not row.get("exchanged"):
        raise UnauthorizedError("session is not active")
    return row


def handle_list(event: dict[str, Any], context: Any) -> dict[str, Any]:
    session = _load_session_from_cookie(event)
    wallet = cast(str, session["wallet_address"])
    wallet = normalize_wallet_address(wallet, "wallet_address")
    body = decode_json_event_body(event)
    continuation_token = parse_optional_string_param(body, "continuation_token")
    prefix = parse_optional_string_param(body, "prefix")
    max_keys = parse_list_max_keys_field(
        body.get("max_keys"),
        default=DEFAULT_LIST_MAX_KEYS,
        cap=LIST_MAX_KEYS_CAP,
    )
    location = str(
        body.get("location") or body.get("region") or session.get("location") or DEFAULT_LOCATION
    ).strip() or DEFAULT_LOCATION

    s3_client = boto3.client("s3", region_name=location)
    bucket_name = bucket_name_from_wallet(wallet)
    try:
        validate_bucket_naming_rules(bucket_name)
    except ValueError as exc:
        raise BadRequestError(str(exc)) from exc

    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if _s3_storage_head_not_found(exc):
            raise NotFoundError("bucket_not_found", "Bucket not found for this wallet.") from exc
        raise

    list_resp = _list_objects_ls_web(
        s3_client,
        bucket_name,
        max_keys=max_keys,
        continuation_token=continuation_token,
        prefix=prefix,
    )
    contents = list_resp.get("Contents") or []
    objects_out: list[dict[str, Any]] = []
    for item in contents:
        key = item.get("Key")
        if not isinstance(key, str):
            continue
        size_bytes = int(item.get("Size") or 0)
        lm = item.get("LastModified")
        objects_out.append(
            {"key": key, "size_bytes": size_bytes, "last_modified": s3_last_modified_iso_utc(lm)}
        )
    is_truncated = bool(list_resp.get("IsTruncated"))
    next_token = list_resp.get("NextContinuationToken")
    next_out: str | None = next_token if isinstance(next_token, str) else None

    _log_api_call_result(
        event,
        context,
        status_code=200,
        result="success",
        wallet_address=wallet,
        object_key=None,
    )
    return _response(
        200,
        {
            "success": True,
            "list_mode": True,
            "bucket": bucket_name,
            "objects": objects_out,
            "is_truncated": is_truncated,
            "next_continuation_token": next_out,
        },
    )


def handle_download(event: dict[str, Any], context: Any) -> dict[str, Any]:
    session = _load_session_from_cookie(event)
    wallet = cast(str, session["wallet_address"])
    wallet = normalize_wallet_address(wallet, "wallet_address")
    body = decode_json_event_body(event)
    keys_raw = body.get("object_keys")
    if not isinstance(keys_raw, list):
        raise BadRequestError("object_keys must be an array")
    if len(keys_raw) < 1:
        raise BadRequestError("object_keys must contain at least one key")
    if len(keys_raw) > DOWNLOAD_MAX_KEYS:
        raise BadRequestError(f"at most {DOWNLOAD_MAX_KEYS} object_keys allowed per request")
    expires_in = coerce_presigned_ttl_seconds(
        body.get("expires_in_seconds"),
        default=DEFAULT_PRESIGNED_TTL_SECONDS,
    )
    location = str(
        body.get("location") or body.get("region") or session.get("location") or DEFAULT_LOCATION
    ).strip() or DEFAULT_LOCATION

    s3_client = boto3.client("s3", region_name=location)
    bucket_name = bucket_name_from_wallet(wallet)
    try:
        validate_bucket_naming_rules(bucket_name)
    except ValueError as exc:
        raise BadRequestError(str(exc)) from exc

    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if _s3_storage_head_not_found(exc):
            raise NotFoundError("bucket_not_found", "Bucket not found for this wallet.") from exc
        raise

    expires_wall = int(time.time()) + expires_in
    expires_iso = _iso_from_epoch(expires_wall)
    results: list[dict[str, Any]] = []
    for raw_key in keys_raw:
        if not isinstance(raw_key, str):
            results.append(
                {
                    "object_key": str(raw_key),
                    "error": "bad_request",
                    "message": "object_key must be a string",
                }
            )
            continue
        try:
            ok = validate_object_key_single_segment(raw_key)
        except BadRequestError as exc:
            results.append({"object_key": raw_key, "error": "bad_request", "message": str(exc)})
            continue
        try:
            s3_client.head_object(Bucket=bucket_name, Key=ok)
        except ClientError as exc:
            if s3_not_found_for_download(exc):
                results.append(
                    {
                        "object_key": ok,
                        "error": "object_not_found",
                        "message": f"Object not found: {ok}.",
                    }
                )
                continue
            raise
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": ok},
            ExpiresIn=expires_in,
            HttpMethod="GET",
        )
        results.append({"object_key": ok, "url": url, "expires_at": expires_iso})

    _log_api_call_result(
        event,
        context,
        status_code=200,
        result="success",
        wallet_address=wallet,
        object_key=None,
    )
    return _response(200, {"success": True, "results": results})


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    path = _api_path(event)
    method = str(event.get("httpMethod") or "GET").upper()
    try:
        if method == "OPTIONS" and path.startswith("/storage/ls-web"):
            return handle_options(event, context)
        if path == "/storage/ls-web/session" and method == "POST":
            return handle_mint(event, context)
        if path == "/storage/ls-web/exchange" and method == "POST":
            return handle_exchange(event, context)
        if path == "/storage/ls-web/list" and method == "POST":
            return handle_list(event, context)
        if path == "/storage/ls-web/download" and method == "POST":
            return handle_download(event, context)
        if path.startswith("/storage/ls-web"):
            raise MethodNotAllowedError("Only POST is supported for this path")
        return _error_response(404, "not_found", "Unknown route")
    except ForbiddenError as exc:
        _log_api_call_result(
            event,
            context,
            status_code=403,
            result="forbidden",
            error_code="forbidden",
            error_message=str(exc),
            wallet_address=None,
            object_key=None,
        )
        return _error_response(403, "forbidden", str(exc))
    except UnauthorizedError as exc:
        _log_api_call_result(
            event,
            context,
            status_code=401,
            result="unauthorized",
            error_code="unauthorized",
            error_message=str(exc),
            wallet_address=None,
            object_key=None,
        )
        return _error_response(401, "unauthorized", str(exc))
    except BadRequestError as exc:
        _log_api_call_result(
            event,
            context,
            status_code=400,
            result="bad_request",
            error_code="bad_request",
            error_message=str(exc),
            wallet_address=None,
            object_key=None,
        )
        return _error_response(400, "Bad request", str(exc))
    except NotFoundError as exc:
        _log_api_call_result(
            event,
            context,
            status_code=404,
            result="not_found",
            error_code=exc.error,
            error_message=exc.message,
            wallet_address=None,
            object_key=None,
        )
        return _error_response(404, exc.error, exc.message)
    except MethodNotAllowedError as exc:
        return _error_response(405, "method_not_allowed", str(exc))
    except ClientError as exc:
        logger.exception("storage_ls_web dynamodb/s3 error")
        _log_api_call_result(
            event,
            context,
            status_code=500,
            result="internal_error",
            error_code="internal_error",
            error_message=str(exc),
            wallet_address=None,
            object_key=None,
        )
        return _error_response(500, "Internal error", str(exc))
    except Exception as exc:
        logger.exception("storage_ls_web internal error")
        _log_api_call_result(
            event,
            context,
            status_code=500,
            result="internal_error",
            error_code="internal_error",
            error_message=str(exc),
            wallet_address=None,
            object_key=None,
        )
        return _error_response(500, "Internal error", str(exc))
