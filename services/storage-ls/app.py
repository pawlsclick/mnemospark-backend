"""
Lambda handler for GET/POST /storage/ls.

Stat mode (object_key present): head_object metadata:
{
  "success": true,
  "key": "<object-key>",
  "size_bytes": <size>,
  "bucket": "mnemospark-<wallet-hash>"
}

List mode (object_key omitted): list_objects_v2:
{
  "success": true,
  "list_mode": true,
  "bucket": "...",
  "objects": [{"key", "size_bytes", "last_modified"}, ...],
  "is_truncated": bool,
  "next_continuation_token": str | null
}
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, cast

import boto3
from botocore.exceptions import ClientError

try:
    from common.http_response_headers import rest_api_json_headers
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        S3ListBucketAccessError,
        S3ListContinuationError,
        bucket_name_from_wallet,
        decode_json_event_body,
        list_objects_v2_page,
        normalize_wallet_address,
        NOT_FOUND_S3_ERROR_CODES,
        parse_list_max_keys_from_params,
        parse_optional_string_param,
        require_authorized_wallet_match,
        s3_error_code,
        s3_last_modified_iso_utc,
        validate_bucket_naming_rules,
        validate_object_key_single_segment,
    )
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.http_response_headers import rest_api_json_headers
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        S3ListBucketAccessError,
        S3ListContinuationError,
        bucket_name_from_wallet,
        decode_json_event_body,
        list_objects_v2_page,
        normalize_wallet_address,
        NOT_FOUND_S3_ERROR_CODES,
        parse_list_max_keys_from_params,
        parse_optional_string_param,
        require_authorized_wallet_match,
        s3_error_code,
        s3_last_modified_iso_utc,
        validate_bucket_naming_rules,
        validate_object_key_single_segment,
    )


log_api_call = load_log_api_call()
_log_api_call_result = load_log_api_call_result("/storage/ls", log_api_call_getter=lambda: log_api_call)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_LOCATION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION
DEFAULT_LIST_MAX_KEYS = 1000
LIST_MAX_KEYS_CAP = 1000

# Backward-compatible names for unit/integration tests and callers.
_bucket_name = bucket_name_from_wallet
_normalize_address = normalize_wallet_address
_decode_event_body = decode_json_event_body
_parse_optional_string = parse_optional_string_param


def _parse_max_keys(params: dict[str, Any]) -> int:
    return parse_list_max_keys_from_params(
        params,
        default=DEFAULT_LIST_MAX_KEYS,
        cap=LIST_MAX_KEYS_CAP,
    )


@dataclass(frozen=True)
class NotFoundError(Exception):
    error: str
    message: str


@dataclass(frozen=True)
class ParsedLsRequest:
    wallet_address: str
    location: str
    list_mode: bool
    object_key: str | None
    continuation_token: str | None
    max_keys: int
    prefix: str | None


def _log_event(level: int, event_name: str, **fields: Any) -> None:
    payload: dict[str, Any] = {"event": event_name}
    payload.update({key: value for key, value in fields.items() if value is not None})
    logger.log(level, json.dumps(payload, default=str, separators=(",", ":")))


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": rest_api_json_headers(),
        "body": json.dumps(body),
    }


def _error_response(status_code: int, error: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body)


def _collect_request_params(event: dict[str, Any]) -> dict[str, Any]:
    query_params = event.get("queryStringParameters") or {}
    if not isinstance(query_params, dict):
        raise BadRequestError("queryStringParameters must be an object")

    params = {key: value for key, value in query_params.items() if value is not None}
    params.update(decode_json_event_body(event))
    return params


def _require_string_field(params: dict[str, Any], field_name: str) -> str:
    value = params.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise BadRequestError(f"{field_name} is required")
    return value.strip()


def _assert_bucket_access(s3_client: Any, bucket_name: str) -> None:
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if s3_error_code(exc) in NOT_FOUND_S3_ERROR_CODES:
            raise NotFoundError("bucket_not_found", "Bucket not found for this wallet") from exc
        raise


def _get_object_size(s3_client: Any, bucket_name: str, object_key: str) -> int:
    try:
        response = s3_client.head_object(Bucket=bucket_name, Key=object_key)
    except ClientError as exc:
        if s3_error_code(exc) in NOT_FOUND_S3_ERROR_CODES:
            raise NotFoundError("object_not_found", f"Object not found: {object_key}") from exc
        raise
    return int(response.get("ContentLength", 0))


def _list_objects(
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


def parse_input(event: dict[str, Any]) -> ParsedLsRequest:
    params = _collect_request_params(event)

    wallet_address = normalize_wallet_address(_require_string_field(params, "wallet_address"), "wallet_address")
    object_key_raw = parse_optional_string_param(params, "object_key")
    location = str(params.get("location") or params.get("region") or DEFAULT_LOCATION).strip() or DEFAULT_LOCATION

    if object_key_raw is not None:
        validate_object_key_single_segment(object_key_raw)
        return ParsedLsRequest(
            wallet_address=wallet_address,
            location=location,
            list_mode=False,
            object_key=object_key_raw,
            continuation_token=None,
            max_keys=DEFAULT_LIST_MAX_KEYS,
            prefix=None,
        )

    continuation_token = parse_optional_string_param(params, "continuation_token")
    prefix = parse_optional_string_param(params, "prefix")
    max_keys = parse_list_max_keys_from_params(
        params,
        default=DEFAULT_LIST_MAX_KEYS,
        cap=LIST_MAX_KEYS_CAP,
    )

    return ParsedLsRequest(
        wallet_address=wallet_address,
        location=location,
        list_mode=True,
        object_key=None,
        continuation_token=continuation_token,
        max_keys=max_keys,
        prefix=prefix,
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request: ParsedLsRequest | None = None
    bucket_name: str | None = None
    try:
        request = parse_input(event)
        _log_event(
            logging.INFO,
            "storage_ls_request_parsed",
            wallet_address=request.wallet_address,
            object_key=request.object_key,
            list_mode=request.list_mode,
            location=request.location,
        )
        require_authorized_wallet_match(event, request.wallet_address)
        _log_event(
            logging.DEBUG,
            "storage_ls_authorized_wallet_confirmed",
            wallet_address=request.wallet_address,
        )
        s3_client = boto3.client("s3", region_name=request.location)
        bucket_name = bucket_name_from_wallet(request.wallet_address)

        try:
            validate_bucket_naming_rules(bucket_name)
        except ValueError as exc:
            raise BadRequestError(str(exc)) from exc

        _assert_bucket_access(s3_client, bucket_name)

        if request.list_mode:
            list_resp = _list_objects(
                s3_client,
                bucket_name,
                max_keys=request.max_keys,
                continuation_token=request.continuation_token,
                prefix=request.prefix,
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
                    {
                        "key": key,
                        "size_bytes": size_bytes,
                        "last_modified": s3_last_modified_iso_utc(lm),
                    }
                )
            is_truncated = bool(list_resp.get("IsTruncated"))
            next_token = list_resp.get("NextContinuationToken")
            next_out: str | None = next_token if isinstance(next_token, str) else None

            _log_event(
                logging.INFO,
                "storage_ls_list_succeeded",
                wallet_address=request.wallet_address,
                bucket_name=bucket_name,
                object_count=len(objects_out),
                is_truncated=is_truncated,
            )
            _log_api_call_result(
                event,
                context,
                status_code=200,
                result="success",
                wallet_address=request.wallet_address,
                object_key=None,
                list_mode=True,
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

        object_key = cast(str, request.object_key)
        object_size = _get_object_size(s3_client, bucket_name, object_key)
        _log_event(
            logging.INFO,
            "storage_ls_succeeded",
            wallet_address=request.wallet_address,
            object_key=object_key,
            bucket_name=bucket_name,
            size_bytes=object_size,
        )
        _log_api_call_result(
            event,
            context,
            status_code=200,
            result="success",
            wallet_address=request.wallet_address,
            object_key=object_key,
        )

        return _response(
            200,
            {
                "success": True,
                "key": object_key,
                "size_bytes": object_size,
                "bucket": bucket_name,
            },
        )
    except ForbiddenError as exc:
        _log_event(
            logging.WARNING,
            "storage_ls_forbidden",
            error_type=type(exc).__name__,
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        _log_api_call_result(
            event,
            context,
            status_code=403,
            result="forbidden",
            error_code="wallet_mismatch",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(403, "forbidden", str(exc))
    except BadRequestError as exc:
        _log_event(
            logging.WARNING,
            "storage_ls_bad_request",
            error_type=type(exc).__name__,
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        _log_api_call_result(
            event,
            context,
            status_code=400,
            result="bad_request",
            error_code="bad_request",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(400, "Bad request", str(exc))
    except NotFoundError as exc:
        _log_event(
            logging.WARNING,
            "storage_ls_not_found",
            error_type=type(exc).__name__,
            error_message=exc.message,
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
            bucket_name=bucket_name,
        )
        _log_api_call_result(
            event,
            context,
            status_code=404,
            result="not_found",
            error_code=exc.error,
            error_message=exc.message,
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(404, exc.error, exc.message)
    except Exception as exc:
        _log_event(
            logging.ERROR,
            "storage_ls_internal_error",
            error_type=type(exc).__name__,
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
            bucket_name=bucket_name,
        )
        _log_api_call_result(
            event,
            context,
            status_code=500,
            result="internal_error",
            error_code="internal_error",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(500, "Internal error", str(exc))
