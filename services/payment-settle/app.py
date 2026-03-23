"""
Lambda handler for POST /payment/settle.

Flow:
1. Parse and validate request payload.
2. Enforce wallet-authorizer context matches wallet_address.
3. Load quote and expected payment requirements.
4. Verify EIP-712 payment authorization and settle (mock/onchain).
5. Persist settlement record in payment ledger with duplicate protection.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import os
import sys
import time
from functools import partial
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

try:
    from common.log_api_call_loader import load_log_api_call
    from common.renewal_keys import (
        billing_period_object_key,
        billing_period_utc,
        synthetic_renewal_quote_id,
        wallet_period_sk,
    )
    from common.request_log_utils import (
        build_log_event,
        request_id,
        request_method,
        request_path,
        sanitize_error_message,
    )
except ModuleNotFoundError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.log_api_call_loader import load_log_api_call
    from common.renewal_keys import (
        billing_period_object_key,
        billing_period_utc,
        synthetic_renewal_quote_id,
        wallet_period_sk,
    )
    from common.request_log_utils import (
        build_log_event,
        request_id,
        request_method,
        request_path,
        sanitize_error_message,
    )


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
log_api_call = load_log_api_call(emit_warning=True, logger=logger)
_log_event = build_log_event(logger)
_request_id = request_id
_request_method = request_method

ROUTE_PATH = "/payment/settle"
QUOTES_TABLE_ENV = "QUOTES_TABLE_NAME"
PAYMENT_LEDGER_TABLE_ENV = "PAYMENT_LEDGER_TABLE_NAME"
ACTIVE_STORAGE_OBJECT_TABLE_ENV = "ACTIVE_STORAGE_OBJECT_TABLE_NAME"
RENEWAL_TRANSACTION_LOG_TABLE_ENV = "RENEWAL_TRANSACTION_LOG_TABLE_NAME"
MAX_LOG_ERROR_MESSAGE_LENGTH = 512
_request_path = partial(request_path, default_path=ROUTE_PATH)

_PAYMENT_CORE: Any | None = None


class BadRequestError(ValueError):
    """Raised when request validation fails."""


class ForbiddenError(ValueError):
    """Raised when wallet authorizer context is missing or mismatched."""


class NotFoundError(ValueError):
    """Raised when required resources are not found."""


class ConflictError(ValueError):
    """Raised when a duplicate payment settlement is attempted."""


@dataclass(frozen=True)
class PaymentRequiredError(Exception):
    message: str
    requirements: dict[str, Any]
    details: Any = None


@dataclass(frozen=True)
class ParsedPaymentSettleRequest:
    wallet_address: str
    payment_header: str | None
    renewal: bool
    quote_id: str
    object_key: str | None


@dataclass(frozen=True)
class QuoteContext:
    storage_price: Decimal
    storage_price_micro: int
    provider: str
    location: str


def _payment_core() -> Any:
    global _PAYMENT_CORE
    if _PAYMENT_CORE is not None:
        return _PAYMENT_CORE

    payment_core_path = Path(__file__).resolve().parents[1] / "storage-upload" / "app.py"
    module_spec = importlib.util.spec_from_file_location("storage_upload_payment_core", payment_core_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load shared storage-upload payment module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    module_spec.loader.exec_module(module)
    _PAYMENT_CORE = module
    return module


def _sanitize_error_message(error_message: str | None) -> str | None:
    return sanitize_error_message(error_message, max_length=MAX_LOG_ERROR_MESSAGE_LENGTH)


def _response(status_code: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    merged_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    }
    if headers:
        merged_headers.update(headers)
    return {
        "statusCode": status_code,
        "headers": merged_headers,
        "body": json.dumps(body, default=str),
    }


def _error_response(
    status_code: int,
    error: str,
    message: str,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body, headers=headers)


def _normalize_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(key, str) and value is not None:
            normalized[key.lower()] = str(value)
    return normalized


def _header_value(headers: dict[str, str], name: str) -> str | None:
    value = headers.get(name.lower())
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _decode_event_body(event: dict[str, Any]) -> dict[str, Any]:
    raw_body = event.get("body")
    if raw_body in (None, ""):
        return {}
    if event.get("isBase64Encoded"):
        try:
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        except Exception as exc:
            raise BadRequestError("body must be valid base64-encoded JSON") from exc

    try:
        decoded = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise BadRequestError("body must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise BadRequestError("JSON body must be an object")
    return decoded


def _require_string_field(params: dict[str, Any], field_name: str) -> str:
    value = params.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise BadRequestError(f"{field_name} is required")
    return value.strip()


def _coerce_int(value: Any, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise BadRequestError(f"{field_name} must be an integer") from exc


def _coerce_decimal(value: Any, field_name: str) -> Decimal:
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise BadRequestError(f"{field_name} must be numeric") from exc


def _normalize_address(value: str, field_name: str) -> str:
    payment_core = _payment_core()
    try:
        return payment_core._normalize_address(value, field_name)
    except Exception as exc:
        raise BadRequestError(str(exc)) from exc


def _extract_authorizer_wallet(event: dict[str, Any]) -> str | None:
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        return None
    authorizer = request_context.get("authorizer")
    if not isinstance(authorizer, dict):
        return None

    candidates: list[Any] = [authorizer.get("walletAddress"), authorizer.get("wallet_address")]
    lambda_authorizer_context = authorizer.get("lambda")
    if isinstance(lambda_authorizer_context, dict):
        candidates.extend(
            [
                lambda_authorizer_context.get("walletAddress"),
                lambda_authorizer_context.get("wallet_address"),
            ]
        )

    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        try:
            return _normalize_address(candidate, "authorizer walletAddress")
        except BadRequestError as exc:
            raise ForbiddenError("wallet authorization context is invalid") from exc
    return None


def _require_authorized_wallet(event: dict[str, Any], wallet_address: str) -> None:
    authorized_wallet = _extract_authorizer_wallet(event)
    if authorized_wallet is None:
        raise ForbiddenError("wallet authorization context is required")
    if authorized_wallet != wallet_address:
        raise ForbiddenError("wallet_address does not match authorized wallet")


def _extract_inline_payment_header(params: dict[str, Any]) -> str | None:
    for field_name in ("payment", "payment_authorization", "payment_signature", "x_payment"):
        candidate = params.get(field_name)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
        if isinstance(candidate, dict):
            return json.dumps(candidate, separators=(",", ":"))

    inline_payload_fields = {}
    for field_name in ("payload", "signature", "authorization", "accepted", "network", "asset"):
        if field_name in params:
            inline_payload_fields[field_name] = params[field_name]
    if inline_payload_fields:
        return json.dumps(inline_payload_fields, separators=(",", ":"))

    return None


def parse_input(event: dict[str, Any], *, now_ts: int | None = None) -> ParsedPaymentSettleRequest:
    params = _decode_event_body(event)
    headers = _normalize_headers(event.get("headers"))
    wallet_address = _normalize_address(_require_string_field(params, "wallet_address"), "wallet_address")

    renewal_raw = params.get("renewal")
    is_renewal = renewal_raw is True
    if renewal_raw is not None and renewal_raw is not False and not is_renewal:
        raise BadRequestError("renewal must be true or omitted")

    if now_ts is None:
        now_ts = int(time.time())
    if is_renewal:
        if params.get("quote_id") is not None:
            raise BadRequestError("quote_id must not be sent when renewal is true")
        object_key = _require_string_field(params, "object_key")
        billing_period = billing_period_utc(now_ts)
        quote_id = synthetic_renewal_quote_id(billing_period, object_key)
    else:
        quote_id = _require_string_field(params, "quote_id")
        object_key = None

    payment_header: str | None = None
    payment_core = _payment_core()
    for header_name in payment_core.PAYMENT_SIGNATURE_HEADER_NAMES:
        value = _header_value(headers, header_name)
        if value:
            payment_header = value
            break
    if payment_header is None:
        payment_header = _extract_inline_payment_header(params)

    return ParsedPaymentSettleRequest(
        wallet_address=wallet_address,
        payment_header=payment_header,
        renewal=is_renewal,
        quote_id=quote_id,
        object_key=object_key,
    )


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return value


def _build_quote_context(quote_item: dict[str, Any] | None, request: ParsedPaymentSettleRequest, now: int) -> QuoteContext:
    if not quote_item:
        raise NotFoundError("quote_not_found")

    expires_at_raw = quote_item.get("expires_at")
    if expires_at_raw is None:
        raise NotFoundError("quote_not_found")
    expires_at = _coerce_int(expires_at_raw, "quote.expires_at")
    if expires_at <= now:
        raise NotFoundError("quote_not_found")

    quote_addr_raw = quote_item.get("addr") or quote_item.get("wallet_address")
    if isinstance(quote_addr_raw, str) and quote_addr_raw.strip():
        quote_addr = _normalize_address(quote_addr_raw, "quote.wallet_address")
        if quote_addr != request.wallet_address:
            raise BadRequestError("wallet_address does not match the quote")

    storage_price = _coerce_decimal(quote_item.get("storage_price"), "quote.storage_price")
    if storage_price <= 0:
        raise BadRequestError("quote.storage_price must be greater than 0")

    payment_core = _payment_core()
    storage_price_micro = int(
        (storage_price * payment_core.USDC_DECIMALS).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )

    provider = str(quote_item.get("provider") or "aws").strip() or "aws"
    default_location = "us-" + "east-1"
    location = str(quote_item.get("location") or quote_item.get("region") or default_location).strip() or default_location

    return QuoteContext(
        storage_price=storage_price,
        storage_price_micro=storage_price_micro,
        provider=provider,
        location=location,
    )


def _quote_context_from_active_inventory(
    item: dict[str, Any] | None,
    *,
    wallet_address: str,
    object_key: str,
    expected_bucket: str,
) -> QuoteContext:
    if not item:
        raise NotFoundError("renewal_not_registered")
    status = str(item.get("status") or "").strip().lower()
    if status != "active":
        raise NotFoundError("renewal_not_registered")
    row_key = str(item.get("object_key") or "").strip()
    if row_key != object_key:
        raise NotFoundError("renewal_not_registered")
    bucket = str(item.get("bucket_name") or "").strip()
    if bucket != expected_bucket:
        raise NotFoundError("renewal_not_registered")

    storage_price = _coerce_decimal(item.get("storage_price"), "inventory.storage_price")
    if storage_price <= 0:
        raise BadRequestError("inventory.storage_price must be greater than 0")

    payment_core = _payment_core()
    storage_price_micro = int(
        (storage_price * payment_core.USDC_DECIMALS).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )

    provider = str(item.get("provider") or "aws").strip() or "aws"
    default_location = "us-" + "east-1"
    location = str(item.get("location") or item.get("region") or default_location).strip() or default_location

    return QuoteContext(
        storage_price=storage_price,
        storage_price_micro=storage_price_micro,
        provider=provider,
        location=location,
    )


def _head_object_or_not_found(s3_client: Any, bucket_name: str, object_key: str) -> None:
    try:
        s3_client.head_object(Bucket=bucket_name, Key=object_key)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in {"404", "NotFound", "NoSuchKey", "NoSuchBucket"}:
            raise NotFoundError("object_not_in_storage") from exc
        raise


def _put_renewal_transaction_log(
    renewal_table: Any,
    *,
    bucket_name: str,
    object_key: str,
    billing_period: str,
    wallet_address: str,
    recipient_wallet: str,
    trans_id: str,
    amount_micro: int,
    amount_str: str,
    network: str,
    asset: str,
    paid_at_iso: str,
) -> None:
    bp_ok = billing_period_object_key(billing_period, object_key)
    wpsk = wallet_period_sk(wallet_address, object_key)
    asset_lower = asset.lower() if isinstance(asset, str) else str(asset)
    renewal_table.put_item(
        Item={
            "bucket_name": bucket_name,
            "billing_period_object_key": bp_ok,
            "object_key": object_key,
            "billing_period": billing_period,
            "paid_at": paid_at_iso,
            "wallet_address": wallet_address,
            "recipient_wallet": recipient_wallet,
            "trans_id": trans_id,
            "amount_micro": amount_micro,
            "amount": amount_str,
            "network": network,
            "asset": asset_lower,
            "wallet_period_sk": wpsk,
        },
        ConditionExpression="attribute_not_exists(billing_period_object_key)",
    )


def _write_payment_ledger(
    payments_table: Any,
    request: ParsedPaymentSettleRequest,
    quote_context: QuoteContext,
    payment_result: Any,
    payment_config: dict[str, str],
    now: int,
) -> None:
    timestamp = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    payment_received_at = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    settlement_mode = os.environ.get("MNEMOSPARK_PAYMENT_SETTLEMENT_MODE", "onchain").strip().lower() or "onchain"

    payment_asset = (
        payment_result.asset.lower() if isinstance(payment_result.asset, str) else str(payment_result.asset)
    )

    try:
        payments_table.put_item(
            Item={
                "wallet_address": request.wallet_address,
                "quote_id": request.quote_id,
                "trans_id": payment_result.trans_id,
                "network": payment_result.network,
                "asset": payment_asset,
                "amount": str(payment_result.amount),
                "payment_status": "confirmed",
                "timestamp": timestamp,
                "payment_received_at": payment_received_at,
                "storage_price": str(quote_context.storage_price),
                "provider": quote_context.provider,
                "location": quote_context.location,
                "recipient_wallet": payment_config["recipient_wallet"],
                "settlement_mode": settlement_mode,
            },
            ConditionExpression=(
                "attribute_exists(wallet_address) AND attribute_exists(quote_id) "
                "AND payment_status = :expected_status"
            ),
            ExpressionAttributeValues={":expected_status": "settlement_in_progress"},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise RuntimeError("payment settlement ledger claim is missing") from exc
        raise


def _claim_payment_ledger(
    payments_table: Any,
    request: ParsedPaymentSettleRequest,
    quote_context: QuoteContext,
    payment_config: dict[str, str],
    now: int,
) -> None:
    timestamp = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    payment_received_at = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    settlement_mode = os.environ.get("MNEMOSPARK_PAYMENT_SETTLEMENT_MODE", "onchain").strip().lower() or "onchain"
    key = {"wallet_address": request.wallet_address, "quote_id": request.quote_id}

    try:
        payments_table.put_item(
            Item={
                **key,
                "payment_status": "settlement_in_progress",
                "timestamp": timestamp,
                "payment_received_at": payment_received_at,
                "storage_price": str(quote_context.storage_price),
                "provider": quote_context.provider,
                "location": quote_context.location,
                "recipient_wallet": payment_config["recipient_wallet"],
                "settlement_mode": settlement_mode,
            },
            ConditionExpression="attribute_not_exists(wallet_address) AND attribute_not_exists(quote_id)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        existing = payments_table.get_item(Key=key, ConsistentRead=True).get("Item") or {}
        existing_status = str(existing.get("payment_status") or "").strip().lower()
        if existing_status == "confirmed":
            raise ConflictError("payment already settled for this quote and wallet") from exc
        raise ConflictError("payment settlement already in progress for this quote and wallet") from exc


def _release_payment_ledger_claim(payments_table: Any, request: ParsedPaymentSettleRequest) -> None:
    delete_item = getattr(payments_table, "delete_item", None)
    if not callable(delete_item):
        return
    try:
        delete_item(
            Key={"wallet_address": request.wallet_address, "quote_id": request.quote_id},
            ConditionExpression="payment_status = :status",
            ExpressionAttributeValues={":status": "settlement_in_progress"},
        )
    except Exception:
        # Best-effort cleanup only when payment settlement has not happened.
        return


def _log_api_call_result(
    event: dict[str, Any],
    context: Any,
    *,
    status_code: int,
    result: str,
    request: ParsedPaymentSettleRequest | None = None,
    trans_id: str | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> None:
    sanitized_error_message = _sanitize_error_message(error_message)
    level = logging.INFO
    if status_code >= 500:
        level = logging.ERROR
    elif status_code >= 400:
        level = logging.WARNING

    _log_event(
        level,
        "payment_settlement_api_result",
        request_id=_request_id(event, context),
        method=_request_method(event),
        path=_request_path(event),
        status=status_code,
        result=result,
        error_code=error_code,
        error_message=sanitized_error_message,
        wallet_address=request.wallet_address if request else None,
        quote_id=request.quote_id if request else None,
        trans_id=trans_id,
    )
    log_api_call(
        event=event,
        context=context,
        route=ROUTE_PATH,
        status_code=status_code,
        result=result,
        error_code=error_code,
        error_message=sanitized_error_message,
        wallet_address=request.wallet_address if request else None,
        quote_id=request.quote_id if request else None,
        trans_id=trans_id,
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request: ParsedPaymentSettleRequest | None = None
    payments_table: Any | None = None
    ledger_claimed = False
    payment_core = _payment_core()

    try:
        now = int(time.time())
        request = parse_input(event, now_ts=now)
        _require_authorized_wallet(event, request.wallet_address)
        _log_event(
            logging.INFO,
            "payment_settlement_request_parsed",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            wallet_address=request.wallet_address,
            quote_id=request.quote_id,
        )

        dynamodb = boto3.resource("dynamodb")
        payments_table = dynamodb.Table(_require_env(PAYMENT_LEDGER_TABLE_ENV))
        renewal_table: Any | None = None

        if request.renewal:
            if not request.object_key:
                raise BadRequestError("object_key is required")
            active_table = dynamodb.Table(_require_env(ACTIVE_STORAGE_OBJECT_TABLE_ENV))
            renewal_table = dynamodb.Table(_require_env(RENEWAL_TRANSACTION_LOG_TABLE_ENV))
            expected_bucket = payment_core._bucket_name(request.wallet_address)
            inv = active_table.get_item(
                Key={"wallet_address": request.wallet_address, "object_key": request.object_key},
                ConsistentRead=True,
            ).get("Item")
            quote_context = _quote_context_from_active_inventory(
                inv,
                wallet_address=request.wallet_address,
                object_key=request.object_key,
                expected_bucket=expected_bucket,
            )
            s3_client = boto3.client("s3", region_name=quote_context.location)
            _head_object_or_not_found(s3_client, expected_bucket, request.object_key)
        else:
            quotes_table = dynamodb.Table(_require_env(QUOTES_TABLE_ENV))
            quote_resp = quotes_table.get_item(Key={"quote_id": request.quote_id}, ConsistentRead=True)
            quote_context = _build_quote_context(quote_resp.get("Item"), request=request, now=now)

        payment_config = payment_core._payment_config()
        requirements = payment_core._payment_requirements(quote_context, payment_config)
        _claim_payment_ledger(
            payments_table=payments_table,
            request=request,
            quote_context=quote_context,
            payment_config=payment_config,
            now=now,
        )
        ledger_claimed = True

        try:
            payment_result = payment_core.verify_and_settle_payment(
                payment_header=request.payment_header,
                wallet_address=request.wallet_address,
                quote_id=request.quote_id,
                expected_amount=quote_context.storage_price_micro,
                expected_recipient=payment_config["recipient_wallet"],
                expected_network=payment_config["payment_network"],
                expected_asset=payment_config["payment_asset"],
                requirements=requirements,
            )
        except Exception as exc:
            if exc.__class__.__name__ != "PaymentRequiredError":
                raise
            if ledger_claimed and payments_table is not None:
                _release_payment_ledger_claim(payments_table, request)
                ledger_claimed = False
            raise PaymentRequiredError(
                message=getattr(exc, "message", "Payment authorization is invalid"),
                requirements=getattr(exc, "requirements", requirements),
                details=getattr(exc, "details", None),
            ) from exc

        _write_payment_ledger(
            payments_table=payments_table,
            request=request,
            quote_context=quote_context,
            payment_result=payment_result,
            payment_config=payment_config,
            now=now,
        )
        ledger_claimed = False

        response_body: dict[str, Any] = {
            "quote_id": request.quote_id,
            "wallet_address": request.wallet_address,
            "trans_id": payment_result.trans_id,
            "network": payment_result.network,
            "asset": payment_result.asset,
            "amount": str(payment_result.amount),
            "payment_status": "confirmed",
            "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
        if request.renewal and request.object_key and renewal_table is not None:
            billing_period = billing_period_utc(now)
            expected_bucket = payment_core._bucket_name(request.wallet_address)
            paid_at_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
            bp_ok = billing_period_object_key(billing_period, request.object_key)
            try:
                _put_renewal_transaction_log(
                    renewal_table,
                    bucket_name=expected_bucket,
                    object_key=request.object_key,
                    billing_period=billing_period,
                    wallet_address=request.wallet_address,
                    recipient_wallet=payment_config["recipient_wallet"],
                    trans_id=payment_result.trans_id,
                    amount_micro=quote_context.storage_price_micro,
                    amount_str=str(payment_result.amount),
                    network=payment_result.network,
                    asset=payment_result.asset,
                    paid_at_iso=paid_at_iso,
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                    raise
                existing_renewal = (
                    renewal_table.get_item(
                        Key={"bucket_name": expected_bucket, "billing_period_object_key": bp_ok},
                        ConsistentRead=True,
                    ).get("Item")
                    or {}
                )
                response_body["result"] = "already_settled"
                if existing_renewal.get("trans_id"):
                    response_body["trans_id"] = str(existing_renewal["trans_id"])
            if request.renewal and request.object_key:
                response_body["renewal"] = True
                response_body["object_key"] = request.object_key
                response_body["billing_period"] = billing_period

        _log_event(
            logging.INFO,
            "payment_settlement_succeeded",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=200,
            wallet_address=request.wallet_address,
            quote_id=request.quote_id,
            trans_id=payment_result.trans_id,
        )
        _log_api_call_result(
            event,
            context,
            status_code=200,
            result="success",
            request=request,
            trans_id=payment_result.trans_id,
        )
        return _response(200, response_body)

    except ForbiddenError as exc:
        _log_api_call_result(
            event,
            context,
            status_code=403,
            result="forbidden",
            request=request,
            error_code="wallet_mismatch",
            error_message=str(exc),
        )
        return _error_response(403, "forbidden", str(exc))
    except BadRequestError as exc:
        _log_api_call_result(
            event,
            context,
            status_code=400,
            result="bad_request",
            request=request,
            error_code="bad_request",
            error_message=str(exc),
        )
        return _error_response(400, "Bad request", str(exc))
    except NotFoundError as exc:
        code = str(exc)
        if code == "renewal_not_registered":
            err = "renewal_not_registered"
            msg = "No active inventory record for this wallet and object_key"
        elif code == "object_not_in_storage":
            err = "object_not_in_storage"
            msg = "Object not found in storage for this wallet"
        else:
            err = "quote_not_found"
            msg = "Quote not found or expired"
        _log_api_call_result(
            event,
            context,
            status_code=404,
            result="not_found",
            request=request,
            error_code=err,
            error_message=msg,
        )
        return _error_response(404, err, msg)
    except PaymentRequiredError as exc:
        headers = payment_core._payment_required_headers(exc.requirements)
        if exc.details:
            _log_event(
                logging.WARNING,
                "payment_required_details",
                request_id=_request_id(event, context),
                message=exc.message,
                details=str(exc.details),
            )
        _log_api_call_result(
            event,
            context,
            status_code=402,
            result="payment_required",
            request=request,
            error_code="payment_required",
            error_message=exc.message,
        )
        return _error_response(402, "payment_required", exc.message, details=exc.details, headers=headers)
    except ConflictError as exc:
        error_message = str(exc)
        if "already settled" in error_message.lower() and payments_table is not None and request is not None:
            try:
                existing = (
                    payments_table.get_item(
                        Key={"wallet_address": request.wallet_address, "quote_id": request.quote_id},
                        ConsistentRead=True,
                    ).get("Item")
                )
            except Exception:
                existing = None
            if existing is not None:
                response_body = {
                    "quote_id": request.quote_id,
                    "wallet_address": request.wallet_address,
                    "trans_id": existing.get("trans_id"),
                    "network": existing.get("network"),
                    "asset": existing.get("asset"),
                    "amount": str(existing.get("amount")) if existing.get("amount") is not None else None,
                    "payment_status": "confirmed",
                    "timestamp": existing.get("timestamp"),
                    "result": "already_settled",
                }
                if request.renewal and request.object_key:
                    response_body["renewal"] = True
                    response_body["object_key"] = request.object_key
                    response_body["billing_period"] = billing_period_utc(now)
                _log_api_call_result(
                    event,
                    context,
                    status_code=200,
                    result="success",
                    request=request,
                    trans_id=response_body.get("trans_id"),
                )
                return _response(200, response_body)

        _log_api_call_result(
            event,
            context,
            status_code=409,
            result="conflict",
            request=request,
            error_code="payment_already_settled",
            error_message=error_message,
        )
        return _error_response(409, "conflict", error_message)
    except Exception as exc:
        if ledger_claimed and payments_table is not None and request is not None:
            _release_payment_ledger_claim(payments_table, request)
            ledger_claimed = False
        _log_event(
            logging.ERROR,
            "payment_settle_internal_error",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=500,
            error_code="internal_error",
            error_type=type(exc).__name__,
            error_message=_sanitize_error_message(str(exc)),
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
        )
        _log_api_call_result(
            event,
            context,
            status_code=500,
            result="internal_error",
            request=request,
            error_code="internal_error",
            error_message=str(exc),
        )
        return _error_response(500, "Internal error", str(exc))
