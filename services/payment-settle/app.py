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
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

try:
    from common.log_api_call_loader import load_log_api_call
except ModuleNotFoundError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.log_api_call_loader import load_log_api_call


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
log_api_call = load_log_api_call(emit_warning=True, logger=logger)

ROUTE_PATH = "/payment/settle"
QUOTES_TABLE_ENV = "QUOTES_TABLE_NAME"
PAYMENT_LEDGER_TABLE_ENV = "PAYMENT_LEDGER_TABLE_NAME"
MAX_LOG_ERROR_MESSAGE_LENGTH = 512

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
    quote_id: str
    wallet_address: str
    payment_header: str | None


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
    module_spec.loader.exec_module(module)
    _PAYMENT_CORE = module
    return module


def _log_event(level: int, event_name: str, **fields: Any) -> None:
    payload: dict[str, Any] = {"event": event_name}
    payload.update({key: value for key, value in fields.items() if value is not None})
    logger.log(level, json.dumps(payload, default=str, separators=(",", ":")))


def _request_context(event: dict[str, Any]) -> dict[str, Any]:
    request_context = event.get("requestContext")
    if isinstance(request_context, dict):
        return request_context
    return {}


def _request_id(event: dict[str, Any], context: Any) -> str | None:
    request_context = _request_context(event)
    candidates = (
        request_context.get("requestId"),
        request_context.get("extendedRequestId"),
        getattr(context, "aws_request_id", None),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _request_method(event: dict[str, Any]) -> str:
    request_context = _request_context(event)
    candidates = (
        event.get("httpMethod"),
        request_context.get("httpMethod"),
        (request_context.get("http") or {}).get("method") if isinstance(request_context.get("http"), dict) else None,
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().upper()
    return "UNKNOWN"


def _request_path(event: dict[str, Any], default_path: str = ROUTE_PATH) -> str:
    request_context = _request_context(event)
    candidates = (
        event.get("resource"),
        request_context.get("resourcePath"),
        event.get("path"),
        request_context.get("path"),
        event.get("rawPath"),
        default_path,
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            path = candidate.strip().split("?", 1)[0]
            if not path.startswith("/"):
                path = f"/{path}"
            return path
    return default_path


def _sanitize_error_message(error_message: str | None) -> str | None:
    if error_message is None:
        return None
    sanitized = str(error_message).replace("\n", " ").replace("\r", " ").strip()
    if len(sanitized) > MAX_LOG_ERROR_MESSAGE_LENGTH:
        sanitized = sanitized[:MAX_LOG_ERROR_MESSAGE_LENGTH]
    return sanitized


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


def parse_input(event: dict[str, Any]) -> ParsedPaymentSettleRequest:
    params = _decode_event_body(event)
    headers = _normalize_headers(event.get("headers"))

    quote_id = _require_string_field(params, "quote_id")
    wallet_address = _normalize_address(_require_string_field(params, "wallet_address"), "wallet_address")

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
        quote_id=quote_id,
        wallet_address=wallet_address,
        payment_header=payment_header,
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
        request = parse_input(event)
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
        quotes_table = dynamodb.Table(_require_env(QUOTES_TABLE_ENV))
        payments_table = dynamodb.Table(_require_env(PAYMENT_LEDGER_TABLE_ENV))

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

        response_body = {
            "quote_id": request.quote_id,
            "wallet_address": request.wallet_address,
            "trans_id": payment_result.trans_id,
            "network": payment_result.network,
            "asset": payment_result.asset,
            "amount": str(payment_result.amount),
            "payment_status": "confirmed",
            "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
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
    except NotFoundError:
        _log_api_call_result(
            event,
            context,
            status_code=404,
            result="not_found",
            request=request,
            error_code="quote_not_found",
            error_message="Quote not found or expired",
        )
        return _error_response(404, "quote_not_found", "Quote not found or expired")
    except PaymentRequiredError as exc:
        headers = payment_core._payment_required_headers(exc.requirements)
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
        _log_api_call_result(
            event,
            context,
            status_code=409,
            result="conflict",
            request=request,
            error_code="payment_already_settled",
            error_message=str(exc),
        )
        return _error_response(409, "conflict", str(exc))
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
