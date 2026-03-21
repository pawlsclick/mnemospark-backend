"""Persist successful relayer settlement transactions to RelayerTransactions (DynamoDB)."""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

RELAYER_TRANSACTIONS_TABLE_ENV = "RELAYER_TRANSACTIONS_TABLE_NAME"
_MISSING_TABLE_ENV_LOGGED = False

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def normalize_relayer_address(address: str) -> str:
    raw = (address or "").strip()
    if not _ADDRESS_RE.match(raw):
        raise ValueError("relayer address must be a 40-hex-character 0x-prefixed address")
    return "0x" + raw[2:].lower()


def record_relayer_transaction_success(
    *,
    relayer_address: str,
    tx_hash_hex: str,
    gas_used: int,
    effective_gas_price: int,
    block_number: int,
) -> None:
    """Idempotent PutItem after on-chain success. No-op if table env unset."""
    global _MISSING_TABLE_ENV_LOGGED
    table_name = os.environ.get(RELAYER_TRANSACTIONS_TABLE_ENV, "").strip()
    if not table_name:
        if not _MISSING_TABLE_ENV_LOGGED:
            logger.warning(
                "relayer_ledger_skip_missing_table_env: %s unset; skipping relayer ledger write",
                RELAYER_TRANSACTIONS_TABLE_ENV,
            )
            _MISSING_TABLE_ENV_LOGGED = True
        return

    wallet = normalize_relayer_address(relayer_address)
    txh = _normalize_tx_hash(tx_hash_hex)
    now = datetime.now(timezone.utc)
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    pk = f"WALLET#{wallet}"
    sk = f"TX#{iso}#{txh}"
    fee_wei = gas_used * effective_gas_price
    item: dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "txHash": txh,
        "status": "success",
        "gasUsed": str(gas_used),
        "effectiveGasPriceWei": str(effective_gas_price),
        "feePaidWei": str(fee_wei),
        "blockNumber": block_number,
        "submittedAt": iso,
        "confirmedAt": iso,
    }

    table = boto3.resource("dynamodb").Table(table_name)
    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            logger.info(
                "relayer_ledger_duplicate_skipped",
                extra={"pk": pk, "sk": sk, "txHash": txh},
            )
            return
        raise


def _normalize_tx_hash(tx_hash_hex: str) -> str:
    raw = (tx_hash_hex or "").strip().lower()
    if raw.startswith("0x"):
        body = raw[2:]
    else:
        body = raw
    if len(body) != 64 or any(c not in "0123456789abcdef" for c in body):
        raise ValueError("transaction hash must be 32-byte hex")
    return "0x" + body
