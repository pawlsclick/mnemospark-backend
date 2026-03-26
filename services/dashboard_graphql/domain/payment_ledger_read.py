"""Read-only access to the payment ledger for dashboard queries."""

from __future__ import annotations

from decimal import Decimal
import re
from typing import Any

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def normalize_wallet_address(wallet_address: str) -> str:
    raw = (wallet_address or "").strip()
    if not raw:
        return ""
    if not _ADDRESS_RE.fullmatch(raw):
        raise ValueError("invalid wallet address")
    return "0x" + raw[2:].lower()


def revenue_summary_for_wallet(*, table: Any, wallet_address: str) -> tuple[int, str]:
    """
    Sum confirmed payment amounts for one wallet (partition key query).

    Expects wallet_address to already be normalized via normalize_wallet_address.
    Returns (confirmed_count, total_amount) where total_amount is a decimal string
    in ledger storage format (USDC amount strings).
    """
    total = Decimal("0")
    count = 0

    query_kwargs = {
        "KeyConditionExpression": "wallet_address = :w",
        "FilterExpression": "payment_status = :s",
        "ExpressionAttributeValues": {":w": wallet_address, ":s": "confirmed"},
        "ProjectionExpression": "amount",
    }

    while True:
        page = table.query(**query_kwargs)
        for item in page.get("Items", []):
            raw = item.get("amount")
            if raw is None:
                continue
            try:
                amount = Decimal(str(raw))
            except Exception:
                continue
            total += amount
            count += 1
        lek = page.get("LastEvaluatedKey")
        if not lek:
            break
        query_kwargs["ExclusiveStartKey"] = lek

    # Normalize to string without scientific notation for small values
    quant = total.quantize(Decimal("0.000001"))
    return count, format(quant, "f")
