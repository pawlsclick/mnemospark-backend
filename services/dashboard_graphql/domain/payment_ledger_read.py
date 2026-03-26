"""Read-only access to the payment ledger for dashboard queries."""

from __future__ import annotations

from decimal import Decimal
from typing import Any


def revenue_summary_for_wallet(*, table: Any, wallet_address: str) -> tuple[int, str]:
    """
    Sum confirmed payment amounts for one wallet (partition key query).

    Returns (confirmed_count, total_amount) where total_amount is a decimal string
    in ledger storage format (USDC amount strings).
    """
    normalized = wallet_address.strip().lower()
    if not normalized.startswith("0x"):
        normalized = f"0x{normalized}"

    paginator = table.meta.client.get_paginator("query")
    total = Decimal("0")
    count = 0

    for page in paginator.paginate(
        TableName=table.name,
        KeyConditionExpression="wallet_address = :w",
        FilterExpression="payment_status = :s",
        ExpressionAttributeValues={":w": normalized, ":s": "confirmed"},
        ProjectionExpression="amount",
    ):
        for item in page.get("Items", []):
            count += 1
            raw = item.get("amount")
            if raw is None:
                continue
            try:
                total += Decimal(str(raw))
            except Exception:
                continue

    # Normalize to string without scientific notation for small values
    quant = total.quantize(Decimal("0.000001"))
    return count, format(quant, "f")
