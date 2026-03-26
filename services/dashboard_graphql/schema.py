"""GraphQL schema for the internal dashboard API (read-only)."""

from __future__ import annotations

import os
from typing import Annotated

import boto3
import strawberry

from dashboard_graphql.domain.payment_ledger_read import revenue_summary_for_wallet


def _payment_ledger_table():
    name = os.environ.get("PAYMENT_LEDGER_TABLE_NAME", "").strip()
    if not name:
        raise RuntimeError("PAYMENT_LEDGER_TABLE_NAME is not set")
    return boto3.resource("dynamodb").Table(name)


@strawberry.type
class Health:
    ok: bool


@strawberry.type
class RevenueSummary:
    wallet_address: str = strawberry.field(name="walletAddress")
    confirmed_payment_count: int = strawberry.field(name="confirmedPaymentCount")
    total_amount: str = strawberry.field(name="totalAmount")


@strawberry.type
class Query:
    @strawberry.field
    def health(self) -> Health:
        return Health(ok=True)

    @strawberry.field(name="revenueSummary")
    def revenue_summary(
        self,
        wallet_address: Annotated[str, strawberry.argument(name="walletAddress")],
    ) -> RevenueSummary:
        w = wallet_address.strip()
        if not w:
            raise ValueError("wallet_address is required")
        table = _payment_ledger_table()
        count, total = revenue_summary_for_wallet(table=table, wallet_address=w)
        return RevenueSummary(
            wallet_address=w,
            confirmed_payment_count=count,
            total_amount=total,
        )


schema = strawberry.Schema(query=Query)
