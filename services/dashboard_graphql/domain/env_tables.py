"""Resolve DynamoDB table names from Lambda environment (same keys as other Lambdas)."""

from __future__ import annotations

import os


def _name(key: str) -> str:
    return (os.environ.get(key, "") or "").strip()


def quotes_table() -> str:
    return _name("QUOTES_TABLE_NAME")


def upload_transaction_log_table() -> str:
    return _name("UPLOAD_TRANSACTION_LOG_TABLE_NAME")


def payment_ledger_table() -> str:
    return _name("PAYMENT_LEDGER_TABLE_NAME")


def wallet_auth_events_table() -> str:
    return _name("WALLET_AUTH_EVENTS_TABLE_NAME")


def api_calls_table() -> str:
    return _name("API_CALLS_TABLE_NAME")
