"""Shared EIP-3009/EIP-712 verification primitives."""

from __future__ import annotations

import re
from typing import Any

TRANSFER_WITH_AUTH_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}

NONCE_PATTERN = re.compile(r"^0x[a-fA-F0-9]{64}$")


def normalize_transfer_with_auth_nonce(nonce: Any, *, error_cls: type[ValueError] = ValueError) -> str:
    if not isinstance(nonce, str):
        raise error_cls("payment nonce must be a hex string")
    normalized = nonce.strip()
    if not NONCE_PATTERN.fullmatch(normalized):
        raise error_cls("payment nonce must be 32 bytes hex (0x-prefixed)")
    return f"0x{normalized[2:].lower()}"
