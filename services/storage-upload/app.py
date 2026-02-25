"""
Placeholder Lambda for POST /storage/upload.
"""

from __future__ import annotations

import json
from typing import Any


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    return _response(
        501,
        {
            "error": "NotImplemented",
            "message": "POST /storage/upload route is configured but not implemented yet.",
            "path": event.get("path"),
            "method": event.get("httpMethod"),
        },
    )
