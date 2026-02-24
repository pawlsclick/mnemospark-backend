"""
Lambda handler for object storage management REST API.

Accepts POST with JSON body: command (upload|ls|list|download|delete),
wallet_address, location, object_key (required for upload/ls/download/delete),
content (base64, required for upload).
Returns JSON; for download, includes content (base64).
KEK is stored in Secrets Manager per wallet (mnemospark/wallet/<wallet_hash>).
"""

import base64
import json
from typing import Any

from storage_core import (
    delete_object,
    download_object,
    list_bucket,
    list_object,
    upload_object,
)

VALID_COMMANDS = ("upload", "ls", "list", "download", "delete")
DEFAULT_LOCATION = "us-east-1"


def parse_input(event: dict[str, Any]) -> dict[str, Any]:
    """Extract command, wallet_address, location, object_key, content from API Gateway event."""
    params = event.get("queryStringParameters") or {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
            params = {**params, **body}
        except (json.JSONDecodeError, TypeError):
            pass
    command = (params.get("command") or params.get("action") or "").strip().lower()
    if command not in VALID_COMMANDS:
        command = "list"  # default to list bucket
    wallet_address = (params.get("wallet_address") or params.get("walletAddress") or "").strip()
    location = (params.get("location") or params.get("region") or DEFAULT_LOCATION).strip()
    object_key = (params.get("object_key") or params.get("objectKey") or "").strip()
    content_b64 = params.get("content") or params.get("body")
    if isinstance(content_b64, str):
        content_b64 = content_b64.strip() or None
    return {
        "command": command,
        "wallet_address": wallet_address,
        "location": location,
        "object_key": object_key,
        "content_b64": content_b64,
    }


def response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body, default=str),
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        inp = parse_input(event)
        wallet = inp["wallet_address"]
        location = inp["location"]
        object_key = inp["object_key"]
        command = inp["command"]

        if not wallet:
            return response(400, {"error": "wallet_address is required"})

        if command == "upload":
            if not object_key:
                return response(400, {"error": "object_key is required for upload"})
            if not inp["content_b64"]:
                return response(400, {"error": "content (base64) is required for upload"})
            try:
                plaintext = base64.b64decode(inp["content_b64"])
            except Exception as e:
                return response(400, {"error": "content must be valid base64", "details": str(e)})
            result = upload_object(wallet, object_key, plaintext, location)
        elif command == "ls":
            if not object_key:
                return response(400, {"error": "object_key is required for ls"})
            result = list_object(wallet, object_key, location)
        elif command == "list":
            result = list_bucket(wallet, location)
        elif command == "download":
            if not object_key:
                return response(400, {"error": "object_key is required for download"})
            result = download_object(wallet, object_key, location)
            if result.get("success") and "content" in result:
                result["content"] = base64.b64encode(result["content"]).decode("ascii")
                # drop raw bytes from JSON-serializable output
        elif command == "delete":
            if not object_key:
                return response(400, {"error": "object_key is required for delete"})
            result = delete_object(wallet, object_key, location)
        else:
            return response(400, {"error": f"Unknown command: {command}"})

        if not result.get("success"):
            code = 404 if result.get("not_found") else 400
            return response(code, {"error": result.get("error", "Operation failed"), **result})
        return response(200, result)
    except Exception as e:
        return response(500, {"error": "Internal error", "message": str(e)})
