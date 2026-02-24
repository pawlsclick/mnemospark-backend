#!/usr/bin/env python3
"""
Object storage script for mnemospark: upload, ls, download, delete.

Uses one S3 bucket per wallet (mnemospark-<wallet-id-hash>), client-held envelope
encryption (KEK/DEK per .company/mvp_option_aws_client_encryption.md), and CloudWatch
Logs for all commands. Requires: boto3, cryptography, AWS credentials with S3 and
logs permissions. Install with:
  python -m pip install -r examples/requirements-object-storage.txt
  uv sync --extra object-storage

Run from the repository root (mnemospark/):

  python3 examples/object_storage_management_aws.py upload --wallet-address <addr> --object-id <local-path> [--location REGION]
  python3 examples/object_storage_management_aws.py ls --wallet-address <addr> --object-key <s3-key> [--location REGION]
  python3 examples/object_storage_management_aws.py download --wallet-address <addr> --object-key <s3-key> [--location REGION]
  python3 examples/object_storage_management_aws.py delete --wallet-address <addr> --object-key <s3-key> [--location REGION]

For upload, --object-id is a local file path; the S3 key is the file name (returned after upload).
For ls/download/delete, --object-key is the S3 object key.
"""

import argparse
import base64
import csv
import hashlib
import json
import logging
import os
import re
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Exit codes
EXIT_SUCCESS = 0
EXIT_VALIDATION = 1
EXIT_S3_OR_ENCRYPTION = 2
EXIT_NOT_FOUND = 3

# S3 bucket naming: 3-63 chars, [a-z0-9.-], must not start/end with . or -
BUCKET_NAME_MIN_LEN = 3
BUCKET_NAME_MAX_LEN = 63
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
BUCKET_FORBIDDEN_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
BUCKET_FORBIDDEN_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
# Simple IP-like check (four dotted decimal octets)
BUCKET_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

LOG_GROUP = "/mnemospark/object-storage"
KEY_STORE_DIR = os.path.expanduser("~/.openclaw/mnemospark/keys")
OBJECT_LOG_PATH = os.path.expanduser("~/.openclaw/mnemospark/object.log")
WALLET_HASH_LEN = 16  # short hash for bucket name (mnemospark- = 11, so 11+16=27 <= 63)

# AES-GCM: 12-byte nonce, 16-byte tag
NONCE_BYTES = 12
TAG_BYTES = 16


def wallet_hash(wallet_address: str, length: int = WALLET_HASH_LEN) -> str:
    """Deterministic short hash of wallet address (hex, lowercase)."""
    return hashlib.sha256(wallet_address.encode()).hexdigest()[:length]


def bucket_name(wallet_address: str) -> str:
    """Build S3 bucket name: mnemospark-<wallet-id-hash>."""
    return f"mnemospark-{wallet_hash(wallet_address)}"


def validate_bucket_name(name: str) -> None:
    """Raise ValueError if name does not satisfy S3 bucket naming rules."""
    if not (BUCKET_NAME_MIN_LEN <= len(name) <= BUCKET_NAME_MAX_LEN):
        raise ValueError(
            f"Bucket name must be {BUCKET_NAME_MIN_LEN}-{BUCKET_NAME_MAX_LEN} characters, got {len(name)}"
        )
    if not BUCKET_NAME_PATTERN.match(name):
        raise ValueError(
            "Bucket name must use only a-z, 0-9, . and -; must start and end with letter or number"
        )
    if name.startswith(BUCKET_FORBIDDEN_PREFIXES) or name.endswith(BUCKET_FORBIDDEN_SUFFIXES):
        raise ValueError("Bucket name uses a forbidden prefix or suffix")
    if BUCKET_IP_PATTERN.match(name):
        raise ValueError("Bucket name must not be formatted as an IP address")


def ensure_bucket_exists(s3_client, bucket_name_str: str, location: str) -> None:
    """Ensure the bucket exists; create it in the given region if missing."""
    try:
        s3_client.head_bucket(Bucket=bucket_name_str)
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "404":
            raise
    # Create bucket
    if location == "us-east-1":
        s3_client.create_bucket(Bucket=bucket_name_str)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name_str,
            CreateBucketConfiguration={"LocationConstraint": location},
        )


def require_bucket_exists(s3_client, bucket_name_str: str) -> None:
    """Raise if bucket does not exist (for ls/download/delete)."""
    try:
        s3_client.head_bucket(Bucket=bucket_name_str)
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            raise ValueError("Bucket not found for this wallet.") from e
        raise


def get_key_store_path(wallet_short_hash: str) -> Path:
    """Path to KEK file for this wallet."""
    path = Path(KEY_STORE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{wallet_short_hash}.key"


def load_or_create_kek(wallet_short_hash: str) -> bytes:
    """Load KEK from key store, or generate and save if missing. Returns 32 bytes."""
    key_path = get_key_store_path(wallet_short_hash)
    if key_path.exists():
        data = key_path.read_bytes()
        if len(data) == 32:
            return data
        if len(data) == 44:  # base64 of 32 bytes
            return base64.b64decode(data)
        raise ValueError("Invalid key file format")
    kek = secrets.token_bytes(32)
    key_path.write_bytes(kek)
    key_path.chmod(0o600)
    return kek


def encrypt_with_dek(plaintext: bytes, dek: bytes) -> bytes:
    """Encrypt plaintext with DEK using AES-256-GCM. Returns nonce + ciphertext + tag (all concatenated)."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    aes = AESGCM(dek)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    """Wrap DEK with KEK (AES-256-GCM). Returns nonce + ciphertext + tag for storage as base64."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    aes = AESGCM(kek)
    ct = aes.encrypt(nonce, dek, None)
    return nonce + ct


def unwrap_dek(wrapped_b64: str, kek: bytes) -> bytes:
    """Unwrap DEK from base64(nonce + ciphertext + tag)."""
    raw = base64.b64decode(wrapped_b64)
    nonce = raw[:NONCE_BYTES]
    ciphertext = raw[NONCE_BYTES:]
    aes = AESGCM(kek)
    return aes.decrypt(nonce, ciphertext, None)


def decrypt_with_dek(ciphertext_with_nonce: bytes, dek: bytes) -> bytes:
    """Decrypt payload produced by encrypt_with_dek."""
    nonce = ciphertext_with_nonce[:NONCE_BYTES]
    ciphertext = ciphertext_with_nonce[NONCE_BYTES:]
    aes = AESGCM(dek)
    return aes.decrypt(nonce, ciphertext, None)


def format_size(size_bytes: int) -> str:
    """Human-readable size."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size_bytes < 1024:
            return f"{size_bytes} {unit}"
        size_bytes //= 1024
    return f"{size_bytes} TiB"


def append_upload_log(bucket: str, key: str, region: str) -> None:
    """Append one CSV line to ~/.openclaw/mnemospark/object.log. Does not raise."""
    try:
        log_path = Path(OBJECT_LOG_PATH)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        dt_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_exists = log_path.exists()
        with open(log_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["datetime", "bucket", "key", "region"])
            writer.writerow([dt_str, bucket, key, region])
    except Exception:
        logging.getLogger(__name__).exception("Failed to write object.log")


def upload_object(
    wallet_address: str,
    object_id_path: str,
    location: str,
    s3_client=None,
) -> dict:
    """Upload local file to S3 with client-held encryption. Returns result dict with success, key, bucket, error."""
    if s3_client is None:
        s3_client = boto3.client("s3", region_name=location)
    path = Path(object_id_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {object_id_path}"}
    object_key = path.name
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key (path traversal not allowed)."}
    try:
        validate_bucket_name(bucket_name(wallet_address))
    except ValueError as e:
        return {"success": False, "error": str(e)}
    try:
        bucket_name_str = bucket_name(wallet_address)
        ensure_bucket_exists(s3_client, bucket_name_str, location)
        wh = wallet_hash(wallet_address)
        kek = load_or_create_kek(wh)
        plaintext = path.read_bytes()
        dek = secrets.token_bytes(32)
        ciphertext = encrypt_with_dek(plaintext, dek)
        wrapped_dek = wrap_dek(dek, kek)
        wrapped_dek_b64 = base64.b64encode(wrapped_dek).decode("ascii")
        s3_client.put_object(
            Bucket=bucket_name_str,
            Key=object_key,
            Body=ciphertext,
            Metadata={"wrapped-dek": wrapped_dek_b64},
        )
        append_upload_log(bucket_name_str, object_key, location)
        return {
            "success": True,
            "bucket": bucket_name_str,
            "key": object_key,
            "region": location,
        }
    except ClientError as e:
        code = e.response["Error"].get("Code", "")
        if code == "404" or "NoSuchBucket" in code:
            return {"success": False, "error": "Bucket not found.", "details": str(e)}
        return {"success": False, "error": f"S3 error: {e.response['Error'].get('Message', str(e))}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def list_object(
    wallet_address: str,
    object_key: str,
    location: str,
    s3_client=None,
) -> dict:
    """List object in S3 (name + size). Returns result dict with success, key, size_bytes, bucket, error."""
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key."}
    if s3_client is None:
        s3_client = boto3.client("s3", region_name=location)
    try:
        validate_bucket_name(bucket_name(wallet_address))
    except ValueError as e:
        return {"success": False, "error": str(e)}
    try:
        bucket_name_str = bucket_name(wallet_address)
        require_bucket_exists(s3_client, bucket_name_str)
        resp = s3_client.head_object(Bucket=bucket_name_str, Key=object_key)
        size = resp.get("ContentLength", 0)
        return {"success": True, "key": object_key, "size_bytes": size, "bucket": bucket_name_str}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except ClientError as e:
        if e.response["Error"].get("Code") == "404":
            return {"success": False, "error": f"Object not found: {object_key}.", "not_found": True}
        return {"success": False, "error": f"S3 error: {e.response['Error'].get('Message', str(e))}"}


def download_object(
    wallet_address: str,
    object_key: str,
    location: str,
    s3_client=None,
) -> dict:
    """Download object from S3, decrypt, write to current directory. Returns result dict."""
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key."}
    if s3_client is None:
        s3_client = boto3.client("s3", region_name=location)
    try:
        validate_bucket_name(bucket_name(wallet_address))
    except ValueError as e:
        return {"success": False, "error": str(e)}
    try:
        bucket_name_str = bucket_name(wallet_address)
        require_bucket_exists(s3_client, bucket_name_str)
        wh = wallet_hash(wallet_address)
        key_path = get_key_store_path(wh)
        if not key_path.exists():
            return {"success": False, "error": "Cannot decrypt: key not found for this wallet."}
        kek = load_or_create_kek(wh)
        resp = s3_client.get_object(Bucket=bucket_name_str, Key=object_key)
        body = resp["Body"].read()
        meta = resp.get("Metadata") or {}
        wrapped_dek_b64 = meta.get("wrapped-dek")
        if not wrapped_dek_b64:
            return {"success": False, "error": "Object metadata missing wrapped-dek (not encrypted?)."}
        dek = unwrap_dek(wrapped_dek_b64, kek)
        plaintext = decrypt_with_dek(body, dek)
        out_path = Path.cwd() / object_key
        out_path.write_bytes(plaintext)
        return {
            "success": True,
            "key": object_key,
            "path": str(out_path.resolve()),
            "bucket": bucket_name_str,
        }
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except ClientError as e:
        if e.response["Error"].get("Code") == "404":
            return {"success": False, "error": f"Object not found: {object_key}.", "not_found": True}
        return {"success": False, "error": f"S3 error: {e.response['Error'].get('Message', str(e))}"}
    except Exception as e:
        return {"success": False, "error": f"Decryption or write failed: {e}"}


def delete_object(
    wallet_address: str,
    object_key: str,
    location: str,
    s3_client=None,
) -> dict:
    """Delete object from S3. If bucket is empty after delete, delete the bucket. Returns result dict."""
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key."}
    if s3_client is None:
        s3_client = boto3.client("s3", region_name=location)
    try:
        validate_bucket_name(bucket_name(wallet_address))
    except ValueError as e:
        return {"success": False, "error": str(e)}
    try:
        bucket_name_str = bucket_name(wallet_address)
        require_bucket_exists(s3_client, bucket_name_str)
        try:
            s3_client.head_object(Bucket=bucket_name_str, Key=object_key)
        except ClientError as e:
            if e.response["Error"].get("Code") == "404":
                return {"success": False, "error": f"Object not found: {object_key}.", "not_found": True}
            raise
        s3_client.delete_object(Bucket=bucket_name_str, Key=object_key)
        bucket_deleted = False
        resp = s3_client.list_objects_v2(Bucket=bucket_name_str, MaxKeys=1)
        if resp.get("KeyCount", 0) == 0:
            s3_client.delete_bucket(Bucket=bucket_name_str)
            bucket_deleted = True
        return {"success": True, "key": object_key, "bucket": bucket_name_str, "bucket_deleted": bucket_deleted}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except ClientError as e:
        return {"success": False, "error": f"Delete failed: {e.response['Error'].get('Message', str(e))}"}


def ensure_log_group(logs_client, log_group: str = LOG_GROUP) -> None:
    """Create log group if it does not exist."""
    try:
        logs_client.create_log_group(logGroupName=log_group)
    except ClientError as e:
        if e.response["Error"].get("Code") != "ResourceAlreadyExistsException":
            raise


def send_log_event(
    command: str,
    wallet_address: str,
    object_id_or_key: str,
    location: str,
    result: dict,
    log_group: str = LOG_GROUP,
) -> None:
    """Send one structured log event to CloudWatch Logs. Swallows errors (fallback to stderr)."""
    try:
        logs = boto3.client("logs")
        ensure_log_group(logs, log_group)
        stream_name = f"script/{int(time.time() * 1000)}"
        try:
            logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)
        except ClientError as e:
            if e.response["Error"].get("Code") != "ResourceAlreadyExistsException":
                raise
        payload = {
            "command": command,
            "wallet_hash": wallet_hash(wallet_address) if wallet_address else None,
            "wallet_address": wallet_address,
            "object_id": object_id_or_key,
            "location": location,
            "bucket": bucket_name(wallet_address) if wallet_address else None,
            "success": result.get("success", False),
            "key": result.get("key"),
            "size_bytes": result.get("size_bytes"),
            "path": result.get("path"),
            "error": result.get("error"),
        }
        event = {
            "timestamp": int(round(time.time() * 1000)),
            "message": json.dumps(payload),
        }
        logs.put_log_events(
            logGroupName=log_group,
            logStreamName=stream_name,
            logEvents=[event],
        )
    except Exception:
        logging.getLogger(__name__).exception("CloudWatch Logs failed")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="mnemospark object storage: upload, ls, download, delete (S3 + client-held encryption)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for cmd in ("upload", "ls", "download", "delete"):
        sub = subparsers.add_parser(cmd, help=f"{cmd} object")
        sub.add_argument("--wallet-address", required=True, help="Base blockchain wallet address")
        sub.add_argument("--location", default="us-east-1", help="AWS region (default: us-east-1)")
        if cmd == "upload":
            sub.add_argument("--object-id", required=True, help="Local file path to upload")
        else:
            sub.add_argument("--object-key", required=True, help="S3 object key")

    args = parser.parse_args()
    command = args.command
    wallet_address = (args.wallet_address or "").strip()
    location = (getattr(args, "location", None) or "us-east-1").strip()

    if not wallet_address:
        print("Error: --wallet-address is required and must be non-empty.", file=sys.stderr)
        return EXIT_VALIDATION
    if not location:
        print("Error: --location must be non-empty.", file=sys.stderr)
        return EXIT_VALIDATION

    if command == "upload":
        object_id = (getattr(args, "object_id", None) or "").strip()
        if not object_id:
            print("Error: --object-id is required and must be non-empty.", file=sys.stderr)
            return EXIT_VALIDATION
        if not os.path.isfile(object_id):
            print(f"Error: File not found: {object_id}", file=sys.stderr)
            send_log_event(command, wallet_address, object_id, location, {"success": False, "error": "File not found"})
            return EXIT_NOT_FOUND
        result = upload_object(wallet_address, object_id, location)
        object_id_or_key = object_id
    else:
        object_key = (getattr(args, "object_key", None) or "").strip()
        if not object_key:
            print("Error: --object-key is required and must be non-empty.", file=sys.stderr)
            return EXIT_VALIDATION
        object_id_or_key = object_key
        if command == "ls":
            result = list_object(wallet_address, object_key, location)
        elif command == "download":
            result = download_object(wallet_address, object_key, location)
        elif command == "delete":
            result = delete_object(wallet_address, object_key, location)
        else:
            print(f"Error: Unknown command {command}", file=sys.stderr)
            return EXIT_VALIDATION

    send_log_event(command, wallet_address, object_id_or_key, location, result)

    if result.get("success"):
        if command == "upload":
            print(
                f"Object stored successfully. Bucket: {result['bucket']}, Key: {result['key']}, Region: {result['region']}."
            )
        elif command == "ls":
            size_str = format_size(result["size_bytes"])
            print(f"{result['bucket']}  {result['key']}  {size_str}")
        elif command == "download":
            print(f"Downloaded {result['key']} to {result['path']}.")
        elif command == "delete":
            msg = f"Object deleted from S3: {result['key']}."
            if result.get("bucket_deleted"):
                msg += " Bucket was empty and has been deleted."
            print(msg)
        return EXIT_SUCCESS

    error_msg = result.get("error", "Unknown error")
    print(f"Error: {error_msg}", file=sys.stderr)
    if result.get("not_found"):
        return EXIT_NOT_FOUND
    if "Bucket not found" in error_msg or "Object not found" in error_msg or "not found" in error_msg.lower():
        return EXIT_NOT_FOUND
    return EXIT_S3_OR_ENCRYPTION


if __name__ == "__main__":
    sys.exit(main())
