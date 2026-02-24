"""
S3 + client-held encryption for Lambda. KEK stored in Secrets Manager (no local key store).
Mirrors object_storage_management_aws.py logic; upload accepts bytes instead of file path.
"""

import base64
import re
import secrets
from typing import Any

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BUCKET_NAME_MIN_LEN = 3
BUCKET_NAME_MAX_LEN = 63
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
BUCKET_FORBIDDEN_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
BUCKET_FORBIDDEN_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
BUCKET_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
WALLET_HASH_LEN = 16
NONCE_BYTES = 12
SECRET_PREFIX = "mnemospark/wallet/"


def wallet_hash(wallet_address: str, length: int = WALLET_HASH_LEN) -> str:
    import hashlib
    return hashlib.sha256(wallet_address.encode()).hexdigest()[:length]


def bucket_name(wallet_address: str) -> str:
    return f"mnemospark-{wallet_hash(wallet_address)}"


def validate_bucket_name(name: str) -> None:
    if not (BUCKET_NAME_MIN_LEN <= len(name) <= BUCKET_NAME_MAX_LEN):
        raise ValueError(f"Bucket name must be {BUCKET_NAME_MIN_LEN}-{BUCKET_NAME_MAX_LEN} characters, got {len(name)}")
    if not BUCKET_NAME_PATTERN.match(name):
        raise ValueError("Bucket name must use only a-z, 0-9, . and -; must start and end with letter or number")
    if name.startswith(BUCKET_FORBIDDEN_PREFIXES) or name.endswith(BUCKET_FORBIDDEN_SUFFIXES):
        raise ValueError("Bucket name uses a forbidden prefix or suffix")
    if BUCKET_IP_PATTERN.match(name):
        raise ValueError("Bucket name must not be formatted as an IP address")


def ensure_bucket_exists(s3_client, bucket_name_str: str, location: str) -> None:
    try:
        s3_client.head_bucket(Bucket=bucket_name_str)
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "404":
            raise
    if location == "us-east-1":
        s3_client.create_bucket(Bucket=bucket_name_str)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name_str,
            CreateBucketConfiguration={"LocationConstraint": location},
        )


def require_bucket_exists(s3_client, bucket_name_str: str) -> None:
    try:
        s3_client.head_bucket(Bucket=bucket_name_str)
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            raise ValueError("Bucket not found for this wallet.") from e
        raise


def _encrypt_with_dek(plaintext: bytes, dek: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    aes = AESGCM(dek)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def _wrap_dek(dek: bytes, kek: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    aes = AESGCM(kek)
    ct = aes.encrypt(nonce, dek, None)
    return nonce + ct


def _unwrap_dek(wrapped_b64: str, kek: bytes) -> bytes:
    raw = base64.b64decode(wrapped_b64)
    nonce = raw[:NONCE_BYTES]
    ciphertext = raw[NONCE_BYTES:]
    aes = AESGCM(kek)
    return aes.decrypt(nonce, ciphertext, None)


def _decrypt_with_dek(ciphertext_with_nonce: bytes, dek: bytes) -> bytes:
    nonce = ciphertext_with_nonce[:NONCE_BYTES]
    ciphertext = ciphertext_with_nonce[NONCE_BYTES:]
    aes = AESGCM(dek)
    return aes.decrypt(nonce, ciphertext, None)


def load_or_create_kek(wallet_short_hash: str, sm_client=None) -> bytes:
    """Get KEK from Secrets Manager, or create and store. Returns 32 bytes."""
    if sm_client is None:
        sm_client = boto3.client("secretsmanager")
    secret_id = SECRET_PREFIX + wallet_short_hash
    try:
        resp = sm_client.get_secret_value(SecretId=secret_id)
        raw = resp.get("SecretString") or resp.get("SecretBinary")
        if isinstance(raw, str):
            raw = base64.b64decode(raw)
        if raw and len(raw) == 32:
            return raw
        if raw and len(raw) == 44:
            return base64.b64decode(raw)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    kek = secrets.token_bytes(32)
    sm_client.create_secret(
        Name=secret_id,
        SecretBinary=base64.b64encode(kek).decode("ascii"),
    )
    return kek


def upload_object(
    wallet_address: str,
    object_key: str,
    plaintext: bytes,
    location: str,
    s3_client=None,
    sm_client=None,
) -> dict[str, Any]:
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key (path traversal not allowed)."}
    try:
        validate_bucket_name(bucket_name(wallet_address))
    except ValueError as e:
        return {"success": False, "error": str(e)}
    try:
        s3_client = s3_client or boto3.client("s3", region_name=location)
        sm_client = sm_client or boto3.client("secretsmanager")
        bucket_name_str = bucket_name(wallet_address)
        ensure_bucket_exists(s3_client, bucket_name_str, location)
        wh = wallet_hash(wallet_address)
        kek = load_or_create_kek(wh, sm_client)
        dek = secrets.token_bytes(32)
        ciphertext = _encrypt_with_dek(plaintext, dek)
        wrapped_dek = _wrap_dek(dek, kek)
        wrapped_dek_b64 = base64.b64encode(wrapped_dek).decode("ascii")
        s3_client.put_object(
            Bucket=bucket_name_str,
            Key=object_key,
            Body=ciphertext,
            Metadata={"wrapped-dek": wrapped_dek_b64},
        )
        return {"success": True, "bucket": bucket_name_str, "key": object_key, "region": location}
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
) -> dict[str, Any]:
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key."}
    s3_client = s3_client or boto3.client("s3", region_name=location)
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
    sm_client=None,
) -> dict[str, Any]:
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key."}
    s3_client = s3_client or boto3.client("s3", region_name=location)
    sm_client = sm_client or boto3.client("secretsmanager")
    try:
        validate_bucket_name(bucket_name(wallet_address))
    except ValueError as e:
        return {"success": False, "error": str(e)}
    try:
        bucket_name_str = bucket_name(wallet_address)
        require_bucket_exists(s3_client, bucket_name_str)
        wh = wallet_hash(wallet_address)
        secret_id = SECRET_PREFIX + wh
        try:
            resp = sm_client.get_secret_value(SecretId=secret_id)
            raw = resp.get("SecretString") or resp.get("SecretBinary")
            if isinstance(raw, str):
                raw = base64.b64decode(raw)
            kek = raw if len(raw) == 32 else base64.b64decode(raw)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return {"success": False, "error": "Cannot decrypt: key not found for this wallet."}
            raise
        resp = s3_client.get_object(Bucket=bucket_name_str, Key=object_key)
        body = resp["Body"].read()
        meta = resp.get("Metadata") or {}
        wrapped_dek_b64 = meta.get("wrapped-dek")
        if not wrapped_dek_b64:
            return {"success": False, "error": "Object metadata missing wrapped-dek (not encrypted?)."}
        dek = _unwrap_dek(wrapped_dek_b64, kek)
        plaintext = _decrypt_with_dek(body, dek)
        return {"success": True, "key": object_key, "content": plaintext, "bucket": bucket_name_str}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except ClientError as e:
        if e.response["Error"].get("Code") == "404":
            return {"success": False, "error": f"Object not found: {object_key}.", "not_found": True}
        return {"success": False, "error": f"S3 error: {e.response['Error'].get('Message', str(e))}"}
    except Exception as e:
        return {"success": False, "error": f"Decryption failed: {e}"}


def list_bucket(
    wallet_address: str,
    location: str,
    s3_client=None,
) -> dict[str, Any]:
    """List object keys (and sizes) in the wallet bucket. Returns success, keys (list of {key, size_bytes}), error."""
    s3_client = s3_client or boto3.client("s3", region_name=location)
    try:
        validate_bucket_name(bucket_name(wallet_address))
    except ValueError as e:
        return {"success": False, "error": str(e)}
    try:
        bucket_name_str = bucket_name(wallet_address)
        require_bucket_exists(s3_client, bucket_name_str)
        keys: list[dict[str, Any]] = []
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name_str):
            for obj in page.get("Contents") or []:
                keys.append({"key": obj["Key"], "size_bytes": obj.get("Size", 0)})
        return {"success": True, "bucket": bucket_name_str, "keys": keys}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except ClientError as e:
        return {"success": False, "error": f"S3 error: {e.response['Error'].get('Message', str(e))}"}


def delete_object(
    wallet_address: str,
    object_key: str,
    location: str,
    s3_client=None,
) -> dict[str, Any]:
    if not object_key or "/" in object_key or object_key in (".", ".."):
        return {"success": False, "error": "Invalid object key."}
    s3_client = s3_client or boto3.client("s3", region_name=location)
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
