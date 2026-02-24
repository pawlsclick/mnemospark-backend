"""Unit tests for storage_core pure functions (no AWS calls needed)."""

import importlib.util
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")

def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

sc = _load_module("storage_core", os.path.join(ROOT, "examples", "object-storage-management-api", "storage_core.py"))


class TestWalletHash:
    def test_deterministic(self):
        h1 = sc.wallet_hash("0xABCDEF1234567890")
        h2 = sc.wallet_hash("0xABCDEF1234567890")
        assert h1 == h2

    def test_length(self):
        h = sc.wallet_hash("0xABCDEF1234567890")
        assert len(h) == 16

    def test_hex_chars(self):
        h = sc.wallet_hash("0xABCDEF1234567890")
        assert all(c in "0123456789abcdef" for c in h)


class TestBucketName:
    def test_prefix(self):
        name = sc.bucket_name("0xABCDEF1234567890")
        assert name.startswith("mnemospark-")

    def test_valid_length(self):
        name = sc.bucket_name("0xABCDEF1234567890")
        assert 3 <= len(name) <= 63


class TestValidateBucketName:
    def test_valid(self):
        sc.validate_bucket_name("mnemospark-abcdef1234567890")

    def test_too_short(self):
        import pytest
        with pytest.raises(ValueError):
            sc.validate_bucket_name("ab")

    def test_too_long(self):
        import pytest
        with pytest.raises(ValueError):
            sc.validate_bucket_name("a" * 64)

    def test_forbidden_prefix(self):
        import pytest
        with pytest.raises(ValueError):
            sc.validate_bucket_name("xn--something")

    def test_ip_address(self):
        import pytest
        with pytest.raises(ValueError):
            sc.validate_bucket_name("192.168.1.1")


class TestEncryptionRoundTrip:
    def test_encrypt_decrypt_with_dek(self):
        import secrets
        dek = secrets.token_bytes(32)
        plaintext = b"Hello, mnemospark!"
        encrypted = sc._encrypt_with_dek(plaintext, dek)
        assert encrypted != plaintext
        decrypted = sc._decrypt_with_dek(encrypted, dek)
        assert decrypted == plaintext

    def test_wrap_unwrap_dek(self):
        import base64
        import secrets
        kek = secrets.token_bytes(32)
        dek = secrets.token_bytes(32)
        wrapped = sc._wrap_dek(dek, kek)
        wrapped_b64 = base64.b64encode(wrapped).decode("ascii")
        unwrapped = sc._unwrap_dek(wrapped_b64, kek)
        assert unwrapped == dek

    def test_full_envelope_encryption(self):
        import base64
        import secrets
        kek = secrets.token_bytes(32)
        dek = secrets.token_bytes(32)
        plaintext = b"Decentralized storage with crypto payments!"
        ciphertext = sc._encrypt_with_dek(plaintext, dek)
        wrapped_dek = sc._wrap_dek(dek, kek)
        wrapped_dek_b64 = base64.b64encode(wrapped_dek).decode("ascii")
        recovered_dek = sc._unwrap_dek(wrapped_dek_b64, kek)
        recovered = sc._decrypt_with_dek(ciphertext, recovered_dek)
        assert recovered == plaintext


class TestObjectStorageParseInput:
    def _load_app(self):
        import sys
        obj_dir = os.path.join(ROOT, "examples", "object-storage-management-api")
        if obj_dir not in sys.path:
            sys.path.insert(0, obj_dir)
        return _load_module("obj_app", os.path.join(obj_dir, "app.py"))

    def test_defaults(self):
        app = self._load_app()
        result = app.parse_input({})
        assert result["command"] == "list"
        assert result["wallet_address"] == ""
        assert result["location"] == "us-east-1"

    def test_upload_body(self):
        import json
        app = self._load_app()
        event = {
            "body": json.dumps({
                "command": "upload",
                "wallet_address": "0xABC",
                "object_key": "test.txt",
                "content": "aGVsbG8=",
            })
        }
        result = app.parse_input(event)
        assert result["command"] == "upload"
        assert result["wallet_address"] == "0xABC"
        assert result["object_key"] == "test.txt"
        assert result["content_b64"] == "aGVsbG8="

    def test_invalid_command_defaults_to_list(self):
        app = self._load_app()
        event = {"queryStringParameters": {"command": "destroy"}}
        result = app.parse_input(event)
        assert result["command"] == "list"
