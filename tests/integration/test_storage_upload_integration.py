import base64
import copy
import importlib.util
import json
import os
import sys
import time
from decimal import Decimal
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-upload" / "app.py"
    module_name = "storage_upload_app_integration"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load storage upload module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeDynamoTable:
    def __init__(self, key_fields):
        self.key_fields = list(key_fields)
        self.items = {}

    def _key_tuple(self, key):
        return tuple((field, key[field]) for field in self.key_fields)

    def get_item(self, Key, ConsistentRead=False):
        del ConsistentRead
        item = self.items.get(self._key_tuple(Key))
        return {"Item": copy.deepcopy(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None):
        key = self._key_tuple(Item)
        if ConditionExpression == "attribute_not_exists(idempotency_key)" and key in self.items:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate idempotency key"}},
                "PutItem",
            )
        self.items[key] = copy.deepcopy(Item)
        return {}

    def delete_item(self, Key):
        self.items.pop(self._key_tuple(Key), None)
        return {}


class FakeDynamoResource:
    def __init__(self, tables):
        self.tables = tables

    def Table(self, name):
        return self.tables[name]


class FakeS3Client:
    def __init__(self):
        self.buckets = set()
        self.put_count = 0

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise ClientError({"Error": {"Code": "404", "Message": "missing"}}, "HeadBucket")
        return {}

    def create_bucket(self, Bucket, CreateBucketConfiguration=None):
        del CreateBucketConfiguration
        self.buckets.add(Bucket)
        return {}

    def put_object(self, Bucket, Key, Body, Metadata):
        del Key, Body, Metadata
        if Bucket not in self.buckets:
            raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "missing"}}, "PutObject")
        self.put_count += 1
        return {}


class StorageUploadIntegrationTests(unittest.TestCase):
    def test_upload_then_idempotent_retry_returns_cached_response(self):
        now = int(time.time())
        wallet_address = "0x1111111111111111111111111111111111111111"
        quote_id = "quote-int-1"
        object_id = "object.bin"
        object_hash = "hash-int-1"

        quotes_table = FakeDynamoTable(["quote_id"])
        quotes_table.put_item(
            Item={
                "quote_id": quote_id,
                "expires_at": now + 3600,
                "storage_price": Decimal("2.0"),
                "addr": wallet_address,
                "object_id": object_id,
                "object_id_hash": object_hash,
                "provider": "aws",
                "location": "[REDACTED]",
            }
        )
        transaction_log_table = FakeDynamoTable(["quote_id", "trans_id"])
        idempotency_table = FakeDynamoTable(["idempotency_key"])
        dynamodb_resource = FakeDynamoResource(
            {
                "quotes": quotes_table,
                "txn-log": transaction_log_table,
                "idem": idempotency_table,
            }
        )
        s3_client = FakeS3Client()

        def mock_client(service_name, **kwargs):
            del kwargs
            if service_name == "s3":
                return s3_client
            raise AssertionError(service_name)

        event = {
            "headers": {
                "x-api-key": "key",
                "PAYMENT-SIGNATURE": "signed",
                "Idempotency-Key": "idem-int-1",
            },
            "body": json.dumps(
                {
                    "quote_id": quote_id,
                    "wallet_address": wallet_address,
                    "object_id": object_id,
                    "object_id_hash": object_hash,
                    "ciphertext": base64.b64encode(b"encrypted").decode("ascii"),
                    "wrapped_dek": base64.b64encode(b"wrapped").decode("ascii"),
                }
            ),
        }

        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xtrans",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=2_000_000,
        )
        env_vars = {
            "QUOTES_TABLE_NAME": "quotes",
            "UPLOAD_TRANSACTION_LOG_TABLE_NAME": "txn-log",
            "UPLOAD_IDEMPOTENCY_TABLE_NAME": "idem",
            "MNEMOSPARK_RECIPIENT_WALLET": "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
            "MNEMOSPARK_PAYMENT_NETWORK": "eip155:8453",
            "MNEMOSPARK_PAYMENT_ASSET": "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            "MNEMOSPARK_PAYMENT_SETTLEMENT_MODE": "mock",
        }

        with (
            mock.patch.dict(os.environ, env_vars, clear=False),
            mock.patch.object(app.boto3, "resource", return_value=dynamodb_resource),
            mock.patch.object(app.boto3, "client", side_effect=mock_client),
            mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result),
        ):
            first = app.lambda_handler(event, None)
            second = app.lambda_handler(event, None)

        self.assertEqual(first["statusCode"], 200)
        self.assertEqual(second["statusCode"], 200)
        self.assertEqual(json.loads(first["body"]), json.loads(second["body"]))
        self.assertEqual(s3_client.put_count, 1)
        self.assertEqual(len(transaction_log_table.items), 1)
        log_item = next(iter(transaction_log_table.items.values()))
        self.assertEqual(
            log_item["recipient_wallet"],
            "0x47d241ae97fe37186ac59894290ca1c54c060a6c",
        )
        self.assertEqual(log_item["payment_network"], "eip155:8453")
        self.assertEqual(
            log_item["payment_asset"],
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        )
        self.assertEqual(log_item["payment_status"], "confirmed")
        self.assertEqual(log_item["payment_amount"], "2000000")

