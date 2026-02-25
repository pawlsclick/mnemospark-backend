import importlib.util
import json
import os
import time
from pathlib import Path
import unittest
from unittest import mock


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "price-storage" / "app.py"
    module_spec = importlib.util.spec_from_file_location("price_storage_app", module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load price storage module")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeDynamoDbClient:
    def __init__(self):
        self.put_item_calls = []

    def put_item(self, **kwargs):
        self.put_item_calls.append(kwargs)
        return {}


class PriceStorageIntegrationTests(unittest.TestCase):
    def test_lambda_handler_with_mocked_estimates_and_dynamodb(self):
        fake_dynamodb = FakeDynamoDbClient()
        event = {
            "body": json.dumps(
                {
                    "wallet_address": "0xabc123",
                    "object_id": "backup.tar.gz",
                    "object_id_hash": "hash-value",
                    "gb": 8,
                    "provider": "aws",
                    "region": "[REDACTED]",
                }
            )
        }

        with (
            mock.patch.object(app, "estimate_storage_cost", return_value=1.25),
            mock.patch.object(app, "estimate_transfer_cost", return_value=0.75),
            mock.patch.object(app, "get_dynamodb_client", return_value=fake_dynamodb),
            mock.patch.dict(
                os.environ,
                {
                    "QUOTES_TABLE_NAME": "quotes-test",
                    "QUOTE_TTL_SECONDS": "3600",
                    "PRICE_STORAGE_MARKUP_PERCENT": "10",
                    "PRICE_STORAGE_TRANSFER_DIRECTION": "out",
                    "PRICE_STORAGE_RATE_TYPE": "BEFORE_DISCOUNTS",
                },
                clear=False,
            ),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["storage_price"], 2.2)
        self.assertEqual(body["addr"], "0xabc123")
        self.assertEqual(body["object_id"], "backup.tar.gz")
        self.assertEqual(body["object_id_hash"], "hash-value")
        self.assertEqual(body["object_size_gb"], 8.0)
        self.assertEqual(body["provider"], "aws")
        self.assertEqual(body["location"], "[REDACTED]")

        self.assertEqual(len(fake_dynamodb.put_item_calls), 1)
        put_item_call = fake_dynamodb.put_item_calls[0]
        self.assertEqual(put_item_call["TableName"], "quotes-test")
        self.assertEqual(put_item_call["Item"]["quote_id"]["S"], body["quote_id"])
        self.assertEqual(put_item_call["Item"]["storage_price"]["N"], "2.20")
        self.assertEqual(put_item_call["Item"]["addr"]["S"], "0xabc123")
        self.assertEqual(put_item_call["Item"]["object_id"]["S"], "backup.tar.gz")
        self.assertEqual(put_item_call["Item"]["provider"]["S"], "aws")

        expires_at = int(put_item_call["Item"]["expires_at"]["N"])
        ttl_delta = expires_at - int(time.time())
        self.assertGreaterEqual(ttl_delta, 3500)
        self.assertLessEqual(ttl_delta, 3700)
