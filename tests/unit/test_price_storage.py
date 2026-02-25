import importlib.util
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


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


class ParseInputTests(unittest.TestCase):
    def test_parse_input_happy_path(self):
        event = {
            "body": json.dumps(
                {
                    "wallet_address": "0xabc123",
                    "object_id": "backup.tar.gz",
                    "object_id_hash": "abc123hash",
                    "gb": 5,
                    "provider": "aws",
                    "region": "[REDACTED]",
                }
            )
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed["wallet_address"], "0xabc123")
        self.assertEqual(parsed["object_id"], "backup.tar.gz")
        self.assertEqual(parsed["object_id_hash"], "abc123hash")
        self.assertEqual(parsed["gb"], 5.0)
        self.assertEqual(parsed["provider"], "aws")
        self.assertEqual(parsed["region"], "[REDACTED]")

    def test_parse_input_rejects_missing_required_field(self):
        event = {"body": json.dumps({"object_id": "backup.tar.gz"})}

        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)

    def test_parse_input_rejects_invalid_provider(self):
        event = {
            "body": json.dumps(
                {
                    "wallet_address": "0xabc123",
                    "object_id": "backup.tar.gz",
                    "object_id_hash": "abc123hash",
                    "gb": 5,
                    "provider": "gcp",
                    "region": "[REDACTED]",
                }
            )
        }

        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)


class MarkupConfigTests(unittest.TestCase):
    def test_markup_accepts_percent_string(self):
        with mock.patch.dict(os.environ, {"PRICE_STORAGE_MARKUP_PERCENT": "15"}, clear=False):
            markup = app._get_markup_multiplier()
        self.assertEqual(markup, 0.15)

    def test_markup_accepts_fraction_string(self):
        with mock.patch.dict(os.environ, {"PRICE_STORAGE_MARKUP_PERCENT": "0.2"}, clear=False):
            markup = app._get_markup_multiplier()
        self.assertEqual(markup, 0.2)


class QuoteWriteTests(unittest.TestCase):
    def test_write_quote_persists_expected_item_and_ttl(self):
        fake_dynamodb = FakeDynamoDbClient()
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        quote = {
            "timestamp": "2026-01-01 12:00:00",
            "quote_id": "quote-123",
            "storage_price": 3.45,
            "addr": "0xabc123",
            "object_id": "backup.tar.gz",
            "object_id_hash": "hash-value",
            "object_size_gb": 5.0,
            "provider": "aws",
            "location": "[REDACTED]",
        }

        app.write_quote(
            quote=quote,
            storage_cost=2.0,
            transfer_cost=1.0,
            markup_multiplier=0.15,
            dynamodb_client=fake_dynamodb,
            table_name="quotes-table",
            ttl_seconds=3600,
            now=now,
        )

        self.assertEqual(len(fake_dynamodb.put_item_calls), 1)
        put_item_call = fake_dynamodb.put_item_calls[0]
        self.assertEqual(put_item_call["TableName"], "quotes-table")
        self.assertEqual(put_item_call["Item"]["quote_id"]["S"], "quote-123")
        self.assertEqual(put_item_call["Item"]["storage_price"]["N"], "3.45")
        self.assertEqual(put_item_call["Item"]["provider"]["S"], "aws")
        self.assertEqual(put_item_call["Item"]["expires_at"]["N"], str(int(now.timestamp()) + 3600))


class LambdaHandlerTests(unittest.TestCase):
    def _valid_event(self):
        return {
            "body": json.dumps(
                {
                    "wallet_address": "0xabc123",
                    "object_id": "backup.tar.gz",
                    "object_id_hash": "hash-value",
                    "gb": 5,
                    "provider": "aws",
                    "region": "[REDACTED]",
                }
            )
        }

    def test_lambda_handler_success(self):
        event = self._valid_event()

        with (
            mock.patch.object(app, "estimate_storage_cost", return_value=2.0),
            mock.patch.object(app, "estimate_transfer_cost", return_value=1.0),
            mock.patch.object(app, "write_quote") as write_quote_mock,
            mock.patch.dict(
                os.environ,
                {
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
        self.assertEqual(body["storage_price"], 3.3)
        self.assertEqual(body["addr"], "0xabc123")
        self.assertEqual(body["object_id"], "backup.tar.gz")
        self.assertEqual(body["provider"], "aws")
        self.assertEqual(body["location"], "[REDACTED]")
        self.assertIn("quote_id", body)
        self.assertIn("timestamp", body)
        write_quote_mock.assert_called_once()

    def test_lambda_handler_returns_bad_request_shape(self):
        response = app.lambda_handler({"body": json.dumps({"wallet_address": "0xabc123"})}, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")
        self.assertIn("message", body)

    def test_lambda_handler_returns_internal_error_shape_on_dynamodb_failure(self):
        event = self._valid_event()
        client_error = ClientError(
            error_response={
                "Error": {
                    "Code": "ProvisionedThroughputExceededException",
                    "Message": "throttled",
                }
            },
            operation_name="PutItem",
        )

        with (
            mock.patch.object(app, "estimate_storage_cost", return_value=2.0),
            mock.patch.object(app, "estimate_transfer_cost", return_value=1.0),
            mock.patch.object(app, "write_quote", side_effect=client_error),
            mock.patch.dict(
                os.environ,
                {
                    "PRICE_STORAGE_MARKUP_PERCENT": "10",
                    "PRICE_STORAGE_TRANSFER_DIRECTION": "out",
                    "PRICE_STORAGE_RATE_TYPE": "BEFORE_DISCOUNTS",
                },
                clear=False,
            ),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 500)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Internal error")
        self.assertEqual(body["message"], "Failed to process price-storage request")
        self.assertEqual(body["details"], "throttled")
