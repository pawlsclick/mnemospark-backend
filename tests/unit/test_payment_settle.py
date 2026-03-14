import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "payment-settle" / "app.py"
    module_name = "payment_settle_app"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load payment-settle module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_module()


@dataclass(frozen=True)
class FakePaymentResult:
    trans_id: str
    network: str
    asset: str
    amount: int


class PaymentRequiredError(Exception):
    def __init__(self, message, requirements, details=None):
        super().__init__(message)
        self.message = message
        self.requirements = requirements
        self.details = details


class FakePaymentCore:
    PAYMENT_SIGNATURE_HEADER_NAMES = ("payment-signature", "x-payment")
    USDC_DECIMALS = Decimal("1000000")

    def __init__(self):
        self.verify_calls = []
        self.next_verify_result = FakePaymentResult(
            trans_id="0xabc123",
            network="eip155:8453",
            asset="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            amount=1_250_000,
        )
        self.verify_raises = None

    def _normalize_address(self, value, field_name):
        del field_name
        value = str(value).strip()
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError("address must be 0x-prefixed 20-byte hex")
        return f"0x{value[2:].lower()}"

    def _payment_config(self):
        return {
            "recipient_wallet": "0x47d241ae97fe37186ac59894290ca1c54c060a6c",
            "payment_asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "payment_network": "eip155:8453",
        }

    def _payment_requirements(self, quote_context, payment_config):
        del quote_context
        return {
            "accepts": [
                {
                    "network": payment_config["payment_network"],
                    "asset": payment_config["payment_asset"],
                    "payTo": payment_config["recipient_wallet"],
                }
            ]
        }

    def _payment_required_headers(self, requirements):
        return {"PAYMENT-REQUIRED": json.dumps(requirements)}

    def verify_and_settle_payment(self, **kwargs):
        self.verify_calls.append(kwargs)
        if self.verify_raises is not None:
            raise self.verify_raises
        return self.next_verify_result


class FakeDynamoTable:
    def __init__(self, key_fields):
        self.key_fields = list(key_fields)
        self.items = {}

    def _key_tuple(self, key):
        return tuple((field, key[field]) for field in self.key_fields)

    def get_item(self, Key, ConsistentRead=False):
        del ConsistentRead
        item = self.items.get(self._key_tuple(Key))
        if item is None:
            return {}
        return {"Item": dict(item)}

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        key_tuple = self._key_tuple(Item)
        if ConditionExpression == "attribute_not_exists(wallet_address) AND attribute_not_exists(quote_id)":
            if key_tuple in self.items:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate"}},
                    "PutItem",
                )
        if (
            ConditionExpression
            == "attribute_exists(wallet_address) AND attribute_exists(quote_id) AND payment_status = :expected_status"
        ):
            expected_status = (
                None if ExpressionAttributeValues is None else ExpressionAttributeValues.get(":expected_status")
            )
            existing = self.items.get(key_tuple)
            if existing is None or existing.get("payment_status") != expected_status:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "missing claim"}},
                    "PutItem",
                )
        self.items[key_tuple] = dict(Item)
        return {}

    def delete_item(self, Key, ConditionExpression=None, ExpressionAttributeValues=None):
        key_tuple = self._key_tuple(Key)
        existing = self.items.get(key_tuple)
        if ConditionExpression == "payment_status = :status":
            expected_status = None if ExpressionAttributeValues is None else ExpressionAttributeValues.get(":status")
            if existing is None or existing.get("payment_status") != expected_status:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
                    "DeleteItem",
                )
        self.items.pop(key_tuple, None)
        return {}


class FakeDynamoResource:
    def __init__(self, tables_by_name):
        self.tables_by_name = tables_by_name

    def Table(self, name):
        return self.tables_by_name[name]


class PaymentSettleHandlerTests(unittest.TestCase):
    def setUp(self):
        self.wallet_address = "0x1111111111111111111111111111111111111111"
        self.quote_id = "quote-123"
        self.now = int(time.time())

        self.quotes_table = FakeDynamoTable(["quote_id"])
        self.quotes_table.put_item(
            Item={
                "quote_id": self.quote_id,
                "expires_at": self.now + 3600,
                "storage_price": Decimal("1.25"),
                "addr": self.wallet_address,
                "provider": "aws",
                "location": "us-east-1",  # pragma: allowlist secret
            }
        )
        self.payments_table = FakeDynamoTable(["wallet_address", "quote_id"])
        self.dynamodb_resource = FakeDynamoResource(
            {
                "quotes-table": self.quotes_table,
                "payments-table": self.payments_table,
            }
        )

        self.fake_payment_core = FakePaymentCore()
        self.original_payment_core = app._PAYMENT_CORE
        app._PAYMENT_CORE = self.fake_payment_core

        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "QUOTES_TABLE_NAME": "quotes-table",
                "PAYMENT_LEDGER_TABLE_NAME": "payments-table",
                "MNEMOSPARK_PAYMENT_SETTLEMENT_MODE": "mock",
            },
            clear=False,
        )
        self.env_patch.start()
        self.resource_patch = mock.patch.object(app.boto3, "resource", return_value=self.dynamodb_resource)
        self.resource_patch.start()

    def tearDown(self):
        self.resource_patch.stop()
        self.env_patch.stop()
        app._PAYMENT_CORE = self.original_payment_core

    def _event(self, *, include_authorizer=True, headers=None, **body_updates):
        body = {
            "quote_id": self.quote_id,
            "wallet_address": self.wallet_address,
        }
        body.update(body_updates)
        event = {"body": json.dumps(body), "headers": headers or {}}
        if include_authorizer:
            event["requestContext"] = {
                "authorizer": {
                    "walletAddress": self.wallet_address,
                }
            }
        return event

    def test_success_settlement_writes_ledger_row(self):
        event = self._event(headers={"PAYMENT-SIGNATURE": "signed-payload"})

        with mock.patch.object(app, "log_api_call") as log_api_call_mock:
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["quote_id"], self.quote_id)
        self.assertEqual(body["wallet_address"], self.wallet_address)
        self.assertEqual(body["trans_id"], "0xabc123")
        self.assertEqual(body["payment_status"], "confirmed")

        ledger_item = self.payments_table.items[(("wallet_address", self.wallet_address), ("quote_id", self.quote_id))]
        self.assertEqual(ledger_item["trans_id"], "0xabc123")
        self.assertEqual(ledger_item["payment_status"], "confirmed")
        self.assertEqual(ledger_item["amount"], "1250000")
        self.assertEqual(ledger_item["recipient_wallet"], "0x47d241ae97fe37186ac59894290ca1c54c060a6c")

        self.assertEqual(len(self.fake_payment_core.verify_calls), 1)
        verify_kwargs = self.fake_payment_core.verify_calls[0]
        self.assertEqual(verify_kwargs["payment_header"], "signed-payload")
        self.assertEqual(verify_kwargs["expected_amount"], 1_250_000)
        self.assertEqual(verify_kwargs["wallet_address"], self.wallet_address)
        self.assertEqual(verify_kwargs["quote_id"], self.quote_id)

        self.assertGreaterEqual(log_api_call_mock.call_count, 1)
        self.assertEqual(log_api_call_mock.call_args.kwargs["status_code"], 200)
        self.assertEqual(log_api_call_mock.call_args.kwargs["route"], "/payment/settle")

    def test_duplicate_settlement_returns_conflict(self):
        event = self._event(headers={"PAYMENT-SIGNATURE": "signed-payload"})

        first = app.lambda_handler(event, None)
        second = app.lambda_handler(event, None)

        self.assertEqual(first["statusCode"], 200)
        self.assertEqual(second["statusCode"], 409)
        second_body = json.loads(second["body"])
        self.assertEqual(second_body["error"], "conflict")
        self.assertEqual(len(self.fake_payment_core.verify_calls), 1)

    def test_confirmed_duplicate_is_blocked_before_settlement(self):
        self.payments_table.put_item(
            Item={
                "wallet_address": self.wallet_address,
                "quote_id": self.quote_id,
                "payment_status": "confirmed",
                "trans_id": "0xalready",
            }
        )
        event = self._event(headers={"PAYMENT-SIGNATURE": "signed-payload"})

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 409)
        self.assertEqual(len(self.fake_payment_core.verify_calls), 0)

    def test_payment_required_releases_ledger_claim(self):
        self.fake_payment_core.verify_raises = PaymentRequiredError(
            "Payment authorization is invalid",
            {"accepts": [{"network": "eip155:8453"}]},
            details="bad_signature",
        )
        event = self._event(headers={"PAYMENT-SIGNATURE": "bad-payload"})

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 402)
        self.assertNotIn((("wallet_address", self.wallet_address), ("quote_id", self.quote_id)), self.payments_table.items)

    def test_missing_authorizer_context_returns_403(self):
        event = self._event(include_authorizer=False, headers={"PAYMENT-SIGNATURE": "signed-payload"})

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")

    def test_quote_not_found_returns_404(self):
        self.quotes_table.items.clear()
        event = self._event(headers={"PAYMENT-SIGNATURE": "signed-payload"})

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "quote_not_found")

    def test_payment_required_maps_to_402_with_headers(self):
        event = self._event(headers={"PAYMENT-SIGNATURE": "bad-payload"})
        self.fake_payment_core.verify_raises = PaymentRequiredError(
            "Payment authorization is invalid",
            {"accepts": [{"network": "eip155:8453"}]},
            details="bad_signature",
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 402)
        self.assertIn("PAYMENT-REQUIRED", response["headers"])
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "payment_required")
        self.assertEqual(body["details"], "bad_signature")

    def test_inline_payment_payload_used_when_header_absent(self):
        event = self._event(
            payment={
                "signature": "0x" + ("11" * 65),
                "authorization": {
                    "from": self.wallet_address,
                    "to": "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
                },
            }
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        verify_kwargs = self.fake_payment_core.verify_calls[-1]
        self.assertIsInstance(verify_kwargs["payment_header"], str)
        self.assertTrue(verify_kwargs["payment_header"].startswith("{"))


if __name__ == "__main__":
    unittest.main()
