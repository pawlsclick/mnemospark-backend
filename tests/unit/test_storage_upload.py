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
    module_name = "storage_upload_app"
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
        self.put_history = []

    def _key_tuple(self, key):
        return tuple((field, key[field]) for field in self.key_fields)

    def get_item(self, Key, ConsistentRead=False):
        del ConsistentRead
        item = self.items.get(self._key_tuple(Key))
        if item is None:
            return {}
        return {"Item": copy.deepcopy(item)}

    def put_item(self, Item, ConditionExpression=None):
        key = self._key_tuple(Item)
        if ConditionExpression == "attribute_not_exists(idempotency_key)" and key in self.items:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate key"}},
                "PutItem",
            )
        self.items[key] = copy.deepcopy(Item)
        self.put_history.append(copy.deepcopy(Item))
        return {}

    def delete_item(self, Key, ConditionExpression=None, ExpressionAttributeValues=None):
        key_tuple = self._key_tuple(Key)
        item = self.items.get(key_tuple)

        if ConditionExpression == "expires_at <= :now":
            now = None if ExpressionAttributeValues is None else ExpressionAttributeValues.get(":now")
            expires_at = None if item is None else item.get("expires_at")
            if now is None or expires_at is None or int(expires_at) > int(now):
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition not met"}},
                    "DeleteItem",
                )

        self.items.pop(key_tuple, None)
        return {}


class FakeDynamoResource:
    def __init__(self, tables_by_name):
        self.tables_by_name = tables_by_name

    def Table(self, name):
        return self.tables_by_name[name]


class FakeS3Client:
    def __init__(self):
        self.buckets = set()
        self.created_buckets = []
        self.put_calls = []

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "not found"}},
                "HeadBucket",
            )
        return {}

    def create_bucket(self, Bucket, CreateBucketConfiguration=None):
        self.buckets.add(Bucket)
        self.created_buckets.append(
            {"Bucket": Bucket, "CreateBucketConfiguration": CreateBucketConfiguration}
        )
        return {}

    def put_object(self, Bucket, Key, Body, Metadata):
        if Bucket not in self.buckets:
            raise ClientError(
                {"Error": {"Code": "NoSuchBucket", "Message": "bucket does not exist"}},
                "PutObject",
            )
        self.put_calls.append(
            {
                "Bucket": Bucket,
                "Key": Key,
                "Body": Body,
                "Metadata": Metadata,
            }
        )
        return {}


class StorageUploadHelperTests(unittest.TestCase):
    def setUp(self):
        self.original_relayer_cache = app._RELAYER_PRIVATE_KEY_CACHE
        app._RELAYER_PRIVATE_KEY_CACHE = None

    def tearDown(self):
        app._RELAYER_PRIVATE_KEY_CACHE = self.original_relayer_cache

    def test_resolve_relayer_private_key_fetches_secret_once_and_caches(self):
        secret_client = mock.Mock()
        secret_client.get_secret_value.return_value = {"SecretString": "  0xabc123  "}

        with (
            mock.patch.dict(
                os.environ,
                {"MNEMOSPARK_RELAYER_SECRET_ID": "mnemospark/relayer-private-key"},
                clear=False,
            ),
            mock.patch.object(app.boto3, "client", return_value=secret_client) as client_mock,
        ):
            first = app._resolve_relayer_private_key()
            second = app._resolve_relayer_private_key()

        self.assertEqual(first, "0xabc123")
        self.assertEqual(second, "0xabc123")
        client_mock.assert_called_once_with("secretsmanager")
        secret_client.get_secret_value.assert_called_once_with(
            SecretId="mnemospark/relayer-private-key"
        )

    def test_resolve_relayer_private_key_decodes_secret_binary(self):
        secret_client = mock.Mock()
        secret_client.get_secret_value.return_value = {
            "SecretBinary": base64.b64encode(b"0xfeedbeef").decode("ascii")
        }

        with (
            mock.patch.dict(
                os.environ,
                {"MNEMOSPARK_RELAYER_SECRET_ID": "mnemospark/relayer-private-key"},
                clear=False,
            ),
            mock.patch.object(app.boto3, "client", return_value=secret_client),
        ):
            relayer_key = app._resolve_relayer_private_key()

        self.assertEqual(relayer_key, "0xfeedbeef")

    def test_ensure_bucket_exists_omits_location_constraint_for_us_east_1(self):
        s3_client = FakeS3Client()

        app._ensure_bucket_exists(
            s3_client=s3_client,
            bucket_name="mnemospark-test-bucket",
            location=app.US_EAST_1_REGION,
        )

        self.assertEqual(len(s3_client.created_buckets), 1)
        self.assertIsNone(s3_client.created_buckets[0]["CreateBucketConfiguration"])

    def test_ensure_bucket_exists_sets_location_constraint_for_other_regions(self):
        s3_client = FakeS3Client()

        app._ensure_bucket_exists(
            s3_client=s3_client,
            bucket_name="mnemospark-test-bucket",
            location="eu-west-1",
        )

        self.assertEqual(len(s3_client.created_buckets), 1)
        self.assertEqual(
            s3_client.created_buckets[0]["CreateBucketConfiguration"],
            {"LocationConstraint": "eu-west-1"},
        )

    def test_extract_transfer_authorization_preserves_explicit_zero_value(self):
        payment_payload = {
            "payload": {
                "signature": "0x" + ("11" * 65),
                "authorization": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "value": 0,
                    "validAfter": 1,
                    "validBefore": 2,
                    "nonce": "0x" + ("ab" * 32),
                    "network": "eip155:8453",
                    "asset": "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
                },
            },
            "accepted": [{"maxAmountRequired": 999999}],
        }

        authorization = app._extract_transfer_authorization(payment_payload)

        self.assertEqual(authorization.value, 0)

    def test_fetch_existing_idempotency_deletes_expired_item_conditionally(self):
        idempotency_table = FakeDynamoTable(["idempotency_key"])
        now = int(time.time())
        idempotency_table.put_item(
            Item={
                "idempotency_key": "idem-expired",
                "status": "in_progress",
                "request_hash": "request-hash",
                "expires_at": now - 10,
            }
        )

        result = app._fetch_existing_idempotency(
            idempotency_table=idempotency_table,
            idempotency_key="idem-expired",
            request_hash="request-hash",
            now=now,
        )

        self.assertIsNone(result)
        self.assertNotIn((("idempotency_key", "idem-expired"),), idempotency_table.items)

    def test_fetch_existing_idempotency_does_not_delete_newer_lock_after_race(self):
        idempotency_table = FakeDynamoTable(["idempotency_key"])
        now = int(time.time())
        idempotency_key = "idem-race"
        key_tuple = (("idempotency_key", idempotency_key),)
        idempotency_table.put_item(
            Item={
                "idempotency_key": idempotency_key,
                "status": "in_progress",
                "request_hash": "request-hash",
                "expires_at": now - 1,
            }
        )

        original_delete_item = idempotency_table.delete_item
        state = {"swapped": False}

        def racing_delete_item(Key, ConditionExpression=None, ExpressionAttributeValues=None):
            if not state["swapped"]:
                state["swapped"] = True
                idempotency_table.items[key_tuple] = {
                    "idempotency_key": idempotency_key,
                    "status": "in_progress",
                    "request_hash": "request-hash",
                    "expires_at": now + 3600,
                }
            return original_delete_item(
                Key=Key,
                ConditionExpression=ConditionExpression,
                ExpressionAttributeValues=ExpressionAttributeValues,
            )

        with mock.patch.object(idempotency_table, "delete_item", side_effect=racing_delete_item):
            with self.assertRaises(app.ConflictError):
                app._fetch_existing_idempotency(
                    idempotency_table=idempotency_table,
                    idempotency_key=idempotency_key,
                    request_hash="request-hash",
                    now=now,
                )

        self.assertIn(key_tuple, idempotency_table.items)
        self.assertGreater(int(idempotency_table.items[key_tuple]["expires_at"]), now)


class StorageUploadLambdaTests(unittest.TestCase):
    def setUp(self):
        self.wallet_address = "0x1111111111111111111111111111111111111111"
        self.quote_id = "quote-123"
        self.object_id = "backup.tar.gz"
        self.object_hash = "f00dbeef"
        self.now = int(time.time())

        self.quotes_table = FakeDynamoTable(["quote_id"])
        self.quotes_table.put_item(
            Item={
                "quote_id": self.quote_id,
                "expires_at": self.now + 3600,
                "storage_price": Decimal("1.25"),
                "addr": self.wallet_address,
                "object_id": self.object_id,
                "object_id_hash": self.object_hash,
                "provider": "aws",
                "location": "[REDACTED]",
            }
        )
        self.transaction_log_table = FakeDynamoTable(["quote_id", "trans_id"])
        self.idempotency_table = FakeDynamoTable(["idempotency_key"])
        self.s3_client = FakeS3Client()

        self.dynamodb_resource = FakeDynamoResource(
            {
                "quotes-table": self.quotes_table,
                "txn-table": self.transaction_log_table,
                "idem-table": self.idempotency_table,
            }
        )

        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "QUOTES_TABLE_NAME": "quotes-table",
                "UPLOAD_TRANSACTION_LOG_TABLE_NAME": "txn-table",
                "UPLOAD_IDEMPOTENCY_TABLE_NAME": "idem-table",
                "MNEMOSPARK_RECIPIENT_WALLET": "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
                "MNEMOSPARK_PAYMENT_NETWORK": "eip155:8453",
                "MNEMOSPARK_PAYMENT_ASSET": "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
                "MNEMOSPARK_PAYMENT_SETTLEMENT_MODE": "mock",
            },
            clear=False,
        )
        self.env_patch.start()

        self.resource_patch = mock.patch.object(app.boto3, "resource", return_value=self.dynamodb_resource)
        self.resource_patch.start()
        self.client_patch = mock.patch.object(app.boto3, "client", side_effect=self._mock_boto_client)
        self.client_patch.start()

    def tearDown(self):
        self.client_patch.stop()
        self.resource_patch.stop()
        self.env_patch.stop()

    def _mock_boto_client(self, service_name, **kwargs):
        del kwargs
        if service_name == "s3":
            return self.s3_client
        raise AssertionError(f"Unexpected boto3 client service: {service_name}")

    def _make_event(self, headers=None, include_authorizer=True, authorizer_wallet=None, **body_updates):
        body = {
            "quote_id": self.quote_id,
            "wallet_address": self.wallet_address,
            "object_id": self.object_id,
            "object_id_hash": self.object_hash,
            "ciphertext": base64.b64encode(b"encrypted-content").decode("ascii"),
            "wrapped_dek": base64.b64encode(b"wrapped-key").decode("ascii"),
        }
        body.update(body_updates)
        event_headers = {}
        if headers:
            event_headers.update(headers)
        event = {"body": json.dumps(body), "headers": event_headers}
        if include_authorizer:
            event["requestContext"] = {
                "authorizer": {
                    "walletAddress": authorizer_wallet or body["wallet_address"],
                }
            }
        return event

    def test_missing_authorizer_wallet_context_returns_403(self):
        event = self._make_event(include_authorizer=False)

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertIn("wallet authorization context is required", body["message"])

    def test_authorizer_wallet_mismatch_returns_403(self):
        event = self._make_event(authorizer_wallet="0x2222222222222222222222222222222222222222")

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertIn("wallet_address does not match authorized wallet", body["message"])

    def test_missing_payment_header_returns_402_with_payment_required_headers(self):
        event = self._make_event()

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 402)
        self.assertIn("PAYMENT-REQUIRED", response["headers"])
        self.assertIn("x-payment-required", response["headers"])
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "payment_required")
        self.assertIn("message", body)

    def test_missing_quote_returns_404(self):
        self.quotes_table.items.clear()
        event = self._make_event(headers={"PAYMENT-SIGNATURE": "mock"})

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "quote_not_found")

    def test_expired_quote_returns_404(self):
        expired_item = self.quotes_table.items[(("quote_id", self.quote_id),)]
        expired_item["expires_at"] = int(time.time()) - 1
        event = self._make_event(headers={"PAYMENT-SIGNATURE": "mock"})

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "quote_not_found")

    def test_object_hash_mismatch_returns_400(self):
        event = self._make_event(headers={"PAYMENT-SIGNATURE": "mock"}, object_id_hash="bad-hash")

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")
        self.assertIn("object_id_hash", body["message"])

    def test_idempotency_in_progress_returns_409(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-123"},
        )
        request_hash = app._request_fingerprint(app.parse_input(event))
        self.idempotency_table.put_item(
            Item={
                "idempotency_key": "idem-123",
                "status": "in_progress",
                "request_hash": request_hash,
                "expires_at": int(time.time()) + 3600,
            }
        )

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 409)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "conflict")

    def test_success_upload_writes_s3_and_transaction_log_and_idempotency(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-456"},
        )
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xabc123",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["quote_id"], self.quote_id)
        self.assertEqual(body["trans_id"], "0xabc123")
        self.assertEqual(body["provider"], "aws")
        self.assertEqual(body["location"], "[REDACTED]")
        self.assertIn("PAYMENT-RESPONSE", response["headers"])
        self.assertIn("x-payment-response", response["headers"])

        self.assertEqual(len(self.s3_client.put_calls), 1)
        put_call = self.s3_client.put_calls[0]
        self.assertEqual(put_call["Key"], self.object_id)
        self.assertEqual(put_call["Metadata"]["wrapped-dek"], base64.b64encode(b"wrapped-key").decode("ascii"))

        self.assertEqual(len(self.transaction_log_table.items), 1)
        log_item = next(iter(self.transaction_log_table.items.values()))
        self.assertEqual(log_item["quote_id"], self.quote_id)
        self.assertEqual(log_item["trans_id"], "0xabc123")
        self.assertEqual(log_item["object_id"], self.object_id)
        self.assertEqual(log_item["object_key"], self.object_id)
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
        self.assertEqual(log_item["payment_amount"], "1250000")

        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-456"),)]
        self.assertEqual(idem_item["status"], "completed")
        self.assertIn("response_body", idem_item)

        # Duplicate with same key should return cached success response.
        with mock.patch.object(app, "verify_and_settle_payment", side_effect=AssertionError("must not be called")):
            duplicate_response = app.lambda_handler(event, None)
        self.assertEqual(duplicate_response["statusCode"], 200)
        self.assertEqual(json.loads(duplicate_response["body"]), body)

    def test_legacy_x_payment_header_is_accepted(self):
        event = self._make_event(headers={"x-payment": "legacy-signed-payload"})
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xlegacy",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )
        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result) as verify_mock:
            response = app.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        call_kwargs = verify_mock.call_args.kwargs
        self.assertEqual(call_kwargs["payment_header"], "legacy-signed-payload")


class Eip712VerificationTests(unittest.TestCase):
    def test_verify_and_settle_payment_onchain_mode_calls_onchain_settlement(self):
        wallet_address = "0x1111111111111111111111111111111111111111"
        recipient_wallet = "0x47d241ae97fe37186ac59894290ca1c54c060a6c"
        asset = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        network = "eip155:8453"
        now = int(time.time())
        authorization = app.TransferAuthorization(
            signature="0x" + ("11" * 65),
            from_address=wallet_address,
            to_address=recipient_wallet,
            value=2_000_000,
            valid_after=now - 5,
            valid_before=now + 300,
            nonce="0x" + ("ab" * 32),
            network=network,
            asset=asset,
            domain_name="USD Coin",
            domain_version="2",
        )
        requirements = {
            "network": network,
            "asset": asset,
            "payTo": recipient_wallet,
            "amount": "2000000",
        }

        with (
            mock.patch.dict(os.environ, {"MNEMOSPARK_PAYMENT_SETTLEMENT_MODE": "onchain"}, clear=False),
            mock.patch.object(app, "_decode_payment_payload", return_value={}),
            mock.patch.object(app, "_extract_transfer_authorization", return_value=authorization),
            mock.patch.object(app, "_recover_authorization_signer", return_value=wallet_address),
            mock.patch.object(app, "_onchain_settle_payment", return_value="0xonchain123") as onchain_mock,
        ):
            result = app.verify_and_settle_payment(
                payment_header="signed-payload",
                wallet_address=wallet_address,
                quote_id="quote-onchain",
                expected_amount=2_000_000,
                expected_recipient=recipient_wallet,
                expected_network=network,
                expected_asset=asset,
                requirements=requirements,
            )

        self.assertEqual(result.trans_id, "0xonchain123")
        self.assertEqual(result.network, network)
        self.assertEqual(result.asset, asset)
        self.assertEqual(result.amount, 2_000_000)
        onchain_mock.assert_called_once_with(authorization)

    def test_verify_and_settle_payment_valid_signature_mock_settlement(self):
        try:
            from eth_account import Account
            from eth_account.messages import encode_typed_data
        except ImportError:
            self.skipTest("eth-account is not installed in this environment")

        account = Account.create()
        wallet_address = app._normalize_address(account.address, "wallet_address")
        recipient_wallet = app._normalize_address(
            "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
            "recipient",
        )
        asset = app._normalize_address(
            "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            "asset",
        )
        network = "eip155:8453"
        now = int(time.time())
        authorization = {
            "from": wallet_address,
            "to": recipient_wallet,
            "value": 2_000_000,
            "validAfter": now - 30,
            "validBefore": now + 300,
            "nonce": "0x" + "ab" * 32,
            "network": network,
            "asset": asset,
            "name": "USD Coin",
            "version": "2",
        }

        signable = encode_typed_data(
            domain_data={
                "name": "USD Coin",
                "version": "2",
                "chainId": 8453,
                "verifyingContract": asset,
            },
            message_types=app.TRANSFER_WITH_AUTH_TYPES,
            message_data={
                "from": authorization["from"],
                "to": authorization["to"],
                "value": authorization["value"],
                "validAfter": authorization["validAfter"],
                "validBefore": authorization["validBefore"],
                "nonce": authorization["nonce"],
            },
        )
        signature = Account.sign_message(signable, private_key=account.key).signature.hex()
        if not signature.startswith("0x"):
            signature = f"0x{signature}"

        payload = {
            "payload": {
                "signature": signature,
                "authorization": authorization,
            }
        }
        payment_header = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        requirements = {
            "network": network,
            "asset": asset,
            "payTo": recipient_wallet,
            "amount": "2000000",
        }

        with mock.patch.dict(os.environ, {"MNEMOSPARK_PAYMENT_SETTLEMENT_MODE": "mock"}, clear=False):
            result = app.verify_and_settle_payment(
                payment_header=payment_header,
                wallet_address=wallet_address,
                quote_id="quote-verify",
                expected_amount=2_000_000,
                expected_recipient=recipient_wallet,
                expected_network=network,
                expected_asset=asset,
                requirements=requirements,
            )

        self.assertTrue(result.trans_id.startswith("0x"))
        self.assertEqual(result.network, network)
        self.assertEqual(result.asset, asset)
        self.assertEqual(result.amount, 2_000_000)
