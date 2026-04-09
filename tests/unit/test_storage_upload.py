import base64
import copy
import hashlib
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

from common.storage_bucket_region import BucketRegionMismatchError  # noqa: E402


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

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        key = self._key_tuple(Item)
        if ConditionExpression == "attribute_not_exists(idempotency_key)" and key in self.items:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate key"}},
                "PutItem",
            )
        if ConditionExpression == "attribute_not_exists(quote_id)" and key in self.items:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate key"}},
                "PutItem",
            )
        if ConditionExpression == "attribute_not_exists(idempotency_key) OR status <> :completed_status":
            existing_item = self.items.get(key)
            completed_status = (
                None
                if ExpressionAttributeValues is None
                else ExpressionAttributeValues.get(":completed_status")
            )
            if existing_item is not None and existing_item.get("status") == completed_status:
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ConditionalCheckFailedException",
                            "Message": "status already completed",
                        }
                    },
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
        self.bucket_home_regions: dict[str, str] = {}
        self.objects = set()
        self.created_buckets = []
        self.put_calls = []
        self.presigned_calls = []

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "not found"}},
                "HeadBucket",
            )
        region = self.bucket_home_regions.get(Bucket, "us-east-1")
        return {"BucketRegion": region}

    def get_bucket_location(self, Bucket):
        r = self.bucket_home_regions.get(Bucket, "us-east-1")
        return {"LocationConstraint": None if r == "us-east-1" else r}

    def create_bucket(self, Bucket, CreateBucketConfiguration=None):
        self.buckets.add(Bucket)
        lc = (
            CreateBucketConfiguration.get("LocationConstraint")
            if CreateBucketConfiguration
            else None
        )
        home = "us-east-1" if not lc else str(lc)
        self.bucket_home_regions[Bucket] = home
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
        self.objects.add((Bucket, Key))
        self.put_calls.append(
            {
                "Bucket": Bucket,
                "Key": Key,
                "Body": Body,
                "Metadata": Metadata,
            }
        )
        return {}

    def generate_presigned_url(self, ClientMethod, Params, ExpiresIn):
        self.presigned_calls.append(
            {
                "ClientMethod": ClientMethod,
                "Params": copy.deepcopy(Params),
                "ExpiresIn": ExpiresIn,
            }
        )
        bucket = Params["Bucket"]
        key = Params["Key"]
        return f"https://example-presigned.local/{bucket}/{key}?expires={ExpiresIn}"

    def head_object(self, Bucket, Key):
        if Bucket not in self.buckets:
            raise ClientError(
                {"Error": {"Code": "NoSuchBucket", "Message": "bucket does not exist"}},
                "HeadObject",
            )
        if (Bucket, Key) not in self.objects:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "object does not exist"}},
                "HeadObject",
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

    def test_ensure_bucket_exists_existing_bucket_matching_region_succeeds(self):
        s3_client = FakeS3Client()
        bucket = "mnemospark-test-bucket"
        s3_client.buckets.add(bucket)
        s3_client.bucket_home_regions[bucket] = "eu-west-1"

        app._ensure_bucket_exists(
            s3_client=s3_client,
            bucket_name=bucket,
            location="eu-west-1",
        )

        self.assertEqual(len(s3_client.created_buckets), 0)

    def test_ensure_bucket_exists_existing_bucket_region_mismatch_raises(self):
        s3_client = FakeS3Client()
        bucket = "mnemospark-test-bucket"
        s3_client.buckets.add(bucket)
        s3_client.bucket_home_regions[bucket] = "eu-west-1"

        with self.assertRaises(BucketRegionMismatchError) as ctx:
            app._ensure_bucket_exists(
                s3_client=s3_client,
                bucket_name=bucket,
                location="us-west-2",
            )

        self.assertEqual(ctx.exception.bucket_home_region, "eu-west-1")
        self.assertEqual(ctx.exception.requested_region, "us-west-2")
        self.assertEqual(len(s3_client.created_buckets), 0)

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

    def test_mark_idempotency_upload_retryable_does_not_overwrite_completed_status(self):
        idempotency_table = FakeDynamoTable(["idempotency_key"])
        now = int(time.time())
        idempotency_table.put_item(
            Item={
                "idempotency_key": "idem-completed",
                "status": "completed",
                "request_hash": "request-hash",
                "response_body": "{}",
                "payment_response": "encoded",
                "completed_at": "2026-01-01T00:00:00+00:00",
                "expires_at": now + 3600,
            }
        )
        payment_result = app.PaymentVerificationResult(
            trans_id="0xpaid",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )
        quote_context = app.QuoteContext(
            storage_price=Decimal("1.25"),
            storage_price_micro=1_250_000,
            provider="aws",
            location="[REDACTED]",
        )

        app._mark_idempotency_upload_retryable(
            idempotency_table=idempotency_table,
            idempotency_key="idem-completed",
            request_hash="request-hash",
            payment_result=payment_result,
            quote_context=quote_context,
            now=now,
        )

        idem_item = idempotency_table.items[(("idempotency_key", "idem-completed"),)]
        self.assertEqual(idem_item["status"], "completed")
        self.assertIn("response_body", idem_item)
        self.assertNotIn("upload_retry_after_payment", idem_item)

    def test_request_fingerprint_keeps_legacy_shape_for_inline_mode(self):
        request = app.ParsedUploadRequest(
            quote_id="quote-123",
            wallet_address="0x1111111111111111111111111111111111111111",
            object_id="object-123",
            object_id_hash="hash-123",
            object_key="object-123",
            provider="aws",
            location="us-east-1",  # pragma: allowlist secret
            mode="inline",
            content_sha256="abc123",
            ciphertext=None,
            wrapped_dek="wrapped",
            idempotency_key=None,
        )
        legacy_payload = {
            "quote_id": request.quote_id,
            "wallet_address": request.wallet_address,
            "object_id": request.object_id,
            "object_id_hash": request.object_id_hash,
            "object_key": request.object_key,
            "provider": request.provider,
            "location": request.location,
            "wrapped_dek": request.wrapped_dek,
            "ciphertext_sha256": request.content_sha256,
        }
        expected_fingerprint = hashlib.sha256(
            json.dumps(legacy_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        self.assertEqual(app._request_fingerprint(request), expected_fingerprint)

    def test_settlement_mode_defaults_to_onchain_when_env_missing(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(app._settlement_mode(), "onchain")

    def test_emit_mock_settlement_warning_once_logs_warning_payload(self):
        original_flag = app._MOCK_SETTLEMENT_WARNING_EMITTED
        app._MOCK_SETTLEMENT_WARNING_EMITTED = False
        try:
            with mock.patch.object(app.logger, "log") as log_mock:
                app._emit_mock_settlement_warning_once("mock")
                app._emit_mock_settlement_warning_once("mock")
                app._emit_mock_settlement_warning_once("onchain")
        finally:
            app._MOCK_SETTLEMENT_WARNING_EMITTED = original_flag

        log_mock.assert_called_once()
        level_arg, payload_arg = log_mock.call_args.args
        self.assertEqual(level_arg, app.logging.WARNING)
        payload = json.loads(payload_arg)
        self.assertEqual(payload["event"], "mock_settlement_mode_active")
        self.assertIn("No real USDC transfers will occur", payload["message"])

    def test_onchain_settle_payment_uses_zero_effective_gas_price(self):
        class _FakeTxHash:
            def __init__(self, value: str):
                self._value = value

            def hex(self) -> str:
                return self._value

        class _FakeContractFn:
            def build_transaction(self, _params):
                return {"tx": "built"}

        class _FakeContractFunctions:
            def transferWithAuthorization(self, *_args):
                return _FakeContractFn()

        class _FakeContract:
            functions = _FakeContractFunctions()

        class _FakeEth:
            gas_price = 123

            def __init__(self):
                self.account = mock.Mock()
                self.account.sign_transaction.return_value = mock.Mock(raw_transaction=b"signed")

            def contract(self, address, abi):
                del address, abi
                return _FakeContract()

            def get_transaction_count(self, _address):
                return 1

            def send_raw_transaction(self, _raw_transaction):
                return _FakeTxHash("0x" + ("ab" * 32))

            def wait_for_transaction_receipt(self, _tx_hash, timeout):
                del timeout
                class _FakeReceipt(dict):
                    status = 1

                return _FakeReceipt(
                    {
                        "gasUsed": 21000,
                        "effectiveGasPrice": 0,
                        "gasPrice": 999,
                        "blockNumber": 7,
                    }
                )

        class _FakeWeb3:
            @staticmethod
            def HTTPProvider(url, request_kwargs=None):
                del url, request_kwargs
                return object()

            @staticmethod
            def to_checksum_address(address):
                return address

            def __init__(self, _provider):
                self.eth = _FakeEth()

            def is_connected(self):
                return True

        authorization = app.TransferAuthorization(
            signature="0x" + ("11" * 65),
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=1,
            valid_after=0,
            valid_before=9999999999,
            nonce="0x" + ("ab" * 32),
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            domain_name="USD Coin",
            domain_version="2",
        )
        record_mock = mock.Mock()

        with (
            mock.patch.dict(
                os.environ,
                {
                    "MNEMOSPARK_BASE_RPC_URL": "https://base.example.invalid",
                    "MNEMOSPARK_RELAYER_SECRET_ID": "relayer-secret",
                },
                clear=False,
            ),
            mock.patch.object(app, "_resolve_relayer_private_key", return_value="0x" + ("12" * 32)),
            mock.patch.dict(
                sys.modules,
                {
                    "web3": mock.Mock(Web3=_FakeWeb3),
                    "eth_account": mock.Mock(Account=mock.Mock(from_key=mock.Mock(return_value=mock.Mock(address="0x3333333333333333333333333333333333333333")))),
                    "common.relayer_ledger": mock.Mock(record_relayer_transaction_success=record_mock),
                },
            ),
        ):
            tx_id = app._onchain_settle_payment(authorization)

        self.assertEqual(tx_id, "0x" + ("ab" * 32))
        record_mock.assert_called_once()
        self.assertEqual(record_mock.call_args.kwargs["effective_gas_price"], 0)


class StorageUploadLambdaTests(unittest.TestCase):
    def setUp(self):
        self.wallet_address = "0x1111111111111111111111111111111111111111"
        self.quote_id = "quote-123"
        self.object_id = "backup.tar.gz"
        self.object_hash = "f00dbeef"
        self.now = int(time.time())
        self.default_payment_trans_id = "0xpaid-default"

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
        self.active_storage_table = FakeDynamoTable(["wallet_address", "object_key"])
        self.payments_table = FakeDynamoTable(["wallet_address", "quote_id"])
        self.payments_table.put_item(
            Item={
                "wallet_address": self.wallet_address,
                "quote_id": self.quote_id,
                "trans_id": self.default_payment_trans_id,
                "network": "eip155:8453",
                "asset": "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
                "amount": "1250000",
                "payment_status": "confirmed",
                "recipient_wallet": "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
            }
        )
        self.s3_client = FakeS3Client()

        self.dynamodb_resource = FakeDynamoResource(
            {
                "quotes-table": self.quotes_table,
                "txn-table": self.transaction_log_table,
                "idem-table": self.idempotency_table,
                "active-storage-table": self.active_storage_table,
                "payments-table": self.payments_table,
            }
        )

        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "QUOTES_TABLE_NAME": "quotes-table",
                "UPLOAD_TRANSACTION_LOG_TABLE_NAME": "txn-table",
                "UPLOAD_IDEMPOTENCY_TABLE_NAME": "idem-table",
                "ACTIVE_STORAGE_OBJECT_TABLE_NAME": "active-storage-table",
                "PAYMENT_LEDGER_TABLE_NAME": "payments-table",
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

    def _remove_payment_record(self):
        self.payments_table.items.pop(
            (("wallet_address", self.wallet_address), ("quote_id", self.quote_id)),
            None,
        )

    def _make_confirm_event(
        self,
        idempotency_key,
        object_key=None,
        wallet_address=None,
        quote_id=None,
        include_authorizer=True,
        authorizer_wallet=None,
        **body_updates,
    ):
        body = {
            "quote_id": quote_id or self.quote_id,
            "wallet_address": wallet_address or self.wallet_address,
            "object_key": object_key or self.object_id,
            "idempotency_key": idempotency_key,
        }
        body.update(body_updates)
        event = {"body": json.dumps(body), "headers": {}}
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

    def test_lambda_handler_logs_api_call_for_payment_required(self):
        self._remove_payment_record()
        event = self._make_event()

        with mock.patch.object(app, "log_api_call") as log_api_call_mock:
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 402)
        self.assertGreaterEqual(log_api_call_mock.call_count, 1)
        kwargs = log_api_call_mock.call_args.kwargs
        self.assertEqual(kwargs["status_code"], 402)
        self.assertEqual(kwargs["result"], "payment_required")
        self.assertEqual(kwargs["route"], "/storage/upload")

    def test_authorizer_wallet_mismatch_returns_403(self):
        event = self._make_event(authorizer_wallet="0x2222222222222222222222222222222222222222")

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertIn("wallet_address does not match authorized wallet", body["message"])

    def test_missing_payment_header_returns_402_with_payment_required_headers(self):
        self._remove_payment_record()
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
        self.assertEqual(body["trans_id"], self.default_payment_trans_id)
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
        self.assertEqual(log_item["trans_id"], self.default_payment_trans_id)
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

    def test_presigned_mode_without_ciphertext_returns_upload_url(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-presigned-confirm"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)

        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xpresigned",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        response_body = json.loads(response["body"])
        self.assertIn("upload_url", response_body)
        self.assertEqual(
            response_body["upload_headers"],
            {
                "content-type": "application/octet-stream",
                "x-amz-meta-wrapped-dek": base64.b64encode(b"wrapped-key").decode("ascii"),
            },
        )
        self.assertTrue(response_body["confirmation_required"])
        self.assertEqual(response_body["trans_id"], self.default_payment_trans_id)
        self.assertEqual(len(self.s3_client.put_calls), 0)
        self.assertEqual(len(self.s3_client.presigned_calls), 1)
        self.assertEqual(len(self.transaction_log_table.items), 0)
        self.assertIn((("quote_id", self.quote_id),), self.quotes_table.items)
        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-presigned-confirm"),)]
        self.assertEqual(idem_item["status"], "pending_confirmation")
        self.assertEqual(
            self.s3_client.presigned_calls[0]["Params"]["Metadata"]["wrapped-dek"],
            base64.b64encode(b"wrapped-key").decode("ascii"),
        )
        self.assertEqual(self.s3_client.presigned_calls[0]["Params"]["ContentLength"], 12345)

    def test_presigned_idempotent_retry_returns_fresh_upload_url(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-presigned"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)

        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xpresigned-idem",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(event, None)

        with mock.patch.object(app, "verify_and_settle_payment", side_effect=AssertionError("must not be called")):
            second_response = app.lambda_handler(event, None)

        self.assertEqual(first_response["statusCode"], 200)
        self.assertEqual(second_response["statusCode"], 200)
        self.assertEqual(len(self.s3_client.presigned_calls), 2)
        first_body = json.loads(first_response["body"])
        second_body = json.loads(second_response["body"])
        self.assertIn("upload_url", first_body)
        self.assertIn("upload_url", second_body)
        self.assertTrue(first_body["confirmation_required"])
        self.assertTrue(second_body["confirmation_required"])
        self.assertEqual(self.s3_client.presigned_calls[0]["Params"]["ContentLength"], 12345)
        self.assertEqual(self.s3_client.presigned_calls[1]["Params"]["ContentLength"], 12345)
        self.assertEqual(
            self.s3_client.presigned_calls[1]["ExpiresIn"],
            app.PRESIGNED_URL_EXPIRES_IN_SECONDS,
        )
        self.assertEqual(len(self.transaction_log_table.items), 0)
        self.assertIn((("quote_id", self.quote_id),), self.quotes_table.items)
        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-presigned"),)]
        self.assertEqual(idem_item["status"], "pending_confirmation")

    def test_inline_replay_with_new_idempotency_key_returns_existing_upload_without_writing_s3(self):
        first_event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-inline-first"},
        )
        replay_event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-inline-replay"},
        )
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xinline-replay",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(first_event, None)
            replay_response = app.lambda_handler(replay_event, None)

        self.assertEqual(first_response["statusCode"], 200)
        self.assertEqual(replay_response["statusCode"], 200)
        self.assertEqual(len(self.s3_client.put_calls), 1)
        self.assertEqual(len(self.transaction_log_table.items), 1)

        first_body = json.loads(first_response["body"])
        replay_body = json.loads(replay_response["body"])
        self.assertEqual(replay_body["quote_id"], first_body["quote_id"])
        self.assertEqual(replay_body["trans_id"], first_body["trans_id"])
        self.assertEqual(replay_body["bucket_name"], first_body["bucket_name"])
        self.assertNotIn("upload_url", replay_body)

        replay_idem = self.idempotency_table.items[(("idempotency_key", "idem-inline-replay"),)]
        self.assertEqual(replay_idem["status"], "completed")

    def test_inline_replay_with_different_object_key_is_rejected_and_releases_lock(self):
        first_event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-inline-first-key"},
        )
        replay_event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-inline-replay-key"},
            object_key="alternate-object-key.bin",
        )
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xinline-replay-key",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(first_event, None)
            replay_response = app.lambda_handler(replay_event, None)

        self.assertEqual(first_response["statusCode"], 200)
        self.assertEqual(replay_response["statusCode"], 409)
        self.assertEqual(len(self.s3_client.put_calls), 1)

        replay_body = json.loads(replay_response["body"])
        self.assertEqual(replay_body["error"], "conflict")
        self.assertIn("quote_already_consumed", replay_body["message"])
        self.assertNotIn((("idempotency_key", "idem-inline-replay-key"),), self.idempotency_table.items)

    def test_presigned_replay_with_new_idempotency_key_returns_completed_response(self):
        first_event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-presigned-first"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        first_body_payload = json.loads(first_event["body"])
        first_body_payload.pop("ciphertext", None)
        first_event["body"] = json.dumps(first_body_payload)

        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xpresigned-replay",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(first_event, None)

        self.assertEqual(first_response["statusCode"], 200)
        first_body = json.loads(first_response["body"])
        self.s3_client.objects.add((first_body["bucket_name"], first_body["object_key"]))
        confirm_event = self._make_confirm_event(idempotency_key="idem-presigned-first")
        confirm_response = app.confirm_upload_handler(confirm_event, None)
        self.assertEqual(confirm_response["statusCode"], 200)

        replay_event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-presigned-replay"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        replay_body_payload = json.loads(replay_event["body"])
        replay_body_payload.pop("ciphertext", None)
        replay_event["body"] = json.dumps(replay_body_payload)

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            replay_response = app.lambda_handler(replay_event, None)

        self.assertEqual(replay_response["statusCode"], 200)
        replay_body = json.loads(replay_response["body"])
        self.assertNotIn("upload_url", replay_body)
        self.assertNotIn("upload_headers", replay_body)
        self.assertNotIn("confirmation_required", replay_body)
        self.assertEqual(replay_body["quote_id"], self.quote_id)
        self.assertEqual(replay_body["trans_id"], self.default_payment_trans_id)
        self.assertEqual(len(self.s3_client.presigned_calls), 1)
        self.assertEqual(len(self.transaction_log_table.items), 1)
        replay_idem = self.idempotency_table.items[(("idempotency_key", "idem-presigned-replay"),)]
        self.assertEqual(replay_idem["status"], "completed")

    def test_confirm_upload_succeeds_when_s3_object_exists(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-confirm-success"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xconfirm-ok",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(event, None)
        first_body = json.loads(first_response["body"])
        self.s3_client.objects.add((first_body["bucket_name"], first_body["object_key"]))

        confirm_event = self._make_confirm_event(idempotency_key="idem-confirm-success")
        response = app.confirm_upload_handler(confirm_event, None)

        self.assertEqual(response["statusCode"], 200)
        response_body = json.loads(response["body"])
        self.assertEqual(response_body["quote_id"], self.quote_id)
        self.assertEqual(response_body["trans_id"], self.default_payment_trans_id)
        self.assertNotIn("upload_url", response_body)
        self.assertNotIn("upload_headers", response_body)
        self.assertNotIn("confirmation_required", response_body)
        self.assertEqual(len(self.transaction_log_table.items), 1)
        # Quote is no longer deleted on confirm - it expires via TTL to support
        # dashboard funnel visibility (quote_created -> ... -> upload_confirmed).
        self.assertIn((("quote_id", self.quote_id),), self.quotes_table.items)
        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-confirm-success"),)]
        self.assertEqual(idem_item["status"], "completed")

    def test_confirm_upload_retries_transient_active_inventory_write_failure(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-confirm-active-retry"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xconfirm-active-retry",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(event, None)
        first_body = json.loads(first_response["body"])
        self.s3_client.objects.add((first_body["bucket_name"], first_body["object_key"]))

        confirm_event = self._make_confirm_event(idempotency_key="idem-confirm-active-retry")
        transient_throttle = ClientError(
            {
                "Error": {
                    "Code": "ProvisionedThroughputExceededException",
                    "Message": "simulated throttle",
                }
            },
            "PutItem",
        )
        original_put_active = app._put_active_storage_object_record

        def fail_once_then_put(*args, **kwargs):
            if fail_once_then_put.calls == 0:
                fail_once_then_put.calls += 1
                raise transient_throttle
            return original_put_active(*args, **kwargs)

        fail_once_then_put.calls = 0
        with (
            mock.patch.object(
                app,
                "_put_active_storage_object_record",
                side_effect=fail_once_then_put,
            ) as put_active_mock,
            mock.patch.object(app.time, "sleep") as sleep_mock,
        ):
            response = app.confirm_upload_handler(confirm_event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(put_active_mock.call_count, 2)
        sleep_mock.assert_called_once()
        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-confirm-active-retry"),)]
        self.assertEqual(idem_item["status"], "completed")
        active_item = self.active_storage_table.items[
            (("wallet_address", self.wallet_address), ("object_key", self.object_id))
        ]
        self.assertEqual(active_item["status"], "active")

    def test_confirm_upload_returns_404_when_s3_object_missing(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-confirm-404"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xconfirm-missing",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            app.lambda_handler(event, None)

        confirm_event = self._make_confirm_event(idempotency_key="idem-confirm-404")
        response = app.confirm_upload_handler(confirm_event, None)

        self.assertEqual(response["statusCode"], 404)
        response_body = json.loads(response["body"])
        self.assertEqual(
            response_body["error"],
            "not_found",
        )
        self.assertEqual(len(self.transaction_log_table.items), 0)
        self.assertIn((("quote_id", self.quote_id),), self.quotes_table.items)
        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-confirm-404"),)]
        self.assertEqual(idem_item["status"], "pending_confirmation")

    def test_confirm_upload_returns_cached_success_when_already_completed(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-confirm-complete"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xconfirm-complete",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(event, None)
        first_body = json.loads(first_response["body"])
        self.s3_client.objects.add((first_body["bucket_name"], first_body["object_key"]))

        confirm_event = self._make_confirm_event(idempotency_key="idem-confirm-complete")
        first_confirm = app.confirm_upload_handler(confirm_event, None)
        second_confirm = app.confirm_upload_handler(confirm_event, None)

        self.assertEqual(first_confirm["statusCode"], 200)
        self.assertEqual(second_confirm["statusCode"], 200)
        self.assertEqual(json.loads(first_confirm["body"]), json.loads(second_confirm["body"]))
        self.assertEqual(len(self.transaction_log_table.items), 1)

    def test_confirm_upload_completed_rejects_wallet_mismatch(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-confirm-wallet-mismatch"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xconfirm-wallet-mismatch",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(event, None)
        first_body = json.loads(first_response["body"])
        self.s3_client.objects.add((first_body["bucket_name"], first_body["object_key"]))

        confirm_event = self._make_confirm_event(idempotency_key="idem-confirm-wallet-mismatch")
        first_confirm = app.confirm_upload_handler(confirm_event, None)
        self.assertEqual(first_confirm["statusCode"], 200)

        attacker_wallet = "0x2222222222222222222222222222222222222222"
        mismatched_wallet_event = self._make_confirm_event(
            idempotency_key="idem-confirm-wallet-mismatch",
            wallet_address=attacker_wallet,
            authorizer_wallet=attacker_wallet,
        )
        mismatched_wallet_response = app.confirm_upload_handler(mismatched_wallet_event, None)

        self.assertEqual(mismatched_wallet_response["statusCode"], 409)
        self.assertEqual(json.loads(mismatched_wallet_response["body"])["error"], "conflict")

    def test_confirm_retry_after_idempotency_completion_failure_does_not_overwrite_log_timestamp(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-confirm-retry-log"},
            mode="presigned",
            content_sha256="abcd1234",
            content_length_bytes=12345,
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xconfirm-retry",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result):
            first_response = app.lambda_handler(event, None)
        first_body = json.loads(first_response["body"])
        self.s3_client.objects.add((first_body["bucket_name"], first_body["object_key"]))

        original_mark_completed = app._mark_idempotency_completed
        mark_attempts = 0

        def fail_once_then_mark(*, idempotency_table, idempotency_key, request_hash, response_body, payment_response_header, now):
            nonlocal mark_attempts
            mark_attempts += 1
            if mark_attempts == 1:
                raise RuntimeError("simulated idempotency completion failure")
            return original_mark_completed(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_body=response_body,
                payment_response_header=payment_response_header,
                now=now,
            )

        confirm_event = self._make_confirm_event(idempotency_key="idem-confirm-retry-log")
        with (
            mock.patch.object(
                app.time,
                "time",
                side_effect=range(1_700_000_100, 1_700_000_300),
            ),
            mock.patch.object(app, "_mark_idempotency_completed", side_effect=fail_once_then_mark),
        ):
            first_confirm = app.confirm_upload_handler(confirm_event, None)
            first_log_item = next(iter(self.transaction_log_table.items.values())).copy()
            second_confirm = app.confirm_upload_handler(confirm_event, None)

        self.assertEqual(first_confirm["statusCode"], 500)
        self.assertEqual(second_confirm["statusCode"], 200)
        self.assertEqual(mark_attempts, 2)
        self.assertEqual(len(self.transaction_log_table.put_history), 1)
        log_item = next(iter(self.transaction_log_table.items.values()))
        self.assertEqual(log_item["timestamp"], first_log_item["timestamp"])
        self.assertEqual(log_item["payment_received_at"], first_log_item["payment_received_at"])

    def test_inline_mode_uses_existing_direct_upload_path(self):
        event = self._make_event(headers={"PAYMENT-SIGNATURE": "mock"}, mode="inline")
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xinline",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with (
            mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result),
            mock.patch.object(app, "_upload_ciphertext_to_s3", return_value="mnemospark-inline-bucket") as upload_mock,
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["bucket_name"], "mnemospark-inline-bucket")
        self.assertNotIn("upload_url", body)
        upload_mock.assert_called_once()
        self.assertEqual(len(self.s3_client.presigned_calls), 0)

    def test_inline_mode_s3_client_error_after_payment_returns_207_and_keeps_idempotency_lock(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-s3-fail"},
            mode="inline",
        )
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xpaid1",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )
        upload_error = ClientError(
            {"Error": {"Code": "InternalError", "Message": "simulated put failure"}},
            "PutObject",
        )

        with (
            mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result),
            mock.patch.object(app, "_upload_ciphertext_to_s3", side_effect=upload_error),
            mock.patch.object(app, "_release_idempotency_lock") as release_lock_mock,
            mock.patch.object(app, "_write_transaction_log") as write_log_mock,
            mock.patch.object(app.logger, "error") as logger_error_mock,
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 207)
        self.assertIn("PAYMENT-RESPONSE", response["headers"])
        self.assertIn("x-payment-response", response["headers"])
        body = json.loads(response["body"])
        self.assertTrue(body["upload_failed"])
        self.assertEqual(body["trans_id"], self.default_payment_trans_id)
        self.assertEqual(body["quote_id"], self.quote_id)
        self.assertEqual(body["object_key"], self.object_id)
        self.assertEqual(body["bucket_name"], app._bucket_name(self.wallet_address))
        self.assertIn("Retry the upload", body["error"])
        release_lock_mock.assert_not_called()
        write_log_mock.assert_not_called()

        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-s3-fail"),)]
        self.assertEqual(idem_item["status"], "in_progress")

        logger_error_mock.assert_called_once()
        log_payload = json.loads(logger_error_mock.call_args.args[0])
        self.assertEqual(log_payload["event"], "s3_upload_failed_after_payment")
        self.assertEqual(log_payload["quote_id"], self.quote_id)
        self.assertEqual(log_payload["trans_id"], self.default_payment_trans_id)
        self.assertEqual(log_payload["wallet_address"], self.wallet_address)
        self.assertEqual(log_payload["object_key"], self.object_id)
        self.assertIn("simulated put failure", log_payload["error"])

    def test_inline_mode_s3_exception_after_payment_returns_207_without_releasing_lock(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-s3-runtime"},
            mode="inline",
        )
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xpaid2",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with (
            mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result),
            mock.patch.object(app, "_upload_ciphertext_to_s3", side_effect=RuntimeError("simulated runtime failure")),
            mock.patch.object(app, "_release_idempotency_lock") as release_lock_mock,
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 207)
        self.assertIn("PAYMENT-RESPONSE", response["headers"])
        body = json.loads(response["body"])
        self.assertTrue(body["upload_failed"])
        self.assertEqual(body["trans_id"], self.default_payment_trans_id)
        release_lock_mock.assert_not_called()

        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-s3-runtime"),)]
        self.assertEqual(idem_item["status"], "in_progress")

    def test_inline_mode_idempotency_retry_marker_failure_still_returns_207(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-s3-marker-fail"},
            mode="inline",
        )
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xpaid3",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )

        with (
            mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result),
            mock.patch.object(
                app,
                "_upload_ciphertext_to_s3",
                side_effect=RuntimeError("simulated upload failure"),
            ),
            mock.patch.object(
                app,
                "_mark_idempotency_upload_retryable",
                side_effect=RuntimeError("simulated idempotency write failure"),
            ),
            mock.patch.object(app, "_release_idempotency_lock") as release_lock_mock,
            mock.patch.object(app, "_write_transaction_log") as write_log_mock,
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 207)
        body = json.loads(response["body"])
        self.assertTrue(body["upload_failed"])
        self.assertEqual(body["trans_id"], self.default_payment_trans_id)
        release_lock_mock.assert_not_called()
        write_log_mock.assert_not_called()

        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-s3-marker-fail"),)]
        self.assertEqual(idem_item["status"], "in_progress")

    def test_inline_mode_retry_with_same_idempotency_key_resumes_upload_after_207(self):
        event = self._make_event(
            headers={"PAYMENT-SIGNATURE": "mock", "Idempotency-Key": "idem-s3-resume"},
            mode="inline",
        )
        fake_payment_result = app.PaymentVerificationResult(
            trans_id="0xresume",
            network="eip155:8453",
            asset="0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
            amount=1_250_000,
        )
        upload_error = ClientError(
            {"Error": {"Code": "InternalError", "Message": "simulated transient put failure"}},
            "PutObject",
        )

        with (
            mock.patch.object(app, "verify_and_settle_payment", return_value=fake_payment_result) as verify_mock,
            mock.patch.object(
                app,
                "_upload_ciphertext_to_s3",
                side_effect=[upload_error, "mnemospark-inline-bucket"],
            ) as upload_mock,
        ):
            first_response = app.lambda_handler(event, None)
            # Resumed upload should not depend on quote-table re-read.
            self.quotes_table.items.clear()
            second_response = app.lambda_handler(event, None)

        self.assertEqual(first_response["statusCode"], 207)
        first_body = json.loads(first_response["body"])
        self.assertTrue(first_body["upload_failed"])
        self.assertEqual(first_body["trans_id"], self.default_payment_trans_id)

        self.assertEqual(second_response["statusCode"], 200)
        second_body = json.loads(second_response["body"])
        self.assertEqual(second_body["trans_id"], self.default_payment_trans_id)
        self.assertEqual(second_body["bucket_name"], "mnemospark-inline-bucket")
        self.assertNotIn("upload_failed", second_body)

        self.assertEqual(verify_mock.call_count, 0)
        self.assertEqual(upload_mock.call_count, 2)
        self.assertEqual(len(self.transaction_log_table.items), 1)

        idem_item = self.idempotency_table.items[(("idempotency_key", "idem-s3-resume"),)]
        self.assertEqual(idem_item["status"], "completed")
        self.assertIn("response_body", idem_item)

    def test_presigned_mode_still_requires_payment_verification(self):
        self._remove_payment_record()
        event = self._make_event(
            headers={"Idempotency-Key": "idem-presigned-payment-required"},
            mode="presigned",
        )
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 402)
        parsed = json.loads(response["body"])
        self.assertEqual(parsed["error"], "payment_required")
        self.assertEqual(len(self.s3_client.put_calls), 0)
        self.assertEqual(len(self.s3_client.presigned_calls), 0)

    def test_presigned_mode_requires_idempotency_key_header(self):
        event = self._make_event(headers={"PAYMENT-SIGNATURE": "mock"}, mode="presigned")
        body = json.loads(event["body"])
        body.pop("ciphertext", None)
        event["body"] = json.dumps(body)

        with mock.patch.object(
            app,
            "verify_and_settle_payment",
            side_effect=AssertionError("must not be called"),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        parsed = json.loads(response["body"])
        self.assertEqual(parsed["error"], "Bad request")
        self.assertEqual(
            parsed["message"],
            "Idempotency-Key header is required for presigned mode",
        )
        self.assertEqual(len(self.s3_client.put_calls), 0)
        self.assertEqual(len(self.s3_client.presigned_calls), 0)

    def test_legacy_x_payment_header_is_accepted(self):
        event = self._make_event(headers={"x-payment": "legacy-signed-payload"})
        with mock.patch.object(app, "verify_and_settle_payment", side_effect=AssertionError("must not be called")):
            response = app.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)


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
