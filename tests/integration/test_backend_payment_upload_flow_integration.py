import base64
import copy
import hashlib
import importlib.util
import json
import os
from decimal import Decimal
from pathlib import Path
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def _load_service_module(service_dir: str, module_name: str):
    module_path = Path(__file__).resolve().parents[2] / "services" / service_dir / "app.py"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError(f"Unable to load module for {service_dir}")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


price_app = _load_service_module("price-storage", "price_storage_app_backend_flow_integration")
payment_app = _load_service_module("payment-settle", "payment_settle_app_backend_flow_integration")
upload_app = _load_service_module("storage-upload", "storage_upload_app_backend_flow_integration")
ls_app = _load_service_module("storage-ls", "storage_ls_app_backend_flow_integration")
download_app = _load_service_module("storage-download", "storage_download_app_backend_flow_integration")
delete_app = _load_service_module("storage-delete", "storage_delete_app_backend_flow_integration")


class FakeApiCallRecorder:
    def __init__(self):
        self.entries: list[dict] = []

    def __call__(self, **kwargs):
        self.entries.append(dict(kwargs))

    def route_statuses(self) -> list[tuple[str | None, int | None]]:
        return [(entry.get("route"), entry.get("status_code")) for entry in self.entries]


class FakeDynamoTable:
    def __init__(self, key_fields: list[str]):
        self.key_fields = list(key_fields)
        self.items = {}
        self.put_history: list[dict] = []

    def _key_tuple(self, key: dict):
        return tuple((field, key[field]) for field in self.key_fields)

    def get_item(self, Key, ConsistentRead=False):
        del ConsistentRead
        item = self.items.get(self._key_tuple(Key))
        if item is None:
            return {}
        return {"Item": copy.deepcopy(item)}

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        key = self._key_tuple(Item)
        existing = self.items.get(key)
        if ConditionExpression == "attribute_not_exists(idempotency_key)" and existing is not None:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate key"}},
                "PutItem",
            )
        if ConditionExpression == "attribute_not_exists(quote_id)" and existing is not None:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate key"}},
                "PutItem",
            )
        if ConditionExpression == "attribute_not_exists(wallet_address) AND attribute_not_exists(quote_id)":
            if existing is not None:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate payment"}},
                    "PutItem",
                )
        if (
            ConditionExpression
            == "attribute_exists(wallet_address) AND attribute_exists(quote_id) AND payment_status = :expected_status"
        ):
            expected_status = (
                None if ExpressionAttributeValues is None else ExpressionAttributeValues.get(":expected_status")
            )
            if existing is None or existing.get("payment_status") != expected_status:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "missing claim"}},
                    "PutItem",
                )
        if ConditionExpression == "attribute_not_exists(idempotency_key) OR status <> :completed_status":
            completed_status = (
                None if ExpressionAttributeValues is None else ExpressionAttributeValues.get(":completed_status")
            )
            if existing is not None and existing.get("status") == completed_status:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "already completed"}},
                    "PutItem",
                )

        self.items[key] = copy.deepcopy(Item)
        self.put_history.append(copy.deepcopy(Item))
        return {}

    def delete_item(self, Key, ConditionExpression=None, ExpressionAttributeValues=None):
        key = self._key_tuple(Key)
        existing = self.items.get(key)
        if ConditionExpression == "payment_status = :status":
            expected_status = None if ExpressionAttributeValues is None else ExpressionAttributeValues.get(":status")
            if existing is None or existing.get("payment_status") != expected_status:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
                    "DeleteItem",
                )
        if ConditionExpression == "expires_at <= :now":
            expected_now = None if ExpressionAttributeValues is None else ExpressionAttributeValues.get(":now")
            if existing is None or expected_now is None or int(existing.get("expires_at", 0)) > int(expected_now):
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
                    "DeleteItem",
                )
        self.items.pop(key, None)
        return {}


class FakeDynamoResource:
    def __init__(self, tables_by_name):
        self.tables_by_name = tables_by_name

    def Table(self, name):
        return self.tables_by_name[name]


class FakeTypedDynamoDbClient:
    def __init__(self, tables_by_name):
        self.tables_by_name = tables_by_name

    def put_item(self, TableName, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        table = self.tables_by_name[TableName]
        python_item = {key: self._from_attr(value) for key, value in Item.items()}
        python_expr = None
        if ExpressionAttributeValues is not None:
            python_expr = {key: self._from_attr(value) for key, value in ExpressionAttributeValues.items()}
        table.put_item(
            Item=python_item,
            ConditionExpression=ConditionExpression,
            ExpressionAttributeValues=python_expr,
        )
        return {}

    @staticmethod
    def _from_attr(attr):
        if not isinstance(attr, dict):
            return attr
        if "S" in attr:
            return attr["S"]
        if "N" in attr:
            numeric = str(attr["N"])
            if numeric.isdigit() or (numeric.startswith("-") and numeric[1:].isdigit()):
                return int(numeric)
            return Decimal(numeric)
        if "BOOL" in attr:
            return bool(attr["BOOL"])
        return attr


class FakeS3Client:
    def __init__(self):
        self.buckets: dict[str, dict[str, dict]] = {}

    def _bucket(self, bucket_name: str) -> dict[str, dict]:
        return self.buckets.setdefault(bucket_name, {})

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise ClientError({"Error": {"Code": "404", "Message": "bucket not found"}}, "HeadBucket")
        return {}

    def create_bucket(self, Bucket, CreateBucketConfiguration=None):
        del CreateBucketConfiguration
        self._bucket(Bucket)
        return {}

    def put_object(self, Bucket, Key, Body, Metadata):
        if Bucket not in self.buckets:
            raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "bucket missing"}}, "PutObject")
        self.buckets[Bucket][Key] = {"Body": bytes(Body), "Metadata": dict(Metadata)}
        return {}

    def head_object(self, Bucket, Key):
        objects = self.buckets.get(Bucket)
        if objects is None:
            raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "bucket missing"}}, "HeadObject")
        object_data = objects.get(Key)
        if object_data is None:
            raise ClientError({"Error": {"Code": "404", "Message": "object missing"}}, "HeadObject")
        return {"ContentLength": len(object_data["Body"])}

    def generate_presigned_url(self, ClientMethod, Params, ExpiresIn, HttpMethod=None):
        del ClientMethod, ExpiresIn, HttpMethod
        return f"https://fake-s3.local/{Params['Bucket']}/{Params['Key']}"

    def delete_object(self, Bucket, Key):
        objects = self.buckets.get(Bucket)
        if objects is None:
            raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "bucket missing"}}, "DeleteObject")
        if Key not in objects:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "object missing"}}, "DeleteObject")
        del objects[Key]
        return {}

    def list_objects_v2(self, Bucket, MaxKeys=1000):
        del MaxKeys
        objects = self.buckets.get(Bucket, {})
        keys = sorted(objects.keys())
        if not keys:
            return {"KeyCount": 0, "Contents": []}
        return {"KeyCount": len(keys), "Contents": [{"Key": key} for key in keys]}

    def delete_bucket(self, Bucket):
        objects = self.buckets.get(Bucket)
        if objects is None:
            raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "bucket missing"}}, "DeleteBucket")
        if objects:
            raise ClientError({"Error": {"Code": "BucketNotEmpty", "Message": "not empty"}}, "DeleteBucket")
        del self.buckets[Bucket]
        return {}


class FakePaymentResult:
    def __init__(self, trans_id: str, network: str, asset: str, amount: int):
        self.trans_id = trans_id
        self.network = network
        self.asset = asset
        self.amount = amount


class FakePaymentCore:
    PAYMENT_SIGNATURE_HEADER_NAMES = ("payment-signature", "x-payment")
    USDC_DECIMALS = Decimal("1000000")

    def __init__(self):
        self.verify_calls: list[dict] = []

    @staticmethod
    def _normalize_address(value, field_name):
        del field_name
        candidate = str(value).strip()
        if not candidate.startswith("0x") or len(candidate) != 42:
            raise ValueError("address must be 0x-prefixed 20-byte hex")
        return f"0x{candidate[2:].lower()}"

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

    @staticmethod
    def _payment_required_headers(requirements):
        return {"PAYMENT-REQUIRED": json.dumps(requirements)}

    def verify_and_settle_payment(self, **kwargs):
        self.verify_calls.append(dict(kwargs))
        digest = hashlib.sha256(
            f"{kwargs['quote_id']}:{kwargs['wallet_address']}:{kwargs.get('payment_header')}".encode("utf-8")
        ).hexdigest()
        return FakePaymentResult(
            trans_id=f"0x{digest[:64]}",
            network=kwargs["expected_network"],
            asset=kwargs["expected_asset"],
            amount=int(kwargs["expected_amount"]),
        )


class BackendFlowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.wallet_a = "0x1111111111111111111111111111111111111111"
        self.wallet_b = "0x2222222222222222222222222222222222222222"
        self.object_id = "backup.tar.gz"
        self.object_hash = "hash-backup-tar-gz"
        self.wrapped_dek = base64.b64encode(b"wrapped-dek").decode("ascii")
        self.ciphertext_b64 = base64.b64encode(b"encrypted-payload").decode("ascii")
        self.api_call_recorder = FakeApiCallRecorder()

        self.quotes_table = FakeDynamoTable(["quote_id"])
        self.payments_table = FakeDynamoTable(["wallet_address", "quote_id"])
        self.txn_table = FakeDynamoTable(["quote_id", "trans_id"])
        self.idem_table = FakeDynamoTable(["idempotency_key"])
        self.active_storage_table = FakeDynamoTable(["wallet_address", "object_key"])
        self.tables_by_name = {
            "quotes": self.quotes_table,
            "payments": self.payments_table,
            "txn-log": self.txn_table,
            "idem": self.idem_table,
            "active-storage": self.active_storage_table,
        }
        self.dynamodb_resource = FakeDynamoResource(self.tables_by_name)
        self.price_dynamodb_client = FakeTypedDynamoDbClient(self.tables_by_name)
        self.s3_client = FakeS3Client()
        self.fake_payment_core = FakePaymentCore()

        self.original_payment_core = payment_app._PAYMENT_CORE
        payment_app._PAYMENT_CORE = self.fake_payment_core

        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "QUOTES_TABLE_NAME": "quotes",
                "PAYMENT_LEDGER_TABLE_NAME": "payments",
                "UPLOAD_TRANSACTION_LOG_TABLE_NAME": "txn-log",
                "UPLOAD_IDEMPOTENCY_TABLE_NAME": "idem",
                "ACTIVE_STORAGE_OBJECT_TABLE_NAME": "active-storage",
                "MNEMOSPARK_PAYMENT_SETTLEMENT_MODE": "mock",
                "MNEMOSPARK_RECIPIENT_WALLET": "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
                "MNEMOSPARK_PAYMENT_NETWORK": "eip155:8453",
                "MNEMOSPARK_PAYMENT_ASSET": "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913",
                "QUOTE_TTL_SECONDS": "3600",
                "PRICE_STORAGE_MARKUP": "10",
                "PRICE_STORAGE_TRANSFER_DIRECTION": "out",
                "PRICE_STORAGE_RATE_TYPE": "BEFORE_DISCOUNTS",
            },
            clear=False,
        )
        self.env_patch.start()

        self.patches = [
            mock.patch.object(price_app, "estimate_storage_cost", return_value=1.2),
            mock.patch.object(price_app, "estimate_transfer_cost", return_value=0.8),
            mock.patch.object(price_app, "get_dynamodb_client", return_value=self.price_dynamodb_client),
            mock.patch.object(payment_app.boto3, "resource", return_value=self.dynamodb_resource),
            mock.patch.object(upload_app.boto3, "resource", return_value=self.dynamodb_resource),
            mock.patch.object(upload_app.boto3, "client", side_effect=self._mock_boto_client),
            mock.patch.object(delete_app.boto3, "resource", return_value=self.dynamodb_resource),
            mock.patch.object(delete_app.boto3, "client", side_effect=self._mock_boto_client),
            mock.patch.object(price_app, "log_api_call", side_effect=self.api_call_recorder),
            mock.patch.object(payment_app, "log_api_call", side_effect=self.api_call_recorder),
            mock.patch.object(upload_app, "log_api_call", side_effect=self.api_call_recorder),
            mock.patch.object(ls_app, "log_api_call", side_effect=self.api_call_recorder),
            mock.patch.object(download_app, "log_api_call", side_effect=self.api_call_recorder),
            mock.patch.object(delete_app, "log_api_call", side_effect=self.api_call_recorder),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.env_patch.stop()
        payment_app._PAYMENT_CORE = self.original_payment_core

    def _mock_boto_client(self, service_name, **kwargs):
        del kwargs
        if service_name == "s3":
            return self.s3_client
        raise AssertionError(f"Unexpected boto3 client request: {service_name}")

    @staticmethod
    def _request_context(wallet: str) -> dict:
        return {"requestContext": {"authorizer": {"walletAddress": wallet}}}

    def _price_event(self, wallet: str, object_id: str, object_hash: str, gb: float = 1.0) -> dict:
        return {
            **self._request_context(wallet),
            "httpMethod": "POST",
            "path": "/price-storage",
            "body": json.dumps(
                {
                    "wallet_address": wallet,
                    "object_id": object_id,
                    "object_id_hash": object_hash,
                    "gb": gb,
                    "provider": "aws",
                    "region": "us-west-2",
                }
            ),
        }

    def _payment_settle_event(self, quote_id: str, wallet: str) -> dict:
        return {
            **self._request_context(wallet),
            "httpMethod": "POST",
            "path": "/payment/settle",
            "headers": {"PAYMENT-SIGNATURE": "signed-payload"},
            "body": json.dumps({"quote_id": quote_id, "wallet_address": wallet}),
        }

    def _upload_event(
        self,
        quote_id: str,
        wallet: str,
        object_id: str,
        object_hash: str,
        *,
        mode: str = "presigned",
        idempotency_key: str = "idem-flow",
        include_authorizer: bool = True,
    ) -> dict:
        body = {
            "quote_id": quote_id,
            "wallet_address": wallet,
            "object_id": object_id,
            "object_id_hash": object_hash,
            "wrapped_dek": self.wrapped_dek,
            "mode": mode,
        }
        if mode == "inline":
            body["ciphertext"] = self.ciphertext_b64
        else:
            body["content_sha256"] = "abc123"
            body["content_length_bytes"] = 16
        event = {
            "httpMethod": "POST",
            "path": "/storage/upload",
            "headers": {"Idempotency-Key": idempotency_key},
            "body": json.dumps(body),
        }
        if include_authorizer:
            event.update(self._request_context(wallet))
        return event

    def _confirm_event(self, quote_id: str, wallet: str, object_key: str, idempotency_key: str) -> dict:
        return {
            **self._request_context(wallet),
            "httpMethod": "POST",
            "path": "/storage/upload/confirm",
            "body": json.dumps(
                {
                    "quote_id": quote_id,
                    "wallet_address": wallet,
                    "object_key": object_key,
                    "idempotency_key": idempotency_key,
                }
            ),
        }

    def test_happy_path_price_payment_upload_confirm_and_storage_endpoints(self):
        price_response = price_app.lambda_handler(
            self._price_event(self.wallet_a, self.object_id, self.object_hash, gb=2.0),
            None,
        )
        self.assertEqual(price_response["statusCode"], 200)
        price_body = json.loads(price_response["body"])
        quote_id = price_body["quote_id"]
        self.assertEqual(price_body["addr"], self.wallet_a)

        settle_response = payment_app.lambda_handler(self._payment_settle_event(quote_id, self.wallet_a), None)
        self.assertEqual(settle_response["statusCode"], 200)
        settle_body = json.loads(settle_response["body"])
        self.assertEqual(settle_body["quote_id"], quote_id)
        self.assertEqual(settle_body["wallet_address"], self.wallet_a)

        upload_response = upload_app.lambda_handler(
            self._upload_event(quote_id, self.wallet_a, self.object_id, self.object_hash, idempotency_key="idem-flow"),
            None,
        )
        self.assertEqual(upload_response["statusCode"], 200)
        upload_body = json.loads(upload_response["body"])
        self.assertTrue(upload_body["confirmation_required"])
        self.assertIn("upload_url", upload_body)

        # Simulate client PUT to S3 via returned presigned URL.
        self.s3_client.put_object(
            Bucket=upload_body["bucket_name"],
            Key=upload_body["object_key"],
            Body=b"encrypted-payload",
            Metadata={"wrapped-dek": self.wrapped_dek},
        )

        confirm_response = upload_app.confirm_upload_handler(
            self._confirm_event(quote_id, self.wallet_a, upload_body["object_key"], "idem-flow"),
            None,
        )
        self.assertEqual(confirm_response["statusCode"], 200)
        confirm_body = json.loads(confirm_response["body"])
        self.assertEqual(confirm_body["quote_id"], quote_id)
        self.assertNotIn("confirmation_required", confirm_body)

        ls_response = ls_app.lambda_handler(
            {
                **self._request_context(self.wallet_a),
                "httpMethod": "GET",
                "path": "/storage/ls",
                "queryStringParameters": {
                    "wallet_address": self.wallet_a,
                    "object_key": self.object_id,
                },
            },
            None,
        )
        self.assertEqual(ls_response["statusCode"], 200)
        ls_body = json.loads(ls_response["body"])
        self.assertEqual(ls_body["key"], self.object_id)
        self.assertGreater(ls_body["size_bytes"], 0)

        download_response = download_app.lambda_handler(
            {
                **self._request_context(self.wallet_a),
                "httpMethod": "GET",
                "path": "/storage/download",
                "queryStringParameters": {
                    "wallet_address": self.wallet_a,
                    "object_key": self.object_id,
                },
            },
            None,
        )
        self.assertEqual(download_response["statusCode"], 200)
        download_body = json.loads(download_response["body"])
        self.assertIn("download_url", download_body)
        self.assertIn(upload_body["bucket_name"], download_body["download_url"])

        delete_response = delete_app.lambda_handler(
            {
                **self._request_context(self.wallet_a),
                "httpMethod": "DELETE",
                "path": "/storage/delete",
                "queryStringParameters": {
                    "wallet_address": self.wallet_a,
                    "object_key": self.object_id,
                },
            },
            None,
        )
        self.assertEqual(delete_response["statusCode"], 200)
        delete_body = json.loads(delete_response["body"])
        self.assertTrue(delete_body["bucket_deleted"])

        self.assertEqual(len(self.txn_table.items), 1)
        txn_item = next(iter(self.txn_table.items.values()))
        self.assertEqual(txn_item["quote_id"], quote_id)
        self.assertEqual(txn_item["addr"], self.wallet_a)

        payment_item = self.payments_table.items[(("wallet_address", self.wallet_a), ("quote_id", quote_id))]
        self.assertEqual(payment_item["payment_status"], "confirmed")
        self.assertEqual(payment_item["quote_id"], quote_id)

        expected_route_statuses = {
            ("/price-storage", 200),
            ("/payment/settle", 200),
            ("/storage/upload", 200),
            ("/storage/upload/confirm", 200),
            ("/storage/ls", 200),
            ("/storage/download", 200),
            ("/storage/delete", 200),
        }
        self.assertTrue(expected_route_statuses.issubset(set(self.api_call_recorder.route_statuses())))

    def test_upload_without_prior_payment_returns_402_payment_required(self):
        price_response = price_app.lambda_handler(self._price_event(self.wallet_a, self.object_id, self.object_hash), None)
        quote_id = json.loads(price_response["body"])["quote_id"]

        upload_response = upload_app.lambda_handler(
            self._upload_event(
                quote_id,
                self.wallet_a,
                self.object_id,
                self.object_hash,
                mode="inline",
                idempotency_key="idem-no-payment",
            ),
            None,
        )
        self.assertEqual(upload_response["statusCode"], 402)
        body = json.loads(upload_response["body"])
        self.assertEqual(body["error"], "payment_required")
        self.assertEqual(body["details"]["reason"], "payment_record_missing")
        self.assertIn(("/storage/upload", 402), set(self.api_call_recorder.route_statuses()))

    def test_payment_and_upload_quote_id_mismatch_returns_402(self):
        first_object_id = "first.bin"
        first_hash = "hash-first-bin"
        second_object_id = "second.bin"
        second_hash = "hash-second-bin"

        first_quote = json.loads(
            price_app.lambda_handler(self._price_event(self.wallet_a, first_object_id, first_hash), None)["body"]
        )["quote_id"]
        settle_response = payment_app.lambda_handler(self._payment_settle_event(first_quote, self.wallet_a), None)
        self.assertEqual(settle_response["statusCode"], 200)

        second_quote = json.loads(
            price_app.lambda_handler(self._price_event(self.wallet_a, second_object_id, second_hash), None)["body"]
        )["quote_id"]
        upload_response = upload_app.lambda_handler(
            self._upload_event(
                second_quote,
                self.wallet_a,
                second_object_id,
                second_hash,
                mode="inline",
                idempotency_key="idem-quote-mismatch",
            ),
            None,
        )
        self.assertEqual(upload_response["statusCode"], 402)
        body = json.loads(upload_response["body"])
        self.assertEqual(body["error"], "payment_required")
        self.assertEqual(body["details"]["reason"], "payment_record_missing")

    def test_upload_with_malformed_payment_wallet_record_returns_402(self):
        quote_id = json.loads(price_app.lambda_handler(self._price_event(self.wallet_a, self.object_id, self.object_hash), None)["body"])[
            "quote_id"
        ]
        settle_response = payment_app.lambda_handler(self._payment_settle_event(quote_id, self.wallet_a), None)
        self.assertEqual(settle_response["statusCode"], 200)

        payment_item = self.payments_table.items[(("wallet_address", self.wallet_a), ("quote_id", quote_id))]
        payment_item["wallet_address"] = self.wallet_b

        upload_response = upload_app.lambda_handler(
            self._upload_event(
                quote_id,
                self.wallet_a,
                self.object_id,
                self.object_hash,
                mode="inline",
                idempotency_key="idem-wallet-mismatch",
            ),
            None,
        )
        self.assertEqual(upload_response["statusCode"], 402)
        body = json.loads(upload_response["body"])
        self.assertEqual(body["error"], "payment_required")
        self.assertEqual(body["details"]["reason"], "payment_wallet_mismatch")

    def test_missing_or_invalid_wallet_proof_paths_return_403(self):
        quote_id = json.loads(price_app.lambda_handler(self._price_event(self.wallet_a, self.object_id, self.object_hash), None)["body"])[
            "quote_id"
        ]

        settle_without_authorizer = {
            "httpMethod": "POST",
            "path": "/payment/settle",
            "headers": {"PAYMENT-SIGNATURE": "signed"},
            "body": json.dumps({"quote_id": quote_id, "wallet_address": self.wallet_a}),
        }
        settle_forbidden = payment_app.lambda_handler(settle_without_authorizer, None)
        self.assertEqual(settle_forbidden["statusCode"], 403)

        upload_mismatched_authorizer = self._upload_event(
            quote_id,
            self.wallet_a,
            self.object_id,
            self.object_hash,
            mode="inline",
            idempotency_key="idem-wallet-proof",
        )
        upload_mismatched_authorizer["requestContext"]["authorizer"]["walletAddress"] = self.wallet_b
        upload_forbidden = upload_app.lambda_handler(upload_mismatched_authorizer, None)
        self.assertEqual(upload_forbidden["statusCode"], 403)

        ls_forbidden = ls_app.lambda_handler(
            {
                "httpMethod": "GET",
                "path": "/storage/ls",
                "queryStringParameters": {"wallet_address": self.wallet_a, "object_key": self.object_id},
            },
            None,
        )
        self.assertEqual(ls_forbidden["statusCode"], 403)

        download_forbidden = download_app.lambda_handler(
            {
                "httpMethod": "GET",
                "path": "/storage/download",
                "queryStringParameters": {"wallet_address": self.wallet_a, "object_key": self.object_id},
            },
            None,
        )
        self.assertEqual(download_forbidden["statusCode"], 403)

        delete_forbidden = delete_app.lambda_handler(
            {
                "httpMethod": "DELETE",
                "path": "/storage/delete",
                "queryStringParameters": {"wallet_address": self.wallet_a, "object_key": self.object_id},
            },
            None,
        )
        self.assertEqual(delete_forbidden["statusCode"], 403)


if __name__ == "__main__":
    unittest.main()
