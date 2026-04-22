import copy
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError

_SERVICES_ROOT = Path(__file__).resolve().parents[2] / "services"
if str(_SERVICES_ROOT) not in sys.path:
    sys.path.insert(0, str(_SERVICES_ROOT))
from common.renewal_keys import billing_period_object_key  # noqa: E402


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-housekeeping" / "app.py"
    module_name = "storage_housekeeping_app_unit"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load storage-housekeeping module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeDynamoTable:
    def __init__(self, key_fields):
        self.key_fields = list(key_fields)
        self.items = {}
        self.deleted_keys = []

    def _key_tuple(self, key):
        return tuple((field, key[field]) for field in self.key_fields)

    def put_item(self, Item):
        self.items[self._key_tuple(Item)] = copy.deepcopy(Item)
        return {}

    def get_item(self, Key, ConsistentRead=False):
        del ConsistentRead
        item = self.items.get(self._key_tuple(Key))
        if item is None:
            return {}
        return {"Item": copy.deepcopy(item)}

    def scan(self, Limit=100, ExclusiveStartKey=None):
        keys = sorted(self.items.keys())
        start_index = 0
        if ExclusiveStartKey:
            start_key_tuple = self._key_tuple(ExclusiveStartKey)
            try:
                start_index = keys.index(start_key_tuple) + 1
            except ValueError:
                start_index = 0

        selected_keys = keys[start_index : start_index + Limit]
        response = {"Items": [copy.deepcopy(self.items[key]) for key in selected_keys]}
        if start_index + Limit < len(keys):
            last_key = selected_keys[-1]
            response["LastEvaluatedKey"] = {
                field: value for field, value in last_key
            }
        return response

    def query(self, IndexName=None, KeyConditionExpression=None, ExpressionAttributeValues=None, ExclusiveStartKey=None):
        del IndexName, KeyConditionExpression, ExclusiveStartKey
        want = (ExpressionAttributeValues or {}).get(":s")
        items = [
            copy.deepcopy(row) for row in self.items.values() if row.get("status_active") == want
        ]
        return {"Items": items}

    def delete_item(self, Key):
        self.deleted_keys.append(copy.deepcopy(Key))
        self.items.pop(self._key_tuple(Key), None)
        return {}


class FakeDynamoResource:
    def __init__(self, tables):
        self.tables = tables

    def Table(self, name):
        return self.tables[name]


class FakeS3Client:
    def __init__(self):
        self.buckets: dict[str, set[str]] = {}
        self.bucket_creation_dates: dict[str, datetime] = {}
        self.deleted_objects: list[tuple[str, str]] = []
        self.deleted_buckets: list[str] = []

    def seed_bucket(self, bucket: str, created_at: datetime | None = None):
        self.buckets.setdefault(bucket, set())
        if created_at is None:
            created_at = datetime.now(timezone.utc)
        self.bucket_creation_dates[bucket] = created_at

    def seed_object(self, bucket: str, key: str):
        self.seed_bucket(bucket)
        self.buckets.setdefault(bucket, set()).add(key)

    def list_buckets(self):
        buckets = []
        for name in sorted(self.buckets):
            created_at = self.bucket_creation_dates.get(name, datetime.now(timezone.utc))
            buckets.append({"Name": name, "CreationDate": created_at})
        return {"Buckets": buckets}

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise ClientError({"Error": {"Code": "404", "Message": "bucket missing"}}, "HeadBucket")
        return {}

    def head_object(self, Bucket, Key):
        keys = self.buckets.get(Bucket)
        if keys is None or Key not in keys:
            raise ClientError({"Error": {"Code": "404", "Message": "object missing"}}, "HeadObject")
        return {}

    def delete_object(self, Bucket, Key):
        keys = self.buckets.get(Bucket)
        if keys is None or Key not in keys:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "object missing"}}, "DeleteObject")
        keys.remove(Key)
        self.deleted_objects.append((Bucket, Key))
        return {}

    def list_objects_v2(self, Bucket, MaxKeys=1000):
        del MaxKeys
        keys = sorted(self.buckets.get(Bucket) or [])
        if not keys:
            return {"KeyCount": 0, "Contents": []}
        return {"KeyCount": len(keys), "Contents": [{"Key": key} for key in keys]}

    def delete_bucket(self, Bucket):
        keys = self.buckets.get(Bucket)
        if keys is None:
            raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "bucket missing"}}, "DeleteBucket")
        if keys:
            raise ClientError({"Error": {"Code": "BucketNotEmpty", "Message": "bucket not empty"}}, "DeleteBucket")
        self.deleted_buckets.append(Bucket)
        self.buckets.pop(Bucket, None)
        self.bucket_creation_dates.pop(Bucket, None)
        return {}


class StorageHousekeepingLambdaTests(unittest.TestCase):
    def setUp(self):
        self.table_name = "txn-log"
        self.transaction_table = FakeDynamoTable(["quote_id", "trans_id"])
        self.dynamodb_resource = FakeDynamoResource({self.table_name: self.transaction_table})
        self.s3_client = FakeS3Client()

        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "UPLOAD_TRANSACTION_LOG_TABLE_NAME": self.table_name,
                "MNEMOSPARK_RECIPIENT_WALLET": "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
                "HOUSEKEEPING_BILLING_INTERVAL_DAYS": "30",
                "HOUSEKEEPING_GRACE_PERIOD_DAYS": "2",
            },
            clear=False,
        )
        self.env_patch.start()

        self.resource_patch = mock.patch.object(app.boto3, "resource", return_value=self.dynamodb_resource)
        self.resource_patch.start()
        self.client_patch = mock.patch.object(app.boto3, "client", return_value=self.s3_client)
        self.client_patch.start()

    def tearDown(self):
        self.client_patch.stop()
        self.resource_patch.stop()
        self.env_patch.stop()

    def _make_txn_item(
        self,
        *,
        quote_id: str,
        trans_id: str,
        wallet_address: str,
        object_key: str,
        paid_at: datetime,
        recipient_wallet: str | None = None,
        payment_status: str = "confirmed",
    ) -> dict[str, str]:
        normalized_wallet = wallet_address.lower()
        bucket_name = app._default_bucket_name(normalized_wallet)
        item = {
            "quote_id": quote_id,
            "trans_id": trans_id,
            "payment_status": payment_status,
            "addr": normalized_wallet,
            "object_key": object_key,
            "bucket_name": bucket_name,
            "location": app.US_EAST_1_REGION,
            "timestamp": paid_at.strftime(app.TIMESTAMP_FORMAT),
            "payment_received_at": paid_at.isoformat(),
        }
        if recipient_wallet is not None:
            item["recipient_wallet"] = recipient_wallet
        return item

    def test_overdue_object_is_deleted_and_transaction_rows_removed(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        wallet = "0x1111111111111111111111111111111111111111"
        object_key = "archive.enc"
        old_payment = now - timedelta(days=33)
        item = self._make_txn_item(
            quote_id="quote-1",
            trans_id="tx-1",
            wallet_address=wallet,
            object_key=object_key,
            paid_at=old_payment,
            recipient_wallet="0x47d241ae97fe37186ac59894290ca1c54c060a6c",
        )
        self.transaction_table.put_item(Item=item)
        self.s3_client.seed_object(item["bucket_name"], object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["housekeeping_mode"], "legacy_interval")
        self.assertEqual(body["objects_due"], 1)
        self.assertEqual(body["objects_deleted"], 1)
        self.assertEqual(body["buckets_deleted"], 1)
        self.assertEqual(body["transaction_rows_deleted"], 1)
        self.assertEqual(len(self.transaction_table.items), 0)
        self.assertIn(item["bucket_name"], self.s3_client.deleted_buckets)

    def test_recent_payment_within_32_days_is_not_deleted(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        wallet = "0x2222222222222222222222222222222222222222"
        object_key = "fresh.enc"
        recent_payment = now - timedelta(days=10)
        item = self._make_txn_item(
            quote_id="quote-2",
            trans_id="tx-2",
            wallet_address=wallet,
            object_key=object_key,
            paid_at=recent_payment,
        )
        self.transaction_table.put_item(Item=item)
        self.s3_client.seed_object(item["bucket_name"], object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["objects_due"], 0)
        self.assertEqual(body["objects_deleted"], 0)
        self.assertEqual(body["transaction_rows_deleted"], 0)
        self.assertIn(self.transaction_table._key_tuple(item), self.transaction_table.items)
        self.assertIn(object_key, self.s3_client.buckets[item["bucket_name"]])

    def test_latest_payment_per_object_prevents_false_overdue_deletion(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        wallet = "0x3333333333333333333333333333333333333333"
        object_key = "rolling.enc"
        old_payment = now - timedelta(days=45)
        recent_payment = now - timedelta(days=5)

        item_old = self._make_txn_item(
            quote_id="quote-3",
            trans_id="tx-old",
            wallet_address=wallet,
            object_key=object_key,
            paid_at=old_payment,
        )
        item_new = self._make_txn_item(
            quote_id="quote-4",
            trans_id="tx-new",
            wallet_address=wallet,
            object_key=object_key,
            paid_at=recent_payment,
        )
        self.transaction_table.put_item(Item=item_old)
        self.transaction_table.put_item(Item=item_new)
        self.s3_client.seed_object(item_old["bucket_name"], object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["objects_evaluated"], 1)
        self.assertEqual(body["objects_due"], 0)
        self.assertEqual(body["objects_deleted"], 0)
        self.assertEqual(len(self.transaction_table.items), 2)

    def test_recipient_mismatch_rows_are_skipped(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        wallet = "0x4444444444444444444444444444444444444444"
        object_key = "wrong-recipient.enc"
        old_payment = now - timedelta(days=60)
        item = self._make_txn_item(
            quote_id="quote-5",
            trans_id="tx-5",
            wallet_address=wallet,
            object_key=object_key,
            paid_at=old_payment,
            recipient_wallet="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.transaction_table.put_item(Item=item)
        self.s3_client.seed_object(item["bucket_name"], object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["rows_skipped_recipient_mismatch"], 1)
        self.assertEqual(body["rows_confirmed"], 0)
        self.assertEqual(body["objects_due"], 0)
        self.assertEqual(body["objects_deleted"], 0)
        self.assertIn(object_key, self.s3_client.buckets[item["bucket_name"]])

    def test_dry_run_reports_due_objects_without_deleting(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        wallet = "0x5555555555555555555555555555555555555555"
        object_key = "dry-run.enc"
        old_payment = now - timedelta(days=40)
        item = self._make_txn_item(
            quote_id="quote-6",
            trans_id="tx-6",
            wallet_address=wallet,
            object_key=object_key,
            paid_at=old_payment,
        )
        self.transaction_table.put_item(Item=item)
        self.s3_client.seed_object(item["bucket_name"], object_key)

        response = app.lambda_handler({"now": now.isoformat(), "dry_run": True}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["dry_run"])
        self.assertEqual(body["objects_due"], 1)
        self.assertEqual(body["objects_deleted"], 0)
        self.assertEqual(body["buckets_deleted"], 0)
        self.assertEqual(body["transaction_rows_deleted"], 0)
        self.assertIn(self.transaction_table._key_tuple(item), self.transaction_table.items)
        self.assertIn(object_key, self.s3_client.buckets[item["bucket_name"]])

    def test_scan_limit_caps_total_rows_scanned(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        wallet = "0x6666666666666666666666666666666666666666"

        for index in range(3):
            item = self._make_txn_item(
                quote_id=f"quote-scan-{index}",
                trans_id=f"tx-scan-{index}",
                wallet_address=wallet,
                object_key=f"object-{index}.enc",
                paid_at=now - timedelta(days=40),
            )
            self.transaction_table.put_item(Item=item)

        with mock.patch.dict(os.environ, {"HOUSEKEEPING_SCAN_LIMIT": "2"}, clear=False):
            response = app.lambda_handler({"now": now.isoformat(), "dry_run": True}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["rows_scanned"], 2)

    def test_non_confirmed_payment_rows_are_skipped(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        wallet = "0x7777777777777777777777777777777777777777"
        object_key = "pending-payment.enc"
        old_payment = now - timedelta(days=60)
        item = self._make_txn_item(
            quote_id="quote-7",
            trans_id="tx-7",
            wallet_address=wallet,
            object_key=object_key,
            paid_at=old_payment,
            payment_status="settlement_in_progress",
        )
        self.transaction_table.put_item(Item=item)
        self.s3_client.seed_object(item["bucket_name"], object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["rows_skipped_payment_not_confirmed"], 1)
        self.assertEqual(body["rows_confirmed"], 0)
        self.assertEqual(body["objects_due"], 0)
        self.assertEqual(body["objects_deleted"], 0)

    def test_lite_bucket_cleanup_failure_does_not_fail_housekeeping(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)

        with mock.patch.object(
            app,
            "_cleanup_empty_mnemospark_lite_buckets",
            side_effect=ClientError({"Error": {"Code": "Throttling"}}, "ListBuckets"),
        ):
            response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["housekeeping_mode"], "legacy_interval")
        self.assertEqual(body["lite_buckets_deleted"], 0)

    def test_lite_bucket_cleanup_skips_recent_empty_bucket(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        bucket_name = "mnemospark-lite-recent"
        self.s3_client.seed_bucket(bucket_name, created_at=now - timedelta(minutes=10))

        deleted = app._cleanup_empty_mnemospark_lite_buckets(self.s3_client, now=now)

        self.assertEqual(deleted, 0)
        self.assertIn(bucket_name, self.s3_client.buckets)
        self.assertNotIn(bucket_name, self.s3_client.deleted_buckets)

    def test_lite_bucket_cleanup_deletes_old_empty_bucket(self):
        now = datetime(2026, 2, 25, 12, 0, tzinfo=timezone.utc)
        bucket_name = "mnemospark-lite-stale"
        self.s3_client.seed_bucket(bucket_name, created_at=now - timedelta(days=2))

        deleted = app._cleanup_empty_mnemospark_lite_buckets(self.s3_client, now=now)

        self.assertEqual(deleted, 1)
        self.assertNotIn(bucket_name, self.s3_client.buckets)
        self.assertIn(bucket_name, self.s3_client.deleted_buckets)


class RenewalCalendarHousekeepingTests(unittest.TestCase):
    def setUp(self):
        self.active_table = FakeDynamoTable(["wallet_address", "object_key"])
        self.renewal_table = FakeDynamoTable(["bucket_name", "billing_period_object_key"])
        self.dynamodb_resource = FakeDynamoResource(
            {
                "active-inv": self.active_table,
                "renewal-log": self.renewal_table,
            }
        )
        self.s3_client = FakeS3Client()
        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "UPLOAD_TRANSACTION_LOG_TABLE_NAME": "txn-unused",
                "ACTIVE_STORAGE_OBJECT_TABLE_NAME": "active-inv",
                "RENEWAL_TRANSACTION_LOG_TABLE_NAME": "renewal-log",
                "MNEMOSPARK_RECIPIENT_WALLET": "0x47D241ae97fE37186AC59894290CA1c54c060A6c",
                "HOUSEKEEPING_MODE": "renewal_calendar",
            },
            clear=False,
        )
        self.env_patch.start()
        self.resource_patch = mock.patch.object(app.boto3, "resource", return_value=self.dynamodb_resource)
        self.resource_patch.start()
        self.client_patch = mock.patch.object(app.boto3, "client", return_value=self.s3_client)
        self.client_patch.start()

    def tearDown(self):
        self.client_patch.stop()
        self.resource_patch.stop()
        self.env_patch.stop()

    def test_deletes_when_no_renewal_row_and_not_first_month(self):
        now = datetime(2026, 4, 3, 12, 0, tzinfo=timezone.utc)
        wallet = "0x1111111111111111111111111111111111111111"
        object_key = "obj.enc"
        bucket = app._default_bucket_name(wallet)
        self.active_table.put_item(
            Item={
                "wallet_address": wallet,
                "object_key": object_key,
                "bucket_name": bucket,
                "location": app.US_EAST_1_REGION,
                "created_at": "2026-03-15T00:00:00+00:00",
                "status": "active",
                "status_active": "ACTIVE",
                "active_inventory_sk": f"{bucket}#x",
            }
        )
        self.s3_client.seed_object(bucket, object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["housekeeping_mode"], "renewal_calendar")
        self.assertEqual(body["objects_due"], 1)
        self.assertEqual(body["objects_deleted"], 1)
        self.assertEqual(body["inventory_rows_deleted"], 1)
        self.assertEqual(len(self.active_table.items), 0)
        self.assertIn(bucket, self.s3_client.deleted_buckets)

    def test_skips_when_renewal_row_exists(self):
        now = datetime(2026, 4, 3, 12, 0, tzinfo=timezone.utc)
        wallet = "0x2222222222222222222222222222222222222222"
        object_key = "paid.enc"
        bucket = app._default_bucket_name(wallet)
        bp_ok = billing_period_object_key("2026-04", object_key)
        self.active_table.put_item(
            Item={
                "wallet_address": wallet,
                "object_key": object_key,
                "bucket_name": bucket,
                "location": app.US_EAST_1_REGION,
                "created_at": "2026-03-01T00:00:00+00:00",
                "status": "active",
                "status_active": "ACTIVE",
                "active_inventory_sk": f"{bucket}#y",
            }
        )
        self.renewal_table.put_item(
            Item={
                "bucket_name": bucket,
                "billing_period_object_key": bp_ok,
                "billing_period": "2026-04",
                "object_key": object_key,
            }
        )
        self.s3_client.seed_object(bucket, object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(body["objects_due"], 0)
        self.assertEqual(body["objects_deleted"], 0)
        self.assertEqual(len(self.active_table.items), 1)

    def test_first_month_grace_skips_delete(self):
        now = datetime(2026, 4, 3, 12, 0, tzinfo=timezone.utc)
        wallet = "0x3333333333333333333333333333333333333333"
        object_key = "new.enc"
        bucket = app._default_bucket_name(wallet)
        self.active_table.put_item(
            Item={
                "wallet_address": wallet,
                "object_key": object_key,
                "bucket_name": bucket,
                "location": app.US_EAST_1_REGION,
                "created_at": "2026-04-01T00:00:00+00:00",
                "status": "active",
                "status_active": "ACTIVE",
                "active_inventory_sk": f"{bucket}#z",
            }
        )
        self.s3_client.seed_object(bucket, object_key)

        response = app.lambda_handler({"now": now.isoformat()}, None)
        body = json.loads(response["body"])

        self.assertEqual(body["objects_due"], 0)
        self.assertEqual(body["objects_deleted"], 0)
        self.assertEqual(len(self.active_table.items), 1)
