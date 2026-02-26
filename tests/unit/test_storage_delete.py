import importlib.util
import json
import sys
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-delete" / "app.py"
    module_name = "storage_delete_app_unit"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load storage-delete module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeS3Client:
    def __init__(self):
        self.buckets: dict[str, set[str]] = {}
        self.deleted_buckets: list[str] = []

    def seed_object(self, bucket: str, key: str):
        self.buckets.setdefault(bucket, set()).add(key)

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "bucket missing"}},
                "HeadBucket",
            )
        return {}

    def head_object(self, Bucket, Key):
        keys = self.buckets.get(Bucket)
        if keys is None or Key not in keys:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "object missing"}},
                "HeadObject",
            )
        return {}

    def delete_object(self, Bucket, Key):
        keys = self.buckets.get(Bucket)
        if keys is None or Key not in keys:
            raise ClientError(
                {"Error": {"Code": "NoSuchKey", "Message": "object missing"}},
                "DeleteObject",
            )
        keys.remove(Key)
        return {}

    def list_objects_v2(self, Bucket, MaxKeys=1000):
        del MaxKeys
        keys = sorted(self.buckets.get(Bucket) or [])
        if not keys:
            return {"KeyCount": 0}
        return {"KeyCount": len(keys), "Contents": [{"Key": key} for key in keys]}

    def delete_bucket(self, Bucket):
        keys = self.buckets.get(Bucket)
        if keys is None:
            raise ClientError(
                {"Error": {"Code": "NoSuchBucket", "Message": "bucket missing"}},
                "DeleteBucket",
            )
        if keys:
            raise ClientError(
                {"Error": {"Code": "BucketNotEmpty", "Message": "bucket not empty"}},
                "DeleteBucket",
            )
        self.deleted_buckets.append(Bucket)
        self.buckets.pop(Bucket, None)
        return {}


class StorageDeleteLambdaTests(unittest.TestCase):
    def test_post_body_deletes_object_and_empty_bucket(self):
        wallet_address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        normalized_wallet = wallet_address.lower()
        object_key = "backup.enc"
        bucket = app._bucket_name(normalized_wallet)
        s3_client = FakeS3Client()
        s3_client.seed_object(bucket, object_key)

        event = {
            "httpMethod": "POST",
            "body": json.dumps(
                {
                    "wallet_address": wallet_address,
                    "object_key": object_key,
                }
            ),
            "requestContext": {
                "authorizer": {
                    "walletAddress": wallet_address,
                }
            },
        }

        with mock.patch.object(app.boto3, "client", return_value=s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["success"], True)
        self.assertEqual(body["key"], object_key)
        self.assertEqual(body["bucket"], bucket)
        self.assertEqual(body["bucket_deleted"], True)
        self.assertNotIn(bucket, s3_client.buckets)
        self.assertIn(bucket, s3_client.deleted_buckets)

    def test_delete_query_keeps_bucket_when_other_objects_exist(self):
        wallet_address = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        object_key = "target.dat"
        other_key = "keep.dat"
        bucket = app._bucket_name(wallet_address)
        s3_client = FakeS3Client()
        s3_client.seed_object(bucket, object_key)
        s3_client.seed_object(bucket, other_key)

        event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": wallet_address,
                "object_key": object_key,
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": wallet_address,
                }
            },
        }

        with mock.patch.object(app.boto3, "client", return_value=s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["bucket_deleted"], False)
        self.assertIn(bucket, s3_client.buckets)
        self.assertEqual(s3_client.buckets[bucket], {other_key})

    def test_missing_object_key_returns_400(self):
        event = {
            "httpMethod": "POST",
            "body": json.dumps({"wallet_address": "0x1111111111111111111111111111111111111111"}),
        }

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")
        self.assertIn("object_key is required", body["message"])

    def test_invalid_wallet_returns_400(self):
        event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": "not-a-wallet",
                "object_key": "file.bin",
            },
        }

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")
        self.assertIn("wallet_address must be a 0x-prefixed 20-byte hex address", body["message"])

    def test_object_not_found_returns_404(self):
        wallet_address = "0x1111111111111111111111111111111111111111"
        bucket = app._bucket_name(wallet_address)
        s3_client = FakeS3Client()
        s3_client.seed_object(bucket, "different.bin")

        event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": wallet_address,
                "object_key": "missing.bin",
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": wallet_address,
                }
            },
        }

        with mock.patch.object(app.boto3, "client", return_value=s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "object_not_found")
        self.assertEqual(body["message"], "Object not found")

    def test_bucket_not_found_returns_404(self):
        s3_client = FakeS3Client()
        event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": "0x1111111111111111111111111111111111111111",
                "object_key": "file.bin",
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": "0x1111111111111111111111111111111111111111",
                }
            },
        }

        with mock.patch.object(app.boto3, "client", return_value=s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "bucket_not_found")
        self.assertEqual(body["message"], "Bucket not found for this wallet")

    def test_missing_authorizer_context_returns_403(self):
        wallet_address = "0x1111111111111111111111111111111111111111"
        event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": wallet_address,
                "object_key": "file.bin",
            },
        }

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertIn("wallet authorization context is required", body["message"])

    def test_authorizer_wallet_mismatch_returns_403(self):
        wallet_address = "0x1111111111111111111111111111111111111111"
        event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": wallet_address,
                "object_key": "file.bin",
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": "0x2222222222222222222222222222222222222222",
                }
            },
        }

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertIn("wallet_address does not match authorized wallet", body["message"])

