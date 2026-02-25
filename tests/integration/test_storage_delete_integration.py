import importlib.util
import json
import sys
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-delete" / "app.py"
    module_name = "storage_delete_app_integration"
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
        self.delete_object_calls: list[tuple[str, str]] = []
        self.delete_bucket_calls: list[str] = []

    def seed_object(self, bucket: str, key: str):
        self.buckets.setdefault(bucket, set()).add(key)

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
        self.delete_object_calls.append((Bucket, Key))
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
        self.buckets.pop(Bucket, None)
        self.delete_bucket_calls.append(Bucket)
        return {}


class StorageDeleteIntegrationTests(unittest.TestCase):
    def test_delete_lifecycle_post_then_delete_query(self):
        wallet_address = "0x9999999999999999999999999999999999999999"
        bucket = app._bucket_name(wallet_address)
        first_key = "one.bin"
        second_key = "two.bin"
        s3_client = FakeS3Client()
        s3_client.seed_object(bucket, first_key)
        s3_client.seed_object(bucket, second_key)

        post_event = {
            "httpMethod": "POST",
            "body": json.dumps(
                {
                    "wallet_address": wallet_address,
                    "object_key": first_key,
                }
            ),
        }
        delete_event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": wallet_address,
                "object_key": second_key,
            },
        }

        with mock.patch.object(app.boto3, "client", return_value=s3_client):
            first_response = app.lambda_handler(post_event, None)
            second_response = app.lambda_handler(delete_event, None)

        self.assertEqual(first_response["statusCode"], 200)
        self.assertEqual(second_response["statusCode"], 200)
        first_body = json.loads(first_response["body"])
        second_body = json.loads(second_response["body"])
        self.assertEqual(first_body["bucket_deleted"], False)
        self.assertEqual(second_body["bucket_deleted"], True)
        self.assertEqual(len(s3_client.delete_object_calls), 2)
        self.assertEqual(s3_client.delete_bucket_calls, [bucket])

    def test_second_delete_after_bucket_removal_returns_404(self):
        wallet_address = "0x7777777777777777777777777777777777777777"
        object_key = "single.bin"
        bucket = app._bucket_name(wallet_address)
        s3_client = FakeS3Client()
        s3_client.seed_object(bucket, object_key)

        event = {
            "httpMethod": "DELETE",
            "queryStringParameters": {
                "wallet_address": wallet_address,
                "object_key": object_key,
            },
        }

        with mock.patch.object(app.boto3, "client", return_value=s3_client):
            first_response = app.lambda_handler(event, None)
            second_response = app.lambda_handler(event, None)

        self.assertEqual(first_response["statusCode"], 200)
        self.assertEqual(second_response["statusCode"], 404)
        error_body = json.loads(second_response["body"])
        self.assertEqual(error_body["error"], "bucket_not_found")
        self.assertEqual(error_body["message"], "Bucket not found for this wallet")

