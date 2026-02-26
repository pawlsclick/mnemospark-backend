import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-ls" / "app.py"
    module_spec = importlib.util.spec_from_file_location("storage_ls_app_integration", module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load storage ls module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeS3Client:
    def __init__(self, objects_by_bucket):
        self.objects_by_bucket = objects_by_bucket
        self.head_bucket_calls = []
        self.head_object_calls = []

    def head_bucket(self, Bucket):
        self.head_bucket_calls.append(Bucket)
        if Bucket not in self.objects_by_bucket:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "bucket not found"}},
                "HeadBucket",
            )
        return {}

    def head_object(self, Bucket, Key):
        self.head_object_calls.append((Bucket, Key))
        objects = self.objects_by_bucket.get(Bucket, {})
        if Key not in objects:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "object not found"}},
                "HeadObject",
            )
        return {"ContentLength": objects[Key]}


class StorageLsIntegrationTests(unittest.TestCase):
    def test_wallet_mismatch_returns_403(self):
        wallet = "0x" + ("2" * 40)
        event = {
            "httpMethod": "GET",
            "queryStringParameters": {
                "wallet_address": wallet,
                "object_key": "archive.tar.gz",
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": "0x" + ("3" * 40),
                }
            },
        }

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")

    def test_get_and_post_return_object_metadata_for_wallet_bucket(self):
        wallet = "0x" + ("2" * 40)
        object_key = "archive.tar.gz"
        expected_size = 987654
        expected_bucket = app._bucket_name(wallet)
        fake_s3 = FakeS3Client({expected_bucket: {object_key: expected_size}})

        get_event = {
            "httpMethod": "GET",
            "queryStringParameters": {
                "wallet_address": wallet,
                "object_key": object_key,
                "location": "us-west-2",
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": wallet,
                }
            },
        }
        post_event = {
            "httpMethod": "POST",
            "body": json.dumps(
                {
                    "wallet_address": wallet,
                    "object_key": object_key,
                    "location": "us-west-2",
                }
            ),
            "requestContext": {
                "authorizer": {
                    "walletAddress": wallet,
                }
            },
        }

        with mock.patch.object(app.boto3, "client", return_value=fake_s3):
            get_response = app.lambda_handler(get_event, None)
            post_response = app.lambda_handler(post_event, None)

        self.assertEqual(get_response["statusCode"], 200)
        self.assertEqual(post_response["statusCode"], 200)
        self.assertEqual(
            json.loads(get_response["body"]),
            {
                "success": True,
                "key": object_key,
                "size_bytes": expected_size,
                "bucket": expected_bucket,
            },
        )
        self.assertEqual(
            json.loads(post_response["body"]),
            {
                "success": True,
                "key": object_key,
                "size_bytes": expected_size,
                "bucket": expected_bucket,
            },
        )
        self.assertEqual(len(fake_s3.head_bucket_calls), 2)
        self.assertEqual(len(fake_s3.head_object_calls), 2)
