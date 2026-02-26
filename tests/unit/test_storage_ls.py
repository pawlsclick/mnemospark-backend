import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-ls" / "app.py"
    module_spec = importlib.util.spec_from_file_location("storage_ls_app", module_path)
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

    def head_bucket(self, Bucket):
        if Bucket not in self.objects_by_bucket:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "bucket not found"}},
                "HeadBucket",
            )
        return {}

    def head_object(self, Bucket, Key):
        objects = self.objects_by_bucket.get(Bucket, {})
        if Key not in objects:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "object not found"}},
                "HeadObject",
            )
        return {"ContentLength": objects[Key]}


class ParseInputTests(unittest.TestCase):
    def setUp(self):
        self.wallet = "0x" + ("a" * 40)

    def test_parse_input_with_query_params(self):
        event = {
            "queryStringParameters": {
                "wallet_address": self.wallet,
                "object_key": "backup.tar.gz",
                "location": "eu-west-1",
            }
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed.wallet_address, self.wallet)
        self.assertEqual(parsed.object_key, "backup.tar.gz")
        self.assertEqual(parsed.location, "eu-west-1")

    def test_parse_input_prefers_json_body_over_query(self):
        event = {
            "queryStringParameters": {
                "wallet_address": self.wallet,
                "object_key": "wrong.txt",
                "location": "us-west-2",
            },
            "body": json.dumps(
                {
                    "wallet_address": self.wallet,
                    "object_key": "right.txt",
                    "location": "ap-south-1",
                }
            ),
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed.object_key, "right.txt")
        self.assertEqual(parsed.location, "ap-south-1")

    def test_parse_input_supports_base64_encoded_body(self):
        body = json.dumps(
            {
                "wallet_address": self.wallet,
                "object_key": "encoded.txt",
            }
        ).encode("utf-8")
        event = {
            "isBase64Encoded": True,
            "body": base64.b64encode(body).decode("ascii"),
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed.wallet_address, self.wallet)
        self.assertEqual(parsed.object_key, "encoded.txt")
        self.assertEqual(parsed.location, app.DEFAULT_LOCATION)

    def test_parse_input_requires_wallet(self):
        with self.assertRaises(app.BadRequestError):
            app.parse_input({"queryStringParameters": {"object_key": "x"}})

    def test_parse_input_rejects_invalid_wallet(self):
        with self.assertRaises(app.BadRequestError):
            app.parse_input(
                {
                    "queryStringParameters": {
                        "wallet_address": "not-a-wallet",
                        "object_key": "x",
                    }
                }
            )

    def test_parse_input_rejects_path_like_object_key(self):
        with self.assertRaises(app.BadRequestError):
            app.parse_input(
                {
                    "queryStringParameters": {
                        "wallet_address": self.wallet,
                        "object_key": "folder/file.txt",
                    }
                }
            )


class LambdaHandlerTests(unittest.TestCase):
    def setUp(self):
        self.wallet = "0x" + ("1" * 40)
        self.object_key = "snapshot.tar.gz"
        self.bucket = app._bucket_name(self.wallet)
        self.s3_client = FakeS3Client({self.bucket: {self.object_key: 12345}})

    def _get_event(self):
        return {
            "httpMethod": "GET",
            "queryStringParameters": {
                "wallet_address": self.wallet,
                "object_key": self.object_key,
                "location": "us-west-2",
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": self.wallet,
                }
            },
        }

    def _post_event(self):
        return {
            "httpMethod": "POST",
            "body": json.dumps(
                {
                    "wallet_address": self.wallet,
                    "object_key": self.object_key,
                    "location": "us-west-2",
                }
            ),
            "requestContext": {
                "authorizer": {
                    "walletAddress": self.wallet,
                }
            },
        }

    def test_lambda_handler_get_success(self):
        with mock.patch.object(app.boto3, "client", return_value=self.s3_client):
            response = app.lambda_handler(self._get_event(), None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertTrue(body["success"])
        self.assertEqual(body["key"], self.object_key)
        self.assertEqual(body["size_bytes"], 12345)
        self.assertEqual(body["bucket"], self.bucket)

    def test_lambda_handler_post_success(self):
        with mock.patch.object(app.boto3, "client", return_value=self.s3_client):
            response = app.lambda_handler(self._post_event(), None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertTrue(body["success"])
        self.assertEqual(body["key"], self.object_key)
        self.assertEqual(body["bucket"], self.bucket)

    def test_lambda_handler_bucket_not_found_returns_404(self):
        with mock.patch.object(app.boto3, "client", return_value=FakeS3Client({})):
            response = app.lambda_handler(self._get_event(), None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "bucket_not_found")

    def test_lambda_handler_object_not_found_returns_404(self):
        with mock.patch.object(app.boto3, "client", return_value=FakeS3Client({self.bucket: {}})):
            response = app.lambda_handler(self._get_event(), None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "object_not_found")

    def test_lambda_handler_bad_request_returns_400(self):
        event = {"queryStringParameters": {"wallet_address": self.wallet}}
        with mock.patch.object(app.boto3, "client", return_value=self.s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")

    def test_lambda_handler_missing_authorizer_context_returns_403(self):
        event = self._get_event()
        event.pop("requestContext")
        with mock.patch.object(app.boto3, "client", return_value=self.s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertIn("wallet authorization context is required", body["message"])

    def test_lambda_handler_authorizer_wallet_mismatch_returns_403(self):
        event = self._get_event()
        event["requestContext"]["authorizer"]["walletAddress"] = "0x" + ("3" * 40)
        with mock.patch.object(app.boto3, "client", return_value=self.s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertIn("wallet_address does not match authorized wallet", body["message"])

    def test_lambda_handler_unexpected_s3_error_returns_500(self):
        class FailingS3Client(FakeS3Client):
            def head_bucket(self, Bucket):
                raise ClientError(
                    {"Error": {"Code": "InternalError", "Message": "boom"}},
                    "HeadBucket",
                )

        with mock.patch.object(app.boto3, "client", return_value=FailingS3Client({self.bucket: {}})):
            response = app.lambda_handler(self._get_event(), None)

        self.assertEqual(response["statusCode"], 500)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Internal error")
