import importlib.util
import json
import sys
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-download" / "app.py"
    module_name = "storage_download_app_unit"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load storage download module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeS3Client:
    def __init__(self, *, bucket_missing=False, object_missing=False):
        self.bucket_missing = bucket_missing
        self.object_missing = object_missing
        self.generate_calls = []

    def head_bucket(self, Bucket):
        if self.bucket_missing:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "missing bucket"}},
                "HeadBucket",
            )
        return {"Bucket": Bucket}

    def head_object(self, Bucket, Key):
        if self.object_missing:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "missing object"}},
                "HeadObject",
            )
        return {"ContentLength": 10, "Bucket": Bucket, "Key": Key}

    def generate_presigned_url(self, ClientMethod, Params, ExpiresIn, HttpMethod):
        self.generate_calls.append(
            {
                "ClientMethod": ClientMethod,
                "Params": Params,
                "ExpiresIn": ExpiresIn,
                "HttpMethod": HttpMethod,
            }
        )
        return f"https://example.test/{Params['Bucket']}/{Params['Key']}?exp={ExpiresIn}"


class ParseInputTests(unittest.TestCase):
    def test_parse_input_get_query(self):
        request = app.parse_input(
            {
                "httpMethod": "GET",
                "queryStringParameters": {
                    "wallet_address": "0x1111111111111111111111111111111111111111",
                    "object_key": "backup.tar.gz",
                    "location": "eu-west-1",
                },
            }
        )

        self.assertEqual(request.wallet_address, "0x1111111111111111111111111111111111111111")
        self.assertEqual(request.object_key, "backup.tar.gz")
        self.assertEqual(request.location, "eu-west-1")
        self.assertEqual(request.expires_in_seconds, app.DEFAULT_PRESIGNED_TTL_SECONDS)

    def test_parse_input_post_body(self):
        request = app.parse_input(
            {
                "httpMethod": "POST",
                "body": json.dumps(
                    {
                        "walletAddress": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "objectKey": "archive.bin",
                        "region": "ap-southeast-1",
                        "expires_in_seconds": 120,
                    }
                ),
            }
        )

        self.assertEqual(request.wallet_address, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(request.object_key, "archive.bin")
        self.assertEqual(request.location, "ap-southeast-1")
        self.assertEqual(request.expires_in_seconds, 120)

    def test_parse_input_rejects_invalid_wallet(self):
        with self.assertRaises(app.BadRequestError):
            app.parse_input(
                {
                    "httpMethod": "GET",
                    "queryStringParameters": {
                        "wallet_address": "not-a-wallet",
                        "object_key": "backup.tar.gz",
                    },
                }
            )

    def test_parse_input_rejects_path_traversal_object_key(self):
        with self.assertRaises(app.BadRequestError):
            app.parse_input(
                {
                    "httpMethod": "GET",
                    "queryStringParameters": {
                        "wallet_address": "0x1111111111111111111111111111111111111111",
                        "object_key": "../secret",
                    },
                }
            )


class LambdaHandlerTests(unittest.TestCase):
    def _event(self, **query):
        return {
            "httpMethod": "GET",
            "queryStringParameters": {
                "wallet_address": "0x1111111111111111111111111111111111111111",
                "object_key": "backup.tar.gz",
                **query,
            },
        }

    def test_lambda_handler_success_returns_presigned_url_shape(self):
        fake_s3_client = FakeS3Client()
        event = self._event()

        with mock.patch.object(app.boto3, "client", return_value=fake_s3_client):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertIn("download_url", body)
        self.assertEqual(body["object_key"], "backup.tar.gz")
        self.assertEqual(body["expires_in_seconds"], app.DEFAULT_PRESIGNED_TTL_SECONDS)
        self.assertEqual(len(fake_s3_client.generate_calls), 1)

        generate_call = fake_s3_client.generate_calls[0]
        self.assertEqual(generate_call["ClientMethod"], "get_object")
        self.assertEqual(generate_call["HttpMethod"], "GET")
        self.assertEqual(
            generate_call["Params"]["Bucket"],
            app._bucket_name("0x1111111111111111111111111111111111111111"),
        )
        self.assertEqual(generate_call["Params"]["Key"], "backup.tar.gz")

    def test_lambda_handler_returns_404_when_bucket_missing(self):
        fake_s3_client = FakeS3Client(bucket_missing=True)

        with mock.patch.object(app.boto3, "client", return_value=fake_s3_client):
            response = app.lambda_handler(self._event(), None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "bucket_not_found")
        self.assertIn("Bucket not found", body["message"])

    def test_lambda_handler_returns_404_when_object_missing(self):
        fake_s3_client = FakeS3Client(object_missing=True)

        with mock.patch.object(app.boto3, "client", return_value=fake_s3_client):
            response = app.lambda_handler(self._event(), None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "object_not_found")
        self.assertIn("Object not found", body["message"])

    def test_lambda_handler_rejects_unsupported_method(self):
        event = self._event()
        event["httpMethod"] = "DELETE"

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 405)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "method_not_allowed")

    def test_lambda_handler_invalid_json_body_returns_400(self):
        event = {
            "httpMethod": "POST",
            "body": "{invalid",
        }

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")
