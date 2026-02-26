import importlib.util
import json
import sys
from pathlib import Path
import unittest
from unittest import mock

import boto3
from botocore.stub import Stubber


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-download" / "app.py"
    module_name = "storage_download_app_integration"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load storage download module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class StorageDownloadIntegrationTests(unittest.TestCase):
    def _event(self):
        return {
            "httpMethod": "GET",
            "queryStringParameters": {
                "wallet_address": "0x1111111111111111111111111111111111111111",
                "object_key": "backup.tar.gz",
                "location": app.US_EAST_1_REGION,
            },
            "requestContext": {
                "authorizer": {
                    "walletAddress": "0x1111111111111111111111111111111111111111",
                }
            },
        }

    def _s3_client(self):
        return boto3.client(
            "s3",
            region_name=app.US_EAST_1_REGION,
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token="testing",
        )

    def test_lambda_handler_wallet_mismatch_returns_403(self):
        event = self._event()
        event["requestContext"]["authorizer"]["walletAddress"] = "0x" + ("2" * 40)

        response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")

    def test_lambda_handler_generates_presigned_url_with_stubbed_s3(self):
        event = self._event()
        expected_bucket = app._bucket_name("0x1111111111111111111111111111111111111111")
        s3_client = self._s3_client()
        stubber = Stubber(s3_client)
        stubber.add_response("head_bucket", {}, {"Bucket": expected_bucket})
        stubber.add_response(
            "head_object",
            {"ContentLength": 10, "ContentType": "application/octet-stream"},
            {"Bucket": expected_bucket, "Key": "backup.tar.gz"},
        )

        with (
            stubber,
            mock.patch.object(app.boto3, "client", return_value=s3_client),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertIn("download_url", body)
        self.assertEqual(body["object_key"], "backup.tar.gz")
        self.assertEqual(body["expires_in_seconds"], app.DEFAULT_PRESIGNED_TTL_SECONDS)
        self.assertIn(expected_bucket, body["download_url"])

    def test_lambda_handler_returns_404_for_missing_object(self):
        event = self._event()
        expected_bucket = app._bucket_name("0x1111111111111111111111111111111111111111")
        s3_client = self._s3_client()
        stubber = Stubber(s3_client)
        stubber.add_response("head_bucket", {}, {"Bucket": expected_bucket})
        stubber.add_client_error(
            "head_object",
            service_error_code="404",
            service_message="missing object",
            http_status_code=404,
            expected_params={"Bucket": expected_bucket, "Key": "backup.tar.gz"},
        )

        with (
            stubber,
            mock.patch.object(app.boto3, "client", return_value=s3_client),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "object_not_found")
