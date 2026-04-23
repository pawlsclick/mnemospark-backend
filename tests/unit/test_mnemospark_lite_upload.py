import importlib.util
import json
import sys
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "mnemospark-lite-upload" / "app.py"
    module_name = "mnemospark_lite_upload_app_unit"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load mnemospark-lite-upload module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeUploadsTable:
    def __init__(self, item):
        self.item = item

    def get_item(self, Key):
        if Key.get("upload_id") == self.item.get("upload_id"):
            return {"Item": self.item}
        return {}


class CompleteUploadTokenAndStatusTests(unittest.TestCase):
    def test_complete_retry_returns_409_when_upload_already_completed(self):
        token = "completion-token"
        upload_id = "up_already_done"
        item = {
            "upload_id": upload_id,
            "completion_token_hash": None,
            "status": "uploaded",
            "bucket": "mnemospark-lite-test",
            "filename": "artifact.bin",
            "payer_wallet": "0x" + ("1" * 40),
            "max_size": 1000,
        }
        event = {
            "body": json.dumps({"uploadId": upload_id, "completion_token": token}),
        }

        with mock.patch.object(app, "_uploads_table", return_value=FakeUploadsTable(item)):
            response = app._handle_post_complete(event)

        self.assertEqual(response["statusCode"], 409)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "conflict")
        self.assertEqual(body["message"], "Upload has already been completed.")


class LambdaHandlerErrorMappingTests(unittest.TestCase):
    def test_bearer_auth_failures_return_403(self):
        event = {"httpMethod": "GET", "path": "/api/mnemospark-lite/uploads"}
        with mock.patch.object(
            app,
            "_handle_get_uploads",
            side_effect=app.UnauthorizedError("Authorization bearer token is required"),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "forbidden")
        self.assertEqual(body["message"], "Authorization bearer token is required")

    def test_complete_before_upload_returns_400_when_s3_key_missing(self):
        token = "completion-token"
        upload_id = "up_123"
        item = {
            "upload_id": upload_id,
            "completion_token_hash": app._hash_token(token),
            "status": "pending",
            "bucket": "mnemospark-lite-test",
            "filename": "artifact.bin",
            "payer_wallet": "0x" + ("1" * 40),
            "max_size": 1000,
            "transaction_hash": "0xabc",
        }
        event = {
            "httpMethod": "POST",
            "path": "/api/mnemospark-lite/upload/complete",
            "body": json.dumps({"uploadId": upload_id, "completion_token": token}),
        }
        missing_object_error = ClientError({"Error": {"Code": "NoSuchKey"}}, "HeadObject")

        with (
            mock.patch.object(app, "_uploads_table", return_value=FakeUploadsTable(item)),
            mock.patch.object(app.s3, "head_object", side_effect=missing_object_error),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "bad_request")
        self.assertIn("Uploaded object not found", body["message"])


class CompleteUploadOrderingTests(unittest.TestCase):
    def test_complete_mints_before_atomic_update_and_returns_409_on_conflict(self):
        token = "completion-token"
        upload_id = "up_conflict"
        item = {
            "upload_id": upload_id,
            "completion_token_hash": app._hash_token(token),
            "status": "pending",
            "bucket": "mnemospark-lite-test",
            "filename": "artifact.bin",
            "payer_wallet": "0x" + ("1" * 40),
            "max_size": 1000,
            "transaction_hash": "0xabc",
        }
        event = {"body": json.dumps({"uploadId": upload_id, "completion_token": token})}
        conditional_error = ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")

        table = mock.Mock()
        table.get_item.return_value = {"Item": item}
        table.update_item.side_effect = conditional_error

        with (
            mock.patch.object(app, "_uploads_table", return_value=table),
            mock.patch.object(app.s3, "head_object", return_value={"ContentLength": 100}),
            mock.patch.object(app, "_mint_ls_web_app_url") as mint_mock,
        ):
            response = app._handle_post_complete(event)

        self.assertEqual(response["statusCode"], 409)
        mint_mock.assert_called_once()
        table.update_item.assert_called_once()

    def test_complete_persists_status_and_urls_in_single_update(self):
        token = "completion-token"
        upload_id = "up_success"
        item = {
            "upload_id": upload_id,
            "completion_token_hash": app._hash_token(token),
            "status": "pending",
            "bucket": "mnemospark-lite-test",
            "filename": "artifact.bin",
            "payer_wallet": "0x" + ("1" * 40),
            "max_size": 1000,
            "transaction_hash": "0xabc",
        }
        event = {"body": json.dumps({"uploadId": upload_id, "completion_token": token})}

        table = mock.Mock()
        table.get_item.return_value = {"Item": item}

        with (
            mock.patch.object(app, "_uploads_table", return_value=table),
            mock.patch.object(app.s3, "head_object", return_value={"ContentLength": 100}),
            mock.patch.object(
                app,
                "_mint_ls_web_app_url",
                return_value={"app": "https://app.mnemospark.ai/?code=abc", "code": "abc", "expires_at": "2030-01-01T00:00:00Z"},
            ),
        ):
            response = app._handle_post_complete(event)

        self.assertEqual(response["statusCode"], 200)
        table.update_item.assert_called_once()
        self.assertIn("public_url=:p", table.update_item.call_args.kwargs["UpdateExpression"])


class BucketLifecycleTests(unittest.TestCase):
    def setUp(self):
        app._LIFECYCLE_ENSURED_BUCKETS.clear()

    def test_ensure_bucket_lifecycle_skips_put_when_rule_exists(self):
        rule_id = f"mnemospark-lite-expire-{app.LIFECYCLE_EXPIRE_DAYS}d"

        with (
            mock.patch.object(
                app.s3,
                "get_bucket_lifecycle_configuration",
                return_value={"Rules": [{"ID": rule_id, "Status": "Enabled"}]},
            ),
            mock.patch.object(app.s3, "put_bucket_lifecycle_configuration") as put_mock,
        ):
            app._ensure_bucket_lifecycle_expiration(bucket="mnemospark-lite-test")

        put_mock.assert_not_called()

    def test_ensure_bucket_lifecycle_preserves_existing_rules_when_adding(self):
        existing_rule = {
            "ID": "external-rule",
            "Status": "Enabled",
            "Filter": {"Prefix": "archive/"},
            "Expiration": {"Days": 365},
        }

        with (
            mock.patch.object(
                app.s3,
                "get_bucket_lifecycle_configuration",
                return_value={"Rules": [existing_rule]},
            ),
            mock.patch.object(app.s3, "put_bucket_lifecycle_configuration") as put_mock,
        ):
            app._ensure_bucket_lifecycle_expiration(bucket="mnemospark-lite-test")

        put_mock.assert_called_once()
        rules = put_mock.call_args.kwargs["LifecycleConfiguration"]["Rules"]
        self.assertIn(existing_rule, rules)
        self.assertTrue(any(rule.get("ID", "").startswith("mnemospark-lite-expire-") for rule in rules))


class PostUploadReliabilityTests(unittest.TestCase):
    def test_strip_nulls_removes_none_values(self):
        self.assertEqual(app._strip_nulls({"a": None, "b": {"c": None, "d": 1}}), {"b": {"d": 1}})

    def test_post_upload_continues_when_lifecycle_ensure_fails(self):
        event = {
            "body": json.dumps(
                {
                    "filename": "artifact.bin",
                    "contentType": "application/octet-stream",
                    "tier": "10mb",
                    "size_bytes": 1024,
                }
            ),
            "headers": {"x-payment": "signed-payment"},
        }
        uploads_table = mock.Mock()
        lifecycle_error = ClientError({"Error": {"Code": "Throttling"}}, "PutBucketLifecycleConfiguration")

        with (
            mock.patch.object(
                app,
                "_payment_requirements",
                return_value={
                    "accepts": [
                        {
                            "scheme": "exact",
                            "network": "eip155:8453",
                            "asset": "0x" + ("a" * 40),
                            "payTo": "0x" + ("b" * 40),
                            "amount": "20000",
                            "maxTimeoutSeconds": 3600,
                            "extra": {"name": "USD Coin", "version": "2"},
                        }
                    ]
                },
            ),
            mock.patch.object(
                app,
                "_decode_payment_payload",
                return_value={
                    "x402Version": 2,
                    "payload": {
                        "authorization": {
                            "from": "0x" + ("1" * 40),
                            "to": "0x" + ("b" * 40),
                            "value": "20000",
                            "validAfter": "1716150000",
                            "validBefore": "2716150000",
                            "nonce": "0x" + ("1" * 64),
                        },
                        "signature": "0x" + ("2" * 130),
                    },
                },
            ),
            mock.patch.object(app, "_verify_payment_locally", return_value=None),
            mock.patch.object(app.s3, "head_bucket", return_value={}),
            mock.patch.object(app, "_ensure_bucket_lifecycle_expiration", side_effect=lifecycle_error),
            mock.patch.object(app.s3, "generate_presigned_url", return_value="https://example.com/upload"),
            mock.patch.object(app, "_uploads_table", return_value=uploads_table),
            mock.patch.object(app, "_payment_config", return_value={"payment_network": "base-sepolia"}),
            mock.patch.object(app, "_sign_bearer", return_value="bearer"),
            mock.patch.object(app.secrets, "token_urlsafe", side_effect=["upload123", "completion123"]),
        ):
            response = app._handle_post_upload(event)

        self.assertEqual(response["statusCode"], 200)
        uploads_table.put_item.assert_called_once()

    def test_post_upload_uses_upload_scoped_object_key(self):
        event = {
            "body": json.dumps(
                {
                    "filename": "artifact.bin",
                    "contentType": "application/octet-stream",
                    "tier": "10mb",
                    "size_bytes": 1024,
                }
            ),
            "headers": {"x-payment": "signed-payment"},
        }
        uploads_table = mock.Mock()

        with (
            mock.patch.object(
                app,
                "_payment_requirements",
                return_value={
                    "accepts": [
                        {
                            "scheme": "exact",
                            "network": "eip155:8453",
                            "asset": "0x" + ("a" * 40),
                            "payTo": "0x" + ("b" * 40),
                            "amount": "20000",
                            "maxTimeoutSeconds": 3600,
                            "extra": {"name": "USD Coin", "version": "2"},
                        }
                    ]
                },
            ),
            mock.patch.object(
                app,
                "_decode_payment_payload",
                return_value={
                    "x402Version": 2,
                    "payload": {
                        "authorization": {
                            "from": "0x" + ("1" * 40),
                            "to": "0x" + ("b" * 40),
                            "value": "20000",
                            "validAfter": "1716150000",
                            "validBefore": "2716150000",
                            "nonce": "0x" + ("1" * 64),
                        },
                        "signature": "0x" + ("2" * 130),
                    },
                },
            ),
            mock.patch.object(app, "_verify_payment_locally", return_value=None),
            mock.patch.object(app.s3, "head_bucket", return_value={}),
            mock.patch.object(app, "_ensure_bucket_lifecycle_expiration", return_value=None),
            mock.patch.object(app.s3, "generate_presigned_url", return_value="https://example.com/upload") as presign_mock,
            mock.patch.object(app, "_uploads_table", return_value=uploads_table),
            mock.patch.object(app, "_payment_config", return_value={"payment_network": "base-sepolia"}),
            mock.patch.object(app, "_sign_bearer", return_value="bearer"),
            mock.patch.object(app.secrets, "token_urlsafe", side_effect=["upload123", "completion123"]),
        ):
            response = app._handle_post_upload(event)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(presign_mock.call_args.kwargs["Params"]["Key"], "upload123/artifact.bin")
        self.assertEqual(uploads_table.put_item.call_args.kwargs["Item"]["object_key"], "upload123/artifact.bin")
        self.assertEqual(uploads_table.put_item.call_args.kwargs["Item"]["filename"], "artifact.bin")


class CdpPostHeaderTests(unittest.TestCase):
    def test_cdp_post_uses_urllib_content_type_key_to_prevent_duplicate_header(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"{}"

        def fake_urlopen(req, timeout):
            self.assertEqual(timeout, 10)
            content_type_headers = [(k, v) for (k, v) in req.header_items() if k.lower() == "content-type"]
            self.assertEqual(content_type_headers, [("Content-type", "application/json")])
            self.assertIn(("Authorization", "Bearer jwt"), req.header_items())
            return FakeResponse()

        with (
            mock.patch.object(
                app,
                "_cdp_facilitator_bearer_token",
                return_value="Bearer jwt",
            ),
            mock.patch.object(app.urllib_request, "urlopen", side_effect=fake_urlopen),
        ):
            response = app._cdp_post("/x402/facilitator/test", {"ok": True})

        self.assertEqual(response, {})
