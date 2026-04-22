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
    def test_complete_does_not_mint_session_when_conditional_update_fails(self):
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
        mint_mock.assert_not_called()
        table.update_item.assert_called_once()

    def test_complete_mints_session_after_status_update_gate(self):
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
        }
        event = {"body": json.dumps({"uploadId": upload_id, "completion_token": token})}

        calls = []

        def update_side_effect(*args, **kwargs):
            calls.append("update")
            return {}

        def mint_side_effect(*args, **kwargs):
            calls.append("mint")
            return {"app": "https://app.mnemospark.ai/?code=abc", "code": "abc", "expires_at": "2030-01-01T00:00:00Z"}

        table = mock.Mock()
        table.get_item.return_value = {"Item": item}
        table.update_item.side_effect = update_side_effect

        with (
            mock.patch.object(app, "_uploads_table", return_value=table),
            mock.patch.object(app.s3, "head_object", return_value={"ContentLength": 100}),
            mock.patch.object(app, "_mint_ls_web_app_url", side_effect=mint_side_effect),
        ):
            response = app._handle_post_complete(event)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(calls, ["update", "mint", "update"])


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
