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
