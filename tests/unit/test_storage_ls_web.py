import importlib.util
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "storage-ls-web" / "app.py"
    module_spec = importlib.util.spec_from_file_location("storage_ls_web_app", module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load storage ls web module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeTable:
    def __init__(self):
        self.by_sid: dict = {}
        self.put_calls: list = []
        self.query_calls: list = []
        self.updates: list = []

    def put_item(self, **kwargs):
        self.put_calls.append(kwargs)
        item = kwargs["Item"]
        self.by_sid[item["session_id"]] = dict(item)

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        kce = kwargs["KeyConditionExpression"]
        vals = getattr(kce, "_values", ())
        wanted = vals[1] if len(vals) > 1 else None
        for row in self.by_sid.values():
            if row.get("exchange_code_hash") == wanted:
                return {"Items": [dict(row)]}
        return {"Items": []}

    def get_item(self, Key):
        sid = Key["session_id"]
        row = self.by_sid.get(sid)
        return {"Item": dict(row)} if row else {}

    def update_item(self, **kwargs):
        self.updates.append(kwargs)
        sid = kwargs["Key"]["session_id"]
        row = self.by_sid.get(sid)
        if not row:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}},
                "UpdateItem",
            )
        expr = kwargs.get("ConditionExpression", "")
        if "exchanged = :f" in expr and row.get("exchanged"):
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}},
                "UpdateItem",
            )
        if row.get("exchange_code_hash") != kwargs["ExpressionAttributeValues"][":h"]:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}},
                "UpdateItem",
            )
        if row.get("session_expires_at", 0) <= kwargs["ExpressionAttributeValues"][":now"]:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}},
                "UpdateItem",
            )
        row["exchanged"] = True
        row.pop("exchange_code_hash", None)


class StorageLsWebMintTests(unittest.TestCase):
    def setUp(self):
        self.wallet = "0x" + ("a" * 40)

    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_mint_returns_code_and_app_url(self, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/session",
            "requestContext": {
                "resourcePath": "/storage/ls-web/session",
                "authorizer": {"walletAddress": self.wallet},
            },
            "body": json.dumps({"location": "us-east-1"}),
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertIn("code", body)
        self.assertIn("app.mnemospark.ai", body["app"])
        self.assertIn("expires_at", body)
        self.assertEqual(len(fake.put_calls), 1)
        stored = fake.by_sid[list(fake.by_sid.keys())[0]]
        self.assertEqual(stored["wallet_address"], self.wallet.lower())
        self.assertEqual(stored["location"], "us-east-1")

    @mock.patch.dict(
        os.environ,
        {"MNEMOSPARK_LS_WEB_APP_PREFIX_QUERY": "api=staging"},
        clear=False,
    )
    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_mint_app_url_includes_prefix_query_before_code(self, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/session",
            "requestContext": {
                "resourcePath": "/storage/ls-web/session",
                "authorizer": {"walletAddress": self.wallet},
            },
            "body": json.dumps({"location": "us-east-1"}),
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertIn("app.mnemospark.ai", body["app"])
        self.assertIn("api=staging", body["app"])
        self.assertRegex(body["app"], r"[?&]api=staging&code=")


class StorageLsWebExchangeTests(unittest.TestCase):
    @mock.patch.dict(
        os.environ,
        {"LS_WEB_COOKIE_DOMAIN": "host-only", "LS_WEB_COOKIE_SAMESITE": "None"},
        clear=False,
    )
    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_exchange_set_cookie_host_only_and_samesite_none(self, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        code = "staging-cookie-code"
        code_hash = app._hash_exchange_code(code)
        sid = "sess-cookie"
        fake.by_sid[sid] = {
            "session_id": sid,
            "wallet_address": "0x" + "e" * 40,
            "exchange_code_hash": code_hash,
            "exchanged": False,
            "session_expires_at": int(time.time()) + 3600,
            "location": "us-east-1",
        }
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/exchange",
            "requestContext": {"resourcePath": "/storage/ls-web/exchange"},
            "body": json.dumps({"code": code}),
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        set_cookie = resp["headers"].get("Set-Cookie") or resp["headers"].get("set-cookie") or ""
        self.assertIn("SameSite=None", set_cookie)
        self.assertNotIn("Domain=", set_cookie)
        self.assertIn("Secure", set_cookie)

    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "_log_api_call_result")
    def test_exchange_invalid_code_logs_audit(self, mock_log, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/exchange",
            "requestContext": {"resourcePath": "/storage/ls-web/exchange"},
            "body": json.dumps({"code": "unknown-code"}),
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 401)
        mock_log.assert_called()
        kwargs = mock_log.call_args.kwargs
        self.assertEqual(kwargs.get("status_code"), 401)
        self.assertEqual(kwargs.get("result"), "unauthorized")
        self.assertEqual(kwargs.get("error_code"), "invalid_or_expired_code")

    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_exchange_replay_rejected(self, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        code = "test-code-value"
        code_hash = app._hash_exchange_code(code)
        sid = "sess1"
        fake.by_sid[sid] = {
            "session_id": sid,
            "wallet_address": "0x" + "b" * 40,
            "exchange_code_hash": code_hash,
            "exchanged": False,
            "session_expires_at": int(time.time()) + 3600,
            "location": "us-east-1",
        }
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/exchange",
            "requestContext": {"resourcePath": "/storage/ls-web/exchange"},
            "body": json.dumps({"code": code}),
        }
        r1 = app.lambda_handler(event, None)
        self.assertEqual(r1["statusCode"], 200)
        r2 = app.lambda_handler(event, None)
        self.assertEqual(r2["statusCode"], 401)


class StorageLsWebDownloadTests(unittest.TestCase):
    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_download_cap_26_keys(self, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        sid = "sidcap"
        fake.by_sid[sid] = {
            "session_id": sid,
            "wallet_address": "0x" + "c" * 40,
            "exchanged": True,
            "session_expires_at": int(time.time()) + 3600,
            "location": "us-east-1",
        }
        keys = [f"k{i}" for i in range(26)]
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/download",
            "requestContext": {"resourcePath": "/storage/ls-web/download"},
            "headers": {"Cookie": f"{app.COOKIE_NAME}={sid}"},
            "body": json.dumps({"object_keys": keys}),
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)

    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "boto3")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_download_lite_allows_upload_id_filename_object_key(self, mock_boto, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        sid = "sidlite"
        fake.by_sid[sid] = {
            "session_id": sid,
            "wallet_address": "0x" + "f" * 40,
            "exchanged": True,
            "session_expires_at": int(time.time()) + 3600,
            "location": "[REDACTED]",
            "bucket_mode": "lite",
        }

        class FakeS3:
            def __init__(self):
                self.head_object_keys = []

            def head_bucket(self, **kwargs):
                return {}

            def head_object(self, **kwargs):
                self.head_object_keys.append(kwargs["Key"])
                return {}

            def generate_presigned_url(self, _operation, *, Params, ExpiresIn, HttpMethod):
                return f"https://example.invalid/{Params['Bucket']}/{Params['Key']}?exp={ExpiresIn}&m={HttpMethod}"

        fake_s3 = FakeS3()
        mock_boto.client.return_value = fake_s3
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/download",
            "requestContext": {"resourcePath": "/storage/ls-web/download"},
            "headers": {"Cookie": f"{app.COOKIE_NAME}={sid}"},
            "body": json.dumps({"object_keys": ["upload123/artifact.bin"]}),
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertEqual(body["results"][0]["object_key"], "upload123/artifact.bin")
        self.assertIn("upload123/artifact.bin", body["results"][0]["url"])
        self.assertEqual(fake_s3.head_object_keys, ["upload123/artifact.bin"])


class StorageLsWebListSessionTests(unittest.TestCase):
    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "boto3")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_list_requires_exchanged_session(self, mock_boto, mock_table_factory):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        sid = "sid1"
        fake.by_sid[sid] = {
            "session_id": sid,
            "wallet_address": "0x" + "d" * 40,
            "exchanged": False,
            "session_expires_at": int(time.time()) + 3600,
            "location": "us-east-1",
        }
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/list",
            "requestContext": {"resourcePath": "/storage/ls-web/list"},
            "headers": {"Cookie": f"{app.COOKIE_NAME}={sid}"},
            "body": "{}",
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 401)

    @mock.patch.object(app, "_lite_uploads_table")
    @mock.patch.object(app, "_session_table")
    @mock.patch.object(app, "boto3")
    @mock.patch.object(app, "_log_api_call_result", lambda *a, **k: None)
    def test_list_lite_enriches_objects_using_full_object_key(
        self,
        mock_boto,
        mock_table_factory,
        mock_lite_uploads_table,
    ):
        fake = FakeTable()
        mock_table_factory.return_value = fake
        sid = "sid-lite-list"
        fake.by_sid[sid] = {
            "session_id": sid,
            "wallet_address": "0x" + "1" * 40,
            "exchanged": True,
            "session_expires_at": int(time.time()) + 3600,
            "location": "[REDACTED]",
            "bucket_mode": "lite",
        }

        class FakeUploadsTable:
            def query(self, **kwargs):
                return {
                    "Items": [
                        {
                            "upload_id": "upload123",
                            "filename": "artifact.bin",
                            "object_key": "upload123/artifact.bin",
                            "content_type": "application/octet-stream",
                            "tier": "standard",
                            "max_size": 1024,
                            "actual_size": 99,
                            "status": "complete",
                        }
                    ]
                }

        class FakeS3:
            def head_bucket(self, **kwargs):
                return {}

            def list_objects_v2(self, **kwargs):
                return {
                    "Contents": [{"Key": "upload123/artifact.bin", "Size": 99}],
                    "IsTruncated": False,
                }

        mock_lite_uploads_table.return_value = FakeUploadsTable()
        mock_boto.client.return_value = FakeS3()
        event = {
            "httpMethod": "POST",
            "path": "/storage/ls-web/list",
            "requestContext": {"resourcePath": "/storage/ls-web/list"},
            "headers": {"Cookie": f"{app.COOKIE_NAME}={sid}"},
            "body": "{}",
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertEqual(body["objects"][0]["key"], "upload123/artifact.bin")
        self.assertEqual(body["objects"][0]["id"], "upload123")
        self.assertEqual(body["objects"][0]["filename"], "artifact.bin")


class StorageLsWebOptionsTests(unittest.TestCase):
    def test_options_returns_cors(self):
        event = {
            "httpMethod": "OPTIONS",
            "path": "/storage/ls-web/exchange",
            "requestContext": {"resourcePath": "/storage/ls-web/exchange"},
        }
        resp = app.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 204)
        self.assertEqual(resp["headers"].get("Access-Control-Allow-Credentials"), "true")
