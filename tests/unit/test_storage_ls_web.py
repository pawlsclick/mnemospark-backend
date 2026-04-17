import importlib.util
import json
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


class StorageLsWebExchangeTests(unittest.TestCase):
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
