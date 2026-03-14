import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


def load_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "common" / "api_call_logger.py"
    module_name = "api_call_logger_unit"
    module_spec = importlib.util.spec_from_file_location(module_name, module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load api_call_logger module")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


api_call_logger = load_module()


class ApiCallLoggerTests(unittest.TestCase):
    def _event(self):
        return {
            "httpMethod": "POST",
            "path": "/storage/upload",
            "body": json.dumps(
                {
                    "quote_id": "quote-123",
                    "object_id": "backup.enc",
                }
            ),
            "requestContext": {
                "requestId": "api-gw-request-1",
                "authorizer": {
                    "walletAddress": "0x1111111111111111111111111111111111111111",
                },
            },
        }

    def test_log_api_call_writes_dynamodb_item_when_table_configured(self):
        ddb_client = mock.Mock()

        with (
            mock.patch.object(api_call_logger, "_dynamodb_client", return_value=ddb_client),
            mock.patch.dict(
                os.environ,
                {"API_CALLS_TABLE_NAME": "api-calls-table", "API_CALLS_TTL_SECONDS": "3600"},
                clear=False,
            ),
        ):
            api_call_logger.log_api_call(
                event=self._event(),
                context=None,
                route="/storage/upload",
                status_code=200,
                result="success",
                trans_id="0xabc123",
            )

        ddb_client.put_item.assert_called_once()
        kwargs = ddb_client.put_item.call_args.kwargs
        self.assertEqual(kwargs["TableName"], "api-calls-table")
        item = kwargs["Item"]
        self.assertEqual(item["request_id"]["S"], "api-gw-request-1")
        self.assertEqual(item["method"]["S"], "POST")
        self.assertEqual(item["path"]["S"], "/storage/upload")
        self.assertEqual(item["status_code"]["N"], "200")
        self.assertEqual(item["result"]["S"], "success")
        self.assertEqual(item["wallet_address"]["S"], "0x1111111111111111111111111111111111111111")
        self.assertEqual(item["quote_id"]["S"], "quote-123")
        self.assertEqual(item["trans_id"]["S"], "0xabc123")
        self.assertIn("expires_at", item)

    def test_log_api_call_swallows_dynamodb_failures(self):
        failing_ddb_client = mock.Mock()
        failing_ddb_client.put_item.side_effect = RuntimeError("ddb down")

        with (
            mock.patch.object(api_call_logger, "_dynamodb_client", return_value=failing_ddb_client),
            mock.patch.dict(
                os.environ,
                {"API_CALLS_TABLE_NAME": "api-calls-table"},
                clear=False,
            ),
        ):
            api_call_logger.log_api_call(
                event=self._event(),
                context=None,
                route="/storage/upload",
                status_code=500,
                result="internal_error",
                error_code="internal_error",
                error_message="boom",
            )

        failing_ddb_client.put_item.assert_called_once()
