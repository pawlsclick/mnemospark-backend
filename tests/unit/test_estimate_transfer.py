import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "estimate-transfer" / "app.py"
    module_spec = importlib.util.spec_from_file_location("estimate_transfer_app", module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load estimate transfer module")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakePricingClient:
    def __init__(self, status_sequence):
        self.status_sequence = list(status_sequence)
        self.batch_create_workload_estimate_usage_calls = []
        self.create_workload_estimate_calls = []
        self.delete_workload_estimate_calls = []
        self.get_workload_estimate_calls = []

    def create_workload_estimate(self, **kwargs):
        self.create_workload_estimate_calls.append(kwargs)
        return {"id": "workload-transfer-123"}

    def batch_create_workload_estimate_usage(self, **kwargs):
        self.batch_create_workload_estimate_usage_calls.append(kwargs)
        return {}

    def get_workload_estimate(self, **kwargs):
        self.get_workload_estimate_calls.append(kwargs)
        if self.status_sequence:
            result = self.status_sequence.pop(0)
        else:
            result = {"status": "PENDING"}
        return result

    def delete_workload_estimate(self, **kwargs):
        self.delete_workload_estimate_calls.append(kwargs)
        return {}


class FakeStsClient:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class ParseInputTests(unittest.TestCase):
    def test_parse_input_with_query_params(self):
        event = {
            "queryStringParameters": {
                "direction": "out",
                "gb": "100",
                "region": "eu-west-1",
                "rateType": "after_discounts",
            }
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed["direction"], "out")
        self.assertEqual(parsed["gb"], 100.0)
        self.assertEqual(parsed["region"], "eu-west-1")
        self.assertEqual(parsed["rateType"], "AFTER_DISCOUNTS")

    def test_parse_input_uses_json_body(self):
        event = {
            "queryStringParameters": {"direction": "in", "gb": "100"},
            "body": json.dumps({"direction": "out", "gb": 55, "region": "us-west-2", "rateType": "BEFORE_DISCOUNTS"}),
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed["direction"], "out")
        self.assertEqual(parsed["gb"], 55.0)
        self.assertEqual(parsed["region"], "us-west-2")
        self.assertEqual(parsed["rateType"], "BEFORE_DISCOUNTS")

    def test_parse_input_decodes_base64_json_body(self):
        raw_body = json.dumps({"direction": "out", "gb": 2})
        event = {
            "queryStringParameters": {},
            "body": base64.b64encode(raw_body.encode("utf-8")).decode("ascii"),
            "isBase64Encoded": True,
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed["direction"], "out")
        self.assertEqual(parsed["gb"], 2.0)
        self.assertEqual(parsed["region"], "[REDACTED]")
        self.assertEqual(parsed["rateType"], "BEFORE_DISCOUNTS")

    def test_parse_input_applies_defaults(self):
        parsed = app.parse_input({"queryStringParameters": {}})

        self.assertEqual(parsed["direction"], "in")
        self.assertEqual(parsed["gb"], 100.0)
        self.assertEqual(parsed["region"], "[REDACTED]")
        self.assertEqual(parsed["rateType"], "BEFORE_DISCOUNTS")

    def test_parse_input_rejects_invalid_direction(self):
        event = {"queryStringParameters": {"direction": "sideways"}}
        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)

    def test_parse_input_rejects_invalid_gb(self):
        event = {"queryStringParameters": {"gb": "not-a-number"}}
        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)

    def test_parse_input_rejects_invalid_rate_type(self):
        event = {"queryStringParameters": {"rateType": "bad-rate"}}
        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)

    def test_parse_input_rejects_invalid_json_body(self):
        event = {"queryStringParameters": {"gb": "1"}, "body": "{invalid"}
        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)


class EstimateCostTests(unittest.TestCase):
    def test_estimate_data_transfer_cost_success_uses_egress_usage_type(self):
        fake_pricing = FakePricingClient(
            status_sequence=[
                {"status": "IN_PROGRESS"},
                {"status": "VALID", "totalCost": "3.99", "costCurrency": "USD"},
            ]
        )
        fake_sts = FakeStsClient()

        result = app.estimate_data_transfer_cost(
            data_gb=100,
            direction="out",
            region="[REDACTED]",
            rate_type="BEFORE_DISCOUNTS",
            pricing_client=fake_pricing,
            sts_client=fake_sts,
            poll_interval_seconds=0,
            max_poll_attempts=3,
        )

        self.assertEqual(result["status"], "VALID")
        self.assertEqual(result["costCurrency"], "USD")
        self.assertEqual(len(fake_pricing.create_workload_estimate_calls), 1)
        self.assertEqual(len(fake_pricing.batch_create_workload_estimate_usage_calls), 1)
        self.assertEqual(len(fake_pricing.delete_workload_estimate_calls), 1)
        usage_record = fake_pricing.batch_create_workload_estimate_usage_calls[0]["usage"][0]
        self.assertEqual(usage_record["serviceCode"], "AmazonEC2")
        self.assertEqual(usage_record["usageType"], "USE1-DataTransfer-Out-Bytes")
        self.assertEqual(usage_record["amount"], 100.0)

    def test_estimate_data_transfer_cost_invalid_estimate_raises(self):
        fake_pricing = FakePricingClient(
            status_sequence=[
                {"status": "INVALID", "failureMessage": "invalid usage"},
            ]
        )
        fake_sts = FakeStsClient()

        with self.assertRaises(RuntimeError):
            app.estimate_data_transfer_cost(
                data_gb=2,
                direction="in",
                pricing_client=fake_pricing,
                sts_client=fake_sts,
                poll_interval_seconds=0,
                max_poll_attempts=1,
            )

        self.assertEqual(len(fake_pricing.delete_workload_estimate_calls), 1)


class UsageTypeTests(unittest.TestCase):
    def test_build_usage_type_in_uses_regional_suffix(self):
        usage_type = app._build_usage_type(direction="in", region="eu-west-1")
        self.assertEqual(usage_type, "EUW1-DataTransfer-Regional-Bytes")

    def test_build_usage_type_unknown_region_falls_back_to_default(self):
        usage_type = app._build_usage_type(direction="out", region="not-real-1")
        self.assertEqual(usage_type, "USE1-DataTransfer-Out-Bytes")


class LambdaHandlerTests(unittest.TestCase):
    def test_lambda_handler_success(self):
        event = {
            "queryStringParameters": {
                "direction": "out",
                "gb": "10",
                "region": "[REDACTED]",
                "rateType": "BEFORE_DISCOUNTS",
            }
        }
        estimate_payload = {"totalCost": "1.11", "costCurrency": "USD"}

        with mock.patch.object(app, "estimate_data_transfer_cost", return_value=estimate_payload):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["estimatedCost"], 1.11)
        self.assertEqual(body["currency"], "USD")
        self.assertEqual(body["dataGb"], 10.0)
        self.assertEqual(body["direction"], "out")
        self.assertEqual(body["region"], "[REDACTED]")
        self.assertEqual(body["rateType"], "BEFORE_DISCOUNTS")

    def test_lambda_handler_bad_request(self):
        response = app.lambda_handler({"queryStringParameters": {"direction": "sideways"}}, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")

    def test_lambda_handler_internal_error(self):
        event = {"queryStringParameters": {"gb": "1"}}
        with mock.patch.object(app, "estimate_data_transfer_cost", side_effect=RuntimeError("boom")):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 500)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Internal error")
