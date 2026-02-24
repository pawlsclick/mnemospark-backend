"""Unit tests for parse_input functions across all Lambda handlers."""

import importlib.util
import json
import os

def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

ROOT = os.path.join(os.path.dirname(__file__), "..")
s3_app = _load_module("s3_app", os.path.join(ROOT, "examples", "s3-cost-estimate-api", "app.py"))
dt_app = _load_module("dt_app", os.path.join(ROOT, "examples", "data-transfer-cost-estimate-api", "app.py"))


class TestS3CostEstimateParseInput:
    def test_defaults(self):
        result = s3_app.parse_input({})
        assert result["gb"] == 100
        assert result["region"] == "us-east-1"
        assert result["rate_type"] == "BEFORE_DISCOUNTS"

    def test_query_params(self):
        event = {"queryStringParameters": {"gb": "50", "region": "eu-north-1", "rate_type": "AFTER_DISCOUNTS"}}
        result = s3_app.parse_input(event)
        assert result["gb"] == 50.0
        assert result["region"] == "eu-north-1"
        assert result["rate_type"] == "AFTER_DISCOUNTS"

    def test_post_body(self):
        event = {"body": json.dumps({"gb": 200, "region": "us-west-2", "rateType": "AFTER_DISCOUNTS"})}
        result = s3_app.parse_input(event)
        assert result["gb"] == 200.0
        assert result["region"] == "us-west-2"
        assert result["rate_type"] == "AFTER_DISCOUNTS"

    def test_invalid_rate_type_defaults(self):
        event = {"queryStringParameters": {"rate_type": "INVALID"}}
        result = s3_app.parse_input(event)
        assert result["rate_type"] == "BEFORE_DISCOUNTS"

    def test_response_format(self):
        resp = s3_app.response(200, {"key": "value"})
        assert resp["statusCode"] == 200
        assert resp["headers"]["Content-Type"] == "application/json"
        assert resp["headers"]["Access-Control-Allow-Origin"] == "*"
        assert json.loads(resp["body"]) == {"key": "value"}


class TestDataTransferParseInput:
    def test_defaults(self):
        result = dt_app.parse_input({})
        assert result["direction"] == "in"
        assert result["gb"] == 100
        assert result["region"] == "us-east-1"
        assert result["rate_type"] == "BEFORE_DISCOUNTS"

    def test_direction_out(self):
        event = {"queryStringParameters": {"direction": "out", "gb": "500"}}
        result = dt_app.parse_input(event)
        assert result["direction"] == "out"
        assert result["gb"] == 500.0

    def test_invalid_direction_defaults(self):
        event = {"queryStringParameters": {"direction": "sideways"}}
        result = dt_app.parse_input(event)
        assert result["direction"] == "in"

    def test_region_codes(self):
        assert dt_app.REGION_CODES["us-east-1"] == "USE1"
        assert dt_app.REGION_CODES["eu-north-1"] == "EUN1"
