import importlib.util
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "price-storage" / "app.py"
    module_spec = importlib.util.spec_from_file_location("price_storage_app", module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load price storage module")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class FakeDynamoDbClient:
    def __init__(self):
        self.put_item_calls = []

    def put_item(self, **kwargs):
        self.put_item_calls.append(kwargs)
        return {}


class FakePricingClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get_products(self, **kwargs):
        self.calls.append(kwargs)
        if not self.responses:
            return {"PriceList": []}
        return self.responses.pop(0)


class PricingHelpersTests(unittest.TestCase):
    @staticmethod
    def _price_list_entry(
        *,
        product_family,
        usagetype,
        unit=None,
        usd=None,
        region="[REDACTED]",
        volume_type="Standard",
        transfer_type="AWS Outbound",
        location_type="AWS Region",
        price_dimensions=None,
    ):
        if price_dimensions is None:
            price_dimensions = [
                {
                    "unit": unit,
                    "pricePerUnit": {"USD": str(usd)},
                    "beginRange": "0",
                    "endRange": "Inf",
                }
            ]
        return json.dumps(
            {
                "product": {
                    "productFamily": product_family,
                    "attributes": {
                        "regionCode": region,
                        "locationType": location_type,
                        "usagetype": usagetype,
                        "volumeType": volume_type,
                        "transferType": transfer_type,
                    }
                },
                "terms": {
                    "OnDemand": {
                        "ondemand.1": {
                            "priceDimensions": {
                                f"dim.{index + 1}": dimension for index, dimension in enumerate(price_dimensions)
                            }
                        }
                    }
                },
            }
        )

    def test_get_s3_storage_price_per_gb_month_uses_lowest_positive_ondemand_rate(self):
        client = FakePricingClient(
            responses=[
                {
                    "PriceList": [
                        self._price_list_entry(
                            product_family="Storage",
                            usagetype="USE1-TimedStorage-ByteHrs",
                            unit="GB-Mo",
                            usd="0.023",
                        ),
                        self._price_list_entry(
                            product_family="Storage",
                            usagetype="USE1-TimedStorage-ByteHrs",
                            unit="GB-Mo",
                            usd="0.021",
                        ),
                    ]
                }
            ]
        )

        price = app.get_s3_storage_price_per_gb_month(region="[REDACTED]", client=client)

        self.assertEqual(price, 0.021)
        self.assertEqual(client.calls[0]["ServiceCode"], "AmazonS3")

    def test_get_data_transfer_out_price_per_gb_uses_matching_usage_type(self):
        client = FakePricingClient(
            responses=[
                {
                    "PriceList": [
                        self._price_list_entry(
                            product_family="Data Transfer",
                            usagetype="USE1-DataTransfer-Regional-Bytes",
                            unit="GB",
                            usd="0.01",
                        ),
                        self._price_list_entry(
                            product_family="Data Transfer",
                            usagetype="USE1-DataTransfer-Out-Bytes",
                            unit="GB",
                            usd="0.09",
                        ),
                    ]
                }
            ]
        )

        price = app.get_data_transfer_out_price_per_gb(region="[REDACTED]", client=client)

        self.assertEqual(price, 0.09)
        self.assertEqual(client.calls[0]["ServiceCode"], "AmazonS3")

    def test_get_data_transfer_in_price_per_gb_returns_zero_without_lookup(self):
        client = FakePricingClient(responses=[])

        price = app.get_data_transfer_out_price_per_gb(region="[REDACTED]", client=client, direction="in")

        self.assertEqual(price, 0.0)
        self.assertEqual(client.calls, [])

    def test_get_s3_storage_price_per_gb_month_selects_tier_for_usage(self):
        client = FakePricingClient(
            responses=[
                {
                    "PriceList": [
                        self._price_list_entry(
                            product_family="Storage",
                            usagetype="USE1-TimedStorage-ByteHrs",
                            price_dimensions=[
                                {
                                    "unit": "GB-Mo",
                                    "pricePerUnit": {"USD": "0.023"},
                                    "beginRange": "0",
                                    "endRange": "50",
                                },
                                {
                                    "unit": "GB-Mo",
                                    "pricePerUnit": {"USD": "0.021"},
                                    "beginRange": "50",
                                    "endRange": "Inf",
                                },
                            ],
                        ),
                    ]
                }
            ]
        )

        price = app.get_s3_storage_price_per_gb_month(region="[REDACTED]", usage_gb=60, client=client)

        self.assertEqual(price, 0.021)

    def test_get_data_transfer_out_price_per_gb_selects_tier_for_usage(self):
        client = FakePricingClient(
            responses=[
                {
                    "PriceList": [
                        self._price_list_entry(
                            product_family="Data Transfer",
                            usagetype="USE1-DataTransfer-Out-Bytes",
                            transfer_type="AWS Outbound",
                            price_dimensions=[
                                {
                                    "unit": "GB",
                                    "pricePerUnit": {"USD": "0.090"},
                                    "beginRange": "0",
                                    "endRange": "10",
                                },
                                {
                                    "unit": "GB",
                                    "pricePerUnit": {"USD": "0.085"},
                                    "beginRange": "10",
                                    "endRange": "Inf",
                                },
                            ],
                        )
                    ]
                }
            ]
        )

        price = app.get_data_transfer_out_price_per_gb(region="[REDACTED]", usage_gb=25, client=client)

        self.assertEqual(price, 0.085)

    def test_get_s3_storage_price_per_gb_month_raises_when_no_matching_sku(self):
        client = FakePricingClient(
            responses=[
                {
                    "PriceList": [
                        self._price_list_entry(
                            product_family="Storage",
                            usagetype="USE1-TimedStorage-ByteHrs",
                            unit="GB-Mo",
                            usd="0.023",
                            volume_type="Standard - Infrequent Access",
                        ),
                    ]
                }
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "No S3 Standard storage SKU found"):
            app.get_s3_storage_price_per_gb_month(region="[REDACTED]", client=client)

    def test_estimate_storage_cost_applies_cumulative_tiers(self):
        client = FakePricingClient(
            responses=[
                {
                    "PriceList": [
                        self._price_list_entry(
                            product_family="Storage",
                            usagetype="USE1-TimedStorage-ByteHrs",
                            price_dimensions=[
                                {
                                    "unit": "GB-Mo",
                                    "pricePerUnit": {"USD": "0.023"},
                                    "beginRange": "0",
                                    "endRange": "50",
                                },
                                {
                                    "unit": "GB-Mo",
                                    "pricePerUnit": {"USD": "0.022"},
                                    "beginRange": "50",
                                    "endRange": "Inf",
                                },
                            ],
                        )
                    ]
                }
            ]
        )

        with mock.patch.object(app, "get_pricing_client", return_value=client):
            cost = app.estimate_storage_cost(gb=100, region="[REDACTED]", rate_type="BEFORE_DISCOUNTS")

        self.assertEqual(cost, 2.25)

    def test_estimate_transfer_cost_applies_cumulative_tiers(self):
        client = FakePricingClient(
            responses=[
                {
                    "PriceList": [
                        self._price_list_entry(
                            product_family="Data Transfer",
                            usagetype="USE1-DataTransfer-Out-Bytes",
                            transfer_type="AWS Outbound",
                            price_dimensions=[
                                {
                                    "unit": "GB",
                                    "pricePerUnit": {"USD": "0.090"},
                                    "beginRange": "0",
                                    "endRange": "10",
                                },
                                {
                                    "unit": "GB",
                                    "pricePerUnit": {"USD": "0.085"},
                                    "beginRange": "10",
                                    "endRange": "Inf",
                                },
                            ],
                        )
                    ]
                }
            ]
        )

        with mock.patch.object(app, "get_pricing_client", return_value=client):
            cost = app.estimate_transfer_cost(
                gb=25,
                region="[REDACTED]",
                direction="out",
                rate_type="BEFORE_DISCOUNTS",
            )

        self.assertEqual(cost, 2.175)

    def test_estimate_transfer_cost_direction_in_returns_zero(self):
        with mock.patch.object(app, "get_pricing_client") as get_pricing_client_mock:
            cost = app.estimate_transfer_cost(
                gb=25,
                region="[REDACTED]",
                direction="in",
                rate_type="BEFORE_DISCOUNTS",
            )

        self.assertEqual(cost, 0.0)
        get_pricing_client_mock.assert_not_called()


class ParseInputTests(unittest.TestCase):
    def test_parse_input_happy_path(self):
        event = {
            "body": json.dumps(
                {
                    "wallet_address": "0xabc123",
                    "object_id": "backup.tar.gz",
                    "object_id_hash": "abc123hash",
                    "gb": 5,
                    "provider": "aws",
                    "region": "[REDACTED]",
                }
            )
        }

        parsed = app.parse_input(event)

        self.assertEqual(parsed["wallet_address"], "0xabc123")
        self.assertEqual(parsed["object_id"], "backup.tar.gz")
        self.assertEqual(parsed["object_id_hash"], "abc123hash")
        self.assertEqual(parsed["gb"], 5.0)
        self.assertEqual(parsed["provider"], "aws")
        self.assertEqual(parsed["region"], "[REDACTED]")

    def test_parse_input_rejects_missing_required_field(self):
        event = {"body": json.dumps({"object_id": "backup.tar.gz"})}

        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)

    def test_parse_input_rejects_invalid_provider(self):
        event = {
            "body": json.dumps(
                {
                    "wallet_address": "0xabc123",
                    "object_id": "backup.tar.gz",
                    "object_id_hash": "abc123hash",
                    "gb": 5,
                    "provider": "gcp",
                    "region": "[REDACTED]",
                }
            )
        }

        with self.assertRaises(app.BadRequestError):
            app.parse_input(event)


class MarkupConfigTests(unittest.TestCase):
    def test_markup_accepts_percent_string(self):
        with mock.patch.dict(os.environ, {"PRICE_STORAGE_MARKUP_PERCENT": "15"}, clear=False):
            markup = app._get_markup_multiplier()
        self.assertEqual(markup, 0.15)

    def test_markup_accepts_fraction_string(self):
        with mock.patch.dict(os.environ, {"PRICE_STORAGE_MARKUP_PERCENT": "0.2"}, clear=False):
            markup = app._get_markup_multiplier()
        self.assertEqual(markup, 0.2)


class QuoteWriteTests(unittest.TestCase):
    def test_write_quote_persists_expected_item_and_ttl(self):
        fake_dynamodb = FakeDynamoDbClient()
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        quote = {
            "timestamp": "2026-01-01 12:00:00",
            "quote_id": "quote-123",
            "storage_price": 3.45,
            "addr": "0xabc123",
            "object_id": "backup.tar.gz",
            "object_id_hash": "hash-value",
            "object_size_gb": 5.0,
            "provider": "aws",
            "location": "[REDACTED]",
        }

        app.write_quote(
            quote=quote,
            storage_cost=2.0,
            transfer_cost=1.0,
            markup_multiplier=0.15,
            dynamodb_client=fake_dynamodb,
            table_name="quotes-table",
            ttl_seconds=3600,
            now=now,
        )

        self.assertEqual(len(fake_dynamodb.put_item_calls), 1)
        put_item_call = fake_dynamodb.put_item_calls[0]
        self.assertEqual(put_item_call["TableName"], "quotes-table")
        self.assertEqual(put_item_call["Item"]["quote_id"]["S"], "quote-123")
        self.assertEqual(put_item_call["Item"]["storage_price"]["N"], "3.45")
        self.assertEqual(put_item_call["Item"]["provider"]["S"], "aws")
        self.assertEqual(put_item_call["Item"]["expires_at"]["N"], str(int(now.timestamp()) + 3600))


class LambdaHandlerTests(unittest.TestCase):
    def _valid_event(self):
        return {
            "body": json.dumps(
                {
                    "wallet_address": "0xabc123",
                    "object_id": "backup.tar.gz",
                    "object_id_hash": "hash-value",
                    "gb": 5,
                    "provider": "aws",
                    "region": "[REDACTED]",
                }
            )
        }

    def test_lambda_handler_success(self):
        event = self._valid_event()

        with (
            mock.patch.object(app, "estimate_storage_cost", return_value=2.0),
            mock.patch.object(app, "estimate_transfer_cost", return_value=1.0),
            mock.patch.object(app, "write_quote") as write_quote_mock,
            mock.patch.dict(
                os.environ,
                {
                    "PRICE_STORAGE_MARKUP_PERCENT": "10",
                    "PRICE_STORAGE_TRANSFER_DIRECTION": "out",
                    "PRICE_STORAGE_RATE_TYPE": "BEFORE_DISCOUNTS",
                },
                clear=False,
            ),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["storage_price"], 3.3)
        self.assertEqual(body["addr"], "0xabc123")
        self.assertEqual(body["object_id"], "backup.tar.gz")
        self.assertEqual(body["provider"], "aws")
        self.assertEqual(body["location"], "[REDACTED]")
        self.assertIn("quote_id", body)
        self.assertIn("timestamp", body)
        write_quote_mock.assert_called_once()

    def test_lambda_handler_reads_authorizer_wallet_context(self):
        event = self._valid_event()
        event["requestContext"] = {
            "authorizer": {
                "walletAddress": "0xabc123",
            }
        }

        with (
            mock.patch.object(app, "estimate_storage_cost", return_value=2.0),
            mock.patch.object(app, "estimate_transfer_cost", return_value=1.0),
            mock.patch.object(app, "write_quote"),
            mock.patch("builtins.print") as print_mock,
            mock.patch.dict(
                os.environ,
                {
                    "PRICE_STORAGE_MARKUP_PERCENT": "10",
                    "PRICE_STORAGE_TRANSFER_DIRECTION": "out",
                    "PRICE_STORAGE_RATE_TYPE": "BEFORE_DISCOUNTS",
                },
                clear=False,
            ),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        print_mock.assert_called()

    def test_lambda_handler_returns_bad_request_shape(self):
        response = app.lambda_handler({"body": json.dumps({"wallet_address": "0xabc123"})}, None)

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Bad request")
        self.assertIn("message", body)

    def test_lambda_handler_returns_internal_error_shape_on_dynamodb_failure(self):
        event = self._valid_event()
        client_error = ClientError(
            error_response={
                "Error": {
                    "Code": "ProvisionedThroughputExceededException",
                    "Message": "throttled",
                }
            },
            operation_name="PutItem",
        )

        with (
            mock.patch.object(app, "estimate_storage_cost", return_value=2.0),
            mock.patch.object(app, "estimate_transfer_cost", return_value=1.0),
            mock.patch.object(app, "write_quote", side_effect=client_error),
            mock.patch.dict(
                os.environ,
                {
                    "PRICE_STORAGE_MARKUP_PERCENT": "10",
                    "PRICE_STORAGE_TRANSFER_DIRECTION": "out",
                    "PRICE_STORAGE_RATE_TYPE": "BEFORE_DISCOUNTS",
                },
                clear=False,
            ),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 500)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Internal error")
        self.assertEqual(body["message"], "Failed to process price-storage request")
        self.assertEqual(body["details"], "throttled")

    def test_lambda_handler_returns_internal_error_shape_on_pricing_failure(self):
        event = self._valid_event()

        with (
            mock.patch.object(app, "estimate_storage_cost", side_effect=RuntimeError("pricing lookup failed")),
            mock.patch.dict(
                os.environ,
                {
                    "PRICE_STORAGE_MARKUP_PERCENT": "10",
                    "PRICE_STORAGE_TRANSFER_DIRECTION": "out",
                    "PRICE_STORAGE_RATE_TYPE": "BEFORE_DISCOUNTS",
                },
                clear=False,
            ),
        ):
            response = app.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 500)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "Internal error")
        self.assertEqual(body["message"], "pricing lookup failed")
