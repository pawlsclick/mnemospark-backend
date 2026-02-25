import importlib.util
from pathlib import Path
import unittest

import boto3
import botocore.exceptions


def load_app_module():
    module_path = Path(__file__).resolve().parents[2] / "services" / "estimate-transfer" / "app.py"
    module_spec = importlib.util.spec_from_file_location("estimate_transfer_app", module_path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError("Unable to load estimate transfer module")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


app = load_app_module()


class EstimateTransferIntegrationTests(unittest.TestCase):
    def test_real_bcm_estimate_or_skip_when_no_credentials(self):
        try:
            credentials = boto3.Session().get_credentials()
        except botocore.exceptions.BotoCoreError as exc:
            self.skipTest(f"Unable to load AWS credentials in this environment: {exc}")

        if credentials is None:
            self.skipTest("AWS credentials not configured; skipping BCM integration test.")

        try:
            result = app.estimate_data_transfer_cost(
                data_gb=1,
                direction="out",
                region=app.DEFAULT_REGION,
                rate_type="BEFORE_DISCOUNTS",
            )
        except botocore.exceptions.NoCredentialsError:
            self.skipTest("AWS credentials not configured; skipping BCM integration test.")
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code in {"InvalidClientTokenId", "UnrecognizedClientException"}:
                self.skipTest(f"AWS credentials are invalid for BCM integration: {error_code}")
            raise

        self.assertEqual(result["status"], "VALID")
        self.assertIn("totalCost", result)
        self.assertIn("costCurrency", result)
