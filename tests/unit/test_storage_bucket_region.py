"""Unit tests for services/common/storage_bucket_region.py."""

from __future__ import annotations

import copy
import pickle
import sys
import unittest
from pathlib import Path

_services = Path(__file__).resolve().parents[2] / "services"
if str(_services) not in sys.path:
    sys.path.insert(0, str(_services))

from common.storage_bucket_region import (  # noqa: E402
    US_EAST_1_REGION,
    BucketRegionMismatchError,
    actual_region_from_head_bucket_response,
    enforce_requested_matches_bucket_home,
    normalize_s3_region,
    resolve_bucket_home_region,
)


class NormalizeRegionTests(unittest.TestCase):
    def test_empty_and_whitespace_maps_to_us_east_1(self):
        self.assertEqual(normalize_s3_region(None), US_EAST_1_REGION)
        self.assertEqual(normalize_s3_region(""), US_EAST_1_REGION)
        self.assertEqual(normalize_s3_region("   "), US_EAST_1_REGION)

    def test_trims_region(self):
        self.assertEqual(normalize_s3_region("  eu-west-1  "), "eu-west-1")


class HeadResponseTests(unittest.TestCase):
    def test_reads_bucket_region_field(self):
        self.assertEqual(
            actual_region_from_head_bucket_response({"BucketRegion": "eu-west-1"}),
            "eu-west-1",
        )

    def test_reads_x_amz_bucket_region_header(self):
        self.assertEqual(
            actual_region_from_head_bucket_response(
                {
                    "ResponseMetadata": {
                        "HTTPHeaders": {"x-amz-bucket-region": "ap-south-1"},
                    }
                }
            ),
            "ap-south-1",
        )


class ResolveBucketHomeRegionTests(unittest.TestCase):
    def test_uses_bucket_region_without_get_bucket_location(self):
        class FakeS3:
            def get_bucket_location(self, Bucket):
                raise AssertionError("get_bucket_location should not be called")

        home = resolve_bucket_home_region(
            FakeS3(), "my-bucket", {"BucketRegion": "eu-central-1"}
        )
        self.assertEqual(home, "eu-central-1")

    def test_fallback_get_bucket_location_none_constraint_is_us_east_1(self):
        class FakeS3:
            def get_bucket_location(self, Bucket):
                return {"LocationConstraint": None}

        home = resolve_bucket_home_region(FakeS3(), "b", {})
        self.assertEqual(home, US_EAST_1_REGION)

    def test_fallback_get_bucket_location_with_constraint(self):
        class FakeS3:
            def get_bucket_location(self, Bucket):
                return {"LocationConstraint": "eu-west-1"}

        home = resolve_bucket_home_region(FakeS3(), "b", {})
        self.assertEqual(home, "eu-west-1")


class EnforceRequestedMatchesTests(unittest.TestCase):
    def test_matching_normalized_regions_noop(self):
        enforce_requested_matches_bucket_home("us-east-1", "")
        enforce_requested_matches_bucket_home("eu-west-1", "eu-west-1")

    def test_mismatch_raises(self):
        with self.assertRaises(BucketRegionMismatchError) as ctx:
            enforce_requested_matches_bucket_home("us-west-2", "eu-west-1")
        self.assertEqual(ctx.exception.requested_region, "us-west-2")
        self.assertEqual(ctx.exception.bucket_home_region, "eu-west-1")

    def test_mismatch_error_supports_pickle_and_copy(self):
        err = BucketRegionMismatchError(
            requested_region="us-west-2", bucket_home_region="eu-west-1"
        )
        restored = pickle.loads(pickle.dumps(err))
        cloned = copy.copy(err)
        self.assertEqual(restored.requested_region, "us-west-2")
        self.assertEqual(restored.bucket_home_region, "eu-west-1")
        self.assertEqual(cloned.requested_region, "us-west-2")
        self.assertEqual(cloned.bucket_home_region, "eu-west-1")


if __name__ == "__main__":
    unittest.main()
