"""Wallet bucket home region: normalize AWS region strings and enforce request parity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

US_EAST_1_REGION = "us-east-1"


def normalize_s3_region(value: str | None) -> str:
    """Trim; map empty / missing to us-east-1 (S3 LocationConstraint semantics)."""
    s = (value or "").strip()
    return US_EAST_1_REGION if not s else s


def actual_region_from_head_bucket_response(response: dict[str, Any]) -> str | None:
    """Best-effort region from boto3 head_bucket output."""
    br = response.get("BucketRegion")
    if isinstance(br, str) and br.strip():
        return br.strip()
    meta = response.get("ResponseMetadata") or {}
    headers = meta.get("HTTPHeaders") or {}
    for key, val in headers.items():
        if key.lower() == "x-amz-bucket-region" and isinstance(val, str) and val.strip():
            return val.strip()
    return None


def resolve_bucket_home_region(
    s3_client: Any, bucket_name: str, head_response: dict[str, Any]
) -> str:
    """Resolve physical bucket region after a successful HeadBucket."""
    raw = actual_region_from_head_bucket_response(head_response)
    if raw:
        return normalize_s3_region(raw)
    loc = s3_client.get_bucket_location(Bucket=bucket_name)
    constraint = loc.get("LocationConstraint")
    if isinstance(constraint, str) and constraint.strip():
        return normalize_s3_region(constraint)
    return normalize_s3_region(None)


@dataclass
class BucketRegionMismatchError(Exception):
    """Requested API location does not match the wallet bucket's home region."""

    requested_region: str
    bucket_home_region: str

    def __post_init__(self) -> None:
        # Keep BaseException.args aligned with constructor arguments for pickle/copy.
        super().__init__(self.requested_region, self.bucket_home_region)

    def __str__(self) -> str:
        return (
            f"Storage for this wallet is in {self.bucket_home_region}; "
            f"requested region was {self.requested_region}. "
            f"Retry with location/region {self.bucket_home_region}."
        )


def enforce_requested_matches_bucket_home(requested_region: str, bucket_home_region: str) -> None:
    req = normalize_s3_region(requested_region)
    home = normalize_s3_region(bucket_home_region)
    if req != home:
        raise BucketRegionMismatchError(requested_region=req, bucket_home_region=home)
