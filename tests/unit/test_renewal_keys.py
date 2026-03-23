from common.renewal_keys import (
    active_inventory_sk,
    billing_period_object_key,
    billing_period_utc,
    object_key_to_url_safe_segment,
    synthetic_renewal_quote_id,
    wallet_period_sk,
)


def test_object_key_segment_is_url_safe_and_deterministic():
    ok = "my/object name.enc"
    a = object_key_to_url_safe_segment(ok)
    b = object_key_to_url_safe_segment(ok)
    assert a == b
    assert "/" not in a


def test_billing_period_and_composite_keys():
    period = billing_period_utc(1_700_000_000)
    assert len(period) == 7
    assert period[4] == "-"
    ok = "f.enc"
    assert billing_period_object_key(period, ok).startswith(f"{period}#")
    assert synthetic_renewal_quote_id(period, ok) == f"renewal#{period}#{object_key_to_url_safe_segment(ok)}"
    assert wallet_period_sk("0xabc", ok).startswith("0xabc#")
    assert active_inventory_sk("mnemospark-deadbeef", ok).startswith("mnemospark-deadbeef#")
