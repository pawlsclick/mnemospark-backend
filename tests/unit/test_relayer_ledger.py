"""Unit tests for relayer DynamoDB ledger writes."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

_SERVICES = Path(__file__).resolve().parents[2] / "services"
if str(_SERVICES) not in sys.path:
    sys.path.insert(0, str(_SERVICES))

from common import relayer_ledger  # noqa: E402


class TestRelayerLedger(unittest.TestCase):
    def test_normalize_relayer_address(self) -> None:
        self.assertEqual(
            relayer_ledger.normalize_relayer_address("0xAbCdEf0123456789aBcDeF0123456789aBcDeF01"),
            "0xabcdef0123456789abcdef0123456789abcdef01",
        )

    def test_normalize_relayer_address_invalid(self) -> None:
        with self.assertRaises(ValueError):
            relayer_ledger.normalize_relayer_address("not-an-address")

    def test_normalize_tx_hash(self) -> None:
        h = "a" * 64
        self.assertEqual(relayer_ledger._normalize_tx_hash("0x" + h), "0x" + h)

    def test_skip_when_table_env_missing(self) -> None:
        relayer_ledger._MISSING_TABLE_ENV_LOGGED = False
        with mock.patch.dict("os.environ", {}, clear=True):
            relayer_ledger.record_relayer_transaction_success(
                relayer_address="0xabcdef0123456789abcdef0123456789abcdef01",
                tx_hash_hex="0x" + "b" * 64,
                gas_used=21000,
                effective_gas_price=1000000,
                block_number=1,
            )

    def test_put_item_called_when_env_set(self) -> None:
        relayer_ledger._MISSING_TABLE_ENV_LOGGED = False
        table_mock = mock.Mock()
        resource_mock = mock.Mock()
        resource_mock.Table.return_value = table_mock
        with (
            mock.patch.dict(
                "os.environ",
                {relayer_ledger.RELAYER_TRANSACTIONS_TABLE_ENV: "relayer-tx-test"},
            ),
            mock.patch("common.relayer_ledger.boto3.resource", return_value=resource_mock),
        ):
            relayer_ledger.record_relayer_transaction_success(
                relayer_address="0xabcdef0123456789abcdef0123456789abcdef01",
                tx_hash_hex="0x" + "c" * 64,
                gas_used=100000,
                effective_gas_price=2,
                block_number=99,
            )
        table_mock.put_item.assert_called_once()
        call_kw = table_mock.put_item.call_args.kwargs
        self.assertIn("ConditionExpression", call_kw)
        item = call_kw["Item"]
        self.assertEqual(item["status"], "success")
        self.assertTrue(item["sk"].startswith("TX#"))
        self.assertTrue(item["sk"].endswith("#0x" + ("c" * 64)))
        self.assertEqual(item["gasUsed"], "100000")
        self.assertEqual(item["effectiveGasPriceWei"], "2")
        self.assertEqual(item["feePaidWei"], "200000")


if __name__ == "__main__":
    unittest.main()
