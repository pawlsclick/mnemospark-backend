"""Unit tests for Base relayer monitor helpers."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


def _load_monitor_app():
    path = Path(__file__).resolve().parents[2] / "services" / "base-relayer-monitor" / "app.py"
    name = "base_relayer_monitor_test_app"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load base-relayer-monitor app")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


monitor_app = _load_monitor_app()


class TestBaseRelayerMonitorCore(unittest.TestCase):
    def test_normalize_wallet_requires_hex_characters(self) -> None:
        with self.assertRaises(ValueError):
            monitor_app.normalize_wallet("0x" + ("Z" * 40))

    def test_normalize_wallet_lowercases_valid_address(self) -> None:
        value = "0xAbCdEf0123456789aBCdEf0123456789abCDeF01"
        self.assertEqual(
            monitor_app.normalize_wallet(value),
            "0xabcdef0123456789abcdef0123456789abcdef01",
        )

    def test_classify_runway_status(self) -> None:
        self.assertEqual(monitor_app.classify_runway_status(None), "ok")
        self.assertEqual(monitor_app.classify_runway_status(10.0), "ok")
        self.assertEqual(monitor_app.classify_runway_status(3.0), "ok")
        self.assertEqual(monitor_app.classify_runway_status(2.9), "warning")
        self.assertEqual(monitor_app.classify_runway_status(1.0), "warning")
        self.assertEqual(monitor_app.classify_runway_status(0.5), "critical")

    def test_stats_partition_key(self) -> None:
        pk = monitor_app.stats_partition_key("0xabc", "DAY", "2025-03-21")
        self.assertEqual(pk, "WALLET#0xabc#PERIOD#DAY#2025-03-21")

    def test_parse_tx_item(self) -> None:
        tx = monitor_app.parse_tx_item(
            {
                "confirmedAt": "2025-03-21T12:00:00Z",
                "feePaidWei": "5000",
                "gasUsed": "21000",
            }
        )
        assert tx is not None
        self.assertEqual(tx.fee_wei, 5000)
        self.assertEqual(tx.gas_used, 21000)

    def test_estimate_runway_days(self) -> None:
        self.assertIsNone(monitor_app._estimate_runway_days(10**18, 0, 0))
        days = monitor_app._estimate_runway_days(7000, 7, 7000)
        self.assertIsNotNone(days)
        assert days is not None
        self.assertAlmostEqual(days, 7.0, places=3)

    def test_lambda_handler_queries_recent_transactions_only(self) -> None:
        wallet = "0xAbCdEf0123456789aBCdEf0123456789abCDeF01"
        env = {
            monitor_app.WALLET_ENV: wallet,
            monitor_app.RPC_ENV: "https://example.invalid",
            monitor_app.RELAYER_TX_TABLE_ENV: "tx-table",
            monitor_app.RELAYER_STATS_TABLE_ENV: "stats-table",
            monitor_app.RELAYER_HEALTH_TABLE_ENV: "health-table",
            monitor_app.TOPIC_ARN_ENV: "",
        }

        tx_tbl = mock.Mock()
        tx_tbl.query.return_value = {"Items": []}
        stats_tbl = mock.Mock()
        health_tbl = mock.Mock()
        ddb = mock.Mock()
        ddb.Table.side_effect = lambda name: {
            "tx-table": tx_tbl,
            "stats-table": stats_tbl,
            "health-table": health_tbl,
        }[name]

        web3_inst = mock.Mock()
        web3_inst.is_connected.return_value = True
        web3_inst.eth.get_balance.return_value = 1_000_000

        with (
            mock.patch.dict(os.environ, env, clear=False),
            mock.patch.object(monitor_app.boto3, "resource", return_value=ddb),
            mock.patch.object(monitor_app, "Web3") as web3_cls,
        ):
            web3_cls.return_value = web3_inst
            web3_cls.HTTPProvider.return_value = object()
            web3_cls.to_checksum_address.side_effect = lambda x: x

            response = monitor_app.lambda_handler({}, None)

        self.assertTrue(response["ok"])
        query_kwargs = tx_tbl.query.call_args.kwargs
        self.assertEqual(query_kwargs["KeyConditionExpression"], "pk = :pk AND sk >= :sk")
        self.assertEqual(
            query_kwargs["ExpressionAttributeValues"][":pk"],
            "WALLET#0xabcdef0123456789abcdef0123456789abcdef01",
        )
        self.assertRegex(
            query_kwargs["ExpressionAttributeValues"][":sk"],
            r"^TX#\d{4}-\d{2}-\d{2}T",
        )


if __name__ == "__main__":
    unittest.main()
