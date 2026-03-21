"""Unit tests for Base relayer monitor helpers."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
