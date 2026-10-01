import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("perf_metrics", pathlib.Path(__file__).parents[1] / "scripts/perf_metrics.py")
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


class PerfMetricsTests(unittest.TestCase):
    def test_stat_parser_ignores_spaces_and_parentheses_in_comm(self):
        fields = ["R"] + ["0"] * 10 + ["123", "45"] + ["0"] * 20
        self.assertEqual(metrics.cpu_ticks_from_stat("42 (worker ) with spaces) " + " ".join(fields)), 168)

    def test_cpu_is_vpn_process_core_percent_and_packets_are_tap_rates(self):
        before = {"at": 10, "ticks": {"server": 100, "client": 20},
                  "packets": {"server": {"rx": 100, "tx": 20}, "client": {"rx": 20, "tx": 100}}}
        after = {"at": 12, "ticks": {"server": 500, "client": 120},
                 "packets": {"server": {"rx": 2100, "tx": 220}, "client": {"rx": 220, "tx": 2100}}}
        result = metrics.summarize(before, after, 100, "upload")
        self.assertEqual(result["server_cpu_pct"], 200)
        self.assertEqual(result["client_cpu_pct"], 50)
        self.assertEqual(result["server_rx_pps"], 1000)
        self.assertEqual(result["client_rx_pps"], 100)

    def test_invalid_or_reset_measurements_fail(self):
        snap = {"at": 1, "ticks": {"server": 1, "client": 1},
                "packets": {"server": {"rx": 0, "tx": 0}, "client": {"rx": 0, "tx": 0}}}
        with self.assertRaises(ValueError):
            metrics.summarize(snap, snap, 100, "upload")
        after = {**snap, "at": 2, "ticks": {"server": 0, "client": 1}}
        with self.assertRaises(ValueError):
            metrics.summarize(snap, after, 100, "upload")
