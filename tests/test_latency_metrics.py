import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("latency", Path(__file__).parents[1] / "scripts/latency_metrics.py")
latency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(latency)


class LatencyTests(unittest.TestCase):
    def test_percentiles_and_loss_include_only_replies(self):
        result = latency.summarize("time=3 ms\ntime=1 ms\ntime=2 ms\n4 packets transmitted, 3 received", "download")
        self.assertEqual((result["p50_ms"], result["p99_ms"], result["loss_pct"]), (2, 3, 25))

    def test_no_reply_is_not_zero_latency(self):
        with self.assertRaises(ValueError):
            latency.summarize("3 packets transmitted, 0 received", "upload")
