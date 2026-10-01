import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("flame", Path(__file__).parents[1] / "scripts/perf_flame.py")
flame = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flame)


class FlameTests(unittest.TestCase):
    def test_stack_weights_and_xml_escape(self):
        counts = flame.stacks("vpn 1 cpu-clock:\n\t123 leaf<&> (vpn)\n\t456 root (vpn)\n\n" * 2)
        self.assertEqual(sum(counts.values()), 2)
        self.assertEqual(next(iter(counts))[0], "root (vpn)")
        ET.fromstring(flame.render(counts))

    def test_empty_capture_is_not_a_successful_profile(self):
        with self.assertRaises(ValueError):
            flame.render(flame.stacks("# no samples"))
