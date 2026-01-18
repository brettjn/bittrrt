import os
import sys
import unittest
from unittest.mock import patch

# ensure package path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bittrrt


class TestPortManager(unittest.TestCase):
    def test_parse_single_range(self):
        cfg = {"port_ranges": "8000-8002"}
        pm = bittrrt.PortManager(cfg)
        self.assertEqual(pm.get_spans(), [(8000, 8002)])

    def test_parse_multiple_ranges_and_single_ports(self):
        cfg = {"port_ranges": "8000-8001, 9000,9002-9003"}
        pm = bittrrt.PortManager(cfg)
        self.assertEqual(pm.get_spans(), [(8000, 8001), (9000, 9000), (9002, 9003)])

    def test_get_next_port_and_exhaust(self):
        cfg = {"port_ranges": "8100-8101"}
        pm = bittrrt.PortManager(cfg)
        p1 = pm.get_next_port()
        p2 = pm.get_next_port()
        p3 = pm.get_next_port()
        self.assertEqual(p1, 8100)
        self.assertEqual(p2, 8101)
        self.assertIsNone(p3)

    def test_release_port_merging(self):
        cfg = {"port_ranges": "8200-8200,8202-8202"}
        pm = bittrrt.PortManager(cfg)
        # consume 8200 and 8202
        self.assertEqual(pm.get_next_port(), 8200)
        self.assertEqual(pm.get_next_port(), 8202)
        self.assertIsNone(pm.get_next_port())
        # release 8201 should create a middle single span
        self.assertTrue(pm.release_port(8201))
        self.assertEqual(pm.get_spans(), [(8201, 8201)])
        # release 8200 and 8202 should merge into (8200,8202)
        self.assertTrue(pm.release_port(8200))
        self.assertTrue(pm.release_port(8202))
        self.assertEqual(pm.get_spans(), [(8200, 8202)])

    def test_release_existing_port_noop(self):
        cfg = {"port_ranges": "8300-8302"}
        pm = bittrrt.PortManager(cfg)
        # releasing a port that's already available should return False
        self.assertFalse(pm.release_port(8301))


if __name__ == '__main__':
    unittest.main()
