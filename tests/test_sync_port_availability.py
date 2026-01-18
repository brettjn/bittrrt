import os
import sys
import unittest
from io import StringIO
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bittrrt


class TestPortAvailabilityAndSyncStart(unittest.TestCase):
    def test_port_manager_count_allocation_and_release(self):
        cfg = {"port_ranges": "8400-8402"}
        pm = bittrrt.PortManager(cfg)
        self.assertEqual(pm.get_available_port_count(), 3)
        p = pm.get_next_port()
        self.assertEqual(p, 8400)
        self.assertEqual(pm.get_available_port_count(), 2)
        self.assertTrue(pm.release_port(8400))
        self.assertEqual(pm.get_available_port_count(), 3)

    def test_start_server_exits_when_ports_insufficient(self):
        cfg = {"--sync-test": True, "port_ranges": "8500-8501"}  # only 2 ports
        br = bittrrt.BittrRt(cfg)
        stderr = StringIO()
        with patch('sys.stderr', stderr):
            with self.assertRaises(SystemExit) as cm:
                br.start_server()
            self.assertEqual(cm.exception.code, 1)
        self.assertIn("Not enough available ports for SyncTest", stderr.getvalue())

    def test_start_server_with_sufficient_ports_calls_run_loop_and_adds_sync(self):
        cfg = {"--sync-test": True, "port_ranges": "8600-8602"}  # 3 ports
        br = bittrrt.BittrRt(cfg)
        # patch run_loop so we don't enter infinite loop
        called = {"run_loop": False}
        def fake_run_loop(self):
            called["run_loop"] = True
        with patch.object(bittrrt.BittrRt, 'run_loop', new=fake_run_loop):
            br.start_server()
        self.assertTrue(called["run_loop"])
        self.assertEqual(len(br.ary_connections), 1)
        self.assertIsInstance(br.ary_connections[0], bittrrt.SyncTest)


if __name__ == '__main__':
    unittest.main()
