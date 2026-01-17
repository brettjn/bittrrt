"""Tests for config file creation and command line argument handling."""
import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch
from io import StringIO


# Add parent directory to path to import bittrrt
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bittrrt


class TestConfigCreation(unittest.TestCase):
    """Test config file creation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for config files
        self.test_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.test_dir, ".bittrrt", "config")

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove the temporary directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_create_config_default_values(self):
        """Test creating config file with default values."""
        test_args = ["bittrrt.py", "--create-config"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with self.assertRaises(SystemExit) as cm:
                    bittrrt.main()
                self.assertEqual(cm.exception.code, 0)
        
        # Verify config file was created
        self.assertTrue(os.path.exists(self.config_path))
        
        # Verify config file contents
        with open(self.config_path, 'r') as f:
            content = f.read()
            self.assertIn("bind_addr=0.0.0.0", content)
            self.assertIn("bind_port=6711", content)
            self.assertIn("port_ranges=6712-6720", content)
            self.assertIn("port_parallelability=SINGLE", content)
            self.assertIn("heartbeat_rate=5000", content)

    def test_create_config_with_custom_values(self):
        """Test creating config file with custom command line values."""
        test_args = [
            "bittrrt.py", 
            "--create-config",
            "--bind-addr", "127.0.0.1",
            "--bind-port", "8080",
            "--port-ranges", "8081-8090",
            "--port-parallelability", "THREAD",
            "--heartbeat-rate", "3000"
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with self.assertRaises(SystemExit) as cm:
                    bittrrt.main()
                self.assertEqual(cm.exception.code, 0)
        
        # Verify config file was created with custom values
        self.assertTrue(os.path.exists(self.config_path))
        
        with open(self.config_path, 'r') as f:
            content = f.read()
            self.assertIn("bind_addr=127.0.0.1", content)
            self.assertIn("bind_port=8080", content)
            self.assertIn("port_ranges=8081-8090", content)
            self.assertIn("port_parallelability=THREAD", content)
            self.assertIn("heartbeat_rate=3000", content)

    def test_create_config_unknown_argument_warning(self):
        """Test warning is shown for unknown arguments."""
        test_args = [
            "bittrrt.py",
            "--create-config",
            "--unknown-arg"
        ]
        
        captured_stderr = StringIO()
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch('sys.stderr', captured_stderr):
                    with self.assertRaises(SystemExit):
                        bittrrt.main()
        
        stderr_output = captured_stderr.getvalue()
        self.assertIn("Warning: Unknown argument '--unknown-arg'", stderr_output)

    def test_create_config_overwrite_with_changes(self):
        """Test overwriting existing config file with changes."""
        # First create the config directory and an existing config file
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            f.write("# bittrt configuration file\n\n")
            f.write("bind_addr=0.0.0.0\n")
            f.write("bind_port=6711\n")
            f.write("port_ranges=6712-6720\n")
            f.write("port_parallelability=SINGLE\n")
            f.write("heartbeat_rate=5000\n")
        
        test_args = [
            "bittrrt.py",
            "--create-config",
            "--bind-addr", "192.168.1.1"
        ]
        
        # Simulate user confirming 'Y'
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch('builtins.input', return_value='y'):
                    with self.assertRaises(SystemExit) as cm:
                        bittrrt.main()
                    self.assertEqual(cm.exception.code, 0)
        
        # Verify config was updated
        with open(self.config_path, 'r') as f:
            content = f.read()
            self.assertIn("bind_addr=192.168.1.1", content)

    def test_create_config_overwrite_abort(self):
        """Test aborting config file overwrite."""
        # First create an existing config file
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            f.write("bind_addr=0.0.0.0\n")
            f.write("bind_port=6711\n")
            f.write("port_ranges=6712-6720\n")
            f.write("port_parallelability=SINGLE\n")
            f.write("heartbeat_rate=5000\n")
        
        test_args = [
            "bittrrt.py",
            "--create-config",
            "--bind-addr", "192.168.1.1"
        ]
        
        # Simulate user rejecting with 'N'
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch('builtins.input', return_value='n'):
                    with self.assertRaises(SystemExit) as cm:
                        bittrrt.main()
                    self.assertEqual(cm.exception.code, 1)
        
        # Verify config was not updated
        with open(self.config_path, 'r') as f:
            content = f.read()
            self.assertIn("bind_addr=0.0.0.0", content)
            self.assertNotIn("bind_addr=192.168.1.1", content)

    def test_create_config_no_changes_warning(self):
        """Test warning when attempting to create config with no changes."""
        # First create an existing config file
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            f.write("bind_addr=0.0.0.0\n")
            f.write("bind_port=6711\n")
            f.write("port_ranges=6712-6720\n")
            f.write("port_parallelability=SINGLE\n")
            f.write("heartbeat_rate=5000\n")
        
        test_args = ["bittrrt.py", "--create-config"]
        
        captured_stderr = StringIO()
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch('sys.stderr', captured_stderr):
                    with self.assertRaises(SystemExit) as cm:
                        bittrrt.main()
                    self.assertEqual(cm.exception.code, 0)
        
        stderr_output = captured_stderr.getvalue()
        self.assertIn("No changes to config file", stderr_output)


class TestCommandLineArguments(unittest.TestCase):
    """Test command line argument handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.test_dir, ".bittrrt", "config")

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_cli_overrides_config_file(self):
        """Test that CLI arguments override config file values."""
        # Create a config file with default values
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            f.write("bind_addr=0.0.0.0\n")
            f.write("bind_port=6711\n")
            f.write("port_ranges=6712-6720\n")
            f.write("port_parallelability=SINGLE\n")
            f.write("heartbeat_rate=5000\n")
        
        test_args = [
            "bittrrt.py",
            "--bind-addr", "10.0.0.1",
            "--bind-port", "9999"
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                # We need to prevent the actual server from starting
                with patch.object(bittrrt.BittrRt, 'start_server') as mock_start:
                    bittrrt.main()
                    # Get the BittrRt instance that was created
                    mock_start.assert_called_once()
        
        # Verify the config was properly merged (we'll test via BittrRt initialization)
        test_args = ["bittrrt.py", "--bind-addr", "10.0.0.1"]
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch.object(bittrrt.BittrRt, 'start_server'):
                    # Capture the BittrRt initialization
                    original_init = bittrrt.BittrRt.__init__
                    captured_config = []
                    
                    def capture_init(self, config):
                        captured_config.append(config)
                        original_init(self, config)
                    
                    with patch.object(bittrrt.BittrRt, '__init__', capture_init):
                        bittrrt.main()
                    
                    # Verify CLI overrode the config file value
                    self.assertEqual(captured_config[0]["bind_addr"], "10.0.0.1")
                    # Verify config file values are still present
                    self.assertEqual(captured_config[0]["bind_port"], "6711")

    def test_sync_test_flag(self):
        """Test that --sync-test flag is properly recognized."""
        # Create a minimal config file
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            f.write("bind_addr=0.0.0.0\n")
            f.write("bind_port=6711\n")
        
        test_args = ["bittrrt.py", "--sync-test"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch.object(bittrrt.BittrRt, 'start_server'):
                    original_init = bittrrt.BittrRt.__init__
                    captured_config = []
                    
                    def capture_init(self, config):
                        captured_config.append(config)
                        original_init(self, config)
                    
                    with patch.object(bittrrt.BittrRt, '__init__', capture_init):
                        bittrrt.main()
                    
                    # Verify --sync-test flag is in config
                    self.assertIn("--sync-test", captured_config[0])
                    self.assertTrue(captured_config[0]["--sync-test"])

    def test_no_config_file_warning(self):
        """Test that a warning is shown when config file doesn't exist."""
        test_args = ["bittrrt.py"]
        
        captured_stdout = StringIO()
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch('sys.stdout', captured_stdout):
                    with patch.object(bittrrt.BittrRt, 'start_server'):
                        bittrrt.main()
        
        stdout_output = captured_stdout.getvalue()
        self.assertIn("Config file not found", stdout_output)
        self.assertIn("use --create-config", stdout_output)

    def test_multiple_cli_arguments(self):
        """Test handling multiple CLI arguments at once."""
        # Create a config file
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            f.write("bind_addr=0.0.0.0\n")
            f.write("bind_port=6711\n")
            f.write("port_ranges=6712-6720\n")
            f.write("port_parallelability=SINGLE\n")
            f.write("heartbeat_rate=5000\n")
        
        test_args = [
            "bittrrt.py",
            "--bind-addr", "172.16.0.1",
            "--bind-port", "7777",
            "--port-ranges", "7778-7788",
            "--port-parallelability", "PROCESS",
            "--heartbeat-rate", "2000"
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('os.path.expanduser', return_value=self.config_path):
                with patch.object(bittrrt.BittrRt, 'start_server'):
                    original_init = bittrrt.BittrRt.__init__
                    captured_config = []
                    
                    def capture_init(self, config):
                        captured_config.append(config)
                        original_init(self, config)
                    
                    with patch.object(bittrrt.BittrRt, '__init__', capture_init):
                        bittrrt.main()
                    
                    # Verify all CLI values override config
                    config = captured_config[0]
                    self.assertEqual(config["bind_addr"], "172.16.0.1")
                    self.assertEqual(config["bind_port"], "7777")
                    self.assertEqual(config["port_ranges"], "7778-7788")
                    self.assertEqual(config["port_parallelability"], "PROCESS")
                    self.assertEqual(config["heartbeat_rate"], "2000")


if __name__ == '__main__':
    unittest.main()
