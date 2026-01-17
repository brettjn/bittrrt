VERSION = "0.2"
VERSION_NOTE = "Added SequenceSpan class with binary serialization, fixed missing imports (struct, typing), config creation tests"

import os
import sys
import time
import struct
from typing import Optional, List, Tuple
from termcolor import colored

class SequenceSpan:
    """Represents a list of sequence number spans (beginning and ending pairs)"""
    
    def __init__(self, spans: Optional[List[Tuple[int, int]]] = None):
        """Initialize with list of (begin, end) tuples or default to full 8-byte span
        
        Spans are automatically sorted by their begin value to ensure lowest sequences
        are at the front of the list.
        """
        if spans is None:
            # Default to complete 8-byte span: 0 to 2^64 - 1
            self.spans = [(0, (2**64) - 1)]
        else:
            # Sort spans by begin value to maintain numerical order
            self.spans = sorted(spans, key=lambda x: x[0])
        # Track the maximum sequence number returned by get_lowest()
        # and how many times get_lowest() returned a sequence that did
        # not increase that maximum.
        self.max_lowest_returned = None  # type: Optional[int]
        self.get_lowest_non_increase_count = 0
    
    def get_spans(self) -> List[Tuple[int, int]]:
        """Return the list of spans"""
        return self.spans
    
    def to_binary(self) -> bytes:
        """Convert spans to binary representation"""
        # Each span is two 8-byte unsigned integers (begin, end)
        # Format: number of spans (4 bytes) followed by span pairs
        result = struct.pack('>I', len(self.spans))  # 4-byte unsigned int for count
        for begin, end in self.spans:
            result += struct.pack('>QQ', begin, end)  # Two 8-byte unsigned long longs
        return result
    
    @classmethod
    def from_binary(cls, binary_data: bytes) -> 'SequenceSpan':
        """Create SequenceSpan from binary representation"""
        if len(binary_data) < 4:
            raise ValueError('Binary data too short for SequenceSpan')
        
        # Read span count (4 bytes)
        span_count = struct.unpack('>I', binary_data[0:4])[0]
        
        # Each span is 16 bytes (two 8-byte unsigned long longs)
        expected_len = 4 + (span_count * 16)
        if len(binary_data) < expected_len:
            raise ValueError(f'Binary data too short: expected {expected_len}, got {len(binary_data)}')
        
        spans = []
        offset = 4
        for i in range(span_count):
            begin, end = struct.unpack('>QQ', binary_data[offset:offset+16])
            spans.append((begin, end))
            offset += 16
        
        return cls(spans)
    
    def get_lowest(self) -> Optional[int]:
        """Get and remove the lowest sequence number from spans
        
        Since spans are always kept in sorted order (by begin value),
        the lowest sequence number is always the first value of the first span.
        """
        if not self.spans or len(self.spans) == 0:
            return None
        
        # Spans are sorted, so first span has lowest begin value
        begin, end = self.spans[0]
        lowest = begin
        
        # Update the span
        if begin == end:
            # Remove this span entirely
            self.spans.pop(0)
        else:
            # Increment the begin value
            self.spans[0] = (begin + 1, end)
        # Update tracking: maximum returned lowest and non-increase count
        try:
            if self.max_lowest_returned is None:
                self.max_lowest_returned = lowest
            else:
                if lowest > self.max_lowest_returned:
                    self.max_lowest_returned = lowest
                else:
                    # did not increase the maximum
                    self.get_lowest_non_increase_count += 1
        except Exception:
            # Be conservative: don't let tracking errors break sequence logic
            pass

        return lowest
    
    def remove_seq(self, seq_num: int) -> bool:
        """Remove a specific sequence number from the spans
        
        If the sequence number is in the middle of a span, split it into two spans.
        For example, removing 8 from span (5, 100) results in spans (5, 7) and (9, 100).
        
        Args:
            seq_num: The sequence number to remove
            
        Returns:
            True if the sequence number was found and removed, False otherwise
        """
        # Find which span contains this sequence number
        for i, (begin, end) in enumerate(self.spans):
            if begin <= seq_num <= end:
                # Found the span containing this sequence number
                
                if begin == end:
                    # Span contains only this one number, remove the entire span
                    self.spans.pop(i)
                elif seq_num == begin:
                    # Removing from the beginning, just increment begin
                    self.spans[i] = (begin + 1, end)
                elif seq_num == end:
                    # Removing from the end, just decrement end
                    self.spans[i] = (begin, end - 1)
                else:
                    # Removing from the middle, split into two spans
                    # First span: from begin to seq_num-1
                    # Second span: from seq_num+1 to end
                    self.spans[i] = (begin, seq_num - 1)
                    self.spans.insert(i + 1, (seq_num + 1, end))
                    # Spans remain in order since we're splitting within a span
                
                return True
        
        # Sequence number not found in any span
        return False


class CommHandler:
    def handle_packets(self, ary_packets):
        raise NotImplementedError("handle_packets must be implemented by subclasses")

class PortCommands(CommHandler):
    def handle_packets(self, ary_packets):
        # Implement packet handling for port commands
        pass

class DataSink(CommHandler):
    def handle_packets(self, ary_packets):
        # Implement packet handling for data sink
        pass

class DataSource(CommHandler):
    def handle_packets(self, ary_packets):
        # Implement packet handling for data source
        pass


class Connection:
    def __init__(self, config):
        self.config = config
        self._established = False

    def run_once(self):
        raise NotImplementedError("run_once must be implemented by subclasses")

    def establish(self):
        raise NotImplementedError("establish must be implemented by subclasses")


class SyncTest(Connection):
    """A simple synchronous test connection for unit/testing purposes."""
    def __init__(self, config):
        super().__init__(config)

    def run_once(self):
        # minimal action for a sync test connection
        print("SyncTest: run_once called")

    def establish(self):
        # For testing, establish once and return True so it gets moved
        if not self._established:
            print("SyncTest: establish successful")
            self._established = True
            return True
        return False

class BittrRt:
    def __init__(self, config):
        self.config = config
        self.port_handler = PortHandler(config)
        # array of active Connection instances
        self.ary_connections = []
        # array of established Connection instances
        self.ary_established = []
        # running flag for the main loop
        self.running = False

    def start_server(self):
        """Prepare connections (optionally add SyncTest) and start the run loop."""
        # If --sync-test flag is present in the config, add a SyncTest connection
        if "--sync-test" in self.config:
            conn = SyncTest(self.config)
            self.ary_connections.append(conn)
        # start the main loop
        self.run_loop()

    def run_loop(self):
        """Run a persistent loop calling `establish()` on pending connections.

        Loops while `self.running` is True. Established connections are moved
        from `ary_connections` to `ary_established`. At the end of each
        iteration prints 'b' and sleeps 0.25 seconds.
        """
        print("Starting run loop...")
        self.running = True
        try:
            while self.running:
                for c in list(self.ary_connections):
                    try:
                        established = c.establish()
                        if established:
                            try:
                                self.ary_connections.remove(c)
                            except ValueError:
                                pass
                            self.ary_established.append(c)
                    except Exception as e:
                        print(f"Connection establish error: {e}", file=sys.stderr)


                for c in list(self.ary_established):
                    try:
                        c.run_once()
                    except Exception as e:
                        print(f"Connection run_once error: {e}", file=sys.stderr)


                # indicate liveliness and sleep
                print('b', end='', flush=True)
                time.sleep(0.25)
        except KeyboardInterrupt:
            print("\nReceived SIGINT, shutting down...", file=sys.stderr)
            self.running = False
            sys.exit(0)

class PortHandler:
    def __init__(self, config):
        self.config = config


def main():
    config_path = os.path.expanduser("~/.bittrrt/config")
    default_config = {
        "bind_addr": "0.0.0.0",
        "bind_port": "6711",
        "port_ranges": "6712-6720",
        "port_parallelability": "SINGLE",
        "heartbeat_rate": "5000"
    }

    # Check for --create-config argument
    if "--create-config" in sys.argv:
        config = default_config.copy()
        arg_map = {
            "--bind-addr": "bind_addr",
            "--bind-port": "bind_port",
            "--port-ranges": "port_ranges",
            "--port-parallelability": "port_parallelability",
            "--heartbeat-rate": "heartbeat_rate"
        }
        known_args = set(["--create-config"] + list(arg_map.keys()))
        used_args = set()
        # Parse known arguments and collect used
        for arg, key in arg_map.items():
            if arg in sys.argv:
                idx = sys.argv.index(arg)
                if idx + 1 < len(sys.argv):
                    config[key] = sys.argv[idx + 1]
                    used_args.add(arg)
                    used_args.add(sys.argv[idx + 1])
        # Warn about unknown arguments
        for i, arg in enumerate(sys.argv[1:]):
            if arg.startswith('--') and arg not in known_args:
                print(f"Warning: Unknown argument '{arg}'", file=sys.stderr)
        # If config file exists, show diff and ask for confirmation
        if os.path.exists(config_path):
            print(f"Config file already exists at {config_path}.")
            # Read old config into a dict
            old_config = {}
            with open(config_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        old_config[k.strip()] = v.strip()
            # Check for any changes
            keys = ["bind_addr", "bind_port", "port_ranges", "port_parallelability", "heartbeat_rate"]
            changes = [(k, old_config.get(k, None), config[k]) for k in keys if old_config.get(k, None) != config[k]]
            if not changes:
                print("Warning: No changes to config file. Nothing to do.", file=sys.stderr)
                sys.exit(0)
            print("Current config:")
            for k in keys:
                v = old_config.get(k, "")
                print(f"  {k}={v}")
            print("\nNew config:")
            for k in keys:
                new_v = config[k]
                old_v = old_config.get(k, None)
                if old_v is not None and new_v != old_v:
                    print(f"  {k}=" + colored(f"{new_v}", "red"))
                else:
                    print(f"  {k}={new_v}")
            confirm = input("Overwrite config file with these changes? (Y/N): ").strip().lower()
            if confirm != 'y':
                print("Aborted config overwrite.")
                sys.exit(1)
        # Create config directory if needed
        config_dir = os.path.dirname(config_path)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        with open(config_path, "w") as f:
            f.write("# bittrt configuration file\n\n")
            f.write("# Server bind settings\n")
            f.write(f"bind_addr={config['bind_addr']}\n")
            f.write(f"bind_port={config['bind_port']}\n\n")
            f.write("# Port ranges for client connections (format: start-end,start-end)\n")
            f.write(f"port_ranges={config['port_ranges']}\n\n")
            f.write("# Parallelization modes: SINGLE, THREAD, PROCESS\n")
            f.write(f"port_parallelability={config['port_parallelability']}\n\n")
            f.write("# Heartbeat and flow control (milliseconds for heartbeat_rate)\n")
            f.write(f"heartbeat_rate={config['heartbeat_rate']}\n")
        print(f"Config file created at {config_path}")
        sys.exit(0)

    config = {}
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
    else:
        print(f"Config file not found: {config_path}\n use --create-config to create a new config file")
    # Override config values with any command-line arguments (CLI wins)
    cli_arg_map = {
        "--bind-addr": "bind_addr",
        "--bind-port": "bind_port",
        "--port-ranges": "port_ranges",
        "--port-parallelability": "port_parallelability",
        "--heartbeat-rate": "heartbeat_rate",
    }
    # copy to avoid mutating iter while parsing
    argv = list(sys.argv)
    for arg, key in cli_arg_map.items():
        if arg in argv:
            idx = argv.index(arg)
            if idx + 1 < len(argv):
                config[key] = argv[idx + 1]
    # Flags without values
    if "--sync-test" in argv:
        config["--sync-test"] = True

    # Initialize BittrRt with merged config (file + CLI overrides)
    bittrrt = BittrRt(config)
    # Start the server main loop (may add test connections via config)
    bittrrt.start_server()

if __name__ == "__main__":
    main()
