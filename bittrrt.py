VERSION = "0.3"
VERSION_NOTE = "Added LoopDelay class for managing timed delays in loops"

import os
import socket
import sys
import time
import struct
import multiprocessing
from enum import Enum
from typing import Optional, List, Tuple, Dict
from termcolor import colored
import errno
from abc import ABC, abstractmethod

ESTABLISH_LOOP_DELAY = 1_000_000  # microseconds
SYNC_TEST_SLEEP      = 3          # seconds
ESTABLISH_MAX_TIME   = 5_000      # milliseconds

class PortType(Enum):
    """Port types for client connections"""
    CONTROL = "control"
    UPLOAD = "upload"
    DOWNLOAD = "download"

class CommMsg(Enum):
    START  = "start"
    STOP   = "stop"
    PAUSE  = "pause"
    RESUME = "resume"

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


class LoopDelay:
    """A class to manage delays in loops, returning True when delay has passed."""

    def __init__(self, delay_us: int):
        """Initialize with delay in microseconds."""
        self.delay_us = delay_us
        self.last_time = None

    def is_time_to_do_it(self) -> bool:
        """Check if enough time has passed since last call.
        
        Returns True on first call or when delay has been reached.
        Saves timestamp and returns False if delay not reached.
        """
        current_time = time.perf_counter_ns() // 1000  # microseconds
        if self.last_time is None:
            self.last_time = current_time
            return True
        if current_time - self.last_time >= self.delay_us:
            self.last_time = current_time
            return True
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
    def __init__(self, config, port_manager):
        self.config          = config
         
        self._established    = False
        self.port_manager    = port_manager
        self.establish_start = time.perf_counter_ns() // 1_000_000  # milliseconds
        
    def run_once(self):
        raise NotImplementedError("run_once must be implemented by subclasses")

    def establish(self):
        raise NotImplementedError("establish must be implemented by subclasses")


class SyncTest(Connection):
    """A simple synchronous test connection for unit/testing purposes."""
    def __init__(self, config, port_manager):
        super().__init__(config, port_manager)
        self.send_queues:  Dict[PortType, multiprocessing.Queue]  = None
        self.recv_queues:  Dict[PortType, multiprocessing.Queue]  = None

        self.ctrl_handler: Optional[CtrlHandler]                  = None
        self.upld_handler:   Optional[UpHandler]                  = None
        self.dnld_handler:   Optional[DnHandler]                  = None

        self.from_handler                                         = multiprocessing.Queue()

        self.sent_start_commands: bool                            = False

    
    def run_once(self):
        # minimal action for a sync test connection
        print("SyncTest: run_once called")

    def establish(self):
        # For testing, establish once and return True so it gets moved
        
        msg=None
        try:
            msg=self.from_handler.get_nowait()
        except:
            pass

        if msg:
            print("SyncTest: received message from handler:", msg)

        if not self._established:
            
            if self.send_queues is None:
                self.send_queues = {}
                self.send_queues[PortType.CONTROL]  = multiprocessing.Queue()
                self.send_queues[PortType.UPLOAD]   = multiprocessing.Queue()
                self.send_queues[PortType.DOWNLOAD] = multiprocessing.Queue()

            if self.recv_queues is None:
                self.recv_queues = {}
                self.recv_queues[PortType.CONTROL]  = multiprocessing.Queue()
                self.recv_queues[PortType.UPLOAD]   = multiprocessing.Queue()
                self.recv_queues[PortType.DOWNLOAD] = multiprocessing.Queue()


            # Instantiate ctrl_handler if it doesn't exist
            if self.ctrl_handler is None:
                ctrl_port = self.port_manager.get_next_port()
                print(f"attempting to instantiate CTRL_HANDLER on port {ctrl_port}")
                if ctrl_port is None:
                    print("SyncTest: Failed to get control port")
                    return False
                self.ctrl_handler = CtrlHandler(
                    ctrl_port,
                    self.send_queues,
                    self.recv_queues,
                    self.from_handler,
                    self.config
                )
                return
            
            if not self.ctrl_handler.process.is_alive():
                print("SyncTest: Control handler process is not alive - removing")
                self.ctrl_handler = None
                return False
            
            # Instantiate upld_handler if it doesn't exist
            if self.upld_handler is None:
                up_port = self.port_manager.get_next_port()
                print(f"attempting to instantiate UP_HANDLER on port {up_port}")
                if up_port is None:
                    print("SyncTest: Failed to get upload port")
                    return False
                self.upld_handler = UpHandler(
                    up_port,
                    self.send_queues,
                    self.recv_queues,
                    self.from_handler,
                    self.config
                )
                return
            
            if not self.upld_handler.process.is_alive():
                print("SyncTest: Upload handler process is not alive")
                return False
            
            # Instantiate dnld_handler if it doesn't exist
            if self.dnld_handler is None:
                dn_port = self.port_manager.get_next_port()
                print(f"attempting to instantiate DN_HANDLER on port {dn_port}")
                if dn_port is None:
                    print("SyncTest: Failed to get download port")
                    return False
                self.dnld_handler = DnHandler(
                    dn_port,
                    self.send_queues,
                    self.recv_queues,
                    self.from_handler,
                    self.config
                )
                return
            
            if not self.dnld_handler.process.is_alive():    
                print("SyncTest: Download handler process is not alive")
                return False

            if self.ctrl_handler.process.is_alive() and self.upld_handler.process.is_alive() and self.dnld_handler.process.is_alive():
                print("SyncTest: All handlers alive")
                if not self.sent_start_commands:
                    self.recv_queues[PortType.CONTROL].put(CommMsg.START)
                    self.recv_queues[PortType.UPLOAD].put(CommMsg.START)
                    self.recv_queues[PortType.DOWNLOAD].put(CommMsg.START)
                    self.sent_start_commands = True
                else:
                    print("SyncTest: establish successful")
                    self._established = True
                    return True
                
        return False

class BittrRt:
    def __init__(self, config):
        self.config = config
        #self.port_handler = PortHandler(config)
        # Initialize PortManager before server start so ranges are ready
        try:
            # allow passing an explicit override in the config dict if present
            pr = config.get("port_ranges") if isinstance(config, dict) else None
            self.port_manager = PortManager(config, port_ranges_arg=pr)
        except Exception:
            self.port_manager = None
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
            # Ensure we have enough available ports to create a communication instance
            pm = getattr(self, 'port_manager', None)
            if pm is None:
                print("Error: PortManager not initialized; cannot start SyncTest.", file=sys.stderr)
                sys.exit(1)
            if pm.get_available_port_count() < 3:
                print("Error: Not enough available ports for SyncTest (need >=3).", file=sys.stderr)
                sys.exit(1)
            conn = SyncTest(self.config, self.port_manager)
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

            elp  = LoopDelay(ESTABLISH_LOOP_DELAY)
            edlp = LoopDelay(ESTABLISH_LOOP_DELAY)

            while self.running:
                if elp.is_time_to_do_it():
                    for c in list(self.ary_connections):
                        try:
                            established = c.establish()
                            if established:
                                try:
                                    self.ary_connections.remove(c)
                                except ValueError:
                                    pass
                                self.ary_established.append(c)
                            elif c.establish_start is not None and (time.perf_counter_ns() // 1_000_000) - c.establish_start > ESTABLISH_MAX_TIME:
                                print("SyncTest: Establish time exceeded")
                                try:
                                    self.ary_connections.remove(c)
                                    c.close()
                                except ValueError:
                                    pass
                        except Exception as e:
                            print(f"Connection establish error: {e}", file=sys.stderr)

                if edlp.is_time_to_do_it():
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


class PortHandler(ABC):
    def __init__(self, config):
        self.config     = config
        self.sync_sleep = 0

        if "--sync-test" in self.config:
            self.sync_sleep = SYNC_TEST_SLEEP

    @abstractmethod
    def run_in_own_process(self):
        raise NotImplementedError("PortHandler.run_in_own_process() must be implemented by subclasses")

    @abstractmethod
    def iter(self):
        raise NotImplementedError("PortHandler.iter() must be implemented by subclasses")        
    
    @abstractmethod
    def port_type(self):
        raise NotImplementedError("PortHandler.port_type() must be implemented by subclasses")

    @abstractmethod
    def handle_message(self, msg):
        raise NotImplementedError("PortHandler.handle_message() must be implemented by subclasses")

    def run(self):
        """Main loop for the handler."""
        try:
            self.usock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.usock.bind((self.config.get("bind_address", "0.0.0.0"), self.port))
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                print(f"Error: Address {self.config.get('bind_address', '0.0.0.0')}:{self.port} is already in use. Please check running processes.")
                self.to_comm.put(f"port_in_use:{self.port}")
                sys.exit(1)
            else:
                # Handle other potential OSErrors
                print(f"An unexpected OSError occurred: {e}")
        except Exception as e:
            print(f"Error setting up socket in {self.__class__.__name__}: {e}", file=sys.stderr)
            return
        
        msg_from_comm = self.recv_queue[self.port_type()].get()
        print(f"{self.__class__.__name__} received initial message from comm queue: {msg_from_comm}")
        if msg_from_comm==CommMsg.START:
            try:
                self.usock.listen()
            except Exception as e:
                print(f"Error listening on socket in {self.__class__.__name__}: {e}", file=sys.stderr)
                return
            
            while True:
                try:
                    # Process incoming messages
                    if not self.recv_queue[self.port_type()].empty():
                        msg = self.recv_queue[self.port_type()].get()
                        self.handle_message(msg)
                except Exception as e:
                    print(f"Error in {self.__class__.__name__} run loop: {e}", file=sys.stderr)

                self.iter()


class CtrlHandler(PortHandler):
    """Handler for control port communication"""
    def __init__(self, port: int, send_queue: multiprocessing.Queue, recv_queue: multiprocessing.Queue, to_comm: multiprocessing.Queue, config):
        super().__init__(config)

        self.port       = port
        self.send_queue = send_queue
        self.recv_queue = recv_queue
        self.to_comm    = to_comm

        self.run_in_own_process()
    
    def port_type(self):
        return(PortType.CONTROL)

    def iter(self):
        print('(CH)', end='', flush=True)
        time.sleep(self.sync_sleep)    

    def handle_message(self, msg):
        """Handle a message received from the queue."""
        print(f"{self.__class__.__name__} received message: {msg}")

    def run_in_own_process(self):
        """Run this handler in its own process."""
        self.process = multiprocessing.Process(target=self.run)
        self.process.start()


class UpHandler(PortHandler):
    """Handler for upload port communication"""
    def __init__(self, port: int, send_queue: multiprocessing.Queue, recv_queue: multiprocessing.Queue, to_comm: multiprocessing.Queue, config):
        super().__init__(config)

        self.port       = port
        self.send_queue = send_queue
        self.recv_queue = recv_queue
        self.to_comm    = to_comm

        self.run_in_own_process()

    def port_type(self):
        return(PortType.CONTROL)

    def iter(self):
        print('(UH)', end='', flush=True)
        time.sleep(self.sync_sleep)    

    def handle_message(self, msg):
        """Handle a message received from the queue."""
        print(f"{self.__class__.__name__} received message: {msg}")

    def run_in_own_process(self):
        """Run this handler in its own process."""
        self.process = multiprocessing.Process(target=self.run)
        self.process.start()


class DnHandler(PortHandler):
    """Handler for download port communication"""
    def __init__(self, port: int, send_queue: multiprocessing.Queue, recv_queue: multiprocessing.Queue, to_comm: multiprocessing.Queue, config):
        super().__init__(config)

        self.port       = port
        self.send_queue = send_queue
        self.recv_queue = recv_queue
        self.to_comm    = to_comm

        self.run_in_own_process()

    def port_type(self):
        return(PortType.CONTROL)

    def iter(self):
        print('(DH)', end='', flush=True)
        time.sleep(self.sync_sleep)    

    def handle_message(self, msg):
        """Handle a message received from the queue."""
        print(f"{self.__class__.__name__} received message: {msg}")

    def run_in_own_process(self):
        """Run this handler in its own process."""
        self.process = multiprocessing.Process(target=self.run)
        self.process.start()

class PortManager:
    """Manage available port numbers using SequenceSpan.

    Parses a port ranges string (format: "start-end,start-end" or single ports)
    from `config['port_ranges']` or an explicit argument and instantiates
    a `SequenceSpan` with the resulting spans.
    """
    def __init__(self, config, port_ranges_arg: str = None):
        self.config = config
        # Determine effective ranges string: explicit arg wins over config
        ranges_str = port_ranges_arg if port_ranges_arg is not None else config.get("port_ranges")
        if not ranges_str:
            # No ranges provided — initialize with an empty span list
            spans = []
        else:
            spans = self._parse_ranges(ranges_str)

        # Create a SequenceSpan from parsed spans
        self.sequence_span = SequenceSpan(spans)

    def _parse_ranges(self, ranges_str: str):
        """Parse a comma-separated ranges string into a list of (begin,end) tuples."""
        spans = []
        for part in ranges_str.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-', 1)
                spans.append((int(a), int(b)))
            else:
                # single port
                p = int(part)
                spans.append((p, p))
        return spans

    def get_next_port(self):
        """Return the next available port (consumes it) or None if none left."""
        return self.sequence_span.get_lowest()

    def get_spans(self):
        """Return current spans list."""
        return self.sequence_span.get_spans()

    def release_port(self, port: int) -> bool:
        """Return a previously consumed port back into the available spans.

        Returns True if the port was added back (or merged), False if the
        port was already available.
        """
        spans = self.sequence_span.spans
        # If there are no spans, create a new one for this port
        if not spans:
            self.sequence_span.spans = [(port, port)]
            return True

        # If port is before the first span
        if port < spans[0][0] - 1:
            spans.insert(0, (port, port))
            return True
        if port == spans[0][0] - 1:
            # extend the first span backward
            spans[0] = (port, spans[0][1])
            return True

        # Iterate to find insertion/merge point
        for i in range(len(spans)):
            begin, end = spans[i]
            if begin <= port <= end:
                # already available
                return False
            if port == end + 1:
                # extend current span forward and possibly merge with next
                spans[i] = (begin, port)
                # merge with next if adjacent
                if i + 1 < len(spans) and spans[i+1][0] == port + 1:
                    spans[i] = (begin, spans[i+1][1])
                    spans.pop(i+1)
                return True
            if port < begin - 1:
                # insert as a separate span before current
                spans.insert(i, (port, port))
                return True
            if port == begin - 1:
                # extend current span backward
                spans[i] = (port, end)
                return True

        # If we reach here, port is after the last span
        last_begin, last_end = spans[-1]
        if port == last_end + 1:
            spans[-1] = (last_begin, port)
            return True
        if port > last_end + 1:
            spans.append((port, port))
            return True

        return False

    def get_available_port_count(self) -> int:
        """Return the total number of available ports across all spans."""
        total = 0
        for begin, end in self.sequence_span.spans:
            total += (end - begin + 1)
        return total


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
