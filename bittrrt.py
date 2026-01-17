VERSION = "0.1"
VERSION_NOTE = "Added Connection/SyncTest, start_server/run_loop, config-based --sync-test, establish handling, graceful shutdown on CTRL+C"

import os
import sys
import time
from termcolor import colored


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

    def run_once(self):
        raise NotImplementedError("run_once must be implemented by subclasses")

    def establish(self):
        raise NotImplementedError("establish must be implemented by subclasses")


class SyncTest(Connection):
    """A simple synchronous test connection for unit/testing purposes."""
    def __init__(self, config):
        super().__init__(config)
        self._established = False

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
    # Initialize BittrRt with loaded config
    bittrrt = BittrRt(config)
    # Start the server main loop (may add test connections via CLI args)
    bittrrt.start_server()

if __name__ == "__main__":
    main()
