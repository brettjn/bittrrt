VERSION = "0.6"
VERSION_NOTE = "Encrypted header fields (channel/sequence/offset) with payload in CommEncryptor; decrypt() now returns header + plaintext. Also heartbeat, stale detection, and port-recycle improvements."

DEBUG_MODE = True

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
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import json
import base64
import traceback

ESTABLISH_LOOP_DELAY = 1_000_000  # microseconds
SYNC_TEST_SLEEP      = 3          # seconds
ESTABLISH_MAX_TIME   = 20_000     # milliseconds
MAIN_RECV_TIMEOUT    = 250_000    # microseconds
MAIN_MAX_PACKETS     = 100        # maximum number of packets to receive in main loop
NEGOTIATION_DELAY    = 1000       # milliseconds
NEGOTIATION_REPEAT   = 50         # number of attempts
PORT_HANDLER_DELAY   = 1000       # milliseconds
CLIENT_CONNECT_DELAY = 1000       # milliseconds
KEEPALIVE_LOOP_DELAY = 5_000_000  # microseconds
NOTIFY_DELAY         = 2000       # milliseconds - how often port handlers notify CommConnection
STALE_CYCLES_MAX     = 5          # number of stale cycles before connection is considered dead
STALE_CYCLES_MAX     = 10         # maximum number of stale cycles before considering a connection dead

NET_OBS_KEY = 'OdiXEOXdvwgWfIizYjdEguhN-IP7eyqp9oITq_0MiBs='


class DoCrypt:
    """Simple wrapper around Fernet for encrypting/decrypting text.

    Initialize with a Fernet key (bytes or str). Methods accept and return
    unicode strings: `fencrypt(text)` -> token string, `fdecrypt(token)` -> text.
    """

    def __init__(self, key):
        # Accept either a str or bytes key
        if isinstance(key, str):
            key = key.encode('utf-8')
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError('Fernet key must be bytes or str')
        
        self._fernet  = Fernet(key)
        self.inc_salt = 0

    def fencrypt(self, text: str) -> str:
        """Encrypt `text` and return a token string.

        Args:
            text: plaintext to encrypt

        Returns:
            URL-safe base64-encoded token as `str`
        """
        if not isinstance(text, str):
            raise TypeError('text must be a str')

        # Prepend an 8-byte (64-bit) incrementing salt to the plaintext
        plaintext_bytes = text.encode('utf-8')
        salt_bytes = struct.pack('>Q', self.inc_salt & 0xFFFFFFFFFFFFFFFF)
        to_encrypt = salt_bytes + plaintext_bytes

        # Increment salt modulo 2**64 for next encryption
        self.inc_salt = (self.inc_salt + 1) & 0xFFFFFFFFFFFFFFFF

        token = self._fernet.encrypt(to_encrypt)
        return token.decode('utf-8')

    def fdecrypt(self, token: str) -> str:
        """Decrypt `token` (str) and return plaintext string.

        Raises `ValueError` if token is invalid or cannot be decrypted.
        """
        if not isinstance(token, str):
            raise TypeError('token must be a str')
        try:
            data = self._fernet.decrypt(token.encode('utf-8'))
        except InvalidToken as e:
            raise ValueError('Invalid token or decryption failed') from e

        # Expect at least eight bytes (the 64-bit salt) followed by the original plaintext
        if len(data) < 8:
            raise ValueError('Decrypted data too short (missing 8-byte salt)')

        # Strip the leading 8-byte salt and return the plaintext
        plaintext_bytes = data[8:]
        return plaintext_bytes.decode('utf-8')


class CommEncryptor:
    """Generate an X25519 key pair for Diffie-Hellman key exchange.

    On instantiation this generates a new private/public key pair and
    exposes the public key as raw bytes via the `public_key_bytes` attribute.

    After receiving the peer's public key, call `derive_shared_secret()` to
    perform the key exchange and set up ChaCha20Poly1305 encryption.

    Example:
        ce = CommEncryptor()
        pub = ce.public_key_bytes  # 32 bytes
        ce.derive_shared_secret(peer_public_key_bytes)
        ciphertext = ce.encrypt(b"hello")
        plaintext = ce.decrypt(ciphertext)
    """

    def __init__(self):
        # Generate private/public key pair
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Public key as raw bytes (32 bytes)
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # ChaCha20Poly1305 cipher (set after derive_shared_secret)
        self.cipher = None

    def get_public_key(self) -> bytes:
        """Return the public key as raw bytes (32 bytes)."""
        return self.public_key_bytes
    
    def derive_shared_secret(self, peer_public_key_bytes: bytes) -> None:
        """Perform Diffie-Hellman key exchange and derive shared secret.
        
        Args:
            peer_public_key_bytes: The peer's X25519 public key (32 bytes)
        """
        # Load peer's public key from raw bytes
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        
        # Perform DH exchange to get shared secret
        shared_secret = self.private_key.exchange(peer_public_key)
        
        # Derive a 32-byte key from the shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'bittrrt-chacha20poly1305',
        ).derive(shared_secret)
        
        # Initialize ChaCha20Poly1305 cipher with derived key
        self.cipher = ChaCha20Poly1305(derived_key)
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = b'', channel: int = 0, sequence: int = 0, offset: int = 0) -> bytes:
        """Encrypt plaintext using ChaCha20Poly1305.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Optional associated data (authenticated but not encrypted)
            
        Returns:
            Nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        if self.cipher is None:
            raise RuntimeError("Must call derive_shared_secret() before encrypting")
        
        # Generate a random 12-byte nonce
        nonce = os.urandom(12)

        # Pack channel (4 bytes unsigned), sequence (8 bytes unsigned), offset (8 bytes unsigned)
        header = struct.pack('>IQQ', int(channel) & 0xFFFFFFFF, int(sequence) & 0xFFFFFFFFFFFFFFFF, int(offset) & 0xFFFFFFFFFFFFFFFF)

        # Prepend header to plaintext so header is encrypted/authenticated with the payload
        to_encrypt = header + plaintext

        # Encrypt and authenticate (ciphertext includes the auth tag)
        ciphertext = self.cipher.encrypt(nonce, to_encrypt, associated_data)

        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes, associated_data: bytes = b''):
        """Decrypt data encrypted with ChaCha20Poly1305.
        
        Args:
            encrypted_data: Nonce (12 bytes) + ciphertext + tag
            associated_data: Optional associated data (must match encryption)
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If authentication fails or data is invalid
        """
        if self.cipher is None:
            raise RuntimeError("Must call derive_shared_secret() before decrypting")
        
        # Expect at least: nonce (12) + auth tag (16)
        min_len = 12 + 16
        if len(encrypted_data) < min_len:
            raise ValueError("Encrypted data too short (missing nonce/ciphertext)")

        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Decrypt and verify authentication
        try:
            decrypted = self.cipher.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        # Decrypted payload must contain header (4+8+8 = 20 bytes) followed by plaintext
        if len(decrypted) < 20:
            raise ValueError("Decrypted payload too short (missing header)")

        header = decrypted[:20]
        plaintext = decrypted[20:]

        try:
            channel, sequence, offset = struct.unpack('>IQQ', header)
        except Exception as e:
            raise ValueError(f"Failed to parse header fields: {e}")

        # Return header fields and plaintext bytes
        return channel, sequence, offset, plaintext

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

    def close(self):
        """Shutdown all handler subprocesses by sending STOP messages and waiting for them to terminate."""
        handlers = [
            (self.ctrl_handler, PortType.CONTROL, "Control"),
            (self.upld_handler, PortType.UPLOAD, "Upload"),
            (self.dnld_handler, PortType.DOWNLOAD, "Download")
        ]
        
        # Send STOP messages to all alive handlers
        for handler, port_type, name in handlers:
            if handler is not None and handler.process.is_alive():
                print(f"SyncTest: Sending STOP to {name} handler")
                self.recv_queues[port_type].put(CommMsg.STOP)
        
        # Wait for all processes to terminate
        for handler, port_type, name in handlers:
            if handler is not None:
                if handler.process.is_alive():
                    print(f"SyncTest: Waiting for {name} handler to terminate...")
                    handler.process.join(timeout=5.0)
                    if handler.process.is_alive():
                        print(f"SyncTest: {name} handler did not terminate, forcing termination")
                        handler.process.terminate()
                        handler.process.join(timeout=1.0)
                        if handler.process.is_alive():
                            print(f"SyncTest: {name} handler still alive, killing")
                            handler.process.kill()
                else:
                    print(f"SyncTest: {name} handler already terminated")
        
        print("SyncTest: All handlers shut down")

class CommConnection(Connection):
    """A communication connection initially identical to SyncTest.

    This class is a placeholder duplicate of `SyncTest` and can be
    specialized later for communication-specific behavior.
    """
    def __init__(self, config, port_manager):
        super().__init__(config, port_manager)
        self.send_queues:  Dict[PortType, multiprocessing.Queue]  = None
        self.recv_queues:  Dict[PortType, multiprocessing.Queue]  = None

        self.ctrl_handler: Optional[CtrlHandler]                  = None
        self.upld_handler:   Optional[UpHandler]                  = None
        self.dnld_handler:   Optional[DnHandler]                  = None

        self.from_handler                                         = multiprocessing.Queue()

        self.sent_start_commands: bool                            = False
        self.ctrl_port                                            = None
        self.up_port                                              = None
        self.dn_port                                              = None
        self._established                                         = False
        
        # Track inpacket counts from handlers for stale detection
        self.handler_inpacket_counts: Dict[str, int]              = {}
        self.stale_cycles                                         = 0

    def is_established(self):
        return self._established

    def run_once(self):
        # minimal action for a comm connection
        print("CommConnection: run_once called")
        if not self._established:
            return True
        
        # Read all available notifications from handlers
        any_count_increased = False
        while True:
            try:
                msg = self.from_handler.get_nowait()
                if isinstance(msg, dict) and "handler" in msg and "inpacket_count" in msg:
                    handler_name = msg["handler"]
                    new_count = msg["inpacket_count"]
                    
                    # Check if this is the first time we've seen this handler
                    if handler_name not in self.handler_inpacket_counts:
                        self.handler_inpacket_counts[handler_name] = new_count
                        print(f"CommConnection: First count from {handler_name}: {new_count}")
                    else:
                        # Check if count has increased
                        old_count = self.handler_inpacket_counts[handler_name]
                        if new_count > old_count:
                            any_count_increased = True
                            print(f"CommConnection: {handler_name} count increased: {old_count} -> {new_count}")
                        self.handler_inpacket_counts[handler_name] = new_count
                else:
                    print(f"CommConnection: received message from handler: {msg}")
            except:
                # No more messages in queue
                break
        
        # Update stale cycles
        if any_count_increased:
            # Reset stale counter if any handler showed activity
            if self.stale_cycles > 0:
                print(f"CommConnection: Resetting stale cycles (was {self.stale_cycles})")
            self.stale_cycles = 0
        else:
            # Only increment if we have received at least one notification from each handler
            expected_handlers = {"CtrlHandler", "UpHandler", "DnHandler"}
            if expected_handlers.issubset(set(self.handler_inpacket_counts.keys())):
                self.stale_cycles += 1
                print(f"CommConnection: Stale cycles: {self.stale_cycles}/{STALE_CYCLES_MAX}")
                
                if self.stale_cycles >= STALE_CYCLES_MAX:
                    print(f"CommConnection: Connection is stale (exceeded {STALE_CYCLES_MAX} cycles)", file=sys.stderr)
                    return False
        
        return True
        

    def establish(self):
        # For testing, establish once and return True so it gets moved
        
        msg=None
        try:
            msg=self.from_handler.get_nowait()
        except:
            pass

        if msg:
            print("CommConnection: received message from handler:", msg)

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
                self.ctrl_port = self.port_manager.get_next_port()
                print(f"attempting to instantiate CTRL_HANDLER on port {self.ctrl_port}")
                if self.ctrl_port is None:
                    print("CommConnection: Failed to get control port")
                    return False
                self.ctrl_handler = CtrlHandler(
                    self.ctrl_port,
                    self.send_queues,
                    self.recv_queues,
                    self.from_handler,
                    self.config
                )
                return
            
            if not self.ctrl_handler.process.is_alive():
                print("CommConnection: Control handler process is not alive - removing")
                self.ctrl_handler = None
                return False
            
            # Instantiate upld_handler if it doesn't exist
            if self.upld_handler is None:
                self.up_port = self.port_manager.get_next_port()
                print(f"attempting to instantiate UP_HANDLER on port {self.up_port}")
                if self.up_port is None:
                    print("CommConnection: Failed to get upload port")
                    return False
                self.upld_handler = UpHandler(
                    self.up_port,
                    self.send_queues,
                    self.recv_queues,
                    self.from_handler,
                    self.config
                )
                return
            
            if not self.upld_handler.process.is_alive():
                print("CommConnection: Upload handler process is not alive")
                return False
            
            # Instantiate dnld_handler if it doesn't exist
            if self.dnld_handler is None:
                self.dn_port = self.port_manager.get_next_port()
                print(f"attempting to instantiate DN_HANDLER on port {self.dn_port}")
                if self.dn_port is None:
                    print("CommConnection: Failed to get download port")
                    return False
                self.dnld_handler = DnHandler(
                    self.dn_port,
                    self.send_queues,
                    self.recv_queues,
                    self.from_handler,
                    self.config
                )
                return
            
            if not self.dnld_handler.process.is_alive():    
                print("CommConnection: Download handler process is not alive")
                return False

            if self.ctrl_handler.process.is_alive() and self.upld_handler.process.is_alive() and self.dnld_handler.process.is_alive():
                print("CommConnection: All handlers alive")
                if not self.sent_start_commands:
                    self.recv_queues[PortType.CONTROL].put(CommMsg.START)
                    self.recv_queues[PortType.UPLOAD].put(CommMsg.START)
                    self.recv_queues[PortType.DOWNLOAD].put(CommMsg.START)
                    self.sent_start_commands = True
                else:
                    print("CommConnection: establish successful SETTING _established = True")
                    self._established = True
                    return True
                
        return False

    def close(self):
        """Shutdown all handler subprocesses by sending STOP messages and waiting for them to terminate."""
        handlers = [
            (self.ctrl_handler, PortType.CONTROL, "Control"),
            (self.upld_handler, PortType.UPLOAD, "Upload"),
            (self.dnld_handler, PortType.DOWNLOAD, "Download")
        ]
        
        # Send STOP messages to all alive handlers
        for handler, port_type, name in handlers:
            if handler is not None and handler.process.is_alive():
                print(f"CommConnection: Sending STOP to {name} handler")
                self.recv_queues[port_type].put(CommMsg.STOP)
        
        # Wait for all processes to terminate
        for handler, port_type, name in handlers:
            if handler is not None:
                if handler.process.is_alive():
                    print(f"CommConnection: Waiting for {name} handler to terminate...")
                    handler.process.join(timeout=5.0)
                    if handler.process.is_alive():
                        print(f"CommConnection: {name} handler did not terminate, forcing termination")
                        handler.process.terminate()
                        handler.process.join(timeout=1.0)
                        if handler.process.is_alive():
                            print(f"CommConnection: {name} handler still alive, killing")
                            handler.process.kill()
                else:
                    print(f"CommConnection: {name} handler already terminated")
        
        print("CommConnection: All handlers shut down")
    
    def release_ports(self):
        """Return the three ports used by this connection back to the port manager."""
        if self.ctrl_port is not None:
            released = self.port_manager.release_port(self.ctrl_port)
            print(f"CommConnection: Released ctrl_port {self.ctrl_port}: {released}")
            self.ctrl_port = None
        
        if self.up_port is not None:
            released = self.port_manager.release_port(self.up_port)
            print(f"CommConnection: Released up_port {self.up_port}: {released}")
            self.up_port = None
        
        if self.dn_port is not None:
            released = self.port_manager.release_port(self.dn_port)
            print(f"CommConnection: Released dn_port {self.dn_port}: {released}")
            self.dn_port = None

class Client:
    def __init__(self, config, addr, client_pubkey_b64, pm, ary_connections):
        self.addr              = addr
        self.ce                = CommEncryptor()   
        self.server_pubkey_b64 = base64.urlsafe_b64encode(self.ce.get_public_key()).decode('ascii')
        self.config            = config
        self.conn              = None

        # Decode the base64 public key and perform DH exchange on server side
        client_pubkey_bytes = base64.urlsafe_b64decode(client_pubkey_b64)
        self.ce.derive_shared_secret(client_pubkey_bytes)    

        # Ensure we have enough available ports to create a communication instance
        
        if pm is None:
            print("Error: PortManager not initialized; cannot start Client.", file=sys.stderr)
            sys.exit(1)
        if pm.get_available_port_count() < 3:
            print("Error: Not enough available ports for Client (need >=3).", file=sys.stderr)
            raise RuntimeError("Not enough available ports for Client (need >=3).")
        self.conn = CommConnection(self.config, pm)
        ary_connections.append(self.conn)

    def get_server_public_key_b64(self):
        return self.server_pubkey_b64
    
    def is_established(self):
        result = self.conn is not None and self.conn.is_established()
        print(f"is_established returning {result}")
        return result
    
    def get_port_numbers(self):
        """Get the three port numbers used by the connection handlers."""
        if self.conn is None:
            return None, None, None
        return self.conn.ctrl_port, self.conn.up_port, self.conn.dn_port
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using the established CommEncryptor."""
        return self.ce.encrypt(data)

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

        self.dc              = DoCrypt(NET_OBS_KEY)
        self.clients         = {}

        # running flag for the main loop
        self.running = False


    def start_server(self):
        """Prepare connections (optionally add SyncTest) and start the run loop."""
        # Setup UDP socket on bind_addr and bind_port
        bind_addr = self.config.get("bind_addr", "0.0.0.0")
        bind_port = int(self.config.get("bind_port", 6711))
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((bind_addr, bind_port))
            # Set socket to non-blocking mode for timeout handling
            timeout_seconds = MAIN_RECV_TIMEOUT / 1_000_000.0  # convert microseconds to seconds
            self.socket.settimeout(timeout_seconds)
            print(f"BittrRt: UDP socket bound to {bind_addr}:{bind_port}")
        except OSError as e:
            print(f"Error: Failed to create UDP socket on {bind_addr}:{bind_port}: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: Unexpected error setting up UDP socket: {e}", file=sys.stderr)
            sys.exit(1)
        
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
            edlp = LoopDelay(KEEPALIVE_LOOP_DELAY)

            while self.running:
                # Try to receive UDP packets
                ary_packets = []
                try:
                    try:
                        timeout_seconds = MAIN_RECV_TIMEOUT / 1_000_000.0  # convert microseconds to seconds
                        self.socket.settimeout(timeout_seconds)
                        data, addr = self.socket.recvfrom(65535)  # max UDP packet size
                        ary_packets.append((data, addr))
                        self.socket.settimeout(0.0)
                        while len(ary_packets) < MAIN_MAX_PACKETS:
                            data, addr = self.socket.recvfrom(65535)  # max UDP packet size
                            ary_packets.append((data, addr))
                    except socket.timeout:
                        # Timeout reached, no more packets available
                        pass
                    except BlockingIOError:
                        # No data available (shouldn't happen with timeout set)
                        pass
                except Exception as e:
                    print(f"Error receiving UDP packets: {e}", file=sys.stderr)
                
                # Process received packets (placeholder for future implementation)
                if ary_packets:
                    print(f"\nReceived {len(ary_packets)} UDP packet(s)")
                    self._handle_packets(ary_packets)
                
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
                            keep_alive = c.run_once()
                            if keep_alive is False:
                                print(f"\nConnection is stale, closing and cleaning up", file=sys.stderr)
                                try:
                                    c.close()
                                except Exception as e:
                                    print(f"Error closing stale connection: {e}", file=sys.stderr)
                                
                                # Release ports back to port manager if this is a CommConnection
                                if isinstance(c, CommConnection):
                                    try:
                                        c.release_ports()
                                    except Exception as e:
                                        print(f"Error releasing ports: {e}", file=sys.stderr)
                                
                                # Remove from established connections
                                try:
                                    self.ary_established.remove(c)
                                except ValueError:
                                    pass
                        except Exception as e:
                            print(f"Connection run_once error: {e}", file=sys.stderr)


                # indicate liveliness and sleep
                if DEBUG_MODE:
                    print('b', end='', flush=True)
                #time.sleep(0.25)

        except KeyboardInterrupt:
            print("\nReceived SIGINT, shutting down...", file=sys.stderr)
            self.running = False
            # Close the UDP socket
            try:
                self.socket.close()
            except Exception as e:
                print(f"Error closing UDP socket: {e}", file=sys.stderr)
            # Cleanly shutdown all connections
            for c in list(self.ary_established) + list(self.ary_connections):
                try:
                    c.close()
                except Exception as e:
                    print(f"Error closing connection: {e}", file=sys.stderr)
            sys.exit(0)

    def _handle_connect(self, payload, addr):
        """Handle a 'connect' command from a client."""
        client = None
        try:
            if self.clients.get(addr):  
                client = self.clients[addr]
                print(f"Client {addr} is already connected")
                
            else:
                client_pubkey_b64 = payload["pubkey"]
                try:
                    client = Client(self.config, addr, client_pubkey_b64,self.port_manager, self.ary_connections)
                    self.clients[addr] = client
                except RuntimeError as e:
                    # Not enough ports available - send error message to client
                    error_response = {"cmd": "error", "message": str(e)}
                    error_json = json.dumps(error_response)
                    error_token = self.dc.fencrypt(error_json)
                    self.socket.sendto(error_token.encode('utf-8'), addr)
                    print(f"Sent error response to client {addr}: {e}", file=sys.stderr)
                    return
            
            # Send "connected" response
            response = {"cmd": "connected", "pubkey": client.get_server_public_key_b64()}
            response_json = json.dumps(response)
            response_token = self.dc.fencrypt(response_json)
            
            self.socket.sendto(response_token.encode('utf-8'), addr)
            print(f"\nNegotiated secure channel with client {addr}")
            
            # If the client connection is established, send port numbers
            if client.is_established():
                ctrl_port, up_port, dn_port = client.get_port_numbers()
                if ctrl_port is not None and up_port is not None and dn_port is not None:
                    port_data = json.dumps({
                        "cmd": "ports",
                        "ctrl_port": ctrl_port,
                        "up_port": up_port,
                        "dn_port": dn_port
                    })
                    encrypted_port_data = client.encrypt_data(port_data.encode('utf-8'))
                    self.socket.sendto(encrypted_port_data, addr)
                    print(f"Sent port numbers to client {addr}: ctrl={ctrl_port}, up={up_port}, dn={dn_port}")
        except Exception as e:
            print(f"Error handling connect from {addr}: {e}", file=sys.stderr)
            stack_trace = traceback.format_exc()
            print(stack_trace, file=sys.stderr) 
            sys.stderr.flush()

    def _handle_packets(self, ary_packets):
        """Handle incoming UDP packets, including connection negotiation."""
        
        for data, addr in ary_packets:
            try:
                # Decrypt the packet
                token = data.decode('utf-8')
                payload_json = self.dc.fdecrypt(token)
                payload = json.loads(payload_json)
                
                # Handle "connect" command
                if payload.get("cmd") == "connect" and "pubkey" in payload:
                    self._handle_connect(payload, addr)
                    
            except Exception as e:
                print(f"Error handling packet from {addr}: {e}", file=sys.stderr)
                    


class PortHandler(ABC):
    def __init__(self, config):
        self.config             = config
        self.sync_sleep         = 0
        self.inpacket           = None
        self.inpacket_count     = 0
        self.last_notify_time   = None  # Track when we last sent notification

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
            self.usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
                # Set socket timeout for non-blocking receives
                if PORT_HANDLER_DELAY > 0:
                    self.usock.settimeout(PORT_HANDLER_DELAY / 1000.0)
                    print(f"{self.__class__.__name__} socket timeout set to {PORT_HANDLER_DELAY} ms")
            except Exception as e:
                print(f"Error setting socket timeout in {self.__class__.__name__}: {e}", file=sys.stderr)
                stack_trace = traceback.format_exc()
                print(stack_trace, file=sys.stderr)
                sys.stderr.flush()  
                return
            
            running = True
            self.last_notify_time = time.perf_counter_ns() // 1_000_000  # milliseconds
            try:
                while running:
                    try:
                        # Process incoming messages
                        if not self.recv_queue[self.port_type()].empty():
                            msg = self.recv_queue[self.port_type()].get()
                            should_continue = self.handle_message(msg)
                            if should_continue is False:
                                running = False
                                break
                    except Exception as e:
                        print(f"Error in {self.__class__.__name__} run loop: {e}", file=sys.stderr)

                    try:
                        data, addr = self.usock.recvfrom(1500)
                        # Print received heartbeat to stderr
                        print(f"{self.__class__.__name__} received heartbeat from {addr}: {data.decode('utf-8', errors='ignore')}", file=sys.stderr)
                        self.inpacket = data
                        self.inpacket_count += 1
                    except socket.timeout:
                        pass
                    except Exception as e:
                        print(f"Error receiving data in {self.__class__.__name__}: {e}", file=sys.stderr)

                    # Check if it's time to send notification to CommConnection
                    current_time = time.perf_counter_ns() // 1_000_000  # milliseconds
                    if current_time - self.last_notify_time >= NOTIFY_DELAY:
                        self.last_notify_time = current_time
                        notification = {
                            "handler": self.__class__.__name__,
                            "inpacket_count": self.inpacket_count
                        }
                        try:
                            self.to_comm.put_nowait(notification)
                        except Exception as e:
                            print(f"Error sending notification from {self.__class__.__name__}: {e}", file=sys.stderr)

                    self.iter()
            except KeyboardInterrupt:
                # Gracefully handle CTRL-C in subprocess
                pass
            
            print(f"{self.__class__.__name__} shutting down")
            try:
                self.usock.close()
            except:
                pass


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
        if self.inpacket is not None:
            print(f"{self.__class__.__name__} received packet: {self.inpacket}")
            self.inpacket = None
        print('(CH)', end='', flush=True)
        time.sleep(self.sync_sleep)    

    def handle_message(self, msg):
        """Handle a message received from the queue. Returns False to stop the loop."""
        print(f"{self.__class__.__name__} received message: {msg}")
        if msg == CommMsg.STOP:
            return False
        return True

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
        return(PortType.UPLOAD)

    def iter(self):
        if self.inpacket is not None:
            print(f"{self.__class__.__name__} received packet: {self.inpacket}")
            self.inpacket = None
        print('(UH)', end='', flush=True)
        time.sleep(self.sync_sleep)    

    def handle_message(self, msg):
        """Handle a message received from the queue. Returns False to stop the loop."""
        print(f"{self.__class__.__name__} received message: {msg}")
        if msg == CommMsg.STOP:
            return False
        return True

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
        return(PortType.DOWNLOAD)

    def iter(self):
        if self.inpacket is not None:
            print(f"{self.__class__.__name__} received packet: {self.inpacket}")
            self.inpacket = None
        print('(DH)', end='', flush=True)
        time.sleep(self.sync_sleep)    

    def handle_message(self, msg):
        """Handle a message received from the queue. Returns False to stop the loop."""
        print(f"{self.__class__.__name__} received message: {msg}")
        if msg == CommMsg.STOP:
            return False
        return True

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


class BittrRtClient:
    """Client helper to send an encrypted UDP 'connect' message to server.

    Usage: instantiate with the `argv` list (typically `sys.argv`) and call
    `run()` which returns True on success, False on failure.
    """

    def __init__(self, argv, net_obs_key=NET_OBS_KEY):
        self.argv = list(argv)
        self.net_obs_key = net_obs_key

    def _parse_target(self):
        address = "127.0.0.1"
        port = 6711
        addr_arg = None
        for arg in self.argv[1:]:
            if not isinstance(arg, str):
                continue
            if not arg.startswith('-'):
                addr_arg = arg
                break
        if addr_arg:
            if ':' in addr_arg:
                parts = addr_arg.split(':', 1)
                address = parts[0] if parts[0] else address
                try:
                    port = int(parts[1])
                except Exception:
                    # keep default port on parse error
                    pass
            else:
                address = addr_arg
        return address, port

    def run(self) -> bool:
        address, port = self._parse_target()
        # Generate an X25519 keypair and get the public key bytes
        ce = CommEncryptor()
        pubkey_bytes = ce.get_public_key()
        # Encode public key bytes as URL-safe base64 string for JSON transport
        pubkey_b64 = base64.urlsafe_b64encode(pubkey_bytes).decode('ascii')

        payload = {"cmd": "connect", "pubkey": pubkey_b64}
        payload_json = json.dumps(payload)

        try:
            dc = DoCrypt(self.net_obs_key)
            
        except Exception as e:
            print(f"Error: failed to encrypt payload: {e}", file=sys.stderr)
            return False
        
        send_timestamp = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(NEGOTIATION_DELAY / 1000.0)  # Convert ms to seconds
            
            # Send connect repeatedly and wait for response
            got_pubkey = False
            for attempt in range(NEGOTIATION_REPEAT):
                token = dc.fencrypt(payload_json)
                if send_timestamp is None or (time.time() - send_timestamp) * 1000 >= CLIENT_CONNECT_DELAY:
                    sock.sendto(token.encode('utf-8'), (address, port))
                    send_timestamp = time.time()
                
                # Try to receive a response
                try:
                    print("Waiting for response from server...", file=sys.stderr)
                    response_data, server_addr = sock.recvfrom(4096)

                    if got_pubkey:
                        # We've already got the pubkey, so this should be the port numbers
                        # Try to decrypt using CommEncryptor (binary data, not UTF-8 encoded)
                        try:
                            channel, sequence, offset, decrypted_port_data = ce.decrypt(response_data)
                            port_info = json.loads(decrypted_port_data.decode('utf-8'))

                            if port_info.get("cmd") == "ports":
                                ctrl_port = port_info.get("ctrl_port")
                                up_port = port_info.get("up_port")
                                dn_port = port_info.get("dn_port")

                                print(f"Received port numbers: ctrl={ctrl_port}, up={up_port}, dn={dn_port} (hdr: ch={channel}, seq={sequence}, off={offset})", file=sys.stderr)

                                # Start heartbeat to the three ports
                                self._start_heartbeat(address, ctrl_port, up_port, dn_port)
                                sock.close()
                                return True
                        except Exception as e:
                            print(f"Error decrypting port data: {e}", file=sys.stderr)
                            # Continue to try again
                            continue
                    
                    # Try to decrypt as a DoCrypt message (the "connected" response)
                    try:
                        print("Decrypting response from server...", file=sys.stderr)
                        response_token = response_data.decode('utf-8')
                        response_json = dc.fdecrypt(response_token)
                        response = json.loads(response_json)
                        
                        # Check if it's an error response
                        if response.get("cmd") == "error":
                            error_msg = response.get("message", "Unknown error")
                            print(f"\nError from server: {error_msg}", file=sys.stderr)
                            sock.close()
                            return False
                        
                        # Check if it's a "connected" response
                        if response.get("cmd") == "connected" and "pubkey" in response:
                            if not got_pubkey:
                                server_pubkey_b64 = response["pubkey"]
                                server_pubkey_bytes = base64.urlsafe_b64decode(server_pubkey_b64)
                            
                                # Perform DH exchange
                                ce.derive_shared_secret(server_pubkey_bytes)
                                
                                print(f"Successfully connected to {address}:{port}", file=sys.stderr)
                                print(f"Established secure channel with server", file=sys.stderr)
                                got_pubkey = True
                    except Exception as e:
                        # If decryption fails, might be port data, will try on next iteration
                        pass
                    
                except socket.timeout:
                    # No response yet, continue trying
                    continue
                except Exception as e:
                    print(f"Error receiving/decrypting response: {e}", file=sys.stderr)
                    continue
            
            sock.close()
            print(f"Failed to establish connection after {NEGOTIATION_REPEAT} attempts", file=sys.stderr)
            return False
            
        except Exception as e:
            print(f"Error sending UDP packet to {address}:{port}: {e}", file=sys.stderr)
            return False
    
    def _start_heartbeat(self, address, ctrl_port, up_port, dn_port):
        """Start sending heartbeat messages to the three ports."""
        # Read heartbeat_rate from config or use default
        config_path = os.path.expanduser("~/.bittrrt/config")
        heartbeat_rate = 5000  # Default: 5 seconds in milliseconds
        
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        if key.strip() == "heartbeat_rate":
                            try:
                                heartbeat_rate = int(value.strip())
                            except ValueError:
                                pass
        
        # Create three UDP sockets
        try:
            ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            print(f"Starting heartbeat every {heartbeat_rate}ms")
            
            # Send heartbeats in a loop
            heartbeat_count = 0
            while True:
                heartbeat_msg = f"heartbeat-{heartbeat_count}".encode('utf-8')
                
                ctrl_sock.sendto(heartbeat_msg, (address, ctrl_port))
                up_sock.sendto(heartbeat_msg, (address, up_port))
                dn_sock.sendto(heartbeat_msg, (address, dn_port))
                
                heartbeat_count += 1
                time.sleep(heartbeat_rate / 1000.0)  # Convert ms to seconds
                
        except KeyboardInterrupt:
            print("\nHeartbeat stopped by user")
            ctrl_sock.close()
            up_sock.close()
            dn_sock.close()
        except Exception as e:
            print(f"Error in heartbeat: {e}", file=sys.stderr)


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

    # Validate unknown dash-arguments: any argument that starts with a dash
    # but is not a recognized CLI option should cause an error and exit.
    known_args = set(cli_arg_map.keys()) | {"--sync-test", "--create-config", "--server"}
    for arg in argv[1:]:
        if isinstance(arg, str) and arg.startswith("-") and arg not in known_args:
            print(f"Error: Unknown argument '{arg}'", file=sys.stderr)
            sys.exit(1)

    for arg, key in cli_arg_map.items():
        if arg in argv:
            idx = argv.index(arg)
            if idx + 1 < len(argv):
                config[key] = argv[idx + 1]

    # Flags without values
    if "--sync-test" in argv:
        config["--sync-test"] = True
    # If --server is provided, run in server mode; otherwise run client mode
    server_mode = "--server" in argv

    if not server_mode:
        # Client mode: delegate to BittrRtClient
        client = BittrRtClient(argv)
        success = client.run()
        sys.exit(0 if success else 1)

    # Server mode: Initialize BittrRt with merged config (file + CLI overrides)
    bittrrt = BittrRt(config)
    # Start the server main loop (may add test connections via config)
    bittrrt.start_server()

if __name__ == "__main__":
    main()
