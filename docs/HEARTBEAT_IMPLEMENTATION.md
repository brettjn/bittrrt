# Heartbeat Message Encryption Implementation

## Overview

This document describes the implementation of encrypted heartbeat messages with flag-based protocol enhancements to the BittrRt communication system.

## Changes Summary

### 1. CommEncryptor Protocol Changes

#### Header Format Modification
The encrypted message header has been modified from 20 bytes to maintain 20 bytes but with a new structure:

**Old Format:**
- Channel: 4 bytes (unsigned int)
- Sequence: 8 bytes (unsigned long long)
- Offset: 8 bytes (unsigned long long)
- **Total: 20 bytes**

**New Format:**
- Flags: 1 byte (unsigned byte)
- Channel: 3 bytes (24-bit unsigned int)
- Sequence: 8 bytes (unsigned long long)
- Offset: 8 bytes (unsigned long long)
- **Total: 20 bytes**

#### encrypt() Method
- Added `flags` parameter (default: 0)
- Channel parameter now supports 3-byte values (0 to 16,777,215)
- Flags and channel are packed together in the header

**Signature:**
```python
def encrypt(self, plaintext: bytes, associated_data: bytes = b'', 
            flags: int = 0, channel: int = 0, sequence: int = 0, offset: int = 0) -> bytes
```

#### decrypt() Method
- Now returns a tuple: `(flags, channel, sequence, offset, plaintext)`
- Previously returned: `(channel, sequence, offset, plaintext)`

**Signature:**
```python
def decrypt(self, encrypted_data: bytes, associated_data: bytes = b'') 
    -> Tuple[int, int, int, int, bytes]
```

### 2. MsgFlags Enum

The existing `MsgFlags` enum defines bit positions for flag masks:

```python
class MsgFlags(Enum):
    URGENT       = 0  # Bit 0
    HEARTBEAT    = 1  # Bit 1
    FLOW_CONTROL = 2  # Bit 2
    UNLOSSY      = 3  # Bit 3
    BINARY       = 4  # Bit 4
    DATA         = 5  # Bit 5
```

Flags are combined using bitwise OR:
```python
flags = (1 << MsgFlags.URGENT.value) | (1 << MsgFlags.HEARTBEAT.value)
# Result: flags = 3 (binary: 0b11)
```

### 3. PortHandler Changes

#### CommEncryptor Integration
All PortHandler classes now accept and store a CommEncryptor instance:

```python
class PortHandler(ABC):
    def __init__(self, config, comm_encryptor=None):
        self.comm_encryptor = comm_encryptor
        # ... rest of initialization
```

#### New handle_heartbeat() Method
A new method processes heartbeat messages:

```python
def handle_heartbeat(self, payload: bytes, addr: tuple, 
                    flags: int, channel: int, sequence: int, offset: int):
```

**Heartbeat Protocol:**
1. Parse payload for `client_ts3` and `echo` parameters
2. If `echo > 0`:
   - Add `server_ts<echo>=<timestamp>` to payload
   - Decrement `echo` by 1
   - Encrypt with URGENT and HEARTBEAT flags set
   - Send response back to client

#### Modified run() Method
The main loop now:
1. Decrypts received packets using CommEncryptor
2. Checks if HEARTBEAT flag is set
3. Calls `handle_heartbeat()` for heartbeat messages
4. Maintains backward compatibility for non-encrypted packets

### 4. CommConnection Changes

CommConnection now:
- Accepts a `comm_encryptor` parameter in `__init__()`
- Passes the CommEncryptor to all handler instances (CtrlHandler, UpHandler, DnHandler)

### 5. Client Changes

The Client class passes its CommEncryptor instance to the CommConnection:

```python
self.conn = CommConnection(self.config, pm, self.ce)
```

## Heartbeat Message Flow

### Client Initial Heartbeat

**Payload Format:**
```
client_ts3=<timestamp_ms> echo=2
```

**Flags:**
- URGENT flag set (bit 0)
- HEARTBEAT flag set (bit 1)
- Combined value: 3 (0b11)

### Server Response (Echo=2)

When server receives heartbeat with `echo=2`:

**Payload:**
```
client_ts3=<timestamp_ms> echo=1 server_ts2=<server_timestamp_ms>
```

### Server Response (Echo=1)

When server receives heartbeat with `echo=1`:

**Payload:**
```
client_ts3=<timestamp_ms> echo=0 server_ts2=<...> server_ts1=<server_timestamp_ms>
```

### Client Final State (Echo=0)

When server receives heartbeat with `echo=0`, no response is sent (echo is not decremented below 0).

## Testing

### New Test: test_heartbeat.py

Comprehensive test demonstrating:
- Heartbeat message encryption with URGENT and HEARTBEAT flags
- Flag checking after decryption
- Server response generation with timestamp addition
- Echo value decrementing
- 3-byte channel encoding/decoding

Run with:
```bash
python3 tests/test_heartbeat.py
```

### Updated Tests

All existing tests have been updated to handle the new decrypt() return format:
- `test_dh_exchange.py` - Diffie-Hellman exchange tests
- `demo_key_exchange.py` - Key exchange demonstration

## Backward Compatibility

The implementation maintains backward compatibility:
- CommEncryptor parameter is optional (defaults to None)
- When `comm_encryptor` is None, handlers fall back to legacy behavior
- All parameters have sensible defaults (flags=0, channel=0, etc.)

## Implementation Details

### 3-Byte Channel Encoding

Channels are encoded as 3 bytes (big-endian):
```python
# Encoding (4 bytes -> 3 bytes)
channel_bytes = struct.pack('>I', channel & 0xFFFFFF)[1:]  # Take last 3 bytes

# Decoding (3 bytes -> 4 bytes)
channel = struct.unpack('>I', b'\x00' + header[1:4])[0]
```

### Timestamp Format

Timestamps are in milliseconds since epoch:
```python
timestamp = time.time_ns() // 1_000_000  # Convert nanoseconds to milliseconds
```

### Error Handling

- Decryption failures are caught and logged
- Invalid payload formats are handled gracefully
- Socket errors don't crash the handler process

## Example Usage

### Encrypting a Heartbeat Message

```python
from bittrrt import CommEncryptor, MsgFlags
import time

ce = CommEncryptor()
# ... perform key exchange ...

# Create heartbeat payload
timestamp = time.time_ns() // 1_000_000
payload = f"client_ts3={timestamp} echo=2"

# Set flags
flags = (1 << MsgFlags.URGENT.value) | (1 << MsgFlags.HEARTBEAT.value)

# Encrypt
encrypted = ce.encrypt(
    payload.encode('utf-8'),
    flags=flags,
    channel=1,
    sequence=100,
    offset=0
)

# Send encrypted packet...
```

### Decrypting and Checking Flags

```python
# Decrypt received packet
flags, channel, sequence, offset, plaintext = ce.decrypt(encrypted_data)

# Check if HEARTBEAT flag is set
if flags & (1 << MsgFlags.HEARTBEAT.value):
    # Handle heartbeat message
    handle_heartbeat(plaintext, sender_addr, flags, channel, sequence, offset)
```

## Version Information

This implementation is part of BittrRt version 0.6:
- Encrypted header fields with payload in CommEncryptor
- decrypt() returns header fields + plaintext
- Heartbeat message support with stale detection
- Port-recycle improvements
