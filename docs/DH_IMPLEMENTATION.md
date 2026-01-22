# Diffie-Hellman Key Exchange Implementation

## Summary

Successfully implemented Diffie-Hellman key exchange between BittrRt client and server with ChaCha20Poly1305 encryption for secure communication.

## Changes Made

### 1. Constants Added
- `NEGOTIATION_DELAY = 100` (milliseconds)
- `NEGOTIATION_REPEAT = 50` (number of connection attempts)

### 2. CommEncryptor Class Enhancement

The `CommEncryptor` class now supports:
- **X25519 Key Generation**: Generates ephemeral key pairs on instantiation
- **Diffie-Hellman Exchange**: `derive_shared_secret(peer_public_key_bytes)` method
- **ChaCha20Poly1305 Encryption**: `encrypt(plaintext, associated_data=b'')` method
- **ChaCha20Poly1305 Decryption**: `decrypt(encrypted_data, associated_data=b'')` method

Key features:
- Uses HKDF-SHA256 to derive encryption key from shared secret
- Includes 12-byte random nonce with each encrypted message
- Provides authenticated encryption (AEAD) with optional associated data
- Detects tampering and authentication failures

### 3. Client Updates (BittrRtClient)

The client now:
1. Generates an X25519 key pair
2. Sends encrypted "connect" message with public key (repeated up to 50 times)
3. Waits for server's "connected" response (with 100ms timeout per attempt)
4. Performs DH exchange upon receiving server's public key
5. Establishes secure channel ready for ChaCha20Poly1305 communication

### 4. Server Updates (BittrRt)

The server now:
1. Receives and decrypts "connect" messages
2. Generates its own X25519 key pair
3. Performs DH exchange with client's public key
4. Sends encrypted "connected" response with its public key
5. Ready for secure ChaCha20Poly1305 communication

### 5. Protocol Flow

```
CLIENT                                    SERVER
------                                    ------
1. Generate X25519 keypair
2. Create {"cmd":"connect", "pubkey":"..."}
3. Encrypt with DoCrypt(NET_OBS_KEY)
4. Send UDP packet (repeat 50x, 100ms delay)
                                          5. Receive & decrypt packet
                                          6. Generate X25519 keypair
                                          7. Derive shared secret (DH)
                                          8. Create {"cmd":"connected", "pubkey":"..."}
                                          9. Encrypt with DoCrypt(NET_OBS_KEY)
                                         10. Send UDP response
11. Receive & decrypt response
12. Derive shared secret (DH)
13. ✓ Secure channel established

Future communication uses ChaCha20Poly1305 with derived shared key
```

## Security Features

1. **Forward Secrecy**: Each connection uses ephemeral X25519 keys
2. **Obfuscation**: Initial handshake encrypted with NET_OBS_KEY (Fernet)
3. **Authenticated Encryption**: ChaCha20Poly1305 provides confidentiality + integrity
4. **Key Derivation**: HKDF-SHA256 derives encryption key from DH shared secret
5. **Nonce Management**: Random 12-byte nonces prevent replay attacks
6. **Tampering Detection**: Authentication tags detect any modification

## Testing

All existing tests pass (18 tests):
```bash
python3 -m unittest discover -v
```

Additional test scripts:
- `test_dh_exchange.py`: Verifies CommEncryptor encryption/decryption
- `demo_key_exchange.py`: Demonstrates complete handshake flow

## Usage Example

### Server Mode
```bash
python3 bittrrt.py --server
```

### Client Mode
```bash
python3 bittrrt.py [address[:port]]
```

Examples:
```bash
python3 bittrrt.py                    # Connect to 127.0.0.1:6711
python3 bittrrt.py 192.168.1.100      # Connect to 192.168.1.100:6711
python3 bittrrt.py 10.0.0.1:7000      # Connect to 10.0.0.1:7000
```

## Next Steps (Future Enhancements)

1. Store and reuse CommEncryptor instances for established connections
2. Implement session management and timeout handling
3. Add connection pooling for multiple simultaneous clients
4. Implement heartbeat/keepalive using secure channel
5. Add session key rotation for long-lived connections
