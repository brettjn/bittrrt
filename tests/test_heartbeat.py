#!/usr/bin/env python3
"""
Test script for heartbeat message encryption and handling.
Demonstrates the new flags-based encryption with URGENT and HEARTBEAT flags.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bittrrt import CommEncryptor, MsgFlags
import time

def test_heartbeat_encryption():
    """Test encrypting and decrypting heartbeat messages with flags."""
    
    print("=== Heartbeat Message Encryption Test ===\n")
    
    # Create two CommEncryptor instances (simulating client and server)
    client_ce = CommEncryptor()
    server_ce = CommEncryptor()
    
    # Exchange public keys
    client_pubkey = client_ce.get_public_key()
    server_pubkey = server_ce.get_public_key()
    
    # Derive shared secrets
    client_ce.derive_shared_secret(server_pubkey)
    server_ce.derive_shared_secret(client_pubkey)
    
    print("✓ Key exchange completed\n")
    
    # Client creates initial heartbeat message
    timestamp = time.time_ns() // 1_000_000  # milliseconds
    client_payload = f"client_ts3={timestamp} echo=2"
    print(f"Client payload: {client_payload}")
    
    # Set URGENT and HEARTBEAT flags
    flags = (1 << MsgFlags.URGENT.value) | (1 << MsgFlags.HEARTBEAT.value)
    print(f"Flags: URGENT={MsgFlags.URGENT.value}, HEARTBEAT={MsgFlags.HEARTBEAT.value}")
    print(f"Combined flags value: {flags} (binary: {bin(flags)})\n")
    
    # Encrypt with flags
    channel = 1
    sequence = 100
    offset = 0
    
    encrypted = client_ce.encrypt(
        client_payload.encode('utf-8'),
        flags=flags,
        channel=channel,
        sequence=sequence,
        offset=offset
    )
    
    print(f"✓ Encrypted {len(encrypted)} bytes\n")
    
    # Server decrypts and checks flags
    decrypted_flags, decrypted_channel, decrypted_sequence, decrypted_offset, decrypted_payload = server_ce.decrypt(encrypted)
    
    print("Server decrypted:")
    print(f"  Flags: {decrypted_flags} (binary: {bin(decrypted_flags)})")
    print(f"  Channel: {decrypted_channel}")
    print(f"  Sequence: {decrypted_sequence}")
    print(f"  Offset: {decrypted_offset}")
    print(f"  Payload: {decrypted_payload.decode('utf-8')}\n")
    
    # Check if HEARTBEAT flag is set
    is_heartbeat = bool(decrypted_flags & (1 << MsgFlags.HEARTBEAT.value))
    is_urgent = bool(decrypted_flags & (1 << MsgFlags.URGENT.value))
    
    print(f"✓ HEARTBEAT flag set: {is_heartbeat}")
    print(f"✓ URGENT flag set: {is_urgent}\n")
    
    # Simulate server response (as would be done in handle_heartbeat)
    if is_heartbeat:
        # Parse payload
        params = {}
        for item in decrypted_payload.decode('utf-8').split():
            if '=' in item:
                key, value = item.split('=', 1)
                params[key] = value
        
        echo = int(params.get('echo', '0'))
        if echo > 0:
            # Add server timestamp
            server_timestamp = time.time_ns() // 1_000_000
            params[f'server_ts{echo}'] = str(server_timestamp)
            params['echo'] = str(echo - 1)
            
            # Create response payload
            response_payload = ' '.join([f'{k}={v}' for k, v in params.items()])
            print(f"Server response payload: {response_payload}\n")
            
            # Encrypt response
            response_encrypted = server_ce.encrypt(
                response_payload.encode('utf-8'),
                flags=flags,
                channel=channel,
                sequence=sequence + 1,
                offset=offset
            )
            
            print(f"✓ Server encrypted response: {len(response_encrypted)} bytes\n")
            
            # Client receives and decrypts response
            resp_flags, resp_channel, resp_sequence, resp_offset, resp_payload = client_ce.decrypt(response_encrypted)
            print("Client received response:")
            print(f"  Payload: {resp_payload.decode('utf-8')}")
            print(f"  Echo value: {resp_payload.decode('utf-8').split('echo=')[1].split()[0]}")
            
            print("\n✓ Heartbeat exchange successful!")
    
    # test functions should not return a value; pytest expects None

def test_3byte_channel():
    """Test that channel is correctly encoded as 3 bytes."""
    
    print("\n=== 3-Byte Channel Test ===\n")
    
    alice = CommEncryptor()
    bob = CommEncryptor()
    
    alice.derive_shared_secret(bob.get_public_key())
    bob.derive_shared_secret(alice.get_public_key())
    
    # Test various channel values
    test_channels = [0, 1, 255, 256, 65535, 16777215]  # 16777215 = 2^24 - 1 (max 3-byte value)
    
    for channel in test_channels:
        plaintext = b"test"
        encrypted = alice.encrypt(plaintext, channel=channel)
        flags, dec_channel, sequence, offset, dec_plaintext = bob.decrypt(encrypted)
        
        assert dec_channel == channel, f"Channel mismatch: {dec_channel} != {channel}"
        assert dec_plaintext == plaintext, "Plaintext mismatch"
        print(f"✓ Channel {channel} (0x{channel:06x}): encrypted and decrypted correctly")
    
    print("\n✓ All 3-byte channel tests passed!")
    # test functions should not return a value; pytest expects None

if __name__ == "__main__":
    try:
        # Run tests as a script: if no exception is raised, exit 0
        test_heartbeat_encryption()
        test_3byte_channel()
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
