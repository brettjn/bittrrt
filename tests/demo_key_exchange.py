#!/usr/bin/env python3
"""Demo script showing the Diffie-Hellman key exchange flow."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Get the path of the current script's directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory's path
parent_dir = os.path.dirname(current_dir)

# Add the parent directory to sys.path (insert at index 0 to prioritize)
sys.path.insert(0, parent_dir)

from bittrrt import CommEncryptor, DoCrypt, NET_OBS_KEY
import json
import base64

def demo_exchange():
    """Demonstrate the complete key exchange process."""
    print("=== Diffie-Hellman Key Exchange Demo ===\n")
    
    # Step 1: Client generates key pair
    print("1. CLIENT: Generate X25519 key pair")
    client_ce = CommEncryptor()
    client_pubkey = client_ce.get_public_key()
    print(f"   Client public key: {base64.b64encode(client_pubkey).decode()[:40]}...")
    
    # Step 2: Client creates connect message
    print("\n2. CLIENT: Create 'connect' message with public key")
    client_pubkey_b64 = base64.urlsafe_b64encode(client_pubkey).decode('ascii')
    connect_payload = {"cmd": "connect", "pubkey": client_pubkey_b64}
    connect_json = json.dumps(connect_payload)
    print(f"   Payload: {connect_json[:80]}...")
    
    # Step 3: Client encrypts with NET_OBS_KEY
    print("\n3. CLIENT: Encrypt with DoCrypt (NET_OBS_KEY)")
    dc = DoCrypt(NET_OBS_KEY)
    connect_encrypted = dc.fencrypt(connect_json)
    print(f"   Encrypted token: {connect_encrypted[:60]}...")
    
    # ===== NETWORK TRANSMISSION =====
    print("\n" + "="*50)
    print("   >>> UDP packet sent to server >>>")
    print("="*50)
    
    # Step 4: Server receives and decrypts
    print("\n4. SERVER: Receive and decrypt with DoCrypt")
    server_decrypted = dc.fdecrypt(connect_encrypted)
    server_payload = json.loads(server_decrypted)
    print(f"   Received cmd: {server_payload['cmd']}")
    client_pubkey_received = base64.urlsafe_b64decode(server_payload['pubkey'])
    print(f"   Client public key: {base64.b64encode(client_pubkey_received).decode()[:40]}...")
    
    # Step 5: Server generates its own key pair
    print("\n5. SERVER: Generate X25519 key pair")
    server_ce = CommEncryptor()
    server_pubkey = server_ce.get_public_key()
    print(f"   Server public key: {base64.b64encode(server_pubkey).decode()[:40]}...")
    
    # Step 6: Server performs DH exchange
    print("\n6. SERVER: Perform Diffie-Hellman exchange")
    server_ce.derive_shared_secret(client_pubkey_received)
    print("   ✓ Server derived shared secret")
    
    # Step 7: Server creates connected response
    print("\n7. SERVER: Create 'connected' response with public key")
    server_pubkey_b64 = base64.urlsafe_b64encode(server_pubkey).decode('ascii')
    connected_payload = {"cmd": "connected", "pubkey": server_pubkey_b64}
    connected_json = json.dumps(connected_payload)
    print(f"   Payload: {connected_json[:80]}...")
    
    # Step 8: Server encrypts response
    print("\n8. SERVER: Encrypt response with DoCrypt")
    connected_encrypted = dc.fencrypt(connected_json)
    print(f"   Encrypted token: {connected_encrypted[:60]}...")
    
    # ===== NETWORK TRANSMISSION =====
    print("\n" + "="*50)
    print("   <<< UDP packet sent back to client <<<")
    print("="*50)
    
    # Step 9: Client receives and decrypts
    print("\n9. CLIENT: Receive and decrypt response")
    client_response = dc.fdecrypt(connected_encrypted)
    response_payload = json.loads(client_response)
    print(f"   Received cmd: {response_payload['cmd']}")
    server_pubkey_received = base64.urlsafe_b64decode(response_payload['pubkey'])
    print(f"   Server public key: {base64.b64encode(server_pubkey_received).decode()[:40]}...")
    
    # Step 10: Client performs DH exchange
    print("\n10. CLIENT: Perform Diffie-Hellman exchange")
    client_ce.derive_shared_secret(server_pubkey_received)
    print("    ✓ Client derived shared secret")
    
    # Step 11: Verify secure channel
    print("\n11. VERIFY: Both sides can now encrypt/decrypt with ChaCha20Poly1305")
    
    # Client sends encrypted message to server
    client_message = b"Hello from client!"
    client_encrypted = client_ce.encrypt(client_message)
    print(f"    Client encrypts: {client_message}")
    print(f"    Ciphertext: {base64.b64encode(client_encrypted).decode()[:60]}...")
    
    # Server decrypts (returns flags, channel, sequence, offset, plaintext)
    flags, channel, sequence, offset, server_decrypted_msg = server_ce.decrypt(client_encrypted)
    print(f"    Server decrypts: {server_decrypted_msg}")
    
    # Server sends encrypted message to client
    server_message = b"Hello from server!"
    server_encrypted = server_ce.encrypt(server_message)
    print(f"    Server encrypts: {server_message}")
    print(f"    Ciphertext: {base64.b64encode(server_encrypted).decode()[:60]}...")
    
    # Client decrypts (returns flags, channel, sequence, offset, plaintext)
    flags, channel, sequence, offset, client_decrypted_msg = client_ce.decrypt(server_encrypted)
    print(f"    Client decrypts: {client_decrypted_msg}")
    
    print("\n" + "="*50)
    print("✓ Secure channel established successfully!")
    print("="*50)

if __name__ == "__main__":
    demo_exchange()
