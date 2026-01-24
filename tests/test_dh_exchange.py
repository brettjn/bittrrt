#!/usr/bin/env python3
"""Test script to verify Diffie-Hellman key exchange and ChaCha20Poly1305 encryption."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Get the path of the current script's directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory's path
parent_dir = os.path.dirname(current_dir)

# Add the parent directory to sys.path (insert at index 0 to prioritize)
sys.path.insert(0, parent_dir)

from bittrrt import CommEncryptor

def test_key_generation():
    """Test that CommEncryptor generates 32-byte public keys."""
    ce = CommEncryptor()
    pubkey = ce.get_public_key()
    assert len(pubkey) == 32, f"Expected 32 bytes, got {len(pubkey)}"
    print("✓ Key generation produces 32-byte public key")

def test_dh_exchange():
    """Test Diffie-Hellman key exchange between two parties."""
    # Alice generates her key pair
    alice = CommEncryptor()
    alice_pubkey = alice.get_public_key()
    
    # Bob generates his key pair
    bob = CommEncryptor()
    bob_pubkey = bob.get_public_key()
    
    # They exchange public keys and derive shared secrets
    alice.derive_shared_secret(bob_pubkey)
    bob.derive_shared_secret(alice_pubkey)
    
    print("✓ Diffie-Hellman exchange completed successfully")

def test_encrypt_decrypt():
    """Test encryption and decryption with ChaCha20Poly1305."""
    # Setup two parties
    alice = CommEncryptor()
    bob = CommEncryptor()
    
    # Exchange keys
    alice.derive_shared_secret(bob.get_public_key())
    bob.derive_shared_secret(alice.get_public_key())
    
    # Alice encrypts a message
    plaintext = b"Hello, Bob! This is a secret message."
    ciphertext = alice.encrypt(plaintext)
    
    # Bob decrypts it (decrypt now returns flags, channel, sequence, offset, plaintext)
    flags, channel, sequence, offset, decrypted = bob.decrypt(ciphertext)
    
    assert decrypted == plaintext, f"Decryption failed: {decrypted} != {plaintext}"
    print("✓ Encryption/decryption works correctly")
    print(f"  Original: {plaintext}")
    print(f"  Decrypted: {decrypted}")

def test_encrypt_decrypt_with_aad():
    """Test encryption with associated authenticated data."""
    alice = CommEncryptor()
    bob = CommEncryptor()
    
    alice.derive_shared_secret(bob.get_public_key())
    bob.derive_shared_secret(alice.get_public_key())
    
    plaintext = b"Secret payload"
    aad = b"metadata-header"
    
    # Encrypt with AAD
    ciphertext = alice.encrypt(plaintext, aad)
    
    # Decrypt with matching AAD (decrypt returns flags, channel, sequence, offset, plaintext)
    flags, channel, sequence, offset, decrypted = bob.decrypt(ciphertext, aad)
    assert decrypted == plaintext
    
    # Try to decrypt with wrong AAD (should fail)
    try:
        bob.decrypt(ciphertext, b"wrong-metadata")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass  # Expected
    
    print("✓ Associated authenticated data works correctly")

def test_tampering_detection():
    """Test that tampering is detected."""
    alice = CommEncryptor()
    bob = CommEncryptor()
    
    alice.derive_shared_secret(bob.get_public_key())
    bob.derive_shared_secret(alice.get_public_key())
    
    ciphertext = alice.encrypt(b"Original message")
    
    # Tamper with the ciphertext
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0xFF  # Flip bits in last byte
    
    # Decryption should fail
    try:
        bob.decrypt(bytes(tampered))
        assert False, "Should have raised ValueError for tampered data"
    except ValueError:
        pass  # Expected
    
    print("✓ Tampering detection works correctly")

def main():
    print("Testing CommEncryptor with Diffie-Hellman and ChaCha20Poly1305\n")
    
    test_key_generation()
    test_dh_exchange()
    test_encrypt_decrypt()
    test_encrypt_decrypt_with_aad()
    test_tampering_detection()
    
    print("\n✓ All tests passed!")

if __name__ == "__main__":
    main()
