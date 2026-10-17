"""Tests for cryptographic operations."""

import pytest

from flux_delegate_starter.crypto import (
    decode_wif,
    privkey_to_pubkey,
    sign_compact,
    verify_compact_signature,
    sha256,
    hash256,
    hash160,
)


class TestWIFDecoding:
    """Tests for WIF decoding."""

    def test_decode_mainnet_compressed(self):
        """Test decoding mainnet compressed WIF."""
        # Example compressed WIF (mainnet)
        wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        privkey, compressed = decode_wif(wif)

        assert len(privkey) == 32
        assert compressed is True

    def test_decode_mainnet_uncompressed(self):
        """Test decoding mainnet uncompressed WIF."""
        # Example uncompressed WIF (mainnet) - starts with 5
        wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        privkey, compressed = decode_wif(wif)

        assert len(privkey) == 32
        assert compressed is False

    def test_invalid_wif(self):
        """Test that invalid WIF raises ValueError."""
        with pytest.raises(ValueError):
            decode_wif("invalid_wif")

    def test_wif_pubkey_derivation(self):
        """Test deriving public key from WIF."""
        wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        privkey, compressed = decode_wif(wif)

        pubkey = privkey_to_pubkey(privkey, compressed=True)

        assert len(pubkey) == 33
        assert pubkey[0] in (0x02, 0x03)


class TestPublicKeyDerivation:
    """Tests for public key derivation."""

    def test_compressed_pubkey(self):
        """Test deriving compressed public key."""
        # Known private key
        privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")

        pubkey = privkey_to_pubkey(privkey, compressed=True)

        assert len(pubkey) == 33
        assert pubkey[0] in (0x02, 0x03)

    def test_uncompressed_pubkey(self):
        """Test deriving uncompressed public key."""
        privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")

        pubkey = privkey_to_pubkey(privkey, compressed=False)

        assert len(pubkey) == 65
        assert pubkey[0] == 0x04


class TestSigning:
    """Tests for compact signature generation and verification."""

    def test_sign_and_verify(self):
        """Test signing and verifying a message."""
        privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        pubkey = privkey_to_pubkey(privkey, compressed=True)

        message = b"Test message"
        message_hash = sha256(message)

        # Sign
        signature = sign_compact(message_hash, privkey)

        assert len(signature) == 65

        # Verify
        is_valid = verify_compact_signature(message_hash, signature, pubkey)
        assert is_valid is True

    def test_verify_invalid_signature(self):
        """Test that invalid signature fails verification."""
        privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        pubkey = privkey_to_pubkey(privkey, compressed=True)

        message_hash = sha256(b"Test message")

        # Create invalid signature (wrong message)
        wrong_hash = sha256(b"Wrong message")
        signature = sign_compact(wrong_hash, privkey)

        # Verify against original message - should fail
        is_valid = verify_compact_signature(message_hash, signature, pubkey)
        assert is_valid is False

    def test_verify_wrong_pubkey(self):
        """Test that signature fails with wrong public key."""
        privkey1 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        privkey2 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")

        pubkey1 = privkey_to_pubkey(privkey1, compressed=True)
        pubkey2 = privkey_to_pubkey(privkey2, compressed=True)

        message_hash = sha256(b"Test message")
        signature = sign_compact(message_hash, privkey1)

        # Verify with wrong pubkey - should fail
        is_valid = verify_compact_signature(message_hash, signature, pubkey2)
        assert is_valid is False


class TestHashFunctions:
    """Tests for hash functions."""

    def test_sha256(self):
        """Test SHA256 hash."""
        data = b"Hello, World!"
        hash_result = sha256(data)

        assert len(hash_result) == 32
        # Known SHA256 of "Hello, World!"
        expected = bytes.fromhex("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
        assert hash_result == expected

    def test_hash256(self):
        """Test double SHA256 hash."""
        data = b"Hello, World!"
        hash_result = hash256(data)

        assert len(hash_result) == 32

        # Should equal SHA256(SHA256(data))
        expected = sha256(sha256(data))
        assert hash_result == expected

    def test_hash160(self):
        """Test HASH160 (RIPEMD160(SHA256(data)))."""
        data = b"Hello, World!"
        hash_result = hash160(data)

        assert len(hash_result) == 20


class TestZelcashMessageSigning:
    """Tests for Zelcash-style message signing."""

    def test_zelcash_message_format(self):
        """Test Zelcash message signing format."""
        privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        pubkey = privkey_to_pubkey(privkey, compressed=True)

        # Simulate transaction hash
        tx_hash = bytes.fromhex("1234567890abcdef" * 4)

        # Build message with Zelcash magic (as done in transaction signing)
        message_magic = b"Zelcash Signed Message:\n"
        message = message_magic + tx_hash.hex().encode('ascii')
        message_hash = sha256(message)

        # Sign
        signature = sign_compact(message_hash, privkey)

        # Verify
        is_valid = verify_compact_signature(message_hash, signature, pubkey)
        assert is_valid is True
