"""Cryptographic operations for fluxnode transactions."""

import hashlib

import base58
from coincurve import PrivateKey, PublicKey


def decode_wif(wif: str) -> tuple[bytes, bool]:
    """
    Decode WIF (Wallet Import Format) to private key bytes and compressed flag.

    Args:
        wif: WIF-encoded private key string

    Returns:
        Tuple of (private_key_bytes, is_compressed)

    Raises:
        ValueError: If WIF is invalid
    """
    try:
        decoded = base58.b58decode_check(wif)
    except Exception as e:
        raise ValueError(f"Invalid WIF format: {e}") from e

    if len(decoded) < 33:
        raise ValueError("WIF too short")

    # First byte is version
    version = decoded[0]

    # Check for valid Flux/Bitcoin version bytes
    # 0x80 = mainnet, 0xEF = testnet
    if version not in (0x80, 0xEF):
        raise ValueError(f"Invalid WIF version byte: {version:#x}")

    # Next 32 bytes are the private key
    privkey = decoded[1:33]

    # If there's a 34th byte and it's 0x01, the key is compressed
    compressed = len(decoded) == 34 and decoded[33] == 0x01

    return privkey, compressed


def privkey_to_pubkey(privkey: bytes, compressed: bool = True) -> bytes:
    """
    Derive public key from private key.

    Args:
        privkey: 32-byte private key
        compressed: Whether to return compressed public key (33 bytes vs 65 bytes)

    Returns:
        Public key bytes (33 bytes if compressed, 65 bytes if uncompressed)
    """
    pk = PrivateKey(privkey)
    pubkey = pk.public_key
    return pubkey.format(compressed=compressed)


def sign_compact(message_hash: bytes, privkey: bytes) -> bytes:
    """
    Sign a message hash with Bitcoin compact recoverable signature format.

    coincurve returns: [r (32 bytes), s (32 bytes), recovery_id (1 byte)]
    Bitcoin compact format: [27/31 + recovery_id (1 byte), r (32 bytes), s (32 bytes)]

    Args:
        message_hash: 32-byte hash to sign (should already be hashed)
        privkey: 32-byte private key

    Returns:
        65-byte compact signature in Bitcoin format
    """
    pk = PrivateKey(privkey)

    # Sign with recoverable signature (hasher=None means data is already hashed)
    sig = pk.sign_recoverable(message_hash, hasher=None)

    # coincurve format: [r (32 bytes), s (32 bytes), recovery_id (1 byte)]
    r = sig[0:32]
    s = sig[32:64]
    recovery_id = sig[64]

    # Determine if the key produces compressed pubkeys
    # For Flux delegate signing, we always use compressed pubkeys
    pubkey = pk.public_key
    is_compressed = len(pubkey.format(compressed=True)) == 33

    # Apply Bitcoin compact format offset
    # Compressed: 31 + recovery_id (31-34), Uncompressed: 27 + recovery_id (27-30)
    compact_byte = (31 if is_compressed else 27) + recovery_id

    # Return Bitcoin compact signature format: [compact_byte, r, s]
    return bytes([compact_byte]) + r + s


def verify_compact_signature(
    message_hash: bytes, signature: bytes, expected_pubkey: bytes
) -> bool:
    """
    Verify a Bitcoin compact signature against an expected public key.

    Bitcoin compact format: [27/31 + recovery_id, r (32 bytes), s (32 bytes)]
    coincurve format: [r (32 bytes), s (32 bytes), recovery_id (1 byte)]

    Args:
        message_hash: 32-byte hash that was signed
        signature: 65-byte Bitcoin compact signature
        expected_pubkey: Expected public key (33 or 65 bytes)

    Returns:
        True if signature is valid and matches expected pubkey
    """
    if len(signature) != 65:
        return False

    try:
        # Extract from Bitcoin compact format: [compact_byte, r, s]
        compact_byte = signature[0]
        r = signature[1:33]
        s = signature[33:65]

        # Decode recovery ID:
        # 27-30: uncompressed, recovery_id = compact_byte - 27
        # 31-34: compressed, recovery_id = compact_byte - 31
        if 31 <= compact_byte <= 34:
            recovery_id = compact_byte - 31  # Compressed
        elif 27 <= compact_byte <= 30:
            recovery_id = compact_byte - 27  # Uncompressed
        else:
            return False  # Invalid compact format

        # Reconstruct coincurve format: [r, s, recovery_id]
        coincurve_sig = r + s + bytes([recovery_id])

        # Recover public key from signature
        recovered_pubkey = PublicKey.from_signature_and_message(
            coincurve_sig, message_hash, hasher=None
        )

        # Compare with expected pubkey
        # Normalize both to compressed format for comparison
        expected = PublicKey(expected_pubkey).format(compressed=True)
        recovered = recovered_pubkey.format(compressed=True)

        return expected == recovered

    except Exception:
        return False


def sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash.

    Args:
        data: Data to hash

    Returns:
        32-byte hash
    """
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """
    Compute double SHA256 hash (SHA256(SHA256(data))).

    This is the standard Bitcoin/Flux hash function.

    Args:
        data: Data to hash

    Returns:
        32-byte hash
    """
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    """
    Compute RIPEMD160 hash.

    Args:
        data: Data to hash

    Returns:
        20-byte hash
    """
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    """
    Compute HASH160 (RIPEMD160(SHA256(data))).

    This is used for Bitcoin/Flux addresses.

    Args:
        data: Data to hash

    Returns:
        20-byte hash
    """
    return ripemd160(sha256(data))


def pubkey_to_address(pubkey: bytes, version: int = 0x1CB8) -> str:
    """
    Convert public key to Flux address.

    Args:
        pubkey: Public key bytes (33 or 65 bytes)
        version: Address version bytes (default 0x1CB8 for Flux mainnet)

    Returns:
        Base58Check encoded address
    """
    # Hash the public key
    pubkey_hash = hash160(pubkey)

    # Add version bytes (Flux uses 2 bytes: 0x1C 0xB8)
    version_bytes = version.to_bytes(2, "big")
    versioned = version_bytes + pubkey_hash

    # Add checksum and encode
    checksum = hash256(versioned)[:4]
    address_bytes = versioned + checksum

    return base58.b58encode(address_bytes).decode("ascii")
