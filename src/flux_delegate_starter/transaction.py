"""Fluxnode transaction building and serialization."""

import struct
import time
from dataclasses import dataclass
from typing import Optional

from .crypto import hash256, sha256, sign_compact, privkey_to_pubkey, verify_compact_signature
from .exceptions import TransactionError


def encode_compact_size(size: int) -> bytes:
    """
    Encode compact size (variable length integer).

    Bitcoin/Flux compact size encoding:
    - 0-252: 1 byte
    - 253-65535: 0xFD + 2 bytes (uint16_t LE)
    - 65536-4294967295: 0xFE + 4 bytes (uint32_t LE)
    - 4294967296+: 0xFF + 8 bytes (uint64_t LE)

    Args:
        size: Integer to encode

    Returns:
        Encoded bytes
    """
    if size < 0:
        raise ValueError("Size must be non-negative")
    elif size < 253:
        return bytes([size])
    elif size <= 0xFFFF:
        return b'\xFD' + struct.pack('<H', size)
    elif size <= 0xFFFFFFFF:
        return b'\xFE' + struct.pack('<I', size)
    else:
        return b'\xFF' + struct.pack('<Q', size)


@dataclass
class COutPoint:
    """
    Transaction outpoint reference (txhash + output index).

    Attributes:
        txhash: 32-byte transaction hash (little-endian)
        index: Output index (uint32_t)
    """
    txhash: bytes  # 32 bytes, little-endian
    index: int     # uint32_t

    def __post_init__(self):
        if len(self.txhash) != 32:
            raise ValueError(f"Transaction hash must be 32 bytes, got {len(self.txhash)}")
        if self.index < 0 or self.index > 0xFFFFFFFF:
            raise ValueError(f"Index must be uint32_t, got {self.index}")

    def serialize(self) -> bytes:
        """Serialize outpoint to bytes."""
        return self.txhash + struct.pack('<I', self.index)

    @classmethod
    def from_hex(cls, txhash_hex: str, index: int) -> 'COutPoint':
        """
        Create COutPoint from hex string.

        Args:
            txhash_hex: Transaction hash as hex string (64 chars)
            index: Output index

        Returns:
            COutPoint instance
        """
        if len(txhash_hex) != 64:
            raise ValueError(f"Transaction hash must be 64 hex chars, got {len(txhash_hex)}")

        # Convert hex to bytes and reverse to little-endian
        txhash_bytes = bytes.fromhex(txhash_hex)[::-1]

        return cls(txhash=txhash_bytes, index=index)


@dataclass
class CFluxnodeDelegates:
    """
    Fluxnode delegate data structure.

    Attributes:
        nDelegateVersion: Delegate version (int8_t, default 1)
        nType: Delegate type (int8_t)
               0 = NONE
               1 = ALL
               2 = SIGNING (default - no keys serialized)
    """
    nDelegateVersion: int = 1
    nType: int = 2  # SIGNING type

    def __post_init__(self):
        if not -128 <= self.nDelegateVersion <= 127:
            raise ValueError("nDelegateVersion must be int8_t")
        if not -128 <= self.nType <= 127:
            raise ValueError("nType must be int8_t")

    def serialize(self) -> bytes:
        """
        Serialize delegate data.

        For SIGNING type (nType=2), no keys are serialized.
        Only version + type = 2 bytes.
        """
        data = struct.pack('b', self.nDelegateVersion)
        data += struct.pack('b', self.nType)

        # For SIGNING type, no additional data
        # For ALL type (1), would serialize keys here
        # For NONE type (0), no additional data

        return data


class FluxnodeStartTransaction:
    """
    Fluxnode START transaction (version 6 with delegates).

    This builds a raw transaction that can be broadcast to start a fluxnode
    using delegated signing.
    """

    # Constants
    FLUXNODE_TX_VERSION = 6
    FLUXNODE_START_TX_TYPE = 0x02
    FLUX_TX_VERSION_NORMAL = 0x0001
    FLUX_TX_VERSION_DELEGATES = 0x0100
    OVERWINTERED_FLAG = 0  # Not overwintered

    def __init__(
        self,
        collateral_txhash: str,
        collateral_index: int,
        collateral_pubkey: bytes,
        fluxnode_pubkey: bytes,
        sig_time: Optional[int] = None,
    ):
        """
        Initialize fluxnode start transaction.

        Args:
            collateral_txhash: Collateral transaction hash (hex string, 64 chars)
            collateral_index: Collateral output index
            collateral_pubkey: Collateral public key (33 bytes compressed or 65 bytes uncompressed)
            fluxnode_pubkey: Fluxnode public key (33 bytes compressed or 65 bytes uncompressed)
            sig_time: Signature timestamp (default: current time)
        """
        # Validate collateral pubkey format
        if len(collateral_pubkey) not in (33, 65):
            raise TransactionError(
                f"Collateral pubkey must be 33 bytes (compressed) or 65 bytes (uncompressed), "
                f"got {len(collateral_pubkey)}"
            )

        # Validate collateral pubkey prefix bytes
        first_byte = collateral_pubkey[0]
        if len(collateral_pubkey) == 33 and first_byte not in (0x02, 0x03):
            raise TransactionError(f"Compressed collateral pubkey must start with 0x02 or 0x03, got {first_byte:#04x}")
        if len(collateral_pubkey) == 65 and first_byte not in (0x04, 0x06, 0x07):
            raise TransactionError(f"Uncompressed collateral pubkey must start with 0x04, 0x06, or 0x07, got {first_byte:#04x}")

        # Validate fluxnode pubkey format
        if len(fluxnode_pubkey) not in (33, 65):
            raise TransactionError(
                f"Fluxnode pubkey must be 33 bytes (compressed) or 65 bytes (uncompressed), "
                f"got {len(fluxnode_pubkey)}"
            )

        # Validate fluxnode pubkey prefix bytes
        first_byte = fluxnode_pubkey[0]
        if len(fluxnode_pubkey) == 33 and first_byte not in (0x02, 0x03):
            raise TransactionError(f"Compressed fluxnode pubkey must start with 0x02 or 0x03, got {first_byte:#04x}")
        if len(fluxnode_pubkey) == 65 and first_byte not in (0x04, 0x06, 0x07):
            raise TransactionError(f"Uncompressed fluxnode pubkey must start with 0x04, 0x06, or 0x07, got {first_byte:#04x}")

        # Set fields
        self.nVersion = self.FLUXNODE_TX_VERSION
        self.nType = self.FLUXNODE_START_TX_TYPE
        self.nFluxTxVersion = self.FLUX_TX_VERSION_NORMAL | self.FLUX_TX_VERSION_DELEGATES

        self.collateralIn = COutPoint.from_hex(collateral_txhash, collateral_index)
        self.collateralPubkey = collateral_pubkey
        self.pubKey = fluxnode_pubkey
        self.sigTime = sig_time if sig_time is not None else int(time.time())

        self.fUsingDelegates = True
        self.delegateData = CFluxnodeDelegates()

        self.sig = b''  # Set during signing

    def _serialize_base(self) -> bytes:
        """
        Serialize base transaction fields up to sigTime.

        Returns:
            Serialized base transaction bytes
        """
        data = b''

        # Header: nVersion | (fOverwintered << 31)
        # fOverwintered = 0 for fluxnode transactions
        header = self.nVersion | (self.OVERWINTERED_FLAG << 31)
        data += struct.pack('<I', header)

        # nType (int8_t)
        data += struct.pack('b', self.nType)

        # nFluxTxVersion (int32_t)
        data += struct.pack('<i', self.nFluxTxVersion)

        # collateralIn (COutPoint: 36 bytes)
        data += self.collateralIn.serialize()

        # collateralPubkey (compact size + pubkey bytes)
        data += encode_compact_size(len(self.collateralPubkey))
        data += self.collateralPubkey

        # pubKey (fluxnode pubkey - compact size + pubkey bytes)
        data += encode_compact_size(len(self.pubKey))
        data += self.pubKey

        # sigTime (uint32_t)
        data += struct.pack('<I', self.sigTime)

        return data

    def serialize_for_hash(self) -> bytes:
        """
        Serialize transaction without signature (for hash calculation).

        Order: base fields → (NO sig) → delegate data

        Returns:
            Serialized transaction bytes (without signature)
        """
        data = self._serialize_base()

        # Delegate data (part of hash, comes after sigTime)
        # fUsingDelegates (bool - 1 byte)
        data += b'\x01' if self.fUsingDelegates else b'\x00'

        # delegateData (only if fUsingDelegates is true)
        if self.fUsingDelegates:
            data += self.delegateData.serialize()

        return data

    def serialize_full(self) -> bytes:
        """
        Serialize complete transaction with signature.

        Order: base fields → sig → delegate data

        Returns:
            Full serialized transaction bytes
        """
        data = self._serialize_base()

        # Signature comes immediately after sigTime (compact size + bytes)
        data += encode_compact_size(len(self.sig))
        data += self.sig

        # Delegate data comes after signature
        # fUsingDelegates (bool - 1 byte)
        data += b'\x01' if self.fUsingDelegates else b'\x00'

        # delegateData (only if fUsingDelegates is true)
        if self.fUsingDelegates:
            data += self.delegateData.serialize()

        return data

    def get_hash(self) -> bytes:
        """
        Get transaction hash (double SHA256).

        This is the hash that gets signed.

        Returns:
            32-byte transaction hash
        """
        serialized = self.serialize_for_hash()
        return hash256(serialized)

    def get_hash_hex(self) -> str:
        """
        Get transaction hash as hex string (reversed, like C++ GetHex()).

        Returns:
            64-character hex string
        """
        return self.get_hash()[::-1].hex()

    def sign(self, delegate_privkey: bytes) -> None:
        """
        Sign transaction with delegate private key.

        The signing process:
        1. Get transaction hash (double SHA256 of serialized tx without sig)
        2. Build message: "Zelcash Signed Message:\\n" + tx_hash_hex
        3. Hash message with SHA256
        4. Sign hash with secp256k1 recoverable signature

        Args:
            delegate_privkey: 32-byte delegate private key

        Raises:
            TransactionError: If signing fails
        """
        try:
            # Get transaction hash
            tx_hash = self.get_hash()

            # Build message with Zelcash magic
            # NOTE: C++ serializes strings with compact size prefix
            message_magic = b"Zelcash Signed Message:\n"
            # IMPORTANT: C++ GetHex() reverses the bytes!
            tx_hash_hex = tx_hash[::-1].hex().encode('ascii')

            # Serialize with compact size prefixes (matches C++ string serialization)
            message = encode_compact_size(len(message_magic)) + message_magic
            message += encode_compact_size(len(tx_hash_hex)) + tx_hash_hex

            # Hash the message (double SHA256, like C hashWriter in fluxd)
            message_hash = hash256(message)

            # Sign with compact recoverable signature
            self.sig = sign_compact(message_hash, delegate_privkey)

            if len(self.sig) != 65:
                raise TransactionError(f"Signature must be 65 bytes, got {len(self.sig)}")

            # Verify our own signature immediately
            delegate_pubkey = privkey_to_pubkey(delegate_privkey, compressed=True)
            if not verify_compact_signature(message_hash, self.sig, delegate_pubkey):
                raise TransactionError("Failed to verify own signature - this should never happen!")

        except Exception as e:
            raise TransactionError(f"Failed to sign transaction: {e}")

    def to_hex(self) -> str:
        """
        Get transaction as hex string for broadcasting.

        Returns:
            Hex-encoded transaction string

        Raises:
            TransactionError: If transaction is not signed
        """
        if not self.sig:
            raise TransactionError("Transaction must be signed before converting to hex")

        return self.serialize_full().hex()

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"FluxnodeStartTransaction(\n"
            f"  nVersion={self.nVersion},\n"
            f"  nType={self.nType:#04x},\n"
            f"  nFluxTxVersion={self.nFluxTxVersion:#06x},\n"
            f"  collateralIn={self.collateralIn.txhash.hex()}:{self.collateralIn.index},\n"
            f"  pubKey={self.pubKey.hex()} ({'compressed' if len(self.pubKey) == 33 else 'uncompressed'}),\n"
            f"  sigTime={self.sigTime},\n"
            f"  fUsingDelegates={self.fUsingDelegates},\n"
            f"  sig={'<unsigned>' if not self.sig else f'{len(self.sig)} bytes'}\n"
            f")"
        )
