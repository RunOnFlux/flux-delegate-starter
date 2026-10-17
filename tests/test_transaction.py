"""Tests for transaction building and serialization."""

import struct

import pytest

from flux_delegate_starter.crypto import decode_wif
from flux_delegate_starter.exceptions import TransactionError
from flux_delegate_starter.transaction import (
    CFluxnodeDelegates,
    COutPoint,
    FluxnodeStartTransaction,
    encode_compact_size,
)


class TestCompactSize:
    """Tests for compact size encoding."""

    def test_small_values(self):
        """Test encoding values < 253."""
        assert encode_compact_size(0) == b"\x00"
        assert encode_compact_size(1) == b"\x01"
        assert encode_compact_size(252) == b"\xfc"

    def test_medium_values(self):
        """Test encoding values 253-65535."""
        assert encode_compact_size(253) == b"\xfd\xfd\x00"
        assert encode_compact_size(255) == b"\xfd\xff\x00"
        assert encode_compact_size(65535) == b"\xfd\xff\xff"

    def test_large_values(self):
        """Test encoding values 65536-4294967295."""
        assert encode_compact_size(65536) == b"\xfe\x00\x00\x01\x00"
        assert encode_compact_size(0xFFFFFFFF) == b"\xfe\xff\xff\xff\xff"

    def test_very_large_values(self):
        """Test encoding values > 4294967295."""
        assert (
            encode_compact_size(0x100000000) == b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"
        )

    def test_negative_values(self):
        """Test that negative values raise ValueError."""
        with pytest.raises(ValueError):
            encode_compact_size(-1)


class TestCOutPoint:
    """Tests for COutPoint."""

    def test_serialize(self):
        """Test outpoint serialization."""
        txhash = bytes.fromhex("0123456789abcdef" * 4)
        index = 42

        outpoint = COutPoint(txhash=txhash, index=index)
        serialized = outpoint.serialize()

        # Should be 32 bytes (hash) + 4 bytes (index)
        assert len(serialized) == 36
        assert serialized[:32] == txhash
        assert serialized[32:] == struct.pack("<I", index)

    def test_from_hex(self):
        """Test creating outpoint from hex string."""
        txhash_hex = "0123456789abcdef" * 4  # 64 chars (16 * 4 = 64)
        index = 1

        outpoint = COutPoint.from_hex(txhash_hex, index)

        # Hash should be reversed (little-endian)
        expected_hash = bytes.fromhex(txhash_hex)[::-1]
        assert outpoint.txhash == expected_hash
        assert outpoint.index == index

    def test_invalid_hash_length(self):
        """Test that invalid hash length raises ValueError."""
        with pytest.raises(ValueError):
            COutPoint(txhash=b"too_short", index=0)

    def test_invalid_index(self):
        """Test that invalid index raises ValueError."""
        txhash = bytes(32)
        with pytest.raises(ValueError):
            COutPoint(txhash=txhash, index=-1)


class TestCFluxnodeDelegates:
    """Tests for CFluxnodeDelegates."""

    def test_default_values(self):
        """Test default delegate values."""
        delegates = CFluxnodeDelegates()

        assert delegates.nDelegateVersion == 1
        assert delegates.nType == 2  # SIGNING type

    def test_serialize_signing_type(self):
        """Test serialization of SIGNING type delegates."""
        delegates = CFluxnodeDelegates(nDelegateVersion=1, nType=2)
        serialized = delegates.serialize()

        # SIGNING type: only version + type = 2 bytes
        assert len(serialized) == 2
        assert serialized[0] == 1  # version
        assert serialized[1] == 2  # type


class TestFluxnodeStartTransaction:
    """Tests for FluxnodeStartTransaction."""

    def test_initialization(self):
        """Test transaction initialization."""
        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_index = 0
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes.fromhex("03" + "00" * 32)

        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=collateral_index,
            collateral_pubkey=collateral_pubkey,
            fluxnode_pubkey=fluxnode_pubkey,
            sig_time=1234567890,
        )

        assert tx.nVersion == 6
        assert tx.nType == 0x02
        assert tx.nFluxTxVersion == 0x0101
        assert tx.sigTime == 1234567890
        assert tx.fUsingDelegates is True
        assert len(tx.sig) == 0  # Not signed yet

    def test_invalid_pubkey_length(self):
        """Test that invalid fluxnode pubkey length raises TransactionError."""
        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes(32)  # Wrong length (not 33 or 65)

        with pytest.raises(TransactionError):
            FluxnodeStartTransaction(
                collateral_txhash=collateral_txhash,
                collateral_index=0,
                collateral_pubkey=collateral_pubkey,
                fluxnode_pubkey=fluxnode_pubkey,
            )

    def test_serialization_structure(self):
        """Test transaction serialization structure."""
        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_index = 0
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes.fromhex("03" + "00" * 32)

        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=collateral_index,
            collateral_pubkey=collateral_pubkey,
            fluxnode_pubkey=fluxnode_pubkey,
            sig_time=1234567890,
        )

        serialized = tx.serialize_for_hash()

        # Check structure
        offset = 0

        # Header (4 bytes): nVersion | (fOverwintered << 31)
        header = struct.unpack("<I", serialized[offset : offset + 4])[0]
        assert header == 6  # nVersion=6, fOverwintered=0
        offset += 4

        # nType (1 byte)
        nType = struct.unpack("b", serialized[offset : offset + 1])[0]
        assert nType == 0x02
        offset += 1

        # nFluxTxVersion (4 bytes)
        nFluxTxVersion = struct.unpack("<i", serialized[offset : offset + 4])[0]
        assert nFluxTxVersion == 0x0101
        offset += 4

        # collateralIn (36 bytes: 32 bytes hash + 4 bytes index)
        offset += 36

        # collateralPubkey (compact size + 33 bytes)
        collateral_pubkey_size = serialized[offset]
        assert collateral_pubkey_size == 33
        offset += 1 + 33

        # pubKey (compact size + 33 bytes)
        pubkey_size = serialized[offset]
        assert pubkey_size == 33
        offset += 1 + 33

        # sigTime (4 bytes)
        sigTime = struct.unpack("<I", serialized[offset : offset + 4])[0]
        assert sigTime == 1234567890
        offset += 4

        # fUsingDelegates (1 byte)
        assert serialized[offset] == 1
        offset += 1

        # delegateData (nDelegateVersion + nType, 2 bytes for SIGNING type)
        offset += 2

        # serialize_for_hash does NOT include sig; that's only in serialize_full
        # Should be at end
        assert offset == len(serialized)

    def test_get_hash(self):
        """Test transaction hash generation."""
        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes.fromhex("03" + "00" * 32)

        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=0,
            collateral_pubkey=collateral_pubkey,
            fluxnode_pubkey=fluxnode_pubkey,
        )

        tx_hash = tx.get_hash()

        assert len(tx_hash) == 32
        assert isinstance(tx_hash, bytes)

    def test_signing(self):
        """Test transaction signing."""
        # Use a known private key
        wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        privkey, _ = decode_wif(wif)

        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes.fromhex("03" + "00" * 32)

        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=0,
            collateral_pubkey=collateral_pubkey,
            fluxnode_pubkey=fluxnode_pubkey,
        )

        # Sign
        tx.sign(privkey)

        # Check signature
        assert len(tx.sig) == 65
        assert isinstance(tx.sig, bytes)

    def test_to_hex_unsigned(self):
        """Test that to_hex fails for unsigned transaction."""
        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes.fromhex("03" + "00" * 32)

        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=0,
            collateral_pubkey=collateral_pubkey,
            fluxnode_pubkey=fluxnode_pubkey,
        )

        with pytest.raises(TransactionError):
            tx.to_hex()

    def test_to_hex_signed(self):
        """Test converting signed transaction to hex."""
        wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        privkey, _ = decode_wif(wif)

        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes.fromhex("03" + "00" * 32)

        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=0,
            collateral_pubkey=collateral_pubkey,
            fluxnode_pubkey=fluxnode_pubkey,
        )

        tx.sign(privkey)
        tx_hex = tx.to_hex()

        # Should be hex string
        assert isinstance(tx_hex, str)
        assert all(c in "0123456789abcdef" for c in tx_hex)

        # Should be even length
        assert len(tx_hex) % 2 == 0

    def test_full_serialization_includes_signature(self):
        """Test that full serialization includes signature."""
        wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        privkey, _ = decode_wif(wif)

        collateral_txhash = "0123456789abcdef" * 4  # 64 hex chars
        collateral_pubkey = bytes.fromhex("02" + "00" * 32)
        fluxnode_pubkey = bytes.fromhex("03" + "00" * 32)

        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=0,
            collateral_pubkey=collateral_pubkey,
            fluxnode_pubkey=fluxnode_pubkey,
        )

        # Before signing
        serialized_before = tx.serialize_for_hash()
        len_before = len(serialized_before)

        # After signing
        tx.sign(privkey)
        serialized_after = tx.serialize_full()
        len_after = len(serialized_after)

        # Full serialization adds only the signature; fUsingDelegates and
        # delegateData are already present in serialize_for_hash.
        # compact_size(65) + 65 bytes (signature) = 66 bytes
        assert len_after == len_before + 66


def _bare_multisig_redeemscript(m: int, pubkeys: list) -> bytes:
    """Build a bare multisig redeem script: OP_m <pubkeys...> OP_n OP_CHECKMULTISIG."""
    script = bytes([0x50 + m])
    for pk in pubkeys:
        script += bytes([len(pk)]) + pk
    script += bytes([0x50 + len(pubkeys), 0xAE])  # OP_n, OP_CHECKMULTISIG
    return script


class TestFluxnodeStartTransactionP2SH:
    """Tests for P2SH (SSP multisig) collateral support."""

    REDEEMSCRIPT = _bare_multisig_redeemscript(
        2,
        [
            bytes.fromhex("02" + "11" * 32),
            bytes.fromhex("03" + "22" * 32),
            bytes.fromhex("02" + "33" * 32),
        ],
    )
    FLUXNODE_PUBKEY = bytes.fromhex("03" + "00" * 32)
    COLLATERAL_TXHASH = "0123456789abcdef" * 4

    def test_sets_p2sh_version_flag(self):
        """P2SH collateral sets nFluxTxVersion to P2SH | DELEGATES."""
        tx = FluxnodeStartTransaction(
            collateral_txhash=self.COLLATERAL_TXHASH,
            collateral_index=0,
            collateral_redeemscript=self.REDEEMSCRIPT,
            fluxnode_pubkey=self.FLUXNODE_PUBKEY,
        )

        assert tx.isP2SH is True
        assert tx.nFluxTxVersion == 0x0102
        assert tx.collateralPubkey is None
        assert tx.collateralRedeemScript == self.REDEEMSCRIPT

    def test_pubkey_and_redeemscript_mutually_exclusive(self):
        """Providing both collateral_pubkey and collateral_redeemscript is an error."""
        with pytest.raises(TransactionError):
            FluxnodeStartTransaction(
                collateral_txhash=self.COLLATERAL_TXHASH,
                collateral_index=0,
                collateral_pubkey=bytes.fromhex("02" + "00" * 32),
                collateral_redeemscript=self.REDEEMSCRIPT,
                fluxnode_pubkey=self.FLUXNODE_PUBKEY,
            )

    def test_requires_one_collateral_type(self):
        """Providing neither collateral_pubkey nor collateral_redeemscript is an error."""
        with pytest.raises(TransactionError):
            FluxnodeStartTransaction(
                collateral_txhash=self.COLLATERAL_TXHASH,
                collateral_index=0,
                fluxnode_pubkey=self.FLUXNODE_PUBKEY,
            )

    def test_redeemscript_must_end_in_checkmultisig(self):
        """A redeem script not ending in OP_CHECKMULTISIG (0xAE) is rejected."""
        with pytest.raises(TransactionError):
            FluxnodeStartTransaction(
                collateral_txhash=self.COLLATERAL_TXHASH,
                collateral_index=0,
                collateral_redeemscript=b"\x51\x52\x53",
                fluxnode_pubkey=self.FLUXNODE_PUBKEY,
            )

    def test_empty_redeemscript_rejected(self):
        """An empty redeem script is rejected."""
        with pytest.raises(TransactionError):
            FluxnodeStartTransaction(
                collateral_txhash=self.COLLATERAL_TXHASH,
                collateral_index=0,
                collateral_redeemscript=b"",
                fluxnode_pubkey=self.FLUXNODE_PUBKEY,
            )

    def test_serialization_order(self):
        """
        P2SH wire order is collateralIn -> pubKey -> redeemscript -> sigTime,
        with NO collateralPubkey field at all (verified against fluxd's
        CTransaction::SerializationOp for FLUXNODE_TX_UPGRADEABLE_VERSION).
        """
        tx = FluxnodeStartTransaction(
            collateral_txhash=self.COLLATERAL_TXHASH,
            collateral_index=0,
            collateral_redeemscript=self.REDEEMSCRIPT,
            fluxnode_pubkey=self.FLUXNODE_PUBKEY,
            sig_time=1234567890,
        )

        serialized = tx.serialize_for_hash()
        offset = 0

        offset += 4  # header
        offset += 1  # nType
        offset += 4  # nFluxTxVersion
        offset += 36  # collateralIn

        # pubKey (fluxnode pubkey) comes FIRST in the P2SH path
        pubkey_size = serialized[offset]
        assert pubkey_size == 33
        offset += 1 + 33

        # Then the redeem script (no collateralPubkey field in between)
        redeemscript_size = serialized[offset]
        assert redeemscript_size == len(self.REDEEMSCRIPT)
        offset += 1 + redeemscript_size

        sig_time = struct.unpack("<I", serialized[offset : offset + 4])[0]
        assert sig_time == 1234567890
        offset += 4

        # fUsingDelegates (1 byte) + delegateData (2 bytes)
        assert serialized[offset] == 1
        offset += 1 + 2

        assert offset == len(serialized)

    def test_sign_and_to_hex(self):
        """A P2SH-collateral transaction can be signed and hex-encoded."""
        wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        privkey, _ = decode_wif(wif)

        tx = FluxnodeStartTransaction(
            collateral_txhash=self.COLLATERAL_TXHASH,
            collateral_index=0,
            collateral_redeemscript=self.REDEEMSCRIPT,
            fluxnode_pubkey=self.FLUXNODE_PUBKEY,
        )
        tx.sign(privkey)
        tx_hex = tx.to_hex()

        assert isinstance(tx_hex, str)
        assert len(tx.sig) == 65
        assert all(c in "0123456789abcdef" for c in tx_hex)
