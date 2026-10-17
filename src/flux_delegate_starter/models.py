"""Pydantic models for data validation."""

import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class CollateralOutpoint(BaseModel):
    """Collateral transaction outpoint."""

    txhash: str = Field(..., description="Transaction hash (64 hex characters)")
    output_index: int = Field(..., ge=0, description="Output index (0 or greater)")

    @field_validator("txhash")
    @classmethod
    def validate_txhash(cls, v: str) -> str:
        """Validate transaction hash format."""
        if not re.match(r"^[0-9a-fA-F]{64}$", v):
            raise ValueError("Transaction hash must be 64 hex characters")
        return v.lower()


class PublicKey(BaseModel):
    """Compressed public key."""

    hex: str = Field(..., description="Compressed public key (66 hex characters)")

    @field_validator("hex")
    @classmethod
    def validate_pubkey(cls, v: str) -> str:
        """Validate public key format."""
        if not re.match(r"^(02|03)[0-9a-fA-F]{64}$", v):
            raise ValueError(
                "Public key must be 66 hex characters starting with 02 or 03 "
                "(compressed format)"
            )
        return v.lower()

    def to_bytes(self) -> bytes:
        """Convert to bytes."""
        return bytes.fromhex(self.hex)


class PrivateKeyWIF(BaseModel):
    """Private key in WIF format."""

    wif: str = Field(..., description="Private key in WIF format")

    @field_validator("wif")
    @classmethod
    def validate_wif(cls, v: str) -> str:
        """Validate WIF format (basic check)."""
        # WIF keys start with specific characters
        # Mainnet: K, L (compressed), 5 (uncompressed)
        # Testnet: c (compressed), 9 (uncompressed)
        if not re.match(r"^[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}$", v):
            raise ValueError("Invalid WIF format")
        return v


class FluxnodeStartRequest(BaseModel):
    """Request to start a fluxnode."""

    collateral: CollateralOutpoint
    fluxnode_pubkey: PublicKey
    delegate_key: PrivateKeyWIF
    sig_time: Optional[int] = Field(None, description="Signature timestamp")

    @field_validator("sig_time")
    @classmethod
    def validate_sig_time(cls, v: Optional[int]) -> Optional[int]:
        """Validate signature timestamp."""
        if v is not None and v < 0:
            raise ValueError("Signature time must be positive")
        return v


class FluxnodeStartResponse(BaseModel):
    """Response from starting a fluxnode."""

    txid: str = Field(..., description="Transaction ID")
    tx_hex: str = Field(..., description="Raw transaction hex")
    success: bool = True

    @field_validator("txid")
    @classmethod
    def validate_txid(cls, v: str) -> str:
        """Validate transaction ID format."""
        if not re.match(r"^[0-9a-fA-F]{64}$", v):
            raise ValueError("Transaction ID must be 64 hex characters")
        return v.lower()


class RPCConfig(BaseModel):
    """RPC connection configuration."""

    host: str = Field(default="127.0.0.1", description="RPC host")
    port: int = Field(default=16124, description="RPC port", ge=1, le=65535)
    username: Optional[str] = Field(None, description="RPC username")
    password: Optional[str] = Field(None, description="RPC password")
    cookie_path: Optional[str] = Field(None, description="Path to .cookie file")
    timeout: int = Field(default=30, description="Request timeout in seconds", ge=1)


class BatchStartItem(BaseModel):
    """Single item in batch start operation."""

    label: str = Field(..., description="Human-readable label")
    collateral_txhash: str = Field(..., description="Collateral transaction hash")
    collateral_index: int = Field(default=0, ge=0, description="Collateral output index (default: 0)")
    collateral_pubkey: str = Field(..., description="Collateral public key (hex)")

    # Delegate key: either inline WIF or file path
    delegate_key: Optional[str] = Field(None, description="Delegate private key (WIF)")
    delegate_key_file: Optional[str] = Field(None, description="Path to delegate key file")

    # Fluxnode key: either pubkey (hex) or privkey (WIF)
    fluxnode_pubkey: Optional[str] = Field(None, description="Fluxnode public key (hex)")
    fluxnode_privkey: Optional[str] = Field(None, description="Fluxnode private key (WIF) - will derive pubkey")

    @field_validator("collateral_txhash")
    @classmethod
    def validate_txhash(cls, v: str) -> str:
        """Validate transaction hash format."""
        if not re.match(r"^[0-9a-fA-F]{64}$", v):
            raise ValueError("Transaction hash must be 64 hex characters")
        return v.lower()

    @field_validator("collateral_pubkey")
    @classmethod
    def validate_collateral_pubkey(cls, v: str) -> str:
        """Validate collateral public key format (compressed or uncompressed)."""
        # Compressed: 02/03 + 64 hex = 66 chars
        # Uncompressed: 04/06/07 + 128 hex = 130 chars
        if re.match(r"^(02|03)[0-9a-fA-F]{64}$", v):
            return v.lower()  # Compressed
        elif re.match(r"^(04|06|07)[0-9a-fA-F]{128}$", v):
            return v.lower()  # Uncompressed
        else:
            raise ValueError(
                "Collateral public key must be either:\n"
                "  - Compressed: 66 hex chars starting with 02 or 03\n"
                "  - Uncompressed: 130 hex chars starting with 04, 06, or 07"
            )

    @field_validator("fluxnode_pubkey")
    @classmethod
    def validate_pubkey(cls, v: Optional[str]) -> Optional[str]:
        """Validate public key format (compressed or uncompressed)."""
        if v is None:
            return None

        # Compressed: 02/03 + 64 hex = 66 chars
        # Uncompressed: 04/06/07 + 128 hex = 130 chars
        if re.match(r"^(02|03)[0-9a-fA-F]{64}$", v):
            return v.lower()  # Compressed
        elif re.match(r"^(04|06|07)[0-9a-fA-F]{128}$", v):
            return v.lower()  # Uncompressed
        else:
            raise ValueError(
                "Public key must be either:\n"
                "  - Compressed: 66 hex chars starting with 02 or 03\n"
                "  - Uncompressed: 130 hex chars starting with 04, 06, or 07"
            )

    @field_validator("delegate_key")
    @classmethod
    def validate_wif(cls, v: Optional[str]) -> Optional[str]:
        """Validate WIF format."""
        if v is None:
            return None
        if not re.match(r"^[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}$", v):
            raise ValueError("Invalid WIF format")
        return v

    @field_validator("fluxnode_privkey")
    @classmethod
    def validate_fluxnode_privkey(cls, v: Optional[str]) -> Optional[str]:
        """Validate fluxnode privkey WIF format."""
        if v is None:
            return None
        if not re.match(r"^[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}$", v):
            raise ValueError("Invalid WIF format")
        return v

    @model_validator(mode='after')
    def validate_keys(self) -> 'BatchStartItem':
        """Validate that required keys are provided."""
        # Must have either delegate_key or delegate_key_file
        if not self.delegate_key and not self.delegate_key_file:
            raise ValueError("Must provide either delegate_key or delegate_key_file")
        if self.delegate_key and self.delegate_key_file:
            raise ValueError("Cannot provide both delegate_key and delegate_key_file")

        # Must have either fluxnode_pubkey or fluxnode_privkey
        if not self.fluxnode_pubkey and not self.fluxnode_privkey:
            raise ValueError("Must provide either fluxnode_pubkey or fluxnode_privkey")
        if self.fluxnode_pubkey and self.fluxnode_privkey:
            raise ValueError("Cannot provide both fluxnode_pubkey and fluxnode_privkey")

        return self


class BatchStartResult(BaseModel):
    """Result of batch start operation."""

    label: str
    success: bool
    txid: Optional[str] = None
    error: Optional[str] = None

    @model_validator(mode='after')
    def check_success_fields(self) -> 'BatchStartResult':
        """Validate success/error field consistency."""
        if self.success and not self.txid:
            raise ValueError("Success=True requires txid")
        if not self.success and not self.error:
            raise ValueError("Success=False requires error message")
        return self
