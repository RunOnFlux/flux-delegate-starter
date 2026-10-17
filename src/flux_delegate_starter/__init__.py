"""
flux-delegate-starter: Build and send raw delegated fluxnode START transactions.

This package provides tools to:
- Build raw fluxnode START transactions from scratch
- Sign transactions with delegate keys using secp256k1
- Send transactions via sendrawtransaction RPC
- Batch process multiple fluxnode starts
"""

__version__ = "0.1.0"

from .transaction import (
    FluxnodeStartTransaction,
    COutPoint,
    CFluxnodeDelegates,
    encode_compact_size,
)
from .crypto import (
    decode_wif,
    privkey_to_pubkey,
    sign_compact,
    verify_compact_signature,
    sha256,
    hash256,
    hash160,
    pubkey_to_address,
)
from .rpc_client import FluxRPCClient
from .api_client import FluxAPIClient
from .exceptions import (
    FluxDelegateStarterError,
    TransactionError,
    SignatureError,
    RPCError,
    ConfigError,
    ValidationError,
)

__all__ = [
    # Version
    "__version__",
    # Transaction
    "FluxnodeStartTransaction",
    "COutPoint",
    "CFluxnodeDelegates",
    "encode_compact_size",
    # Crypto
    "decode_wif",
    "privkey_to_pubkey",
    "sign_compact",
    "verify_compact_signature",
    "sha256",
    "hash256",
    "hash160",
    "pubkey_to_address",
    # RPC & API
    "FluxRPCClient",
    "FluxAPIClient",
    # Exceptions
    "FluxDelegateStarterError",
    "TransactionError",
    "SignatureError",
    "RPCError",
    "ConfigError",
    "ValidationError",
]
