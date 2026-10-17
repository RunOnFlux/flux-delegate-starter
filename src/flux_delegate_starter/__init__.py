"""
flux-delegate-starter: Build and send raw delegated fluxnode START transactions.

This package provides tools to:
- Build raw fluxnode START transactions from scratch
- Sign transactions with delegate keys using secp256k1
- Send transactions via sendrawtransaction RPC
- Batch process multiple fluxnode starts
"""

__version__ = "0.2.0"

from .api_client import FluxAPIClient
from .crypto import (
    decode_wif,
    hash160,
    hash256,
    privkey_to_pubkey,
    pubkey_to_address,
    sha256,
    sign_compact,
    verify_compact_signature,
)
from .exceptions import (
    ConfigError,
    FluxDelegateStarterError,
    RPCError,
    SignatureError,
    TransactionError,
    ValidationError,
)
from .rpc_client import FluxRPCClient
from .transaction import (
    CFluxnodeDelegates,
    COutPoint,
    FluxnodeStartTransaction,
    encode_compact_size,
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
