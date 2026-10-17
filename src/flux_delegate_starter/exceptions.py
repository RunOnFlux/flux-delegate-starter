"""Custom exceptions for flux-delegate-starter."""


class FluxDelegateStarterError(Exception):
    """Base exception for all flux-delegate-starter errors."""
    pass


class TransactionError(FluxDelegateStarterError):
    """Error during transaction building or serialization."""
    pass


class SignatureError(FluxDelegateStarterError):
    """Error during signature creation or verification."""
    pass


class RPCError(FluxDelegateStarterError):
    """Error from RPC call."""

    def __init__(self, rpc_error: dict):
        self.code = rpc_error.get('code', -1)
        self.message = rpc_error.get('message', 'Unknown RPC error')
        super().__init__(f"RPC Error {self.code}: {self.message}")


class ConfigError(FluxDelegateStarterError):
    """Error in configuration."""
    pass


class ValidationError(FluxDelegateStarterError):
    """Error in data validation."""
    pass
