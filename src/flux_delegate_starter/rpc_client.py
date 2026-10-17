"""Flux RPC client for direct HTTP JSON-RPC communication."""

from typing import Any

import aiohttp

from .exceptions import ConfigError, RPCError


class FluxRPCClient:
    """
    Async HTTP JSON-RPC 1.0 client for Flux daemon.

    Uses username/password authentication.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 16124,
        username: str | None = None,
        password: str | None = None,
        timeout: int = 30,
    ):
        """
        Initialize RPC client.

        Args:
            host: RPC server host
            port: RPC server port
            username: RPC username (required)
            password: RPC password (required)
            timeout: Request timeout in seconds

        Raises:
            ConfigError: If username/password not provided
        """
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self._request_id = 0

        # Require username and password
        if not username or not password:
            raise ConfigError(
                "RPC authentication required: provide --rpc-user and --rpc-password"
            )

        self._auth_header = aiohttp.encode_basic_auth(username, password)

    async def call(self, method: str, *params: Any) -> Any:
        """
        Call RPC method.

        Args:
            method: RPC method name
            *params: Method parameters

        Returns:
            RPC result

        Raises:
            RPCError: If RPC returns an error
            aiohttp.ClientError: If HTTP request fails
        """
        self._request_id += 1

        payload = {
            "jsonrpc": "1.0",
            "id": self._request_id,
            "method": method,
            "params": list(params),
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.post(
                self.base_url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": self._auth_header,
                },
            ) as response,
        ):
            response.raise_for_status()
            result = await response.json()

            if result.get("error"):
                raise RPCError(result["error"])

            return result.get("result")

    async def send_raw_transaction(self, hex_string: str) -> str:
        """
        Send raw transaction to network.

        Args:
            hex_string: Hex-encoded transaction

        Returns:
            Transaction ID (txid) as hex string

        Raises:
            RPCError: If transaction is rejected
        """
        return await self.call("sendrawtransaction", hex_string)

    async def decode_raw_transaction(self, hex_string: str) -> dict:
        """
        Decode raw transaction (debug helper).

        Args:
            hex_string: Hex-encoded transaction

        Returns:
            Decoded transaction as dict

        Raises:
            RPCError: If transaction cannot be decoded
        """
        return await self.call("decoderawtransaction", hex_string)

    async def get_blockchain_info(self) -> dict:
        """
        Get blockchain information (connection test).

        Returns:
            Blockchain info dict
        """
        return await self.call("getblockchaininfo")

    async def get_raw_transaction(self, txid: str, verbose: bool = False) -> str | dict:
        """
        Get raw transaction by txid.

        Args:
            txid: Transaction ID
            verbose: If True, return decoded transaction

        Returns:
            Raw transaction hex or decoded transaction dict
        """
        if verbose:
            return await self.call("getrawtransaction", txid, 1)
        else:
            return await self.call("getrawtransaction", txid)

    async def get_transaction(self, txid: str) -> dict:
        """
        Get transaction details from wallet.

        Args:
            txid: Transaction ID

        Returns:
            Transaction details dict
        """
        return await self.call("gettransaction", txid)

    async def list_unspent(
        self,
        min_conf: int = 1,
        max_conf: int = 9999999,
        addresses: list[str] | None = None,
    ) -> list[dict]:
        """
        List unspent transaction outputs.

        Args:
            min_conf: Minimum confirmations
            max_conf: Maximum confirmations
            addresses: Filter by addresses

        Returns:
            List of unspent outputs
        """
        params: list[Any] = [min_conf, max_conf]
        if addresses:
            params.append(addresses)

        return await self.call("listunspent", *params)

    async def get_fluxnode_status(self) -> dict:
        """
        Get fluxnode status.

        Returns:
            Fluxnode status dict
        """
        return await self.call("getfluxnodestatus")

    async def list_fluxnodes(self) -> list[dict]:
        """
        List all fluxnodes.

        Returns:
            List of fluxnode info dicts
        """
        return await self.call("listfluxnodes")

    async def get_start_list(self) -> list[dict]:
        """
        Get list of fluxnodes in START tracker.

        Returns:
            List of fluxnode start entries
        """
        return await self.call("getstartlist")

    async def start_fluxnode_as_delegate(
        self, collateral_txhash: str, collateral_index: int, delegate_address: str
    ) -> dict:
        """
        Start fluxnode using high-level RPC command (for comparison).

        Args:
            collateral_txhash: Collateral transaction hash
            collateral_index: Collateral output index
            delegate_address: Delegate address

        Returns:
            Result dict with txid
        """
        return await self.call(
            "startfluxnodeasdelegate",
            collateral_txhash,
            str(collateral_index),
            delegate_address,
        )

    def __repr__(self) -> str:
        """String representation."""
        return f"FluxRPCClient(url={self.base_url})"
