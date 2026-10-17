"""Flux public API client for HTTPS communication."""

import asyncio
import json
import ssl
from typing import Any, Optional

import aiohttp
import certifi

from .exceptions import RPCError


class FluxAPIClient:
    """
    Async HTTP client for Flux public API.

    Uses https://api.runonflux.io endpoints with retry logic.
    """

    DEFAULT_BASE_URL = "https://api.runonflux.io"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """
        Initialize API client.

        Args:
            base_url: API base URL (default: https://api.runonflux.io)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Create SSL context with certifi certificates for HTTPS requests
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())

    async def _make_request_with_retry(
        self,
        method: str,
        url: str,
        on_retry_callback: Optional[callable] = None,
        **kwargs
    ) -> dict:
        """
        Make HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL
            on_retry_callback: Optional callback function(attempt, max_attempts, error)
            **kwargs: Additional arguments for aiohttp

        Returns:
            Response JSON

        Raises:
            RPCError: If all retries fail
        """
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.request(method, url, ssl=self.ssl_context, **kwargs) as response:
                        response.raise_for_status()
                        result = await response.json()

                        # Check for API error format
                        if isinstance(result, dict):
                            # Flux API returns {status: "error", data: {message: ...}} on error
                            if result.get("status") == "error":
                                error_msg = result.get("data", {}).get("message", "Unknown error")
                                raise RPCError({"message": error_msg, "code": -1})

                            # Success: {status: "success", data: ...}
                            if result.get("status") == "success":
                                return result.get("data")

                        # Return raw result if not standard format
                        return result

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = e

                # Call retry callback before retrying
                if attempt < self.max_retries:
                    if on_retry_callback:
                        on_retry_callback(attempt, self.max_retries, str(e))
                    await asyncio.sleep(self.retry_delay)
                    continue

        # All retries failed
        raise RPCError({
            "message": f"Request failed after {self.max_retries} attempts: {last_error}",
            "code": -1
        })

    async def send_raw_transaction(
        self,
        hex_string: str,
        allow_high_fees: bool = False,
        on_retry_callback: Optional[callable] = None
    ) -> str:
        """
        Send raw transaction via public API.

        Args:
            hex_string: Hex-encoded transaction
            allow_high_fees: Allow high fees (default: False)
            on_retry_callback: Optional callback function(attempt, max_attempts, error)

        Returns:
            Transaction ID (txid)

        Raises:
            RPCError: If transaction is rejected or request fails
        """
        url = f"{self.base_url}/daemon/sendrawtransaction"

        payload = {
            "hexstring": hex_string,
            "allowhighfees": allow_high_fees
        }

        result = await self._make_request_with_retry(
            "POST",
            url,
            on_retry_callback=on_retry_callback,
            data=json.dumps(payload),
            headers={}  # Don't set Content-Type so express.json() doesn't intercept
        )

        # API returns the txid directly as string
        if isinstance(result, str):
            return result

        # Or in data field
        if isinstance(result, dict) and "data" in result:
            return result["data"]

        return str(result)

    async def get_blockchain_info(self) -> dict:
        """
        Get blockchain information via public API.

        Returns:
            Blockchain info dict
        """
        url = f"{self.base_url}/daemon/getblockchaininfo"
        return await self._make_request_with_retry("GET", url)

    async def decode_raw_transaction(self, hex_string: str) -> dict:
        """
        Decode raw transaction via public API.

        Args:
            hex_string: Hex-encoded transaction

        Returns:
            Decoded transaction dict
        """
        url = f"{self.base_url}/daemon/decoderawtransaction"

        payload = {"hexstring": hex_string}

        return await self._make_request_with_retry(
            "POST",
            url,
            data=json.dumps(payload),
            headers={}  # Don't set Content-Type so express.json() doesn't intercept
        )

    async def list_fluxnodes(self, filter: Optional[str] = None) -> list[dict]:
        """
        List all fluxnodes via public API.

        Args:
            filter: Optional filter (searches txhash, IP, payment address, etc)

        Returns:
            List of fluxnode dicts
        """
        url = f"{self.base_url}/daemon/viewdeterministicfluxnodelist"
        if filter:
            url += f"?filter={filter}"

        return await self._make_request_with_retry("GET", url)

    async def get_start_list(self) -> list[dict]:
        """
        Get list of fluxnodes in START tracker via public API.

        Returns:
            List of fluxnode start entries
        """
        url = f"{self.base_url}/daemon/getstartlist"
        return await self._make_request_with_retry("GET", url)

    async def get_block(self, hash_or_height: str | int, verbosity: int = 1) -> dict:
        """
        Get block by hash or height via public API.

        Args:
            hash_or_height: Block hash or height
            verbosity: 0=hex, 1=json, 2=json with tx details

        Returns:
            Block data dict
        """
        url = f"{self.base_url}/daemon/getblock/{hash_or_height}/{verbosity}"
        return await self._make_request_with_retry("GET", url)

    async def get_raw_transaction(self, txid: str, verbose: bool = True) -> dict | str:
        """
        Get raw transaction by txid via public API.

        Args:
            txid: Transaction ID
            verbose: If True, return decoded transaction dict; if False, return hex

        Returns:
            Transaction dict (if verbose=True) or hex string (if verbose=False)
        """
        verbosity = 1 if verbose else 0
        url = f"{self.base_url}/daemon/getrawtransaction/{txid}/{verbosity}"
        return await self._make_request_with_retry("GET", url)

    def __repr__(self) -> str:
        """String representation."""
        return f"FluxAPIClient(url={self.base_url}, max_retries={self.max_retries})"
