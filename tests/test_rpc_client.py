"""Tests for RPC client."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from flux_delegate_starter.exceptions import ConfigError, RPCError
from flux_delegate_starter.rpc_client import FluxRPCClient


class TestFluxRPCClient:
    """Tests for FluxRPCClient."""

    def test_initialization_with_credentials(self):
        """Test initializing with username/password."""
        client = FluxRPCClient(
            host="localhost",
            port=16124,
            username="user",
            password="pass",
        )

        assert client.base_url == "http://localhost:16124"
        assert client._auth_header == aiohttp.encode_basic_auth("user", "pass")

    def test_missing_credentials(self):
        """Test that missing credentials raises ConfigError."""
        with pytest.raises(ConfigError, match="RPC authentication required"):
            FluxRPCClient(host="127.0.0.1", port=16124)

    @pytest.mark.asyncio
    async def test_call_success(self):
        """Test successful RPC call."""
        client = FluxRPCClient(username="user", password="pass")

        mock_response = MagicMock()
        mock_response.json = AsyncMock(
            return_value={
                "result": {"blocks": 12345},
                "error": None,
                "id": 1,
            }
        )
        mock_response.raise_for_status = MagicMock()

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await client.call("getblockchaininfo")

            assert result == {"blocks": 12345}

    @pytest.mark.asyncio
    async def test_call_rpc_error(self):
        """Test RPC call that returns an error."""
        client = FluxRPCClient(username="user", password="pass")

        mock_response = MagicMock()
        mock_response.json = AsyncMock(
            return_value={
                "result": None,
                "error": {"code": -1, "message": "Test error"},
                "id": 1,
            }
        )
        mock_response.raise_for_status = MagicMock()

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response

            with pytest.raises(RPCError) as exc_info:
                await client.call("invalidmethod")

            assert exc_info.value.code == -1
            assert "Test error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_send_raw_transaction(self):
        """Test send_raw_transaction method."""
        client = FluxRPCClient(username="user", password="pass")

        expected_txid = "0123456789abcdef" * 8

        with patch.object(client, "call", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = expected_txid

            txid = await client.send_raw_transaction("deadbeef")

            assert txid == expected_txid
            mock_call.assert_called_once_with("sendrawtransaction", "deadbeef")

    @pytest.mark.asyncio
    async def test_decode_raw_transaction(self):
        """Test decode_raw_transaction method."""
        client = FluxRPCClient(username="user", password="pass")

        expected_result = {"txid": "abc123", "version": 6}

        with patch.object(client, "call", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = expected_result

            result = await client.decode_raw_transaction("deadbeef")

            assert result == expected_result
            mock_call.assert_called_once_with("decoderawtransaction", "deadbeef")

    @pytest.mark.asyncio
    async def test_get_blockchain_info(self):
        """Test get_blockchain_info method."""
        client = FluxRPCClient(username="user", password="pass")

        expected_result = {"chain": "main", "blocks": 12345}

        with patch.object(client, "call", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = expected_result

            result = await client.get_blockchain_info()

            assert result == expected_result
            mock_call.assert_called_once_with("getblockchaininfo")
