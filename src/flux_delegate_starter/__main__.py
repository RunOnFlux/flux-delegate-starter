"""CLI interface for flux-delegate-starter."""

import asyncio
import sys
from pathlib import Path

import typer
import yaml
from coincurve import PublicKey
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .api_client import FluxAPIClient
from .crypto import decode_wif, privkey_to_pubkey
from .exceptions import (
    FluxDelegateStarterError,
)
from .key_manager import DelegateKeyManager, secure_zero_memory
from .models import BatchStartItem, BatchStartResult
from .rpc_client import FluxRPCClient
from .transaction import FluxnodeStartTransaction

app = typer.Typer(
    name="flux-delegate-starter",
    help="Build and send raw delegated fluxnode START transactions",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@app.command()
def start(
    collateral_txhash: str = typer.Argument(
        ..., help="Collateral transaction hash (64 hex chars)"
    ),
    collateral_index: int = typer.Option(
        0, "--index", "-i", help="Collateral output index"
    ),
    collateral_pubkey: str | None = typer.Option(
        None,
        "--collateral-pubkey",
        help="P2PKH collateral public key (hex). Use this OR --collateral-redeemscript.",
    ),
    collateral_redeemscript: str | None = typer.Option(
        None,
        "--collateral-redeemscript",
        help="P2SH multisig collateral redeem script (hex), for SSP/`t3...` nodes. "
        "Use instead of --collateral-pubkey.",
    ),
    fluxnode_pubkey: str | None = typer.Option(
        None, "--fluxnode-pubkey", help="Fluxnode public key (hex)"
    ),
    fluxnode_privkey: str | None = typer.Option(
        None,
        "--fluxnode-privkey",
        help="Fluxnode private key (WIF) - will derive pubkey",
    ),
    delegate_key: str | None = typer.Option(
        None, "--delegate-key", "-d", help="Delegate private key (WIF format)"
    ),
    delegate_key_file: Path | None = typer.Option(
        None,
        "--delegate-key-file",
        "-k",
        help="Path to delegate key file (plain or age-encrypted)",
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        "-p",
        help="Passphrase for encrypted key (will prompt if not provided)",
    ),
    compress_pubkeys: bool = typer.Option(
        False,
        "--compress-pubkeys",
        help="Auto-compress uncompressed pubkeys to compressed format",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Build transaction but don't send"
    ),
    decode: bool = typer.Option(
        False, "--decode", help="Decode transaction before sending"
    ),
    transport: str = typer.Option(
        "api",
        "--transport",
        "-t",
        help="Transport method: 'api' (default, https://api.runonflux.io) or 'rpc' (direct RPC)",
    ),
    rpc_host: str = typer.Option(
        "127.0.0.1", "--host", help="RPC host (only for --transport rpc)"
    ),
    rpc_port: int = typer.Option(
        16124, "--port", help="RPC port (only for --transport rpc)"
    ),
    rpc_user: str | None = typer.Option(
        None, "--rpc-user", help="RPC username (only for --transport rpc)"
    ),
    rpc_password: str | None = typer.Option(
        None, "--rpc-password", help="RPC password (only for --transport rpc)"
    ),
):
    """
    Build and send a delegated fluxnode START transaction.

    This command builds a raw transaction from scratch, signs it with the delegate key,
    and sends it via sendrawtransaction RPC.

    You must provide either --fluxnode-pubkey OR --fluxnode-privkey.
    You must provide either --collateral-pubkey (P2PKH, e.g. Zelcore `t1...`)
    OR --collateral-redeemscript (P2SH multisig, e.g. SSP `t3...`).

    Example (P2PKH collateral):
        flux-delegate-starter start <txhash> \\
            --collateral-pubkey 02a2ba3b31f8cfa485b0c36cf7b4f311fa4a774dc0ddad2743238de3ac87745a4b \\
            --fluxnode-privkey <WIF> \\
            --delegate-key-file delegate.key.age

    Example (P2SH/SSP collateral):
        flux-delegate-starter start <txhash> \\
            --collateral-redeemscript <redeem_script_hex> \\
            --fluxnode-privkey <WIF> \\
            --delegate-key-file delegate.key.age
    """
    # Validate: must provide either delegate_key or delegate_key_file
    if not delegate_key and not delegate_key_file:
        console.print(
            "[red]Error:[/red] Must provide either --delegate-key or --delegate-key-file option"
        )
        sys.exit(1)
    if delegate_key and delegate_key_file:
        console.print(
            "[red]Error:[/red] Cannot provide both --delegate-key and --delegate-key-file"
        )
        sys.exit(1)

    # Validate: must provide either fluxnode_pubkey or fluxnode_privkey
    if not fluxnode_pubkey and not fluxnode_privkey:
        console.print(
            "[red]Error:[/red] Must provide either --fluxnode-pubkey or --fluxnode-privkey"
        )
        sys.exit(1)
    if fluxnode_pubkey and fluxnode_privkey:
        console.print(
            "[red]Error:[/red] Cannot provide both --fluxnode-pubkey and --fluxnode-privkey"
        )
        sys.exit(1)

    # Validate transport
    if transport not in ("api", "rpc"):
        err_console.print(
            f"[red]Error:[/red] Invalid transport '{transport}'. Must be 'api' or 'rpc'"
        )
        sys.exit(1)

    asyncio.run(
        _start(
            collateral_txhash,
            collateral_index,
            collateral_pubkey,
            collateral_redeemscript,
            fluxnode_pubkey,
            fluxnode_privkey,
            delegate_key,
            delegate_key_file,
            passphrase,
            compress_pubkeys,
            dry_run,
            decode,
            transport,
            rpc_host,
            rpc_port,
            rpc_user,
            rpc_password,
        )
    )


async def _start(
    collateral_txhash: str,
    collateral_index: int,
    collateral_pubkey_hex: str | None,
    collateral_redeemscript_hex: str | None,
    fluxnode_pubkey_hex: str | None,
    fluxnode_privkey_wif: str | None,
    delegate_key_wif: str | None,
    delegate_key_file: Path | None,
    passphrase: str | None,
    compress_pubkeys: bool,
    dry_run: bool,
    decode: bool,
    transport: str,
    rpc_host: str,
    rpc_port: int,
    rpc_user: str | None,
    rpc_password: str | None,
):
    """Internal async implementation of start command."""
    try:
        # Check for passphrase from stdin if not provided via option
        if passphrase is None and not sys.stdin.isatty():
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                passphrase = stdin_data
                console.print("[dim]Using passphrase from stdin[/dim]")

        # Load delegate key
        if delegate_key_file:
            console.print(
                f"[cyan]Loading delegate key from {delegate_key_file}...[/cyan]"
            )
            delegate_key_wif = DelegateKeyManager.load_key(
                delegate_key_file, passphrase
            )
            console.print("[green]✓[/green] Delegate key loaded")

        # Validate and decode inputs
        console.print("[cyan]Validating inputs...[/cyan]")

        # Collateral: P2PKH pubkey OR P2SH redeem script (mutually exclusive)
        if collateral_pubkey_hex and collateral_redeemscript_hex:
            console.print(
                "[red]Error:[/red] Provide --collateral-pubkey OR --collateral-redeemscript, not both"
            )
            sys.exit(1)
        if not collateral_pubkey_hex and not collateral_redeemscript_hex:
            console.print(
                "[red]Error:[/red] Must provide --collateral-pubkey (P2PKH) or --collateral-redeemscript (P2SH)"
            )
            sys.exit(1)

        collateral_pubkey = None
        collateral_redeemscript = None
        if collateral_redeemscript_hex:
            collateral_redeemscript = bytes.fromhex(collateral_redeemscript_hex)
            console.print(
                f"[green]✓[/green] P2SH multisig collateral (redeem script {len(collateral_redeemscript)} bytes)"
            )
        else:
            # Decode collateral pubkey
            assert collateral_pubkey_hex is not None  # checked above
            collateral_pubkey = bytes.fromhex(collateral_pubkey_hex)
            # Validate format
            if len(collateral_pubkey) == 65 and collateral_pubkey[0] == 0x04:
                # Uncompressed format
                if compress_pubkeys:
                    pk = PublicKey(collateral_pubkey)
                    collateral_pubkey = pk.format(compressed=True)
                    console.print(
                        "[yellow]Note:[/yellow] Auto-converted uncompressed collateral pubkey to compressed format"
                    )
                else:
                    console.print(
                        "[yellow]Note:[/yellow] Preserving uncompressed collateral pubkey format"
                    )
            elif len(collateral_pubkey) == 33 and collateral_pubkey[0] in (0x02, 0x03):
                # Compressed format - OK
                pass
            else:
                console.print("[red]Error:[/red] Invalid collateral pubkey format")
                console.print(
                    "[yellow]Expected: 33 bytes starting with 02/03 (compressed) or 65 bytes starting with 04 (uncompressed)[/yellow]"
                )
                console.print(
                    f"[yellow]Got: {len(collateral_pubkey)} bytes starting with {collateral_pubkey[0]:02x}[/yellow]"
                )
                sys.exit(1)

        # Derive fluxnode pubkey if privkey provided
        if fluxnode_privkey_wif:
            fluxnode_privkey_bytes, is_compressed = decode_wif(fluxnode_privkey_wif)
            # Use compress_pubkeys flag when deriving
            fluxnode_pubkey = privkey_to_pubkey(
                fluxnode_privkey_bytes, compressed=compress_pubkeys or is_compressed
            )
            format_str = (
                "compressed" if (compress_pubkeys or is_compressed) else "uncompressed"
            )
            console.print(
                f"[green]✓[/green] Fluxnode pubkey derived from privkey ({format_str})"
            )
        else:
            assert fluxnode_pubkey_hex is not None  # checked by caller
            fluxnode_pubkey = bytes.fromhex(fluxnode_pubkey_hex)
            # Validate format
            if len(fluxnode_pubkey) == 65 and fluxnode_pubkey[0] == 0x04:
                # Uncompressed format
                if compress_pubkeys:
                    pk = PublicKey(fluxnode_pubkey)
                    fluxnode_pubkey = pk.format(compressed=True)
                    console.print(
                        "[yellow]Note:[/yellow] Auto-converted uncompressed fluxnode pubkey to compressed format"
                    )
                else:
                    console.print(
                        "[yellow]Note:[/yellow] Preserving uncompressed fluxnode pubkey format"
                    )
            elif len(fluxnode_pubkey) == 33 and fluxnode_pubkey[0] in (0x02, 0x03):
                # Compressed format - OK
                pass
            else:
                console.print("[red]Error:[/red] Invalid fluxnode pubkey format")
                console.print(
                    "[yellow]Expected: 33 bytes starting with 02/03 (compressed) or 65 bytes starting with 04 (uncompressed)[/yellow]"
                )
                console.print(
                    f"[yellow]Got: {len(fluxnode_pubkey)} bytes starting with {fluxnode_pubkey[0]:02x}[/yellow]"
                )
                sys.exit(1)

        # Decode WIF - use bytearray for secure zeroing
        assert delegate_key_wif is not None  # enforced by the start command
        delegate_privkey_bytes, is_compressed = decode_wif(delegate_key_wif)
        delegate_privkey = bytearray(delegate_privkey_bytes)

        # Derive and display delegate pubkey for verification
        delegate_pubkey = privkey_to_pubkey(delegate_privkey_bytes, compressed=True)
        console.print("[green]✓[/green] Delegate privkey decoded")
        console.print(f"[dim]  Delegate pubkey: {delegate_pubkey.hex()}[/dim]")

        # Build transaction
        console.print("[cyan]Building transaction...[/cyan]")
        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=collateral_index,
            collateral_pubkey=collateral_pubkey,
            collateral_redeemscript=collateral_redeemscript,
            fluxnode_pubkey=fluxnode_pubkey,
        )

        console.print("[green]✓[/green] Transaction created")
        console.print(f"  Signature time: {tx.sigTime}")
        console.print(f"  Transaction hash: {tx.get_hash_hex()}")

        try:
            # Sign transaction
            console.print("[cyan]Signing transaction...[/cyan]")
            tx.sign(bytes(delegate_privkey))  # Convert bytearray to bytes for signing
            console.print(f"[green]✓[/green] Transaction signed ({len(tx.sig)} bytes)")

            # Securely zero the private key from memory IMMEDIATELY after signing
            secure_zero_memory(delegate_privkey)
            console.print("[dim]Private key zeroed from memory[/dim]")

            # Get hex
            tx_hex = tx.to_hex()
            console.print("\n[bold cyan]Transaction hex:[/bold cyan]")
            console.print(f"[dim]{tx_hex}[/dim]\n")

            # Decode if requested
            if decode:
                console.print("[cyan]Decoding transaction...[/cyan]")
                if transport == "rpc":
                    client = FluxRPCClient(
                        host=rpc_host,
                        port=rpc_port,
                        username=rpc_user,
                        password=rpc_password,
                    )
                else:
                    client = FluxAPIClient()

                try:
                    decoded = await client.decode_raw_transaction(tx_hex)
                    console.print(
                        Panel.fit(
                            _format_decoded_tx(decoded),
                            title="Decoded Transaction",
                            border_style="cyan",
                        )
                    )
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not decode: {e}[/yellow]")

            # Send transaction
            if dry_run:
                console.print("[yellow]Dry run - not sending transaction[/yellow]")
                return

            # Define retry callback for nice CLI feedback
            def on_retry(attempt: int, max_attempts: int, error: str):
                console.print(f"[yellow]Attempt {attempt} failed: {error}[/yellow]")
                console.print(
                    f"[cyan]Retrying in 1 second... ({attempt}/{max_attempts - 1} retries)[/cyan]"
                )

            console.print(
                f"[cyan]Sending transaction via {transport.upper()}...[/cyan]"
            )

            if transport == "rpc":
                client = FluxRPCClient(
                    host=rpc_host,
                    port=rpc_port,
                    username=rpc_user,
                    password=rpc_password,
                )
                txid = await client.send_raw_transaction(tx_hex)
            else:
                client = FluxAPIClient()
                txid = await client.send_raw_transaction(
                    tx_hex, on_retry_callback=on_retry
                )

            console.print("\n[bold green]✓ Success![/bold green]")
            console.print(f"Transaction ID: [bold]{txid}[/bold]")

        finally:
            # Ensure private key is always zeroed, even if error occurs
            if "delegate_privkey" in locals():
                secure_zero_memory(delegate_privkey)

    except FluxDelegateStarterError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


@app.command()
def batch(
    yaml_file: Path = typer.Argument(..., help="YAML file with batch start data"),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Build transactions but don't send"
    ),
    continue_on_error: bool = typer.Option(
        True, "--continue-on-error", help="Continue if a transaction fails"
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        "-p",
        help="Passphrase for encrypted key files (applies to all)",
    ),
    compress_pubkeys: bool = typer.Option(
        False,
        "--compress-pubkeys",
        help="Auto-compress uncompressed pubkeys to compressed format",
    ),
    transport: str = typer.Option(
        "api", "--transport", "-t", help="Transport method: 'api' (default) or 'rpc'"
    ),
    rpc_host: str = typer.Option(
        "127.0.0.1", "--host", help="RPC host (only for --transport rpc)"
    ),
    rpc_port: int = typer.Option(
        16124, "--port", help="RPC port (only for --transport rpc)"
    ),
    rpc_user: str | None = typer.Option(
        None, "--rpc-user", help="RPC username (only for --transport rpc)"
    ),
    rpc_password: str | None = typer.Option(
        None, "--rpc-password", help="RPC password (only for --transport rpc)"
    ),
):
    """
    Start multiple fluxnodes from a YAML file.

    YAML format:
    fluxnodes:
      - label: "node-1"
        collateral_txhash: "..."
        collateral_index: 0
        collateral_pubkey: "..."
        delegate_key: "..."
        fluxnode_pubkey: "..."

    Example:
        flux-delegate-starter batch collaterals.yaml
    """
    # Validate transport
    if transport not in ("api", "rpc"):
        err_console.print(
            f"[red]Error:[/red] Invalid transport '{transport}'. Must be 'api' or 'rpc'"
        )
        sys.exit(1)

    asyncio.run(
        _batch(
            yaml_file,
            dry_run,
            continue_on_error,
            passphrase,
            compress_pubkeys,
            transport,
            rpc_host,
            rpc_port,
            rpc_user,
            rpc_password,
        )
    )


async def _batch(
    yaml_file: Path,
    dry_run: bool,
    continue_on_error: bool,
    passphrase: str | None,
    compress_pubkeys: bool,
    transport: str,
    rpc_host: str,
    rpc_port: int,
    rpc_user: str | None,
    rpc_password: str | None,
):
    """Internal async implementation of batch command."""
    try:
        # Check for passphrase from stdin if not provided via option
        if passphrase is None and not sys.stdin.isatty():
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                passphrase = stdin_data
                console.print("[dim]Using passphrase from stdin[/dim]")

        # Load YAML
        console.print(f"[cyan]Loading YAML file: {yaml_file}[/cyan]")

        if not yaml_file.exists():
            console.print(f"[red]Error: File not found: {yaml_file}[/red]")
            sys.exit(1)

        items = []
        with yaml_file.open("r") as f:
            data = yaml.safe_load(f)
            fluxnodes = data.get("fluxnodes", [])

            for node in fluxnodes:
                try:
                    item = BatchStartItem(**node)
                    items.append(item)
                except Exception as e:
                    console.print(
                        f"[yellow]Warning: Invalid node '{node.get('label', 'unknown')}': {e}[/yellow]"
                    )

        console.print(f"[green]✓[/green] Loaded {len(items)} items")

        if not items:
            console.print("[yellow]No valid items found[/yellow]")
            return

        # Process each item
        results = []

        # Create client based on transport
        if transport == "rpc":
            client = FluxRPCClient(
                host=rpc_host, port=rpc_port, username=rpc_user, password=rpc_password
            )
        else:
            client = FluxAPIClient()

        # Define retry callback
        def on_retry(attempt: int, max_attempts: int, error: str):
            console.print(
                f"  [yellow]Retry {attempt}/{max_attempts - 1}: {error}[/yellow]"
            )

        for i, item in enumerate(items, 1):
            console.print(f"\n[cyan]Processing [{i}/{len(items)}]: {item.label}[/cyan]")

            try:
                # Get delegate key (from inline WIF or file)
                if item.delegate_key_file:
                    delegate_key_wif = DelegateKeyManager.load_key(
                        Path(item.delegate_key_file), passphrase=passphrase
                    )
                    console.print(
                        f"  [dim]Loaded delegate key from {item.delegate_key_file}[/dim]"
                    )
                else:
                    delegate_key_wif = item.delegate_key

                # item's model_validator guarantees one of the two is set
                assert delegate_key_wif is not None
                delegate_privkey, _ = decode_wif(delegate_key_wif)

                # Decode collateral pubkey
                collateral_pubkey = bytes.fromhex(item.collateral_pubkey)
                # Auto-convert uncompressed to compressed if requested
                if len(collateral_pubkey) == 65 and collateral_pubkey[0] == 0x04:
                    if compress_pubkeys:
                        from coincurve import PublicKey as CPublicKey

                        pk = CPublicKey(collateral_pubkey)
                        collateral_pubkey = pk.format(compressed=True)
                        console.print(
                            "  [dim]Auto-converted collateral pubkey to compressed[/dim]"
                        )
                    else:
                        console.print(
                            "  [dim]Preserving uncompressed collateral pubkey format[/dim]"
                        )

                # Get fluxnode pubkey (from hex or derive from privkey)
                if item.fluxnode_privkey:
                    fluxnode_privkey_bytes, is_compressed = decode_wif(
                        item.fluxnode_privkey
                    )
                    # Use compress_pubkeys flag
                    compress = compress_pubkeys or is_compressed
                    fluxnode_pubkey = privkey_to_pubkey(
                        fluxnode_privkey_bytes, compressed=compress
                    )
                    format_str = "compressed" if compress else "uncompressed"
                    console.print(
                        f"  [dim]Derived fluxnode pubkey from privkey ({format_str})[/dim]"
                    )
                else:
                    # item's model_validator guarantees one of the two is set
                    assert item.fluxnode_pubkey is not None
                    fluxnode_pubkey = bytes.fromhex(item.fluxnode_pubkey)
                    # Auto-convert uncompressed to compressed if requested
                    if len(fluxnode_pubkey) == 65 and fluxnode_pubkey[0] == 0x04:
                        if compress_pubkeys:
                            from coincurve import PublicKey as CPublicKey

                            pk = CPublicKey(fluxnode_pubkey)
                            fluxnode_pubkey = pk.format(compressed=True)
                            console.print(
                                "  [dim]Auto-converted fluxnode pubkey to compressed[/dim]"
                            )
                        else:
                            console.print(
                                "  [dim]Preserving uncompressed fluxnode pubkey format[/dim]"
                            )

                # Build and sign transaction
                tx = FluxnodeStartTransaction(
                    collateral_txhash=item.collateral_txhash,
                    collateral_index=item.collateral_index,
                    collateral_pubkey=collateral_pubkey,
                    fluxnode_pubkey=fluxnode_pubkey,
                )
                tx.sign(delegate_privkey)

                tx_hex = tx.to_hex()

                # Send (unless dry run)
                if not dry_run:
                    if isinstance(client, FluxAPIClient):
                        txid = await client.send_raw_transaction(
                            tx_hex, on_retry_callback=on_retry
                        )
                    else:
                        txid = await client.send_raw_transaction(tx_hex)

                    console.print(f"[green]✓[/green] Success: {txid}")
                    results.append(
                        BatchStartResult(
                            label=item.label,
                            success=True,
                            txid=txid,
                        )
                    )
                else:
                    console.print(f"[yellow]✓[/yellow] Dry run: {tx_hex[:32]}...")
                    results.append(
                        BatchStartResult(
                            label=item.label,
                            success=True,
                            txid="dry-run",
                        )
                    )

            except Exception as e:
                error_msg = str(e)
                console.print(f"[red]✗[/red] Failed: {error_msg}")
                results.append(
                    BatchStartResult(
                        label=item.label,
                        success=False,
                        error=error_msg,
                    )
                )

                if not continue_on_error:
                    console.print("[red]Stopping due to error[/red]")
                    break

        # Print summary
        console.print("\n" + "=" * 60)
        console.print("[bold]Summary[/bold]")
        console.print("=" * 60)

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Label", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("TxID / Error", style="white")

        for result in results:
            if result.success:
                table.add_row(
                    result.label, "[green]✓ Success[/green]", result.txid or ""
                )
            else:
                table.add_row(result.label, "[red]✗ Failed[/red]", result.error or "")

        console.print(table)

        success_count = sum(1 for r in results if r.success)
        console.print(f"\n[bold]Total:[/bold] {len(results)}")
        console.print(f"[green]Success:[/green] {success_count}")
        console.print(f"[red]Failed:[/red] {len(results) - success_count}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


@app.command()
def build(
    collateral_txhash: str = typer.Argument(..., help="Collateral transaction hash"),
    collateral_index: int = typer.Option(
        0, "--index", "-i", help="Collateral output index"
    ),
    collateral_pubkey: str | None = typer.Option(
        None,
        "--collateral-pubkey",
        help="P2PKH collateral public key (hex). Use this OR --collateral-redeemscript.",
    ),
    collateral_redeemscript: str | None = typer.Option(
        None,
        "--collateral-redeemscript",
        help="P2SH multisig collateral redeem script (hex), for SSP/`t3...` nodes. "
        "Use instead of --collateral-pubkey.",
    ),
    fluxnode_pubkey: str | None = typer.Option(
        None, "--fluxnode-pubkey", help="Fluxnode public key (hex)"
    ),
    fluxnode_privkey: str | None = typer.Option(
        None,
        "--fluxnode-privkey",
        help="Fluxnode private key (WIF) - will derive pubkey",
    ),
    delegate_key: str | None = typer.Option(
        None, "--delegate-key", "-d", help="Delegate private key (WIF format)"
    ),
    delegate_key_file: Path | None = typer.Option(
        None, "--delegate-key-file", "-k", help="Path to delegate key file"
    ),
    passphrase: str | None = typer.Option(
        None, "--passphrase", "-p", help="Passphrase for encrypted key"
    ),
    compress_pubkeys: bool = typer.Option(
        False,
        "--compress-pubkeys",
        help="Auto-compress uncompressed pubkeys to compressed format",
    ),
):
    """
    Build transaction and output hex (don't send).

    This is useful for debugging or manual broadcasting.

    You must provide either --fluxnode-pubkey OR --fluxnode-privkey.
    You must provide either --collateral-pubkey (P2PKH) OR --collateral-redeemscript (P2SH).

    Example:
        flux-delegate-starter build <txhash> \\
            --collateral-pubkey 02a2ba3b31f8cfa485b0c36cf7b4f311fa4a774dc0ddad2743238de3ac87745a4b \\
            --fluxnode-privkey <WIF> -k delegate.key.age
    """
    asyncio.run(
        _build(
            collateral_txhash,
            collateral_index,
            collateral_pubkey,
            collateral_redeemscript,
            fluxnode_pubkey,
            fluxnode_privkey,
            delegate_key,
            delegate_key_file,
            passphrase,
            compress_pubkeys,
        )
    )


async def _build(
    collateral_txhash: str,
    collateral_index: int,
    collateral_pubkey_hex: str | None,
    collateral_redeemscript_hex: str | None,
    fluxnode_pubkey_hex: str | None,
    fluxnode_privkey_wif: str | None,
    delegate_key_wif: str | None,
    delegate_key_file: Path | None,
    passphrase: str | None,
    compress_pubkeys: bool,
):
    """Internal async implementation of build command."""
    try:
        # Validate fluxnode key input
        if not fluxnode_pubkey_hex and not fluxnode_privkey_wif:
            err_console.print(
                "[red]Error:[/red] Must provide either --fluxnode-pubkey or --fluxnode-privkey"
            )
            sys.exit(1)
        if fluxnode_pubkey_hex and fluxnode_privkey_wif:
            err_console.print(
                "[red]Error:[/red] Cannot provide both --fluxnode-pubkey and --fluxnode-privkey"
            )
            sys.exit(1)

        # Collateral: P2PKH pubkey OR P2SH redeem script (mutually exclusive)
        if collateral_pubkey_hex and collateral_redeemscript_hex:
            err_console.print(
                "[red]Error:[/red] Provide --collateral-pubkey OR --collateral-redeemscript, not both"
            )
            sys.exit(1)
        if not collateral_pubkey_hex and not collateral_redeemscript_hex:
            err_console.print(
                "[red]Error:[/red] Must provide --collateral-pubkey (P2PKH) or --collateral-redeemscript (P2SH)"
            )
            sys.exit(1)

        collateral_pubkey = None
        collateral_redeemscript = None
        if collateral_redeemscript_hex:
            collateral_redeemscript = bytes.fromhex(collateral_redeemscript_hex)
        else:
            # Decode collateral pubkey
            assert collateral_pubkey_hex is not None  # checked above
            collateral_pubkey = bytes.fromhex(collateral_pubkey_hex)
            # Auto-compress if requested
            if (
                compress_pubkeys
                and len(collateral_pubkey) == 65
                and collateral_pubkey[0] == 0x04
            ):
                from coincurve import PublicKey as CPublicKey

                pk = CPublicKey(collateral_pubkey)
                collateral_pubkey = pk.format(compressed=True)

        # Derive fluxnode pubkey if privkey provided
        if fluxnode_privkey_wif:
            fluxnode_privkey_bytes, is_compressed = decode_wif(fluxnode_privkey_wif)
            fluxnode_pubkey = privkey_to_pubkey(
                fluxnode_privkey_bytes, compressed=compress_pubkeys or is_compressed
            )
        else:
            assert fluxnode_pubkey_hex is not None  # checked above
            fluxnode_pubkey = bytes.fromhex(fluxnode_pubkey_hex)
            # Auto-compress if requested
            if (
                compress_pubkeys
                and len(fluxnode_pubkey) == 65
                and fluxnode_pubkey[0] == 0x04
            ):
                from coincurve import PublicKey as CPublicKey

                pk = CPublicKey(fluxnode_pubkey)
                fluxnode_pubkey = pk.format(compressed=True)

        # Load delegate key
        if delegate_key_file:
            delegate_key_wif = DelegateKeyManager.load_key(
                delegate_key_file, passphrase
            )
        elif not delegate_key_wif:
            err_console.print(
                "[red]Error:[/red] Must provide either --delegate-key or --delegate-key-file"
            )
            sys.exit(1)

        # Decode delegate key
        delegate_privkey, _ = decode_wif(delegate_key_wif)

        # Build and sign transaction
        tx = FluxnodeStartTransaction(
            collateral_txhash=collateral_txhash,
            collateral_index=collateral_index,
            collateral_pubkey=collateral_pubkey,
            collateral_redeemscript=collateral_redeemscript,
            fluxnode_pubkey=fluxnode_pubkey,
        )
        tx.sign(delegate_privkey)

        # Output hex only (for piping/scripting)
        print(tx.to_hex())

    except FluxDelegateStarterError as e:
        err_console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        err_console.print(f"[red]Unexpected error:[/red] {e}")
        sys.exit(1)


@app.command()
def derive_pubkey(
    wif_key: str | None = typer.Argument(
        None, help="Private key in WIF format (or omit to use --key-file)"
    ),
    key_file: Path | None = typer.Option(
        None, "--key-file", "-k", help="Path to key file (plain or age-encrypted)"
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        "-p",
        help="Passphrase for encrypted key (will prompt if not provided)",
    ),
):
    """
    Derive public key from WIF private key.

    This is a utility to help you get public keys from your private keys.

    Examples:
        # From WIF argument
        flux-delegate-starter derive-pubkey KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn

        # From key file
        flux-delegate-starter derive-pubkey --key-file delegate.key.age

        # From stdin
        echo "password" | flux-delegate-starter derive-pubkey --key-file delegate.key.age
    """
    try:
        # Validate: must provide either wif_key or key_file
        if not wif_key and not key_file:
            console.print(
                "[red]Error:[/red] Must provide either WIF key argument or --key-file option"
            )
            sys.exit(1)
        if wif_key and key_file:
            console.print(
                "[red]Error:[/red] Cannot provide both WIF key argument and --key-file"
            )
            sys.exit(1)

        # Check for passphrase from stdin if not provided via option
        if passphrase is None and not sys.stdin.isatty():
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                passphrase = stdin_data
                console.print("[dim]Using passphrase from stdin[/dim]")

        # Load key
        if key_file:
            console.print(f"[cyan]Loading key from {key_file}...[/cyan]")
            wif_key = DelegateKeyManager.load_key(key_file, passphrase)
            console.print("[green]✓[/green] Key loaded")

        # Decode WIF
        assert wif_key is not None  # checked above
        privkey, is_compressed = decode_wif(wif_key)

        # Derive public key (match the WIF format)
        pubkey = privkey_to_pubkey(privkey, compressed=is_compressed)
        pubkey_hex = pubkey.hex()

        console.print("\n[green]✓[/green] Derived public key:")
        console.print(f"[bold]{pubkey_hex}[/bold]")
        console.print(
            f"\n[dim]Format: {'Compressed' if is_compressed else 'Uncompressed'}[/dim]"
        )
        console.print(
            f"[dim]Length: {len(pubkey_hex)} hex chars ({len(pubkey)} bytes)[/dim]"
        )

        if not is_compressed:
            console.print(
                "\n[yellow]Note:[/yellow] This is an uncompressed key (starts with '04')."
            )
            console.print(
                "[yellow]Compressed format starts with '02' or '03' and is 33 bytes.[/yellow]"
            )

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@app.command()
def generate_delegate_key(
    output_dir: Path = typer.Option(
        Path("."), "--output-dir", "-o", help="Output directory for keys"
    ),
    name: str = typer.Option(
        "delegate",
        "--name",
        "-n",
        help="Key name (files will be name.key.age/name.key and name.pub)",
    ),
    no_encrypt: bool = typer.Option(
        False, "--no-encrypt", help="Don't encrypt the private key (NOT RECOMMENDED)"
    ),
):
    """
    Generate a new delegate keypair for signing fluxnode START transactions.

    The private key will be age-encrypted by default (saved as name.key.age).
    Use --no-encrypt to save unencrypted (as name.key, NOT RECOMMENDED).
    The public key will be saved unencrypted for easy sharing.

    Example:
        flux-delegate-starter generate-delegate-key --name my-delegate
    """
    try:
        console.print("[cyan]Generating delegate keypair...[/cyan]")

        # Generate keypair (returns secp256k1 privkey as bytes)
        privkey_bytes, pubkey_bytes = DelegateKeyManager.generate_keypair()

        # Convert privkey to WIF format (compressed)
        import hashlib

        import base58

        # Mainnet WIF prefix (0x80) + privkey + compressed flag (0x01)
        wif_data = b"\x80" + privkey_bytes + b"\x01"
        checksum = hashlib.sha256(hashlib.sha256(wif_data).digest()).digest()[:4]
        privkey_wif = base58.b58encode(wif_data + checksum).decode("ascii")

        # Securely zero the raw privkey bytes
        privkey_bytearray = bytearray(privkey_bytes)
        secure_zero_memory(privkey_bytearray)

        console.print("[green]✓[/green] Keypair generated")

        # Create output directory if needed
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save private key (use .key.age for encrypted, .key for unencrypted)
        encrypt = not no_encrypt

        if encrypt:
            privkey_path = output_dir / f"{name}.key.age"
            console.print("[cyan]Encrypting private key...[/cyan]")
        else:
            privkey_path = output_dir / f"{name}.key"

        DelegateKeyManager.save_key(privkey_wif, privkey_path, encrypt=encrypt)

        if encrypt:
            console.print(
                f"[green]✓[/green] Private key saved (age-encrypted): {privkey_path}"
            )
        else:
            console.print(
                f"[yellow]⚠[/yellow] Private key saved (UNENCRYPTED): {privkey_path}"
            )
            console.print(
                "[yellow]  WARNING: Unencrypted private keys are a security risk![/yellow]"
            )

        # Save public key
        pubkey_path = output_dir / f"{name}.pub"
        pubkey_hex = pubkey_bytes.hex()
        pubkey_path.write_text(pubkey_hex)
        console.print(f"[green]✓[/green] Public key saved: {pubkey_path}")

        console.print("\n[bold]Summary:[/bold]")
        console.print(f"  Private key: {privkey_path}")
        console.print(f"  Public key:  {pubkey_path}")
        console.print(f"  Pubkey hex:  {pubkey_hex}")

        console.print("\n[dim]To use this key:[/dim]")
        console.print(
            f"[dim]  flux-delegate-starter start <args> --delegate-key-file {privkey_path}[/dim]"
        )

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


@app.command()
def find_start_tx(
    collateral_txid: str = typer.Argument(
        ..., help="Collateral transaction ID (64 hex chars)"
    ),
    collateral_index: int = typer.Argument(..., help="Collateral output index"),
    transport: str = typer.Option(
        "api", "--transport", "-t", help="Transport method: 'api' (default) or 'rpc'"
    ),
    rpc_host: str = typer.Option(
        "127.0.0.1", "--host", help="RPC host (only for --transport rpc)"
    ),
    rpc_port: int = typer.Option(
        16124, "--port", help="RPC port (only for --transport rpc)"
    ),
    rpc_user: str | None = typer.Option(
        None, "--rpc-user", help="RPC username (only for --transport rpc)"
    ),
    rpc_password: str | None = typer.Option(
        None, "--rpc-password", help="RPC password (only for --transport rpc)"
    ),
):
    """
    Find the START transaction for a fluxnode by its collateral.

    This searches the blockchain for the START transaction that activated
    a fluxnode with the given collateral outpoint.

    Example:
        flux-delegate-starter find-start-tx 1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d0 0
    """
    # Validate transport
    if transport not in ("api", "rpc"):
        err_console.print(
            f"[red]Error:[/red] Invalid transport '{transport}'. Must be 'api' or 'rpc'"
        )
        sys.exit(1)

    asyncio.run(
        _find_start_tx(
            collateral_txid,
            collateral_index,
            transport,
            rpc_host,
            rpc_port,
            rpc_user,
            rpc_password,
        )
    )


@app.command()
def check_delegates(
    collateral_txhash: str = typer.Argument(..., help="Collateral transaction hash"),
    collateral_index: int = typer.Option(
        0, "--index", "-i", help="Collateral output index"
    ),
):
    """
    Check what delegate keys are registered for a collateral.

    This queries the Flux API to see which delegate starting keys
    are authorized for the specified collateral.

    Example:
        flux-delegate-starter check-delegates 1fa2f8c38b2c62792b5a6d08e13d90acc5120c52ebde2a99a490bf40436c611a
    """
    asyncio.run(_check_delegates(collateral_txhash, collateral_index))


async def _check_delegates(collateral_txhash: str, collateral_index: int):
    """Internal implementation."""
    try:
        from .api_client import FluxAPIClient

        client = FluxAPIClient()
        console.print(
            f"[cyan]Checking delegates for collateral {collateral_txhash}:{collateral_index}...[/cyan]"
        )

        # Get fluxnode list and find this collateral
        nodes = await client.list_fluxnodes()

        # Find matching node
        matching_node = None
        for node in nodes:
            if node.get("txhash") == collateral_txhash and node.get("outidx") == str(
                collateral_index
            ):
                matching_node = node
                break

        if not matching_node:
            console.print(
                f"[yellow]No fluxnode found with collateral {collateral_txhash}:{collateral_index}[/yellow]"
            )
            return

        console.print("[green]✓[/green] Found fluxnode")
        console.print(f"  IP: {matching_node.get('ip', 'N/A')}")
        console.print(f"  Tier: {matching_node.get('tier', 'N/A')}")
        console.print(
            f"  Payment Address: {matching_node.get('payment_address', 'N/A')}"
        )

        # Check for delegate info
        if "delegates" in matching_node:
            delegates = matching_node["delegates"]
            console.print("\n[cyan]Delegate Information:[/cyan]")
            console.print(f"  Version: {delegates.get('version', 'N/A')}")
            console.print(f"  Type: {delegates.get('type', 'N/A')}")

            keys = delegates.get("keys", [])
            if keys:
                console.print(f"\n[cyan]Authorized Delegate Keys ({len(keys)}):[/cyan]")
                for i, key in enumerate(keys, 1):
                    console.print(f"  {i}. {key}")
            else:
                console.print("\n[yellow]No delegate keys registered[/yellow]")
        else:
            console.print(
                "\n[yellow]No delegate information found for this fluxnode[/yellow]"
            )

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@app.command()
def test_connection(
    transport: str = typer.Option(
        "api", "--transport", "-t", help="Transport method: 'api' (default) or 'rpc'"
    ),
    rpc_host: str = typer.Option(
        "127.0.0.1", "--host", help="RPC host (only for --transport rpc)"
    ),
    rpc_port: int = typer.Option(
        16124, "--port", help="RPC port (only for --transport rpc)"
    ),
    rpc_user: str | None = typer.Option(
        None, "--rpc-user", help="RPC username (only for --transport rpc)"
    ),
    rpc_password: str | None = typer.Option(
        None, "--rpc-password", help="RPC password (only for --transport rpc)"
    ),
):
    """
    Test connection to Flux daemon or API.
    """
    # Validate transport
    if transport not in ("api", "rpc"):
        err_console.print(
            f"[red]Error:[/red] Invalid transport '{transport}'. Must be 'api' or 'rpc'"
        )
        sys.exit(1)

    asyncio.run(_test_connection(transport, rpc_host, rpc_port, rpc_user, rpc_password))


async def _find_start_tx(
    collateral_txid: str,
    collateral_index: int,
    transport: str,
    rpc_host: str,
    rpc_port: int,
    rpc_user: str | None,
    rpc_password: str | None,
):
    """Internal async implementation of find-start-tx."""
    import json
    import re

    try:
        # Validate txid format
        if not re.match(r"^[0-9a-fA-F]{64}$", collateral_txid):
            err_console.print(
                "[red]Error:[/red] Invalid txid format (must be 64 hex characters)"
            )
            sys.exit(1)

        # Create client
        if transport == "rpc":
            client = FluxRPCClient(
                host=rpc_host, port=rpc_port, username=rpc_user, password=rpc_password
            )
        else:
            client = FluxAPIClient()

        console.print("[cyan]Searching for START transaction...[/cyan]")
        console.print(f"[cyan]Collateral: {collateral_txid}:{collateral_index}[/cyan]")
        console.print()

        # Step 1: Check viewdeterministicfluxnodelist (includes both confirmed and unconfirmed nodes)
        console.print("[yellow][1/4][/yellow] Querying network state...")

        if isinstance(client, FluxAPIClient):
            fluxnodes = await client.list_fluxnodes(filter=collateral_txid)
        else:
            fluxnodes = await client.list_fluxnodes()

        added_height = None
        for node in fluxnodes:
            if (
                isinstance(node, dict)
                and node.get("txhash") == collateral_txid
                and str(node.get("outidx")) == str(collateral_index)
            ):
                added_height = node.get("added_height")
                console.print(
                    f"[green]✓[/green] Found node at block height: {added_height}"
                )
                break

        # Fallback: check start list if not in viewdeterministicfluxnodelist
        if added_height is None:
            console.print(
                "[dim]Not in deterministic list, checking start list...[/dim]"
            )
            start_list = await client.get_start_list()

            for node in start_list:
                if (
                    isinstance(node, dict)
                    and node.get("txhash") == collateral_txid
                    and str(node.get("outidx")) == str(collateral_index)
                ):
                    added_height = node.get("added_height")
                    console.print(
                        f"[green]✓[/green] Found node in start list at block height: {added_height}"
                    )
                    break

        if added_height is None:
            err_console.print(
                f"[red]Error:[/red] Fluxnode not found with collateral {collateral_txid}:{collateral_index}"
            )
            err_console.print(
                "[yellow]The node may not be registered yet, or the collateral is incorrect.[/yellow]"
            )
            sys.exit(1)

        console.print()

        # Step 2: Get the block at added_height with full transaction details
        console.print(
            f"[yellow][2/4][/yellow] Fetching block {added_height} with all transaction details..."
        )

        if isinstance(client, FluxAPIClient):
            block = await client.get_block(added_height, verbosity=2)
        else:
            block = await client.call("getblock", str(added_height), 2)

        if not block or "tx" not in block:
            err_console.print(f"[red]Error:[/red] Failed to fetch block {added_height}")
            sys.exit(1)

        transactions = block["tx"]
        console.print(
            f"[green]✓[/green] Fetched block with {len(transactions)} transactions"
        )
        console.print()

        # Step 3: Search for START transaction in decoded transactions
        console.print("[yellow][3/4][/yellow] Searching for START transaction...")

        found_start_tx = None
        tx_details = None

        for tx_data in transactions:
            # Check if it's a START transaction (version 5 or 6, type "Starting a fluxnode")
            # that references our collateral
            if (
                tx_data.get("version") in (5, 6)
                and tx_data.get("type") == "Starting a fluxnode"
                and tx_data.get("txhash") == collateral_txid
                and str(tx_data.get("outidx")) == str(collateral_index)
            ):
                found_start_tx = tx_data.get("txid")
                tx_details = tx_data
                # Add block metadata (not included in tx when from getblock verbosity=2)
                tx_details["blockhash"] = block.get("hash")
                tx_details["height"] = block.get("height")
                tx_details["confirmations"] = block.get("confirmations")
                tx_details["time"] = block.get("time")
                tx_details["blocktime"] = block.get("time")
                break

        console.print(f"[green]✓[/green] Searched {len(transactions)} transactions")
        console.print()

        # Step 4: Report results
        console.print("[yellow][4/4][/yellow] Results:")
        console.print()

        if found_start_tx and tx_details:
            console.print("[green]✓ Found START transaction![/green]")
            console.print()
            console.print("[cyan]START Transaction ID:[/cyan]")
            console.print(f"[bold]{found_start_tx}[/bold]")
            console.print()

            console.print("[cyan]Transaction Details:[/cyan]")
            console.print(f"  Version: {tx_details.get('version')}")
            console.print(f"  Type: {tx_details.get('type')}")
            console.print(f"  Collateral: {tx_details.get('collateral')}")
            console.print(f"  Block: {tx_details.get('blockhash')}")
            console.print(f"  Height: {tx_details.get('height')}")
            console.print(f"  Confirmations: {tx_details.get('confirmations')}")

            if tx_details.get("using_delegates"):
                console.print("  Using Delegates: [green]Yes[/green]")
                delegate_data = tx_details.get("delegate_data", {})
                console.print(
                    f"  Delegate Type: {delegate_data.get('type')} ({'UPDATE' if delegate_data.get('type') == 1 else 'SIGNING'})"
                )
                if delegate_data.get("keys"):
                    console.print("  Authorized Delegate Keys:")
                    for key in delegate_data.get("keys", []):
                        console.print(f"    - {key}")

            console.print()
            console.print("[dim]Full JSON:[/dim]")
            console.print(json.dumps(tx_details, indent=2))
        else:
            err_console.print("[red]✗ START transaction not found[/red]")
            console.print()
            console.print("[yellow]Possible reasons:[/yellow]")
            console.print("  - The collateral txid or output index is incorrect")
            console.print("  - The node was started with a different mechanism")
            console.print("  - Block data is incomplete or corrupted")
            sys.exit(1)

    except FluxDelegateStarterError as e:
        err_console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        err_console.print(f"[red]Unexpected error:[/red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


async def _test_connection(
    transport: str,
    rpc_host: str,
    rpc_port: int,
    rpc_user: str | None,
    rpc_password: str | None,
):
    """Internal async implementation of test connection."""
    try:
        if transport == "rpc":
            console.print(
                f"[cyan]Testing RPC connection to {rpc_host}:{rpc_port}...[/cyan]"
            )
            client = FluxRPCClient(
                host=rpc_host, port=rpc_port, username=rpc_user, password=rpc_password
            )
        else:
            console.print(
                "[cyan]Testing API connection to https://api.runonflux.io...[/cyan]"
            )
            client = FluxAPIClient()

        info = await client.get_blockchain_info()

        console.print(
            f"[green]✓[/green] Connected successfully via {transport.upper()}!"
        )
        console.print(f"  Chain: {info.get('chain', 'unknown')}")
        console.print(f"  Blocks: {info.get('blocks', 0)}")
        console.print(f"  Best block hash: {info.get('bestblockhash', 'unknown')}")

    except Exception as e:
        err_console.print(f"[red]✗[/red] Connection failed: {e}")
        sys.exit(1)


def _format_decoded_tx(decoded: dict) -> str:
    """Format decoded transaction for display."""
    lines = []
    lines.append(f"TxID: {decoded.get('txid', 'N/A')}")
    lines.append(f"Version: {decoded.get('version', 'N/A')}")

    # Handle both RPC and API response formats
    if "type" in decoded:
        lines.append(f"Type: {decoded['type']}")

    # Fluxnode data
    if decoded.get("type") == "Starting a fluxnode" or "collateral" in decoded:
        lines.append("\nFluxnode Data:")
        lines.append(
            f"  Collateral: {decoded.get('collateral', decoded.get('collateral_output', 'N/A'))}"
        )

        collateral_pk = decoded.get("collateral_pubkey", "")
        if collateral_pk:
            lines.append(f"  Collateral Pubkey: {collateral_pk}")
        else:
            lines.append("  Collateral Pubkey: (empty)")

        # VPS pubkey - try different field names
        vps_pubkey = decoded.get("zelnode_pubkey", decoded.get("pubKey", "N/A"))
        lines.append(f"  VPS Pubkey: {vps_pubkey}")

        sigtime = decoded.get("sigtime", decoded.get("sigTime"))
        if sigtime:
            lines.append(f"  Signature Time: {sigtime}")

        # Delegate data
        if decoded.get("using_delegates") or "delegate_data" in decoded:
            lines.append(f"  Using Delegates: {decoded.get('using_delegates', False)}")

            if "delegate_data" in decoded:
                dd = decoded["delegate_data"]
                lines.append(f"  Delegate Version: {dd.get('version', 'N/A')}")
                dtype_map = {0: "NONE", 1: "ALL", 2: "SIGNING"}
                dtype = dd.get("type", "N/A")
                dtype_str = dtype_map.get(dtype, str(dtype))
                lines.append(f"  Delegate Type: {dtype_str}")

                keys = dd.get("keys", [])
                if keys:
                    lines.append(f"  Delegate Keys: {len(keys)} keys")

    return "\n".join(lines)


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
