"""Secure key management with age encryption."""

import getpass
import os
import sys
from pathlib import Path

import pyrage

from .crypto import privkey_to_pubkey
from .exceptions import ConfigError


class DelegateKeyManager:
    """Manage delegate keys with age encryption."""

    AGE_ARMOR_PREFIX = "-----BEGIN AGE ENCRYPTED FILE-----"

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """
        Generate a new secp256k1 keypair for delegate use.

        Returns:
            Tuple of (private_key, public_key) as bytes
        """
        # Generate random 32-byte private key
        privkey = os.urandom(32)

        # Derive compressed public key
        pubkey = privkey_to_pubkey(privkey, compressed=True)

        return privkey, pubkey

    @staticmethod
    def read_passphrase_from_stdin() -> str | None:
        """
        Read passphrase from stdin if available.

        Returns:
            Passphrase from stdin, or None if stdin is a tty (interactive terminal)
        """
        # Only read from stdin if it's NOT a terminal (i.e., piped/redirected)
        if not sys.stdin.isatty():
            passphrase = sys.stdin.readline().rstrip("\n\r")
            return passphrase if passphrase else None
        return None

    @staticmethod
    def prompt_passphrase(confirm: bool = True) -> str:
        """
        Prompt user for encryption passphrase.

        Args:
            confirm: If True, prompt twice to confirm

        Returns:
            Passphrase string

        Raises:
            ValueError: If passphrases don't match
        """
        passphrase = getpass.getpass("Enter encryption passphrase: ")

        if confirm:
            passphrase2 = getpass.getpass("Confirm encryption passphrase: ")
            if passphrase != passphrase2:
                raise ValueError("Passphrases do not match")

        return passphrase

    @staticmethod
    def encrypt_key(privkey_wif: str, passphrase: str) -> str:
        """
        Encrypt a WIF private key with age using passphrase.

        Args:
            privkey_wif: Private key in WIF format
            passphrase: Encryption passphrase

        Returns:
            Age-encrypted armored string
        """
        # Encrypt with passphrase (armored=True for ASCII output)
        # pyrage is a Rust extension with no type stubs; its real members
        # aren't visible to static analysis.
        encrypted = pyrage.passphrase.encrypt(  # ty: ignore[unresolved-attribute]  # pyright: ignore[reportAttributeAccessIssue]
            privkey_wif.encode("utf-8"), passphrase, armored=True
        )

        # Return armored format
        return encrypted.decode("utf-8")

    @staticmethod
    def decrypt_key(encrypted_data: str, passphrase: str) -> str:
        """
        Decrypt an age-encrypted private key.

        Args:
            encrypted_data: Age-encrypted armored string
            passphrase: Decryption passphrase

        Returns:
            Decrypted WIF private key

        Raises:
            ValueError: If decryption fails
        """
        try:
            # pyrage is a Rust extension with no type stubs; its real members
            # aren't visible to static analysis.
            decrypted = pyrage.passphrase.decrypt(  # ty: ignore[unresolved-attribute]  # pyright: ignore[reportAttributeAccessIssue]
                encrypted_data.encode("utf-8"), passphrase
            )
            return decrypted.decode("utf-8")
        except pyrage.DecryptError as e:  # ty: ignore[unresolved-attribute]  # pyright: ignore[reportAttributeAccessIssue]
            raise ValueError(
                "Incorrect passphrase or corrupted age-encrypted data"
            ) from e
        except Exception as e:
            raise ValueError(f"Age decryption error: {e}") from e

    @staticmethod
    def is_encrypted(data: str) -> bool:
        """
        Check if a string is age-encrypted.

        Args:
            data: String to check

        Returns:
            True if encrypted, False otherwise
        """
        return data.strip().startswith(DelegateKeyManager.AGE_ARMOR_PREFIX)

    @staticmethod
    def load_key(key_path: Path, passphrase: str | None = None) -> str:
        """
        Load a private key from file, decrypting if necessary.

        Passphrase sources (in order of priority):
        1. passphrase parameter
        2. stdin (if not a tty, e.g., echo "pass" | command)
        3. Interactive prompt

        Args:
            key_path: Path to key file
            passphrase: Optional passphrase (will try stdin, then prompt if encrypted and not provided)

        Returns:
            Decrypted WIF private key

        Raises:
            ConfigError: If file not found or decryption fails
        """
        if not key_path.exists():
            raise ConfigError(f"Key file not found: {key_path}")

        key_data = key_path.read_text().strip()

        # Check if encrypted
        if DelegateKeyManager.is_encrypted(key_data):
            if passphrase is None:
                # Try reading from stdin first
                passphrase = DelegateKeyManager.read_passphrase_from_stdin()

                # If still None, prompt interactively
                if passphrase is None:
                    passphrase = getpass.getpass(
                        f"Enter passphrase for {key_path.name}: "
                    )

            try:
                return DelegateKeyManager.decrypt_key(key_data, passphrase)
            except ValueError as e:
                raise ConfigError(str(e)) from e
        else:
            # Not encrypted, return as-is
            return key_data

    @staticmethod
    def save_key(
        privkey_wif: str,
        output_path: Path,
        encrypt: bool = True,
        passphrase: str | None = None,
    ) -> None:
        """
        Save a private key to file, optionally encrypting it.

        Passphrase sources (in order of priority):
        1. passphrase parameter
        2. stdin (if not a tty, e.g., echo "pass" | command)
        3. Interactive prompt with confirmation

        Args:
            privkey_wif: Private key in WIF format
            output_path: Where to save the key
            encrypt: Whether to encrypt (default: True)
            passphrase: Encryption passphrase (will try stdin, then prompt if encrypt=True and not provided)

        Raises:
            ValueError: If passphrases don't match
        """
        if encrypt:
            if passphrase is None:
                # Try reading from stdin first
                passphrase = DelegateKeyManager.read_passphrase_from_stdin()

                # If still None, prompt interactively with confirmation
                if passphrase is None:
                    passphrase = DelegateKeyManager.prompt_passphrase(confirm=True)

            encrypted_data = DelegateKeyManager.encrypt_key(privkey_wif, passphrase)
            output_path.write_text(encrypted_data)
        else:
            output_path.write_text(privkey_wif)

        # Set restrictive permissions (owner read/write only)
        output_path.chmod(0o600)


def secure_zero_memory(data: bytearray) -> None:
    """
    Securely zero out memory containing sensitive data.

    Args:
        data: Bytearray to zero out
    """
    # Overwrite with zeros
    for i in range(len(data)):
        data[i] = 0
