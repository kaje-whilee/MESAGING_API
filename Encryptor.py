from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class Encryptor:
    def encrypt(self, data: str, key: bytes) -> bytes:
        """
        Encrypt the given data using AES-GCM with the provided key.

        Args:
            data (str): The plaintext data to encrypt.
            key (bytes): A 128-bit, 192-bit, or 256-bit key for AES-GCM.

        Returns:
            bytes: The nonce concatenated with the ciphertext.

        Raises:
            ValueError: If the key size is invalid or the data is empty.
        """
        if not isinstance(key, bytes) or len(key) not in [16, 24, 32]:
            raise ValueError("Key must be a valid AES-GCM key of 16, 24, or 32 bytes.")
        if not data:
            raise ValueError("Data to encrypt must not be empty.")

        try:
            nonce = os.urandom(12)  # AES-GCM requires a 12-byte nonce
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
            return nonce + ciphertext
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")

    def decrypt(self, encrypted_data: bytes, key: bytes) -> str:
        """
        Decrypt the given encrypted data using AES-GCM with the provided key.

        Args:
            encrypted_data (bytes): The encrypted data (nonce + ciphertext).
            key (bytes): A 128-bit, 192-bit, or 256-bit key for AES-GCM.

        Returns:
            str: The decrypted plaintext data.

        Raises:
            ValueError: If the key size is invalid, the nonce size is incorrect,
                        or the decryption fails.
        """
        if not isinstance(key, bytes) or len(key) not in [16, 24, 32]:
            raise ValueError("Key must be a valid AES-GCM key of 16, 24, or 32 bytes.")
        if not encrypted_data or len(encrypted_data) <= 12:
            raise ValueError("Encrypted data must include a 12-byte nonce and ciphertext.")

        try:
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None).decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
