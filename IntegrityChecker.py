import hmac
import hashlib

class IntegrityChecker:
    @staticmethod
    def generate_mac(data: bytes, key: bytes) -> bytes:
        """
        Generate a Message Authentication Code (MAC) using HMAC-SHA256.

        Args:
            data (bytes): The input data to authenticate.
            key (bytes): A cryptographic key.

        Returns:
            bytes: The generated MAC.

        Raises:
            ValueError: If data or key is invalid.
        """
        if not isinstance(data, bytes) or not data:
            raise ValueError("Data must be a non-empty byte string.")
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("Key must be a non-empty byte string.")

        try:
            return hmac.new(key, data, hashlib.sha256).digest()
        except Exception as e:
            raise ValueError(f"MAC generation failed: {e}")

    @staticmethod
    def verify_mac(data: bytes, key: bytes, mac: bytes) -> bool:
        """
        Verify the integrity of data using a provided MAC.

        Args:
            data (bytes): The original data.
            key (bytes): The cryptographic key used for generating the MAC.
            mac (bytes): The MAC to verify.

        Returns:
            bool: True if the MAC is valid, False otherwise.

        Raises:
            ValueError: If any input is invalid.
        """
        if not isinstance(data, bytes) or not data:
            raise ValueError("Data must be a non-empty byte string.")
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("Key must be a non-empty byte string.")
        if not isinstance(mac, bytes) or len(mac) != hashlib.sha256().digest_size:
            raise ValueError("MAC must be a valid byte string of the correct length.")

        try:
            expected_mac = hmac.new(key, data, hashlib.sha256).digest()
            return hmac.compare_digest(mac, expected_mac)
        except Exception as e:
            raise ValueError(f"MAC verification failed: {e}")
