from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

class KeyManager:
    @staticmethod
    def generate_key_pair():
        """
        Generate an elliptic curve private and public key pair.

        Returns:
            tuple: A tuple containing the private key and public key.

        Raises:
            Exception: If key generation fails.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            raise ValueError(f"Key pair generation failed: {e}")

    @staticmethod
    def deserialize_private_key(private_key_pem: bytes) -> EllipticCurvePrivateKey:
        """
        Deserialize a PEM-encoded private key.

        Args:
            private_key_pem (bytes): The PEM-encoded private key.

        Returns:
            EllipticCurvePrivateKey: The deserialized private key.

        Raises:
            ValueError: If the private key cannot be deserialized.
        """
        if not isinstance(private_key_pem, bytes) or not private_key_pem:
            raise ValueError("Private key PEM must be a non-empty byte string.")

        try:
            return serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
        except ValueError as e:
            raise ValueError(f"Private key deserialization failed: {e}")

    @staticmethod
    def deserialize_public_key(public_key_pem: bytes) -> EllipticCurvePublicKey:
        """
        Deserialize a PEM-encoded public key.

        Args:
            public_key_pem (bytes): The PEM-encoded public key.

        Returns:
            EllipticCurvePublicKey: The deserialized public key.

        Raises:
            ValueError: If the public key cannot be deserialized.
        """
        if not isinstance(public_key_pem, bytes) or not public_key_pem:
            raise ValueError("Public key PEM must be a non-empty byte string.")

        try:
            return serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
        except ValueError as e:
            raise ValueError(f"Public key deserialization failed: {e}")

    @staticmethod
    def serialize_public_key(public_key: EllipticCurvePublicKey) -> bytes:
        """
        Serialize a public key to PEM format.

        Args:
            public_key (EllipticCurvePublicKey): The public key to serialize.

        Returns:
            bytes: The PEM-encoded public key.

        Raises:
            ValueError: If serialization fails.
        """
        if not isinstance(public_key, EllipticCurvePublicKey):
            raise ValueError("The public key must be an instance of EllipticCurvePublicKey.")

        try:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            raise ValueError(f"Public key serialization failed: {e}")

    @staticmethod
    def derive_shared_secret(private_key: EllipticCurvePrivateKey, peer_public_key: EllipticCurvePublicKey) -> bytes:
        """
        Derive a shared secret using ECDH and HKDF.

        Args:
            private_key (EllipticCurvePrivateKey): The private key of the local user.
            peer_public_key (EllipticCurvePublicKey): The public key of the peer.

        Returns:
            bytes: A 256-bit derived shared secret.

        Raises:
            ValueError: If the peer's public key is invalid.
        """
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise ValueError("private_key must be an instance of EllipticCurvePrivateKey.")
        if not isinstance(peer_public_key, EllipticCurvePublicKey):
            raise ValueError("peer_public_key must be an instance of EllipticCurvePublicKey.")

        try:
            # Perform ECDH key exchange to derive the shared secret
            shared_secret = private_key.exchange(ECDH(), peer_public_key)

            # Use HKDF to derive a fixed-length key (256 bits for AES-GCM)
            hkdf = HKDF(
                algorithm=SHA256(),
                length=32,  # 256 bits
                salt=None,  # Optional: Add a salt for additional security
                info=b"shared secret",  # Context-specific information
                backend=default_backend()
            )
            derived_key = hkdf.derive(shared_secret)
            return derived_key
        except Exception as e:
            raise ValueError(f"Shared secret derivation failed: {e}")
