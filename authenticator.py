import os
import time
import hmac
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode

class Authenticator:
    def __init__(self):
        self.secret_key = os.getenv("AUTH_SECRET_KEY", "default_secure_key")
        self.token_expiry_seconds = 1800  # Tokens valid for 30 minutes
        if not self.secret_key or self.secret_key == "default_secure_key":
            raise ValueError("Using default secret key. Set 'AUTH_SECRET_KEY' in the environment for better security.")

    def generate_token(self, user_id: str) -> str:
        try:
            # Generate the expiration timestamp
            expiry = int(time.time()) + self.token_expiry_seconds

            # Create the payload
            payload = f"{user_id}:{expiry}"

            # Generate the HMAC signature for the payload
            signature = self._generate_signature(payload)

            # Construct the token
            token = f"{payload}:{signature}"
            return urlsafe_b64encode(token.encode()).decode()
        except Exception as e:
            raise ValueError("Failed to generate token") from e

    def validate_token(self, token: str) -> bool:
        try:
            # Decode the token
            decoded_token = urlsafe_b64decode(token).decode()
            payload, signature = decoded_token.rsplit(":", 1)
            user_id, expiry = payload.split(":")

            # Validate token expiration
            if time.time() > int(expiry):
                return False

            # Validate the signature
            expected_signature = self._generate_signature(payload)
            if not hmac.compare_digest(expected_signature, signature):
                return False

            return True
        except Exception:
            return False

    def extract_user_id(self, token: str) -> str:
        try:
            # Decode the token
            decoded_token = urlsafe_b64decode(token).decode()
            payload, _ = decoded_token.rsplit(":", 1)
            user_id, _ = payload.split(":")
            return user_id
        except Exception:
            raise ValueError("Invalid token")

    def _generate_signature(self, data: str) -> str:
        try:
            # Generate the HMAC-SHA256 signature
            return hmac.new(
                self.secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()
        except Exception as e:
            raise ValueError("Failed to generate signature") from e
