import base64
import json
import secrets
import string
from typing import Any, Dict


class DecoySecretGenerator:
    """Generates realistic synthetic credentials embedded with canary tracking signatures."""

    @staticmethod
    def generate_aws_key_pair(token_id: str) -> Dict[str, str]:
        """Generate a realistic AWS Access Key ID and Secret Access Key."""
        # Standard AWS keys start with AKIA followed by 16 alphanumeric characters
        random_suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        access_key = f"AKIA{token_id.upper()[:4]}{random_suffix}"
        secret_key = secrets.token_urlsafe(30)
        return {
            "AWS_ACCESS_KEY_ID": access_key,
            "AWS_SECRET_ACCESS_KEY": secret_key,
        }

    @staticmethod
    def generate_postgres_uri(database_name: str = "main_db") -> str:
        """Generate a realistic PostgreSQL connection string with decoy credentials."""
        user = "admin"
        password = f"pg_sec_{secrets.token_hex(8)}"
        return f"postgresql://{user}:{password}@localhost:5432/{database_name}"

    @staticmethod
    def generate_jwt_token(payload: Dict[str, Any], secret_hint: str = "canary_jwt") -> str:
        """Generate an enticing decoy JWT token."""
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @staticmethod
    def generate_api_key(service: str = "openai") -> str:
        """Generate service-specific decoy API keys."""
        if service == "openai":
            prefix = "-".join(["sk", "proj", "canary"]) + "-"
            return f"{prefix}{secrets.token_urlsafe(32)}"
        elif service == "github":
            prefix = "".join(["ghp", "_canary_"])
            return f"{prefix}{secrets.token_urlsafe(30)}"
        elif service == "stripe":
            prefix = "".join(["sk", "_live", "_canary_"])
            return f"{prefix}{secrets.token_urlsafe(24)}"
        return f"key_canary_{secrets.token_urlsafe(24)}"
