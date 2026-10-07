import logging
import math
import re
from collections import Counter
from typing import Any, Dict, List
from deception.decoy_secrets import DecoySecretGenerator

logger = logging.getLogger("mirror.mirror.sanitization")


class MirrorSanitizer:
    """Sanitizes environment variables and generates synthetic mock data for the mirror environment.

    Employs 3 layers of defense:
    1. Known Secret Signatures (Regex for GitHub, Stripe, Slack, JWT, GCP, PEM).
    2. Comprehensive Keyword Matching (TOKEN, KEY, AUTH, PRIVATE, etc.).
    3. Shannon Entropy Analysis (Auto-flags high-randomness credentials).
    """

    KNOWN_SIGNATURE_PATTERNS = [
        (re.compile(r"gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}"), "mirror_decoy_github_token_9941827481928472"),
        (re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,}"), "mirror_decoy_stripe_key_991827364"),
        (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "mirror_decoy_slack_token_9941"),
        (re.compile(r"AIza[0-9A-Za-z-_]{35}"), "mirror_decoy_gcp_key_991827364819283"),
        (re.compile(r"eyJh[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mirrorDecoyPayload.mirrorSignature9941"),
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "-----" + "BEGIN PRIVATE KEY" + "-----\n[DECOY_MIRROR_PRIVATE_KEY_REDACTED]\n-----" + "END PRIVATE KEY" + "-----"),
        (re.compile(r"(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@"), None),  # handled specially
    ]

    SENSITIVE_KEYWORD_SUBSTRINGS = [
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "API_KEY",
        "AUTH",
        "PRIVATE",
        "CREDENTIAL",
        "DATABASE_URL",
        "DB_URL",
        "CONN_STR",
        "SIGNING",
        "JWT",
        "BEARER",
        "SALT",
        "CERT",
        "ID_RSA",
        "SSH_KEY",
    ]

    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy for a given string."""
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @classmethod
    def sanitize_environment(cls, original_env: List[str]) -> List[str]:
        """Strip real secrets from environment variables and replace with realistic decoy secrets."""
        sanitized = []
        aws_keys = DecoySecretGenerator.generate_aws_key_pair("mirror")
        decoy_pg = DecoySecretGenerator.generate_postgres_uri("mirror_db")
        decoy_openai = DecoySecretGenerator.generate_api_key("openai")

        for item in original_env:
            if "=" not in item:
                continue
            key, val = item.split("=", 1)
            key_upper = key.upper()

            # Rule 1: Specific provider replacements
            if "AWS_ACCESS_KEY" in key_upper:
                sanitized.append(f"{key}={aws_keys['AWS_ACCESS_KEY_ID']}")
                continue
            elif "AWS_SECRET" in key_upper:
                sanitized.append(f"{key}={aws_keys['AWS_SECRET_ACCESS_KEY']}")
                continue
            elif "DATABASE_URL" in key_upper or "DB_URL" in key_upper:
                sanitized.append(f"{key}={decoy_pg}")
                continue
            elif "OPENAI_API_KEY" in key_upper or "OPENAI_KEY" in key_upper:
                sanitized.append(f"{key}={decoy_openai}")
                continue

            # Rule 2: Signature pattern match on value
            matched_pattern = False
            for pattern, decoy_val in cls.KNOWN_SIGNATURE_PATTERNS:
                if pattern.search(val):
                    replacement = decoy_val if decoy_val else decoy_pg
                    sanitized.append(f"{key}={replacement}")
                    matched_pattern = True
                    break
            if matched_pattern:
                continue

            # Rule 3: Comprehensive Keyword match on key name
            is_sensitive_key = any(kw in key_upper for kw in cls.SENSITIVE_KEYWORD_SUBSTRINGS)
            if is_sensitive_key:
                sanitized.append(f"{key}=mirror_decoy_{key.lower()}_9941")
                continue

            # Rule 4: Shannon Entropy on value (high-randomness credentials)
            # High entropy (> 3.6) and length >= 20 characters is almost certainly a secret/hash
            if len(val) >= 20 and cls.calculate_entropy(val) > 3.6:
                logger.info("High entropy value detected in env var '%s' (H=%.2f). Sanitizing.", key, cls.calculate_entropy(val))
                sanitized.append(f"{key}=mirror_decoy_{key.lower()}_entropy_masked")
                continue

            # Variable deemed safe
            sanitized.append(item)

        # Essential decoy markers injected
        sanitized.append("MIRROR_WORLD_ACTIVE=true")
        sanitized.append("ENVIRONMENT=mirror_shadow")
        return sanitized

    @staticmethod
    def generate_synthetic_sql_seed() -> str:
        """Generate realistic synthetic database schema and fake records for databases in the mirror world."""
        return (
            "-- Synthetic Schema for Mirror PostgreSQL Instance\n"
            "CREATE TABLE IF NOT EXISTS users (\n"
            "    id SERIAL PRIMARY KEY,\n"
            "    username VARCHAR(50) NOT NULL,\n"
            "    email VARCHAR(100) NOT NULL,\n"
            "    password_hash VARCHAR(255) NOT NULL,\n"
            "    is_admin BOOLEAN DEFAULT FALSE\n"
            ");\n\n"
            "CREATE TABLE IF NOT EXISTS transactions (\n"
            "    id SERIAL PRIMARY KEY,\n"
            "    user_id INT REFERENCES users(id),\n"
            "    amount NUMERIC(10, 2) NOT NULL,\n"
            "    description VARCHAR(255) NOT NULL,\n"
            "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n"
            ");\n\n"
            "-- Synthetic Honey Records\n"
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES\n"
            "('admin_master', 'secops@internal.net', '$2b$12$e8Y6iKz7fakeHashForAttackerAttraction', TRUE),\n"
            "('john_doe', 'jdoe@internal.net', '$2b$12$syntheticPasswordHash9912837482348', FALSE),\n"
            "('alice_smith', 'asmith@internal.net', '$2b$12$syntheticPasswordHash8827364821', FALSE);\n\n"
            "INSERT INTO transactions (user_id, amount, description) VALUES\n"
            "(1, 145000.00, 'Enterprise Vault Transfer - Canary Reference TR-9941'),\n"
            "(2, 350.50, 'Quarterly IT Services'),\n"
            "(3, 1200.00, 'Cloud Infrastructure Allocation');\n"
        )
