# core/vault.py
import os
import base64
from cryptography.fernet import Fernet
import structlog

logger = structlog.get_logger("crypto_vault")

# Deterministic fallback key for development environments
FALLBACK_KEY = b"aW5zZWN1cmVfZGV2X2ZhbGxiYWNrX2tleV8zMmJ5dGU="

def get_secret_vault_key() -> bytes:
    key_str = os.getenv("RAE_SECRET_KEY", "")
    if not key_str:
        logger.warning("RAE_SECRET_KEY env variable not set! Using insecure development fallback key.")
        return FALLBACK_KEY
    try:
        # Validate if key is a valid Fernet key
        key_bytes = key_str.encode()
        Fernet(key_bytes)
        return key_bytes
    except Exception as e:
        logger.error(f"Invalid RAE_SECRET_KEY provided: {e}. Falling back to insecure key.")
        return FALLBACK_KEY

def decrypt_secret(val: str) -> str:
    """Decrypts a value if it starts with 'encrypted:'. Otherwise returns it raw."""
    if not val:
        return val
    if not val.startswith("encrypted:"):
        return val
    try:
        encrypted_part = val[len("encrypted:"):]
        key = get_secret_vault_key()
        f = Fernet(key)
        return f.decrypt(encrypted_part.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption of secret failed: {e}")
        raise ValueError("Decryption of secret failed (possible corrupt key or payload). Fail-Closed.")

def encrypt_secret(val: str) -> str:
    """Helper to encrypt a secret value using the active vault key."""
    if not val:
        return val
    key = get_secret_vault_key()
    f = Fernet(key)
    encrypted_bytes = f.encrypt(val.encode())
    return "encrypted:" + encrypted_bytes.decode()
