# RAE-Quality/tests/test_iteration5.py
import pytest
import os
from unittest.mock import patch
from core.vault import decrypt_secret, encrypt_secret, FALLBACK_KEY

def test_vault_noop_for_unencrypted_secrets():
    """Vault should return the secret as-is if it does not have the 'encrypted:' prefix."""
    assert decrypt_secret("plain_secret_123") == "plain_secret_123"
    assert decrypt_secret("") == ""
    assert decrypt_secret(None) is None

def test_vault_encryption_and_decryption_with_fallback():
    """Vault should encrypt and decrypt successfully using the fallback key if RAE_SECRET_KEY is not set."""
    with patch.dict(os.environ, {}, clear=True):
        secret = "secret_to_hide"
        encrypted = encrypt_secret(secret)
        
        assert encrypted.startswith("encrypted:")
        assert encrypted != secret
        
        decrypted = decrypt_secret(encrypted)
        assert decrypted == secret

def test_vault_encryption_and_decryption_with_custom_key():
    """Vault should encrypt and decrypt successfully using a custom RAE_SECRET_KEY."""
    from cryptography.fernet import Fernet
    custom_key = Fernet.generate_key().decode()
    
    with patch.dict(os.environ, {"RAE_SECRET_KEY": custom_key}):
        secret = "super_secure_sonar_token"
        encrypted = encrypt_secret(secret)
        
        assert encrypted.startswith("encrypted:")
        
        decrypted = decrypt_secret(encrypted)
        assert decrypted == secret

def test_vault_fail_closed_on_corrupt_payload():
    """Vault must raise ValueError (Fail-Closed) if decryption fails due to corrupt payload or invalid key."""
    # Test decrypting with a wrong key
    from cryptography.fernet import Fernet
    key1 = Fernet.generate_key().decode()
    key2 = Fernet.generate_key().decode()
    
    with patch.dict(os.environ, {"RAE_SECRET_KEY": key1}):
        encrypted = encrypt_secret("some_secret")
        
    with patch.dict(os.environ, {"RAE_SECRET_KEY": key2}):
        with pytest.raises(ValueError, match="Decryption of secret failed.*Fail-Closed"):
            decrypt_secret(encrypted)
            
    # Test decrypting a corrupt payload
    with pytest.raises(ValueError, match="Decryption of secret failed.*Fail-Closed"):
        decrypt_secret("encrypted:corrupt_base64_data")
