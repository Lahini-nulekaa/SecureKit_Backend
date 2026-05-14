# backend/securekit/crypto_vault.py
import base64
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Any

class CryptoVault:
    """Reusable Security Framework component for AES-256-GCM encryption."""
    
    def __init__(self, key: str | bytes | None = None):
        if not key:
            key = os.environ.get("DATA_ENCRYPTION_KEY")
        
        if not key:
            raise RuntimeError("CRITICAL ERROR: No encryption key provided to CryptoVault.")
        
        self.key = self._normalize_key(key)
        self.aesgcm = AESGCM(self.key)

    def _normalize_key(self, key: str | bytes) -> bytes:
        if isinstance(key, bytes):
            return key
        
        # Try hex
        try:
            if all(c in "0123456789abcdefABCDEF" for c in key) and len(key) == 64:
                return bytes.fromhex(key)
        except:
            pass
            
        # Try base64
        try:
            padding = "=" * (-len(key) % 4)
            return base64.urlsafe_b64decode(key + padding)
        except:
            raise ValueError("Encryption key must be 32 bytes (64 hex chars or base64url).")

    @staticmethod
    def _b64encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _b64decode(text: str) -> bytes:
        padding = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode((text or "") + padding)

    def encrypt_payload(self, data: Any) -> dict:
        """Universal encryption for any JSON-serializable payload."""
        plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        
        return {
            "__enc__": 1,
            "alg": "AES-256-GCM",
            "nonce": self._b64encode(nonce),
            "ciphertext": self._b64encode(ciphertext),
        }

    def decrypt_payload(self, encrypted_value: Any) -> Any:
        """Universal decryption for both SecureKit JSON objects and legacy combined base64 strings."""
        if not encrypted_value:
            return ""
            
        # Case 1: Legacy base64 combined string (nonce + ciphertext)
        if isinstance(encrypted_value, str) and not (encrypted_value.startswith('{') or encrypted_value.startswith('[')):
            try:
                data = base64.b64decode(encrypted_value)
                if len(data) > 12:
                    nonce = data[:12]
                    ciphertext = data[12:]
                    return self.aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
            except:
                pass # Fall through to other checks

        # Case 2: SecureKit JSON object
        if not self.is_secure_payload(encrypted_value):
            return encrypted_value
            
        nonce = self._b64decode(encrypted_value.get("nonce", ""))
        ciphertext = self._b64decode(encrypted_value.get("ciphertext", ""))
        
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
            return json.loads(plaintext)
        except:
            return plaintext

    @staticmethod
    def is_secure_payload(value: Any) -> bool:
        return isinstance(value, dict) and value.get("__enc__") == 1

# Backward Compatibility
_default_vault = None

def _get_vault():
    global _default_vault
    if not _default_vault:
        _default_vault = CryptoVault()
    return _default_vault

def encrypt_text(text: str) -> dict:
    return _get_vault().encrypt_payload(text)

def decrypt_text(value: Any) -> str:
    return _get_vault().decrypt_payload(value)
