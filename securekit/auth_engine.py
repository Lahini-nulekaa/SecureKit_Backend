# backend/securekit/auth_engine.py
import os
import hashlib
import hmac
import time
import json
import base64
from typing import Any, List, Optional
from fastapi import Request, HTTPException, Depends

class AuthEngine:
    """Universal Security Framework component for Identity and Access Management."""
    
    def __init__(self, secret_key: str | None = None, allowed_roles: list[str] | None = None):
        self.secret = secret_key or os.environ.get('SECRET_KEY')
        if not self.secret:
            raise RuntimeError("CRITICAL ERROR: No SECRET_KEY provided to AuthEngine.")
        
        self.allowed_roles = allowed_roles or ["admin", "user", "guest"]

    @staticmethod
    def hash_credentials(password: str) -> str:
        """Hash a password using PBKDF2-HMAC-SHA256."""
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
        return salt.hex() + ':' + dk.hex()

    @staticmethod
    def verify_credentials(stored: str, provided: str) -> bool:
        """Verify stored hash against provided password."""
        try:
            salt_hex, hash_hex = stored.split(':')
            salt = bytes.fromhex(salt_hex)
            dk = hashlib.pbkdf2_hmac('sha256', provided.encode('utf-8'), salt, 100_000)
            return dk.hex() == hash_hex
        except:
            return False

    def issue_token(self, identity: str, role: str, expires_in: int = 86400, extra_claims: dict | None = None) -> str:
        """Universally issue a signed token for any identity and role."""
        if role not in self.allowed_roles:
             # We allow it but log a warning if role isn't pre-defined
             pass
             
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": identity, 
            "role": role,
            "exp": int(time.time()) + int(expires_in)
        }
        if extra_claims:
            payload.update(extra_claims)
            
        return self._encode_and_sign(header, payload)

    def _encode_and_sign(self, header: dict, payload: dict) -> str:
        def b64(d): return base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode('utf-8')).rstrip(b"=").decode('utf-8')
        
        h_b = b64(header)
        p_b = b64(payload)
        signing_input = f"{h_b}.{p_b}".encode('utf-8')
        sig = hmac.new(self.secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
        sig_b = base64.urlsafe_b64encode(sig).rstrip(b"=").decode('utf-8')
        
        return f"{h_b}.{p_b}.{sig_b}"

    def validate_token(self, token: str, context: dict | None = None) -> dict | None:
        """Validate token and check optional context bindings (IP/UA)."""
        try:
            parts = token.split('.')
            if len(parts) != 3: return None
            
            h_b, p_b, s_b = parts
            signing_input = f"{h_b}.{p_b}".encode('utf-8')
            expected_sig = hmac.new(self.secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
            
            sig = base64.urlsafe_b64decode(s_b + '=' * (-len(s_b) % 4))
            if not hmac.compare_digest(sig, expected_sig):
                return None
                
            payload = json.loads(base64.urlsafe_b64decode(p_b + '=' * (-len(p_b) % 4)).decode('utf-8'))
            
            if 'exp' in payload and int(time.time()) > int(payload['exp']):
                return None
            
            # Contextual Binding check
            if context:
                # Check User-Agent (stable across requests in a session)
                if 'ua' in payload and payload['ua'] != context.get('ua'):
                    return None
                
                # Check IP only if explicitly requested (unstable on Render/Proxies)
                if os.getenv("STRICT_IP_CHECK", "false").lower() == "true":
                    if 'ip' in payload and payload['ip'] != context.get('ip'):
                        return None
                        
            return payload
        except:
            return None

    def require_role(self, allowed_roles: List[str]):
        """FastAPI Dependency: Protect routes with RBAC."""
        # Normalize to lowercase
        allowed_roles = [r.lower() for r in allowed_roles]
        
        async def dependency(request: Request):
            # 1. Try Cookie
            token = request.cookies.get("access_token")
            # 2. Try Authorization Header
            if not token:
                auth_header = request.headers.get("Authorization")
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]
            
            if not token:
                 raise HTTPException(status_code=401, detail="SecureKit: Missing authentication token")
            
            # Extract context for binding check
            # Truncate UA to 256 to match the login logic truncation
            ua = request.headers.get("user-agent")
            context = {
                "ip": request.client.host if request.client else None,
                "ua": ua[:256] if ua else None
            }
            
            # Allow disabling contextual binding for stability in cloud environments
            if os.getenv("BIND_TOKEN_TO_CONTEXT", "true").lower() != "true":
                context = None

            payload = self.validate_token(token, context=context)
            if not payload:
                 raise HTTPException(status_code=401, detail="SecureKit: Invalid or expired token")
            
            role = str(payload.get("role") or "").lower()
            if role not in allowed_roles:
                 raise HTTPException(status_code=403, detail="SecureKit: Privilege level insufficient")
            
            return payload
            
        return dependency

# Backward Compatibility
_default_engine = None
def _get_engine():
    global _default_engine
    if not _default_engine:
        _default_engine = AuthEngine()
    return _default_engine

def create_token(email: str, expires_in: int = 86400, extra_claims: dict | None = None) -> str:
    role = (extra_claims or {}).get('role', 'user')
    return _get_engine().issue_token(email, role, expires_in, extra_claims)

def verify_token(token: str, expected_ip: str | None = None, expected_ua: str | None = None):
    if os.getenv("BIND_TOKEN_TO_CONTEXT", "true").lower() != "true":
        return _get_engine().validate_token(token, None)
        
    context = {}
    if expected_ip: context['ip'] = expected_ip
    if expected_ua: context['ua'] = expected_ua[:256]
    return _get_engine().validate_token(token, context)

def hash_password(pw): return AuthEngine.hash_credentials(pw)
def verify_password(stored, prov): return AuthEngine.verify_credentials(stored, prov)
