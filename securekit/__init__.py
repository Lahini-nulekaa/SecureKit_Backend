# backend/securekit/__init__.py
"""
SecureKit Security Framework - Bridge Initializer
Provides backward compatibility and a clean framework interface.
"""

from .core import get_framework, boot_securekit

# --- Legacy Bridge: Maps old utility names to new framework engines ---

def log_security_event(message: str):
    get_framework().telemetry.log_event(message)

def create_token(*args, **kwargs):
    # Bridge Logic: If role is missing in args/kwargs, try to extract it from extra_claims (legacy pattern)
    if len(args) < 2 and 'role' not in kwargs:
        extra = kwargs.get('extra_claims', {})
        role = extra.get('role', 'user')
        kwargs['role'] = role
        
    # Bridge Logic: Handle 'email' as 'identity' for backward compatibility
    if 'email' in kwargs and 'identity' not in kwargs:
        kwargs['identity'] = kwargs.pop('email')
        
    return get_framework().auth.issue_token(*args, **kwargs)

def verify_token(*args, **kwargs):
    import os
    if os.getenv("BIND_TOKEN_TO_CONTEXT", "true").lower() != "true":
        return get_framework().auth.validate_token(*args, context=None, **kwargs)

    context = {}
    if 'expected_ip' in kwargs: 
        context['ip'] = kwargs.pop('expected_ip')
    if 'expected_ua' in kwargs: 
        ua = kwargs.pop('expected_ua')
        context['ua'] = ua[:256] if ua else None
    return get_framework().auth.validate_token(*args, context=context, **kwargs)

def hash_password(password: str):
    return get_framework().auth.hash_credentials(password)

def verify_password(stored: str, provided: str):
    return get_framework().auth.verify_credentials(stored, provided)

def encrypt_text(text: str):
    return get_framework().vault.encrypt_payload(text)

def decrypt_text(value: any):
    return get_framework().vault.decrypt_payload(value)

# Identity Tools (2FA)
from .identity import generate_secret, generate_qr_code, verify_totp

# Access to the RBAC dependency constructor
def require_role(roles: list[str]):
    return get_framework().auth.require_role(roles)

# Middleware Bridge
from .middleware.rate_limiter import limiter
