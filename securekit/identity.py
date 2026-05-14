# backend/securekit/identity.py
import pyotp
import qrcode
import io
import base64

class IdentityGuard:
    """Security Framework component for Multi-Factor Authentication (MFA/2FA)."""
    
    @staticmethod
    def create_mfa_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_mfa_qr(secret: str, account_id: str, issuer: str = "SecureKit") -> str:
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=account_id, issuer_name=issuer)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b = base64.b64encode(buf.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{b}"

    @staticmethod
    def verify_mfa_token(secret: str, token: str) -> bool:
        try:
            return pyotp.TOTP(secret).verify(token)
        except:
            return False

# Backward Compatibility
def generate_secret(): return IdentityGuard.create_mfa_secret()
def generate_qr_code(s, e): return IdentityGuard.get_mfa_qr(s, e)
def verify_totp(s, c): return IdentityGuard.verify_mfa_token(s, c)
