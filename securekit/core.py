# backend/securekit/core.py
from .auth_engine import AuthEngine
from .crypto_vault import CryptoVault
from .audit_logger import AuditTelemetry
from .middleware.rate_limiter import UniversalRateLimiter
# from .middleware.geo_blocker import GeoShield

class SecureKitFramework:
    """The central entry point for the SecureKit Security Framework.
    
    This class handles the Inversion of Control, allowing the application
    to inject its own configuration and dependencies.
    """
    
    def __init__(self, config: dict):
        self.config = config
        
        # Initialize specialized engines with configuration-driven settings
        self.auth = AuthEngine(
            secret_key=config.get("secret_key"),
            allowed_roles=config.get("roles")
        )
        
        self.vault = CryptoVault(
            key=config.get("encryption_key")
        )
        
        self.telemetry = AuditTelemetry()
        
        self.traffic_control = UniversalRateLimiter()
        
        # GeoShield is now a middleware added directly to the FastAPI app stack
        # self.boundary_control = GeoShield(...)

        self.telemetry.log_event("SecureKit Framework Core Initialized", severity="INFO")

# Universal instance for the application to consume
_framework_instance = None

def boot_securekit(config: dict) -> SecureKitFramework:
    global _framework_instance
    if not _framework_instance:
        _framework_instance = SecureKitFramework(config)
    return _framework_instance

def get_framework() -> SecureKitFramework:
    if not _framework_instance:
         raise RuntimeError("SecureKit must be booted before usage.")
    return _framework_instance
