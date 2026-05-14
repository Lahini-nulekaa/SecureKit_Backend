# backend/securekit/middleware/geo_blocker.py
import os
import geoip2.database
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pathlib import Path
from ..audit_logger import AuditTelemetry

class GeoShield(BaseHTTPMiddleware):
    """
    GeoShield Middleware: Protects the application by blocking requests from 
    unauthorized geographic locations using the MaxMind GeoIP database.
    """
    def __init__(self, app, blocked_countries=None, trusted_ips=None):
        super().__init__(app)
        # Accept ALLOWED_COUNTRIES from env, default to "LK" (Sri Lanka)
        allowed_env = os.getenv("ALLOWED_COUNTRIES", "LK")
        self.allowed_countries = [c.strip() for c in allowed_env.split(",")]
        
        # Local IPs and explicit trusted IPs to bypass the check
        self.trusted_ips = trusted_ips or ["127.0.0.1", "localhost", "::1"]
        
        # Path to the MaxMind Database
        self.db_path = Path(__file__).resolve().parent.parent.parent / "data" / "GeoLite2-Country.mmdb"

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "Unknown"
        
        # 1. Bypass check for local/trusted IPs
        if client_ip in self.trusted_ips:
            return await call_next(request)

        try:
            # 2. Check if the MaxMind database exists
            if not self.db_path.exists():
                AuditTelemetry.log_event(
                    message=f"GeoShield CRITICAL: MaxMind DB missing at {self.db_path}",
                    severity="CRITICAL",
                    entity="GEO_SHIELD"
                )
                return JSONResponse(
                    status_code=403, 
                    content={"detail": "Security service unavailable: Geo-location database missing."}
                )

            # 3. Resolve Country using GeoIP2
            with geoip2.database.Reader(str(self.db_path)) as reader:
                response = reader.country(client_ip)
                country_code = response.country.iso_code
                
                # 4. Validate against allowed countries list
                if country_code not in self.allowed_countries:
                    AuditTelemetry.log_event(
                        message=f"Geo-Blocked: Unauthorized country {country_code} from IP {client_ip} on route {request.url.path}",
                        severity="WARNING",
                        entity="GEO_SHIELD"
                    )
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Access denied: Your location is not authorized to access this service."}
                    )
                    
        except Exception as e:
            # 5. Handle unknown IPs or resolution errors by blocking (Fail-Safe)
            AuditTelemetry.log_event(
                message=f"Geo-Blocked: Unknown/Error IP {client_ip} on {request.url.path} - Info: {str(e)}",
                severity="CRITICAL",
                entity="GEO_SHIELD"
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied: Unable to verify request origin."}
            )

        # 6. Proceed if allowed
        return await call_next(request)
