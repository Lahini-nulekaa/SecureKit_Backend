# backend/securekit/middleware/rate_limiter.py
from slowapi import Limiter
from slowapi.util import get_remote_address

class UniversalRateLimiter:
    """Security Framework component for traffic shaping and DDoS mitigation."""
    
    def __init__(self):
        # Default strategy: Throttle by remote IP
        self.limiter = Limiter(key_func=get_remote_address)

# Global Instance for the App
limiter_instance = UniversalRateLimiter()
limiter = limiter_instance.limiter
