# backend/securekit/audit_logger.py
import logging
import re
import time
from pathlib import Path

# Framework Default: log to the app's root directory or a specialized logging partition
_LOG_PATH = Path(__file__).resolve().parent.parent / "security_audit.log"

try:
    logging.basicConfig(
        filename=str(_LOG_PATH),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [AUDIT] %(message)s"
    )
except (OSError, PermissionError):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [AUDIT] %(message)s"
    )

class AuditTelemetry:
    """A professional-grade framework component for universal telemetry logs."""
    
    @staticmethod
    def _mask_pii(text: str) -> str:
        """Internal helper to scrub PII from audit logs."""
        email_regex = r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        
        # Mask Email
        text = re.sub(email_regex, lambda m: f"{m.group(1)[0]}***{m.group(1)[-1]}@{m.group(2)}", text)
        # Mask IP
        text = re.sub(ip_regex, lambda m: ".".join(m.group(0).split('.')[:2]) + ".*.*", text)
        return text

    @classmethod
    def log_event(cls, message: str, severity: str = "INFO", entity: str = "SYSTEM"):
        """Centralized logging for any security-related event."""
        sanitized = cls._mask_pii(str(message))
        formatted = f"[{severity}] [{entity}] {sanitized}"
        print(f"[SecureKit] {formatted}")
        logging.info(formatted)

    @classmethod
    def log_breach_attempt(cls, ip_address: str, target: str, severity: str = "CRITICAL"):
        """Specialized logger for potential attacks."""
        cls.log_event(
            message=f"Access Violation Detected from {ip_address} on endpoint {target}",
            severity=severity,
            entity="THREAT_DETECTOR"
        )

# Backward Compatibility for existing code
def log_security_event(message: str):
    AuditTelemetry.log_event(message)
