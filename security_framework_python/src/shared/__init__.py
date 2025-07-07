"""
MAESTRO Shared Security Components
Common security utilities and base classes for all MAESTRO layers

This module provides shared security components used across all MAESTRO layers,
including classification management, audit logging, threat detection, and
compliance validation.

Patent Innovations:
- Cross-layer security monitoring for air-gapped systems
- Classification-aware security inheritance
- Real-time compliance validation
"""

from .classification import SecurityClassification

# Try to import optional components gracefully
try:
    from .audit_logger import AuditLogger
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    class AuditLogger:
        def __init__(self, *args, **kwargs):
            pass

try:
    from .threat_detector import ThreatDetector
    THREAT_DETECTOR_AVAILABLE = True
except ImportError:
    THREAT_DETECTOR_AVAILABLE = False
    class ThreatDetector:
        def __init__(self, *args, **kwargs):
            pass
        def validate_cross_layer(self):
            return {"status": "mock"}

try:
    from .compliance_validator import ComplianceValidator
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False
    class ComplianceValidator:
        def __init__(self, *args, **kwargs):
            pass
        def validate_all(self):
            return {"status": "mock"}

__all__ = [
    "SecurityClassification",
    "AuditLogger", 
    "ThreatDetector",
    "ComplianceValidator"
]