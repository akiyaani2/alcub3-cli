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
from .audit_logger import AuditLogger
from .threat_detector import ThreatDetector
from .compliance_validator import ComplianceValidator
from .crypto_utils import FIPSCryptoUtils

__all__ = [
    "SecurityClassification",
    "AuditLogger", 
    "ThreatDetector",
    "ComplianceValidator",
    "FIPSCryptoUtils"
]