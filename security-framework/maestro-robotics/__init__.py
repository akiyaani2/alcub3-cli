"""
ALCUB3 MAESTRO Robotics Security Integration
Patent-Pending Universal Security HAL for Defense Robotics
"""

from .core.universal_hal import UniversalSecurityHAL
from .core.platform_adapter import PlatformSecurityAdapter
from .core.security_policy import SecurityPolicyEngine
from .core.command_validator import CommandValidationPipeline

__all__ = [
    'UniversalSecurityHAL',
    'PlatformSecurityAdapter',
    'SecurityPolicyEngine',
    'CommandValidationPipeline'
]

__version__ = '1.0.0'