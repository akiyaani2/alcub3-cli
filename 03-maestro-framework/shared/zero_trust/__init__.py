#!/usr/bin/env python3
"""
ALCUB3 Zero-Trust Architecture Implementation
Task 1.6 - Comprehensive zero-trust security beyond current MAESTRO framework

This module implements defense-grade zero-trust architecture with:
- Microsegmentation for all network traffic
- Continuous verification for all connections
- Identity-based access controls
- Device trust scoring
- Integrated with existing MAESTRO L1-L3 framework

Patent-Pending Innovations:
- Classification-aware microsegmentation
- AI-behavioral continuous verification
- Defense-grade device trust scoring
- Multi-level zero-trust policy engine
- Air-gapped zero-trust operations
"""

from .microsegmentation_engine import MicrosegmentationEngine
from .continuous_verification import ContinuousVerificationSystem
from .identity_access_control import IdentityAccessControl
from .device_trust_scorer import DeviceTrustScorer
from .zero_trust_policy import ZeroTrustPolicyEngine
from .zt_network_gateway import ZeroTrustNetworkGateway

__all__ = [
    'MicrosegmentationEngine',
    'ContinuousVerificationSystem', 
    'IdentityAccessControl',
    'DeviceTrustScorer',
    'ZeroTrustPolicyEngine',
    'ZeroTrustNetworkGateway'
]

__version__ = '1.0.0'
__author__ = 'ALCUB3 CTO'