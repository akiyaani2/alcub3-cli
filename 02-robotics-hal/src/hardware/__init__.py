"""
Hardware Security Module Integration Package

This package provides hardware-based security features for ALCUB3's Universal Robotics Platform,
including TPM 2.0 integration, secure element interfaces, and hardware-enforced cryptography.

Key Components:
- TPM 2.0 Integration: Hardware root of trust and attestation
- Secure Element Bridge: Multi-vendor secure element abstraction
- Hardware Key Management: Hierarchical key derivation with hardware protection

Patent-Defensible Innovations:
- Robotic platform hardware attestation
- Mission-scoped cryptographic keys
- Cross-platform hardware security orchestration
"""

from .tpm_integration import (
    TPM2Interface,
    TPMError,
    TPMAuthSession,
    TPMKeyHandle,
    PCRBank,
    RoboticsPCRAllocation,
    TPMHierarchy
)

from .tpm_attestation import (
    TPMAttestationEngine,
    AttestationType,
    AttestationResult,
    RobotStateVector
)

from .tpm_key_manager import (
    HardwareKeyManager,
    KeyPurpose,
    KeyLifecycle,
    ManagedKey
)

__all__ = [
    # TPM Core
    'TPM2Interface',
    'TPMError',
    'TPMAuthSession',
    'TPMKeyHandle',
    'PCRBank',
    'RoboticsPCRAllocation',
    'TPMHierarchy',
    # Attestation
    'TPMAttestationEngine',
    'AttestationType',
    'AttestationResult',
    'RobotStateVector',
    # Key Management
    'HardwareKeyManager',
    'KeyPurpose',
    'KeyLifecycle',
    'ManagedKey'
]