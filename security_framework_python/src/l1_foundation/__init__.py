"""
MAESTRO Layer 1: Foundation Models Security
Air-Gapped AI Model Security Implementation

This module implements MAESTRO L1 security controls specifically designed for
foundation models operating in air-gapped defense environments.

MAESTRO L1 Threat Landscape (from framework):
- Adversarial Examples: Inputs crafted to fool AI models
- Model Stealing: Extracting model copies through API queries
- Backdoor Attacks: Hidden triggers causing malicious behavior
- Membership Inference: Determining training data membership
- Data Poisoning: Injecting malicious training data
- Reprogramming Attacks: Repurposing models for malicious tasks

Patent Innovations:
- Air-gapped adversarial example detection
- Offline model integrity verification
- Classification-aware model security controls

Security Requirements:
- 99.9% prompt injection prevention (Task 2.9)
- <100ms security validation overhead (Task 2.6)
- FIPS 140-2 Level 3+ compliance (Task 2.2)
"""

from .model_security import FoundationModelsSecurity

__all__ = [
    "FoundationModelsSecurity"
]