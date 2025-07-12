#!/usr/bin/env python3
"""
ALCUB3 Device Trust Scoring System
Hardware-backed device trust assessment with attestation validation

This module implements patent-pending device trust scoring that:
- Validates hardware attestation certificates
- Assesses software inventory and patch levels
- Monitors behavioral anomalies
- Integrates with TPM/HSM modules
- Provides real-time trust scores

Performance Targets:
- <100ms initial trust calculation
- <10ms cached trust score retrieval
- Support for 50,000+ devices
"""

import asyncio
import hashlib
import logging
import time
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from collections import deque
from pathlib import Path
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtensionOID

# Import MAESTRO components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError
from shared.hsm_integration import HSMIntegration
from shared.real_time_monitor import RealTimeMonitor

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """Device trust levels."""
    UNTRUSTED = "untrusted"      # 0-20
    LOW = "low"                  # 21-40
    MEDIUM = "medium"            # 41-60
    HIGH = "high"                # 61-80
    FULLY_TRUSTED = "fully_trusted"  # 81-100


class AttestationType(Enum):
    """Types of device attestation."""
    TPM_2_0 = "tpm_2_0"
    SECURE_BOOT = "secure_boot"
    MEASURED_BOOT = "measured_boot"
    HARDWARE_ROOT_OF_TRUST = "hardware_root_of_trust"
    REMOTE_ATTESTATION = "remote_attestation"
    RUNTIME_ATTESTATION = "runtime_attestation"


class DeviceType(Enum):
    """Types of devices."""
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    MOBILE = "mobile"
    SERVER = "server"
    IOT = "iot"
    EMBEDDED = "embedded"
    VIRTUAL = "virtual"


@dataclass
class HardwareAttestation:
    """Hardware attestation data."""
    attestation_type: AttestationType
    certificate_chain: List[x509.Certificate]
    platform_certificate: Optional[x509.Certificate]
    attestation_key: Optional[bytes]
    pcr_values: Dict[int, bytes] = field(default_factory=dict)  # TPM PCR values
    quote: Optional[bytes] = None
    nonce: Optional[bytes] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    is_valid: bool = False
    validation_errors: List[str] = field(default_factory=list)


@dataclass
class SoftwareInventory:
    """Device software inventory."""
    os_name: str
    os_version: str
    os_build: str
    kernel_version: Optional[str] = None
    installed_packages: Dict[str, str] = field(default_factory=dict)  # Package -> Version
    running_processes: Set[str] = field(default_factory=set)
    security_products: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    last_boot_time: Optional[datetime] = None
    patch_level: Optional[str] = None
    compliance_status: Dict[str, bool] = field(default_factory=dict)


@dataclass
class DeviceProfile:
    """Complete device profile for trust scoring."""
    device_id: str
    device_type: DeviceType
    manufacturer: str
    model: str
    serial_number: str
    hardware_attestation: Optional[HardwareAttestation] = None
    software_inventory: Optional[SoftwareInventory] = None
    network_interfaces: List[Dict[str, str]] = field(default_factory=list)
    location: Optional[str] = None
    owner: Optional[str] = None
    registration_date: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    behavioral_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    trust_history: deque = field(default_factory=lambda: deque(maxlen=100))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustScore:
    """Device trust score with component breakdown."""
    overall_score: float  # 0-100
    hardware_score: float
    software_score: float
    behavior_score: float
    compliance_score: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class DeviceTrustScorer:
    """
    Patent-pending device trust scoring system with hardware attestation.
    
    This system provides comprehensive device trust assessment based on
    hardware attestation, software inventory, and behavioral analysis.
    """
    
    def __init__(
        self,
        audit_logger: AuditLogger,
        hsm_integration: Optional[HSMIntegration] = None,
        monitor: Optional[RealTimeMonitor] = None,
        attestation_ca_path: Optional[str] = None
    ):
        """
        Initialize the device trust scorer.
        
        Args:
            audit_logger: Audit logger for trust events
            hsm_integration: HSM for cryptographic operations
            monitor: Real-time monitoring system
            attestation_ca_path: Path to attestation CA certificates
        """
        self.audit_logger = audit_logger
        self.hsm = hsm_integration
        self.monitor = monitor
        
        # Device registry
        self.devices: Dict[str, DeviceProfile] = {}
        self.trust_scores: Dict[str, TrustScore] = {}
        
        # Attestation validation
        self.trusted_cas: Dict[str, x509.Certificate] = {}
        self.attestation_policies: Dict[AttestationType, Dict[str, Any]] = {}
        
        if attestation_ca_path:
            self._load_attestation_cas(attestation_ca_path)
        
        # Behavioral analysis
        self.anomaly_thresholds = {
            'login_failures': 5,
            'privilege_escalations': 3,
            'unusual_processes': 10,
            'network_anomalies': 20,
            'file_system_changes': 100
        }
        
        # Trust score weights
        self.score_weights = {
            'hardware': 0.35,
            'software': 0.25,
            'behavior': 0.25,
            'compliance': 0.15
        }
        
        # Performance optimization
        self.score_cache: Dict[str, Tuple[TrustScore, datetime]] = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Statistics
        self.stats = {
            'devices_registered': 0,
            'attestations_validated': 0,
            'trust_scores_calculated': 0,
            'cache_hits': 0,
            'avg_calculation_time_ms': 0.0,
            'high_trust_devices': 0,
            'untrusted_devices': 0
        }
        
        # Initialize default policies
        self._initialize_attestation_policies()
        
        logger.info("Device trust scorer initialized")
    
    def _initialize_attestation_policies(self):
        """Initialize default attestation policies."""
        self.attestation_policies[AttestationType.TPM_2_0] = {
            'required_pcrs': [0, 1, 2, 3, 4, 5, 6, 7],  # Boot measurements
            'max_quote_age_seconds': 300,
            'required_algorithms': ['SHA256', 'SHA384'],
            'min_key_size': 2048
        }
        
        self.attestation_policies[AttestationType.SECURE_BOOT] = {
            'required_signatures': ['Microsoft', 'UEFI'],
            'allowed_boot_modes': ['UEFI', 'Secure'],
            'max_certificate_age_days': 365
        }
        
        self.attestation_policies[AttestationType.MEASURED_BOOT] = {
            'required_measurements': ['bootloader', 'kernel', 'initrd'],
            'hash_algorithms': ['SHA256', 'SHA384'],
            'max_measurement_age_seconds': 3600
        }
    
    def _load_attestation_cas(self, ca_path: str):
        """Load trusted attestation CA certificates."""
        ca_dir = Path(ca_path)
        if not ca_dir.exists():
            logger.warning("Attestation CA directory not found: %s", ca_path)
            return
        
        for ca_file in ca_dir.glob("*.pem"):
            try:
                with open(ca_file, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    self.trusted_cas[subject] = cert
                    logger.info("Loaded attestation CA: %s", subject)
            except Exception as e:
                logger.error("Failed to load CA certificate %s: %s", ca_file, str(e))
    
    async def register_device(
        self,
        device_id: str,
        device_type: DeviceType,
        manufacturer: str,
        model: str,
        serial_number: str,
        hardware_attestation: Optional[HardwareAttestation] = None,
        software_inventory: Optional[SoftwareInventory] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DeviceProfile:
        """
        Register a device for trust scoring.
        
        Args:
            device_id: Unique device identifier
            device_type: Type of device
            manufacturer: Device manufacturer
            model: Device model
            serial_number: Device serial number
            hardware_attestation: Initial attestation data
            software_inventory: Initial software inventory
            metadata: Additional device metadata
            
        Returns:
            Created DeviceProfile
        """
        # Check if device already exists
        if device_id in self.devices:
            raise SecurityError(f"Device {device_id} already registered")
        
        # Create device profile
        device = DeviceProfile(
            device_id=device_id,
            device_type=device_type,
            manufacturer=manufacturer,
            model=model,
            serial_number=serial_number,
            hardware_attestation=hardware_attestation,
            software_inventory=software_inventory,
            metadata=metadata or {}
        )
        
        # Validate attestation if provided
        if hardware_attestation:
            await self._validate_attestation(device, hardware_attestation)
        
        # Store device
        self.devices[device_id] = device
        self.stats['devices_registered'] += 1
        
        # Calculate initial trust score
        trust_score = await self.calculate_trust_score(device_id)
        
        # Audit log
        await self.audit_logger.log_event(
            "DEVICE_REGISTERED",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'device_id': device_id,
                'device_type': device_type.value,
                'manufacturer': manufacturer,
                'model': model,
                'initial_trust_score': trust_score.overall_score,
                'trust_level': trust_score.trust_level.value
            }
        )
        
        logger.info("Registered device %s with trust score %.2f",
                   device_id, trust_score.overall_score)
        
        return device
    
    async def calculate_trust_score(
        self,
        device_id: str,
        force_recalculate: bool = False
    ) -> TrustScore:
        """
        Calculate comprehensive trust score for a device.
        
        Args:
            device_id: Device identifier
            force_recalculate: Force recalculation ignoring cache
            
        Returns:
            Calculated TrustScore
        """
        start_time = time.time()
        
        # Check cache first
        if not force_recalculate and device_id in self.score_cache:
            cached_score, cache_time = self.score_cache[device_id]
            if (datetime.utcnow() - cache_time).total_seconds() < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return cached_score
        
        # Get device profile
        device = self.devices.get(device_id)
        if not device:
            raise SecurityError(f"Device {device_id} not found")
        
        # Calculate component scores
        hardware_score = await self._calculate_hardware_score(device)
        software_score = await self._calculate_software_score(device)
        behavior_score = await self._calculate_behavior_score(device)
        compliance_score = await self._calculate_compliance_score(device)
        
        # Calculate weighted overall score
        overall_score = (
            hardware_score * self.score_weights['hardware'] +
            software_score * self.score_weights['software'] +
            behavior_score * self.score_weights['behavior'] +
            compliance_score * self.score_weights['compliance']
        )
        
        # Determine trust level
        trust_level = self._get_trust_level(overall_score)
        
        # Identify risk factors
        risk_factors = []
        if hardware_score < 50:
            risk_factors.append("Low hardware trust score")
        if software_score < 50:
            risk_factors.append("Outdated or vulnerable software")
        if behavior_score < 50:
            risk_factors.append("Anomalous device behavior detected")
        if compliance_score < 50:
            risk_factors.append("Non-compliant with security policies")
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            device, hardware_score, software_score, behavior_score, compliance_score
        )
        
        # Create trust score
        trust_score = TrustScore(
            overall_score=round(overall_score, 2),
            hardware_score=round(hardware_score, 2),
            software_score=round(software_score, 2),
            behavior_score=round(behavior_score, 2),
            compliance_score=round(compliance_score, 2),
            trust_level=trust_level,
            risk_factors=risk_factors,
            recommendations=recommendations
        )
        
        # Update device history
        device.trust_history.append((datetime.utcnow(), overall_score))
        device.last_seen = datetime.utcnow()
        
        # Cache the score
        self.score_cache[device_id] = (trust_score, datetime.utcnow())
        self.trust_scores[device_id] = trust_score
        
        # Update statistics
        self.stats['trust_scores_calculated'] += 1
        calculation_time = (time.time() - start_time) * 1000
        self._update_avg_calculation_time(calculation_time)
        
        if trust_level == TrustLevel.FULLY_TRUSTED:
            self.stats['high_trust_devices'] += 1
        elif trust_level == TrustLevel.UNTRUSTED:
            self.stats['untrusted_devices'] += 1
        
        # Monitor trust score
        if self.monitor:
            await self.monitor.record_metric(
                'device_trust.score',
                overall_score,
                {
                    'device_id': device_id,
                    'device_type': device.device_type.value,
                    'trust_level': trust_level.value
                }
            )
        
        logger.debug("Calculated trust score %.2f for device %s in %.2fms",
                    overall_score, device_id, calculation_time)
        
        return trust_score
    
    async def _calculate_hardware_score(self, device: DeviceProfile) -> float:
        """Calculate hardware-based trust score."""
        score = 0.0
        
        # Check for hardware attestation
        if not device.hardware_attestation:
            return 20.0  # Minimal score without attestation
        
        attestation = device.hardware_attestation
        
        # Attestation validity (40 points)
        if attestation.is_valid:
            score += 40.0
        else:
            score += 10.0  # Partial credit for attempted attestation
        
        # Certificate chain validation (20 points)
        if attestation.certificate_chain:
            if self._validate_certificate_chain(attestation.certificate_chain):
                score += 20.0
            else:
                score += 5.0
        
        # TPM/Hardware root of trust (20 points)
        if attestation.attestation_type in [
            AttestationType.TPM_2_0,
            AttestationType.HARDWARE_ROOT_OF_TRUST
        ]:
            score += 20.0
        elif attestation.attestation_type == AttestationType.SECURE_BOOT:
            score += 15.0
        else:
            score += 10.0
        
        # PCR values validation (10 points)
        if attestation.pcr_values:
            if self._validate_pcr_values(attestation.pcr_values):
                score += 10.0
            else:
                score += 5.0
        
        # Attestation freshness (10 points)
        age_minutes = (datetime.utcnow() - attestation.timestamp).total_seconds() / 60
        if age_minutes < 5:
            score += 10.0
        elif age_minutes < 30:
            score += 7.0
        elif age_minutes < 60:
            score += 5.0
        else:
            score += 2.0
        
        return min(100.0, score)
    
    async def _calculate_software_score(self, device: DeviceProfile) -> float:
        """Calculate software-based trust score."""
        if not device.software_inventory:
            return 30.0  # Minimal score without inventory
        
        inventory = device.software_inventory
        score = 0.0
        
        # OS patch level (30 points)
        if inventory.patch_level:
            patch_age_days = self._get_patch_age_days(inventory.patch_level)
            if patch_age_days < 30:
                score += 30.0
            elif patch_age_days < 60:
                score += 20.0
            elif patch_age_days < 90:
                score += 10.0
            else:
                score += 5.0
        
        # Security products (25 points)
        security_score = 0.0
        required_products = ['antivirus', 'firewall', 'edr']
        for product in required_products:
            if product in inventory.security_products:
                product_info = inventory.security_products[product]
                if product_info.get('enabled', False) and product_info.get('updated', False):
                    security_score += 25.0 / len(required_products)
        score += security_score
        
        # Vulnerable software check (25 points)
        vulnerable_packages = self._check_vulnerable_packages(inventory.installed_packages)
        if not vulnerable_packages:
            score += 25.0
        else:
            # Deduct based on severity
            deduction = min(25.0, len(vulnerable_packages) * 5.0)
            score += max(0.0, 25.0 - deduction)
        
        # Compliance status (20 points)
        if inventory.compliance_status:
            compliant_count = sum(1 for v in inventory.compliance_status.values() if v)
            total_checks = len(inventory.compliance_status)
            if total_checks > 0:
                compliance_ratio = compliant_count / total_checks
                score += compliance_ratio * 20.0
        
        return min(100.0, score)
    
    async def _calculate_behavior_score(self, device: DeviceProfile) -> float:
        """Calculate behavior-based trust score."""
        if not device.behavioral_history:
            return 80.0  # Default score for new devices
        
        score = 100.0  # Start with perfect score
        
        # Analyze recent behavior
        recent_events = list(device.behavioral_history)[-100:]  # Last 100 events
        
        anomaly_counts = {
            'login_failures': 0,
            'privilege_escalations': 0,
            'unusual_processes': 0,
            'network_anomalies': 0,
            'file_system_changes': 0
        }
        
        for event in recent_events:
            if isinstance(event, dict):
                event_type = event.get('type', '')
                if event_type in anomaly_counts:
                    anomaly_counts[event_type] += 1
        
        # Deduct points for anomalies
        for anomaly_type, count in anomaly_counts.items():
            threshold = self.anomaly_thresholds.get(anomaly_type, 10)
            if count > threshold:
                # Exponential penalty for exceeding threshold
                penalty = min(20.0, (count / threshold - 1) ** 2 * 10)
                score -= penalty
        
        # Check trust score trend
        if len(device.trust_history) >= 5:
            recent_scores = [score for _, score in list(device.trust_history)[-5:]]
            if all(recent_scores[i] <= recent_scores[i-1] for i in range(1, len(recent_scores))):
                # Declining trust trend
                score -= 10.0
        
        return max(0.0, score)
    
    async def _calculate_compliance_score(self, device: DeviceProfile) -> float:
        """Calculate compliance-based trust score."""
        score = 0.0
        
        # Device registration compliance (25 points)
        if device.registration_date:
            registration_age_days = (datetime.utcnow() - device.registration_date).days
            if registration_age_days > 7:  # Registered for at least a week
                score += 25.0
            else:
                score += 15.0
        
        # Attestation compliance (25 points)
        if device.hardware_attestation and device.hardware_attestation.is_valid:
            score += 25.0
        elif device.hardware_attestation:
            score += 10.0
        
        # Software compliance (25 points)
        if device.software_inventory:
            inventory = device.software_inventory
            if inventory.compliance_status:
                compliant_ratio = sum(
                    1 for v in inventory.compliance_status.values() if v
                ) / len(inventory.compliance_status)
                score += compliant_ratio * 25.0
        
        # Regular check-in compliance (25 points)
        if device.last_seen:
            hours_since_seen = (datetime.utcnow() - device.last_seen).total_seconds() / 3600
            if hours_since_seen < 1:
                score += 25.0
            elif hours_since_seen < 24:
                score += 20.0
            elif hours_since_seen < 72:
                score += 10.0
            else:
                score += 5.0
        
        return min(100.0, score)
    
    def _get_trust_level(self, score: float) -> TrustLevel:
        """Determine trust level from score."""
        if score >= 81:
            return TrustLevel.FULLY_TRUSTED
        elif score >= 61:
            return TrustLevel.HIGH
        elif score >= 41:
            return TrustLevel.MEDIUM
        elif score >= 21:
            return TrustLevel.LOW
        else:
            return TrustLevel.UNTRUSTED
    
    def _validate_certificate_chain(self, chain: List[x509.Certificate]) -> bool:
        """Validate certificate chain."""
        if not chain:
            return False
        
        try:
            # Check each certificate in the chain
            for i in range(len(chain) - 1):
                cert = chain[i]
                issuer_cert = chain[i + 1]
                
                # Verify signature
                issuer_public_key = issuer_cert.public_key()
                if isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                
                # Check validity period
                if datetime.utcnow() > cert.not_valid_after_utc:
                    return False
            
            # Check if root is trusted
            root_cert = chain[-1]
            root_subject = root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            return root_subject in self.trusted_cas
            
        except Exception as e:
            logger.error("Certificate chain validation failed: %s", str(e))
            return False
    
    def _validate_pcr_values(self, pcr_values: Dict[int, bytes]) -> bool:
        """Validate TPM PCR values."""
        # Check required PCRs based on policy
        policy = self.attestation_policies.get(AttestationType.TPM_2_0, {})
        required_pcrs = policy.get('required_pcrs', [])
        
        for pcr in required_pcrs:
            if pcr not in pcr_values:
                return False
            
            # Check if PCR has been extended (not all zeros)
            if pcr_values[pcr] == b'\x00' * 32:
                return False
        
        return True
    
    def _get_patch_age_days(self, patch_level: str) -> int:
        """Get age of patch level in days."""
        # This is a simplified implementation
        # In production, this would query patch databases
        try:
            # Assume patch_level is in format "2024-01-15"
            patch_date = datetime.strptime(patch_level, "%Y-%m-%d")
            return (datetime.utcnow() - patch_date).days
        except:
            return 999  # Unknown patch age
    
    def _check_vulnerable_packages(
        self,
        installed_packages: Dict[str, str]
    ) -> List[str]:
        """Check for known vulnerable packages."""
        # This is a simplified implementation
        # In production, this would query CVE databases
        vulnerable = []
        
        # Example vulnerable versions
        vulnerable_versions = {
            'openssl': ['1.0.1', '1.0.2'],
            'log4j': ['2.14.0', '2.14.1'],
            'apache': ['2.4.41', '2.4.43']
        }
        
        for package, version in installed_packages.items():
            if package in vulnerable_versions:
                if any(version.startswith(v) for v in vulnerable_versions[package]):
                    vulnerable.append(f"{package}:{version}")
        
        return vulnerable
    
    def _generate_recommendations(
        self,
        device: DeviceProfile,
        hardware_score: float,
        software_score: float,
        behavior_score: float,
        compliance_score: float
    ) -> List[str]:
        """Generate recommendations for improving trust score."""
        recommendations = []
        
        if hardware_score < 60:
            recommendations.append("Enable hardware attestation with TPM 2.0")
            recommendations.append("Update device firmware to latest version")
        
        if software_score < 60:
            recommendations.append("Apply latest security patches")
            recommendations.append("Enable all security products")
            recommendations.append("Remove or update vulnerable software")
        
        if behavior_score < 60:
            recommendations.append("Investigate recent anomalous behavior")
            recommendations.append("Review privileged access patterns")
        
        if compliance_score < 60:
            recommendations.append("Ensure regular device check-ins")
            recommendations.append("Complete compliance validation")
        
        return recommendations
    
    async def _validate_attestation(
        self,
        device: DeviceProfile,
        attestation: HardwareAttestation
    ) -> bool:
        """Validate hardware attestation."""
        try:
            # Validate certificate chain
            if not self._validate_certificate_chain(attestation.certificate_chain):
                attestation.validation_errors.append("Invalid certificate chain")
                attestation.is_valid = False
                return False
            
            # Validate based on attestation type
            if attestation.attestation_type == AttestationType.TPM_2_0:
                if not await self._validate_tpm_attestation(attestation):
                    return False
            elif attestation.attestation_type == AttestationType.SECURE_BOOT:
                if not await self._validate_secure_boot_attestation(attestation):
                    return False
            
            attestation.is_valid = True
            self.stats['attestations_validated'] += 1
            
            await self.audit_logger.log_event(
                "DEVICE_ATTESTATION_VALIDATED",
                classification=ClassificationLevel.UNCLASSIFIED,
                details={
                    'device_id': device.device_id,
                    'attestation_type': attestation.attestation_type.value,
                    'validation_result': 'success'
                }
            )
            
            return True
            
        except Exception as e:
            logger.error("Attestation validation failed: %s", str(e))
            attestation.validation_errors.append(str(e))
            attestation.is_valid = False
            return False
    
    async def _validate_tpm_attestation(
        self,
        attestation: HardwareAttestation
    ) -> bool:
        """Validate TPM attestation."""
        policy = self.attestation_policies.get(AttestationType.TPM_2_0, {})
        
        # Check quote age
        if attestation.quote and attestation.timestamp:
            quote_age = (datetime.utcnow() - attestation.timestamp).total_seconds()
            max_age = policy.get('max_quote_age_seconds', 300)
            if quote_age > max_age:
                attestation.validation_errors.append("TPM quote too old")
                return False
        
        # Validate PCR values
        if not self._validate_pcr_values(attestation.pcr_values):
            attestation.validation_errors.append("Invalid PCR values")
            return False
        
        # TODO: Verify quote signature with attestation key
        
        return True
    
    async def _validate_secure_boot_attestation(
        self,
        attestation: HardwareAttestation
    ) -> bool:
        """Validate secure boot attestation."""
        # Simplified validation
        # In production, this would verify UEFI signatures
        return len(attestation.certificate_chain) > 0
    
    def _update_avg_calculation_time(self, calculation_time_ms: float):
        """Update average calculation time metric."""
        current_avg = self.stats['avg_calculation_time_ms']
        total_calculations = self.stats['trust_scores_calculated']
        
        # Calculate running average
        self.stats['avg_calculation_time_ms'] = (
            (current_avg * (total_calculations - 1) + calculation_time_ms) / total_calculations
        )
    
    async def update_device_behavior(
        self,
        device_id: str,
        event_type: str,
        event_data: Dict[str, Any]
    ):
        """Update device behavioral history."""
        device = self.devices.get(device_id)
        if not device:
            logger.warning("Device %s not found for behavior update", device_id)
            return
        
        # Add to behavioral history
        device.behavioral_history.append({
            'type': event_type,
            'timestamp': datetime.utcnow(),
            'data': event_data
        })
        
        # Recalculate trust score if significant event
        if event_type in self.anomaly_thresholds:
            await self.calculate_trust_score(device_id, force_recalculate=True)
    
    async def cleanup_expired_devices(self, max_age_days: int = 90):
        """Clean up devices not seen in specified days."""
        cutoff_time = datetime.utcnow() - timedelta(days=max_age_days)
        expired_devices = []
        
        for device_id, device in self.devices.items():
            if device.last_seen < cutoff_time:
                expired_devices.append(device_id)
        
        for device_id in expired_devices:
            del self.devices[device_id]
            if device_id in self.trust_scores:
                del self.trust_scores[device_id]
            if device_id in self.score_cache:
                del self.score_cache[device_id]
        
        if expired_devices:
            logger.info("Cleaned up %d expired devices", len(expired_devices))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current system statistics."""
        trust_level_distribution = {
            level.value: 0 for level in TrustLevel
        }
        
        for trust_score in self.trust_scores.values():
            trust_level_distribution[trust_score.trust_level.value] += 1
        
        return {
            **self.stats,
            'trust_level_distribution': trust_level_distribution,
            'cache_size': len(self.score_cache),
            'trusted_cas': len(self.trusted_cas)
        }