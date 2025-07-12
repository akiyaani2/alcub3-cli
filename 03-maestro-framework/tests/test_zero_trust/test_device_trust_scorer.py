#!/usr/bin/env python3
"""
Tests for ALCUB3 Device Trust Scorer
Validates hardware attestation and device trust scoring functionality
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import secrets

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.zero_trust.device_trust_scorer import (
    DeviceTrustScorer,
    DeviceType,
    DeviceProfile,
    TrustScore,
    TrustLevel,
    ComplianceStatus,
    HardwareAttestation
)
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError
from shared.hsm_integration import HSMIntegration
from shared.real_time_monitor import RealTimeMonitor


@pytest.fixture
async def mock_audit_logger():
    """Create mock audit logger."""
    logger = Mock(spec=AuditLogger)
    logger.log_event = AsyncMock()
    return logger


@pytest.fixture
async def mock_hsm():
    """Create mock HSM integration."""
    hsm = Mock(spec=HSMIntegration)
    hsm.generate_key = AsyncMock(return_value=b"mock_key")
    hsm.sign_data = AsyncMock(return_value=b"mock_signature")
    hsm.verify_signature = AsyncMock(return_value=True)
    return hsm


@pytest.fixture
async def mock_monitor():
    """Create mock real-time monitor."""
    monitor = Mock(spec=RealTimeMonitor)
    monitor.record_event = AsyncMock()
    monitor.record_metric = AsyncMock()
    return monitor


@pytest.fixture
async def device_trust_scorer(mock_audit_logger, mock_hsm, mock_monitor):
    """Create device trust scorer instance."""
    scorer = DeviceTrustScorer(
        audit_logger=mock_audit_logger,
        hsm_integration=mock_hsm,
        monitor=mock_monitor,
        attestation_ca_path=None
    )
    return scorer


class TestDeviceTrustScorer:
    """Test cases for device trust scorer."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, device_trust_scorer):
        """Test scorer initialization."""
        scorer = device_trust_scorer
        
        assert scorer.trust_thresholds == {
            TrustLevel.UNTRUSTED: 0,
            TrustLevel.LOW: 30,
            TrustLevel.MEDIUM: 50,
            TrustLevel.HIGH: 70,
            TrustLevel.TRUSTED: 85
        }
        assert len(scorer.devices) == 0
        assert scorer.enable_behavioral_analysis is True
    
    @pytest.mark.asyncio
    async def test_register_device(self, device_trust_scorer):
        """Test device registration."""
        scorer = device_trust_scorer
        
        # Mock hardware attestation
        attestation_data = {
            'tpm_ekpub': 'mock_public_key',
            'pcr_values': {'0': 'hash0', '1': 'hash1'},
            'quote': 'mock_quote',
            'signature': 'mock_signature'
        }
        
        device = await scorer.register_device(
            device_id="laptop-001",
            device_type=DeviceType.LAPTOP,
            manufacturer="Dell",
            model="Latitude 7420",
            serial_number="DL7420X123",
            hardware_attestation=attestation_data
        )
        
        assert device.device_id == "laptop-001"
        assert device.device_type == DeviceType.LAPTOP
        assert device.manufacturer == "Dell"
        assert device.model == "Latitude 7420"
        assert device.serial_number == "DL7420X123"
        assert device.hardware_attestation is not None
        assert device.device_id in scorer.devices
    
    @pytest.mark.asyncio
    async def test_calculate_trust_score_new_device(self, device_trust_scorer):
        """Test trust score calculation for new device."""
        scorer = device_trust_scorer
        
        # Register device
        device = await scorer.register_device(
            device_id="laptop-001",
            device_type=DeviceType.LAPTOP,
            manufacturer="Dell",
            model="Latitude 7420",
            serial_number="DL7420X123"
        )
        
        # Calculate trust score
        trust_score = await scorer.calculate_trust_score("laptop-001")
        
        assert trust_score.device_id == "laptop-001"
        assert 0 <= trust_score.overall_score <= 100
        assert trust_score.trust_level in TrustLevel
        assert len(trust_score.factors) > 0
        
        # New device without attestation should have low-medium trust
        assert trust_score.overall_score < 60
    
    @pytest.mark.asyncio
    async def test_hardware_attestation_validation(self, device_trust_scorer):
        """Test hardware attestation validation."""
        scorer = device_trust_scorer
        
        # Register device with valid attestation
        valid_attestation = {
            'tpm_ekpub': secrets.token_hex(32),
            'pcr_values': {str(i): secrets.token_hex(20) for i in range(24)},
            'quote': secrets.token_hex(64),
            'signature': secrets.token_hex(64),
            'certificate_chain': ['cert1', 'cert2']
        }
        
        device = await scorer.register_device(
            device_id="secure-laptop",
            device_type=DeviceType.LAPTOP,
            manufacturer="HP",
            model="EliteBook",
            serial_number="HP123",
            hardware_attestation=valid_attestation
        )
        
        # Should have hardware attestation
        assert device.hardware_attestation is not None
        assert device.hardware_attestation.tpm_version == "2.0"
        assert device.hardware_attestation.verified is True
        
        # Calculate trust score - should be higher with attestation
        trust_score = await scorer.calculate_trust_score("secure-laptop")
        assert trust_score.factors['hardware_attestation'] > 80
    
    @pytest.mark.asyncio
    async def test_compliance_check(self, device_trust_scorer):
        """Test device compliance checking."""
        scorer = device_trust_scorer
        
        # Register device
        device = await scorer.register_device(
            device_id="laptop-001",
            device_type=DeviceType.LAPTOP,
            manufacturer="Dell",
            model="Latitude 7420",
            serial_number="DL7420X123"
        )
        
        # Set compliant configuration
        device.os_version = "Windows 11 22H2"
        device.security_patches = ["KB5023696", "KB5023697"]
        device.antivirus_status = "active"
        device.firewall_enabled = True
        device.disk_encryption = True
        device.secure_boot = True
        
        # Check compliance
        compliance = await scorer._check_compliance(device)
        
        assert compliance.is_compliant is True
        assert len(compliance.violations) == 0
        assert compliance.last_check is not None
    
    @pytest.mark.asyncio
    async def test_non_compliance_detection(self, device_trust_scorer):
        """Test detection of non-compliant devices."""
        scorer = device_trust_scorer
        
        # Register device with non-compliant config
        device = await scorer.register_device(
            device_id="laptop-002",
            device_type=DeviceType.LAPTOP,
            manufacturer="Lenovo",
            model="ThinkPad",
            serial_number="LN123"
        )
        
        # Set non-compliant configuration
        device.os_version = "Windows 10 1903"  # Outdated
        device.antivirus_status = "disabled"
        device.firewall_enabled = False
        device.disk_encryption = False
        device.secure_boot = False
        
        # Check compliance
        compliance = await scorer._check_compliance(device)
        
        assert compliance.is_compliant is False
        assert len(compliance.violations) > 0
        assert "os_outdated" in compliance.violations
        assert "antivirus_disabled" in compliance.violations
        
        # Trust score should be impacted
        trust_score = await scorer.calculate_trust_score("laptop-002")
        assert trust_score.factors['compliance'] < 50
    
    @pytest.mark.asyncio
    async def test_behavioral_analysis(self, device_trust_scorer):
        """Test device behavioral analysis."""
        scorer = device_trust_scorer
        
        # Register device
        device = await scorer.register_device(
            device_id="laptop-001",
            device_type=DeviceType.LAPTOP,
            manufacturer="Dell",
            model="Latitude 7420",
            serial_number="DL7420X123"
        )
        
        # Update device behavior over time
        for i in range(10):
            await scorer.update_device_behavior(
                device_id="laptop-001",
                activity_data={
                    'login_location': 'office',
                    'network_traffic': 1000 + i * 100,  # MB
                    'applications_used': ['outlook', 'chrome', 'vscode'],
                    'access_patterns': {'morning': 5, 'afternoon': 10}
                }
            )
            await asyncio.sleep(0.01)  # Small delay
        
        # Analyze behavior
        behavior_score = await scorer._analyze_behavior(device)
        
        assert 0 <= behavior_score <= 100
        assert device.last_activity is not None
        
        # Test anomaly detection
        anomaly_detected = await scorer._detect_behavioral_anomaly(
            device,
            {
                'login_location': 'unknown_country',  # Anomaly
                'network_traffic': 50000,  # Very high
                'applications_used': ['unknown_app1', 'unknown_app2']
            }
        )
        
        assert anomaly_detected is True
    
    @pytest.mark.asyncio
    async def test_trust_level_classification(self, device_trust_scorer):
        """Test trust level classification based on scores."""
        scorer = device_trust_scorer
        
        test_cases = [
            (10, TrustLevel.UNTRUSTED),
            (35, TrustLevel.LOW),
            (55, TrustLevel.MEDIUM),
            (75, TrustLevel.HIGH),
            (90, TrustLevel.TRUSTED)
        ]
        
        for score, expected_level in test_cases:
            level = scorer._get_trust_level(score)
            assert level == expected_level
    
    @pytest.mark.asyncio
    async def test_risk_factor_analysis(self, device_trust_scorer):
        """Test comprehensive risk factor analysis."""
        scorer = device_trust_scorer
        
        # Register device with mixed risk factors
        device = await scorer.register_device(
            device_id="laptop-001",
            device_type=DeviceType.LAPTOP,
            manufacturer="Dell",
            model="Latitude 7420",
            serial_number="DL7420X123",
            hardware_attestation={
                'tpm_ekpub': 'valid_key',
                'pcr_values': {'0': 'hash0'},
                'quote': 'quote',
                'signature': 'sig'
            }
        )
        
        # Set various attributes
        device.jailbroken = False
        device.developer_mode = False
        device.unknown_certificates = []
        device.compliance_status = ComplianceStatus(
            is_compliant=True,
            violations=[],
            last_check=datetime.utcnow()
        )
        
        # Calculate trust score
        trust_score = await scorer.calculate_trust_score("laptop-001")
        
        # Check individual factors
        assert 'hardware_attestation' in trust_score.factors
        assert 'compliance' in trust_score.factors
        assert 'behavior' in trust_score.factors
        assert 'device_age' in trust_score.factors
        assert 'patch_level' in trust_score.factors
        
        # Overall should be reasonable
        assert 50 <= trust_score.overall_score <= 85
    
    @pytest.mark.asyncio
    async def test_classification_requirements(self, device_trust_scorer):
        """Test trust requirements for different classification levels."""
        scorer = device_trust_scorer
        
        # Register devices with different trust levels
        devices = []
        for i, trust_level in enumerate([20, 40, 60, 80, 95]):
            device = await scorer.register_device(
                device_id=f"device-{i}",
                device_type=DeviceType.LAPTOP,
                manufacturer="Test",
                model="Model",
                serial_number=f"SN{i}"
            )
            # Mock trust score
            device._mock_trust_score = trust_level
            devices.append(device)
        
        # Test classification requirements
        test_cases = [
            (ClassificationLevel.UNCLASSIFIED, 30),
            (ClassificationLevel.CONFIDENTIAL, 50),
            (ClassificationLevel.SECRET, 70),
            (ClassificationLevel.TOP_SECRET, 85)
        ]
        
        for classification, min_trust in test_cases:
            approved = await scorer.check_classification_access(
                device_id="device-3",  # Trust score 80
                classification_level=classification
            )
            
            if min_trust <= 80:
                assert approved is True
            else:
                assert approved is False
    
    @pytest.mark.asyncio
    async def test_device_quarantine(self, device_trust_scorer):
        """Test device quarantine functionality."""
        scorer = device_trust_scorer
        
        # Register device
        device = await scorer.register_device(
            device_id="laptop-001",
            device_type=DeviceType.LAPTOP,
            manufacturer="Dell",
            model="Latitude 7420",
            serial_number="DL7420X123"
        )
        
        # Quarantine device
        await scorer.quarantine_device(
            device_id="laptop-001",
            reason="Suspicious activity detected"
        )
        
        assert device.quarantined is True
        assert device.quarantine_reason == "Suspicious activity detected"
        
        # Trust score should be zero when quarantined
        trust_score = await scorer.calculate_trust_score("laptop-001")
        assert trust_score.overall_score == 0
        assert trust_score.trust_level == TrustLevel.UNTRUSTED
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, device_trust_scorer):
        """Test performance tracking."""
        scorer = device_trust_scorer
        
        # Register multiple devices
        for i in range(20):
            await scorer.register_device(
                device_id=f"device-{i}",
                device_type=DeviceType.LAPTOP if i % 2 == 0 else DeviceType.MOBILE,
                manufacturer="Test",
                model=f"Model-{i}",
                serial_number=f"SN{i}"
            )
        
        # Calculate trust scores
        for i in range(20):
            await scorer.calculate_trust_score(f"device-{i}")
        
        stats = scorer.get_statistics()
        assert stats['devices_registered'] == 20
        assert stats['trust_scores_calculated'] == 20
        assert stats['avg_calculation_time_ms'] < 10  # Should be fast
        assert stats['quarantined_devices'] == 0
    
    @pytest.mark.asyncio
    async def test_concurrent_scoring(self, device_trust_scorer):
        """Test concurrent trust score calculations."""
        scorer = device_trust_scorer
        
        # Register devices
        device_ids = []
        for i in range(50):
            device = await scorer.register_device(
                device_id=f"device-{i}",
                device_type=DeviceType.LAPTOP,
                manufacturer="Test",
                model="Model",
                serial_number=f"SN{i}"
            )
            device_ids.append(device.device_id)
        
        # Calculate scores concurrently
        tasks = []
        for device_id in device_ids:
            task = scorer.calculate_trust_score(device_id)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        assert len(results) == 50
        assert all(isinstance(r, TrustScore) for r in results)
        assert all(0 <= r.overall_score <= 100 for r in results)
    
    @pytest.mark.asyncio
    async def test_device_lifecycle(self, device_trust_scorer):
        """Test device lifecycle from registration to removal."""
        scorer = device_trust_scorer
        
        # Register device
        device = await scorer.register_device(
            device_id="lifecycle-device",
            device_type=DeviceType.LAPTOP,
            manufacturer="Dell",
            model="Latitude",
            serial_number="DL123"
        )
        
        # Update device over time
        for i in range(5):
            await scorer.update_device_behavior(
                device_id="lifecycle-device",
                activity_data={
                    'login_location': 'office',
                    'network_traffic': 1000
                }
            )
            
            # Update compliance
            device.last_compliance_check = datetime.utcnow()
            device.compliance_status = ComplianceStatus(
                is_compliant=True,
                violations=[],
                last_check=datetime.utcnow()
            )
            
            await asyncio.sleep(0.01)
        
        # Check final state
        trust_score = await scorer.calculate_trust_score("lifecycle-device")
        assert trust_score.overall_score > 30
        
        # Remove device
        removed = await scorer.remove_device("lifecycle-device")
        assert removed is True
        assert "lifecycle-device" not in scorer.devices
    
    @pytest.mark.asyncio
    async def test_ml_integration(self, device_trust_scorer):
        """Test ML model integration for behavioral analysis."""
        scorer = device_trust_scorer
        
        # Register device
        device = await scorer.register_device(
            device_id="ml-device",
            device_type=DeviceType.LAPTOP,
            manufacturer="Test",
            model="ML-Model",
            serial_number="ML123"
        )
        
        # Train behavioral model with normal patterns
        for i in range(20):
            await scorer.update_device_behavior(
                device_id="ml-device",
                activity_data={
                    'cpu_usage': 30 + (i % 10),
                    'memory_usage': 50 + (i % 20),
                    'network_connections': 10 + (i % 5),
                    'process_count': 50 + (i % 10)
                }
            )
        
        # Test anomaly detection with abnormal pattern
        anomaly_score = await scorer._calculate_anomaly_score(
            device,
            {
                'cpu_usage': 95,  # Very high
                'memory_usage': 98,  # Very high
                'network_connections': 500,  # Suspicious
                'process_count': 300  # Suspicious
            }
        )
        
        assert anomaly_score > 0.7  # Should detect as anomaly


if __name__ == "__main__":
    pytest.main([__file__, "-v"])