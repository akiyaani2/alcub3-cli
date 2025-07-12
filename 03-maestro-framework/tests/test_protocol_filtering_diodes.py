"""
MAESTRO Protocol Filtering Diodes Test Suite
Comprehensive testing for air-gapped security data transfer validation.

This test suite validates:
- Unidirectional data transfer enforcement
- Protocol filtering and validation
- Malware and steganography detection
- Hardware attestation simulation
- Performance and security metrics
- Threat level assessment
- Classification-aware filtering
"""

import asyncio
import unittest
import time
import json
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

# Import PFD components
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src', 'shared'))

from protocol_filtering_diodes import (
    ProtocolFilteringDiode, PFDManager, PFDConfiguration, 
    DataTransferRequest, TransferResult, ProtocolAnalysisResult,
    TransferDirection, ProtocolType, ThreatLevel, TransferStatus,
    PFDException, TransferBlockedException, ProtocolViolationException,
    HardwareAttestationFailedException
)

class TestProtocolFilteringDiodes(unittest.IsolatedAsyncioTestCase):
    """Test Protocol Filtering Diode functionality."""
    
    async def asyncSetUp(self):
        """Set up test environment."""
        # Create test PFD configuration
        self.test_config = PFDConfiguration(
            diode_id="TEST-PFD-001",
            transfer_direction=TransferDirection.OUTBOUND,
            allowed_protocols=[ProtocolType.HTTP, ProtocolType.HTTPS, ProtocolType.SFTP],
            classification_level="secret",
            max_transfer_size=10 * 1024 * 1024,  # 10MB
            enable_content_inspection=True,
            enable_malware_scanning=True,
            enable_steganography_detection=True,
            hardware_attestation_required=True,
            tempest_protection_enabled=True,
            monitoring_level="high"
        )
        
        # Create PFD instance
        self.pfd = ProtocolFilteringDiode(self.test_config)
        
        # Create test transfer request
        self.test_request = DataTransferRequest(
            transfer_id="TRANSFER-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=1024 * 1024,  # 1MB
            data_hash="a1b2c3d4e5f6",
            content_type="application/json",
            timestamp=time.time(),
            metadata={"purpose": "data_export", "user": "test_user"}
        )
    
    async def test_successful_transfer(self):
        """Test successful data transfer through PFD."""
        result = await self.pfd.process_transfer_request(self.test_request)
        
        self.assertIsInstance(result, TransferResult)
        self.assertEqual(result.transfer_id, self.test_request.transfer_id)
        self.assertEqual(result.status, TransferStatus.TRANSFERRED)
        self.assertEqual(result.bytes_transferred, self.test_request.data_size)
        self.assertIsNone(result.error_message)
        self.assertIsNotNone(result.hardware_attestation)
        self.assertIsNotNone(result.validation_result)
        
        # Check validation result
        validation = result.validation_result
        self.assertTrue(validation.protocol_valid)
        self.assertTrue(validation.content_safe)
        self.assertTrue(validation.classification_verified)
        self.assertFalse(validation.malware_detected)
        self.assertFalse(validation.steganography_detected)
        
        # Check hardware attestation
        attestation = result.hardware_attestation
        self.assertEqual(attestation["diode_id"], self.test_config.diode_id)
        self.assertEqual(attestation["transfer_id"], self.test_request.transfer_id)
        self.assertIn("signature", attestation)
    
    async def test_blocked_protocol(self):
        """Test transfer blocked due to disallowed protocol."""
        # Create request with blocked protocol
        blocked_request = DataTransferRequest(
            transfer_id="TRANSFER-BLOCKED-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.FTP,  # Not in allowed protocols
            classification="secret",
            data_size=1024,
            data_hash="blocked123",
            content_type="text/plain",
            timestamp=time.time(),
            metadata={}
        )
        
        result = await self.pfd.process_transfer_request(blocked_request)
        
        self.assertEqual(result.status, TransferStatus.REJECTED)
        self.assertEqual(result.bytes_transferred, 0)
        self.assertIsNotNone(result.error_message)
        self.assertIn("Protocol", result.error_message)
        self.assertIsNone(result.hardware_attestation)
    
    async def test_oversized_transfer_blocked(self):
        """Test transfer blocked due to size limit."""
        # Create oversized request
        oversized_request = DataTransferRequest(
            transfer_id="TRANSFER-OVERSIZED-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=100 * 1024 * 1024,  # 100MB (over 10MB limit)
            data_hash="oversized123",
            content_type="application/octet-stream",
            timestamp=time.time(),
            metadata={}
        )
        
        result = await self.pfd.process_transfer_request(oversized_request)
        
        self.assertEqual(result.status, TransferStatus.REJECTED)
        self.assertEqual(result.bytes_transferred, 0)
        self.assertIsNotNone(result.error_message)
        self.assertIn("size exceeds", result.error_message)
    
    async def test_malware_detection(self):
        """Test malware detection in transfer."""
        # Create request with malicious hash
        malware_request = DataTransferRequest(
            transfer_id="TRANSFER-MALWARE-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=1024,
            data_hash="d41d8cd98f00b204e9800998ecf8427e",  # Known malware signature
            content_type="application/octet-stream",
            timestamp=time.time(),
            metadata={}
        )
        
        result = await self.pfd.process_transfer_request(malware_request)
        
        self.assertEqual(result.status, TransferStatus.REJECTED)
        self.assertEqual(result.bytes_transferred, 0)
        self.assertIsNotNone(result.error_message)
        self.assertIn("Malware detected", result.error_message)
    
    async def test_steganography_detection(self):
        """Test steganography detection in transfer."""
        # Create request with steganographic content
        stego_request = DataTransferRequest(
            transfer_id="TRANSFER-STEGO-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=1024,
            data_hash="stego123",
            content_type="image/stego",  # Suspicious content type
            timestamp=time.time(),
            metadata={}
        )
        
        result = await self.pfd.process_transfer_request(stego_request)
        
        self.assertEqual(result.status, TransferStatus.REJECTED)
        self.assertEqual(result.bytes_transferred, 0)
        self.assertIsNotNone(result.error_message)
        self.assertIn("Steganography detected", result.error_message)
    
    async def test_classification_validation(self):
        """Test classification level validation."""
        # Test different classification levels
        classifications = ["unclassified", "cui", "secret", "top_secret"]
        
        for classification in classifications:
            test_request = DataTransferRequest(
                transfer_id=f"TRANSFER-{classification.upper()}-001",
                source_system="secure-workstation-01",
                destination_system="external-server-01",
                protocol=ProtocolType.HTTPS,
                classification=classification,
                data_size=1024,
                data_hash=f"{classification}123",
                content_type="application/json",
                timestamp=time.time(),
                metadata={}
            )
            
            result = await self.pfd.process_transfer_request(test_request)
            
            # Should succeed for secret and below (PFD configured for secret)
            if classification in ["unclassified", "cui", "secret"]:
                self.assertEqual(result.status, TransferStatus.TRANSFERRED)
            else:
                # top_secret should be blocked by secret-level PFD
                self.assertEqual(result.status, TransferStatus.REJECTED)
    
    async def test_performance_metrics(self):
        """Test performance metrics tracking."""
        # Process multiple transfers
        for i in range(5):
            test_request = DataTransferRequest(
                transfer_id=f"TRANSFER-PERF-{i:03d}",
                source_system="secure-workstation-01",
                destination_system="external-server-01",
                protocol=ProtocolType.HTTPS,
                classification="secret",
                data_size=1024 * (i + 1),
                data_hash=f"perf{i}123",
                content_type="application/json",
                timestamp=time.time(),
                metadata={}
            )
            
            await self.pfd.process_transfer_request(test_request)
        
        # Check metrics
        status = self.pfd.get_status()
        metrics = status["performance_metrics"]
        
        self.assertEqual(metrics["total_transfers"], 5)
        self.assertEqual(metrics["successful_transfers"], 5)
        self.assertEqual(metrics["blocked_transfers"], 0)
        self.assertGreater(metrics["average_analysis_time"], 0)
        self.assertGreater(metrics["average_transfer_time"], 0)
    
    async def test_anomaly_detection(self):
        """Test anomaly detection in transfers."""
        # Create request with multiple anomalies
        anomaly_request = DataTransferRequest(
            transfer_id="TRANSFER-ANOMALY-001",
            source_system="unknown_system",  # Suspicious source
            destination_system="external-server-01",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=5 * 1024 * 1024,  # Large transfer (but under limit)
            data_hash="anomaly123",
            content_type="application/octet-stream",
            timestamp=time.time(),
            metadata={}
        )
        
        result = await self.pfd.process_transfer_request(anomaly_request)
        
        # Should still succeed but with higher threat level
        self.assertEqual(result.status, TransferStatus.TRANSFERRED)
        self.assertIsNotNone(result.validation_result)
        
        # Check for detected anomalies
        validation = result.validation_result
        self.assertGreater(len(validation.anomalies_detected), 0)
        self.assertIn("unknown_source_system", validation.anomalies_detected)
    
    async def test_hardware_status_validation(self):
        """Test hardware status validation."""
        # Get initial status
        status = self.pfd.get_status()
        self.assertTrue(status["operational"])
        
        # Simulate hardware failure
        self.pfd.hardware_status["operational"] = False
        self.pfd.hardware_status["attestation_valid"] = False
        
        # Should fail hardware validation
        result = await self.pfd.process_transfer_request(self.test_request)
        self.assertEqual(result.status, TransferStatus.FAILED)
        
        # Restore hardware status
        self.pfd.hardware_status["operational"] = True
        self.pfd.hardware_status["attestation_valid"] = True
        
        # Should work again
        result = await self.pfd.process_transfer_request(self.test_request)
        self.assertEqual(result.status, TransferStatus.TRANSFERRED)

class TestPFDManager(unittest.IsolatedAsyncioTestCase):
    """Test PFD Manager functionality."""
    
    async def asyncSetUp(self):
        """Set up test environment."""
        self.pfd_manager = PFDManager(classification_level="secret")
        
        # Create multiple PFD configurations
        self.inbound_config = PFDConfiguration(
            diode_id="INBOUND-PFD-001",
            transfer_direction=TransferDirection.INBOUND,
            allowed_protocols=[ProtocolType.HTTPS, ProtocolType.SFTP],
            classification_level="secret",
            max_transfer_size=5 * 1024 * 1024,
            enable_content_inspection=True,
            enable_malware_scanning=True,
            enable_steganography_detection=False,
            hardware_attestation_required=True,
            tempest_protection_enabled=True,
            monitoring_level="high"
        )
        
        self.outbound_config = PFDConfiguration(
            diode_id="OUTBOUND-PFD-001",
            transfer_direction=TransferDirection.OUTBOUND,
            allowed_protocols=[ProtocolType.HTTP, ProtocolType.HTTPS],
            classification_level="secret",
            max_transfer_size=10 * 1024 * 1024,
            enable_content_inspection=True,
            enable_malware_scanning=True,
            enable_steganography_detection=True,
            hardware_attestation_required=True,
            tempest_protection_enabled=False,
            monitoring_level="medium"
        )
    
    async def test_add_multiple_pfds(self):
        """Test adding multiple PFDs to manager."""
        # Add inbound PFD
        added_inbound = await self.pfd_manager.add_pfd("inbound-1", self.inbound_config)
        self.assertTrue(added_inbound)
        
        # Add outbound PFD
        added_outbound = await self.pfd_manager.add_pfd("outbound-1", self.outbound_config)
        self.assertTrue(added_outbound)
        
        # Check status
        status = self.pfd_manager.get_comprehensive_status()
        self.assertEqual(status["global_metrics"]["total_diodes"], 2)
        self.assertEqual(status["global_metrics"]["active_diodes"], 2)
        self.assertIn("inbound-1", status["diodes"])
        self.assertIn("outbound-1", status["diodes"])
    
    async def test_process_transfers_through_manager(self):
        """Test processing transfers through manager."""
        # Add PFDs
        await self.pfd_manager.add_pfd("test-pfd", self.outbound_config)
        
        # Create test request
        test_request = DataTransferRequest(
            transfer_id="MANAGER-TRANSFER-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=1024,
            data_hash="manager123",
            content_type="application/json",
            timestamp=time.time(),
            metadata={}
        )
        
        # Process through manager
        result = await self.pfd_manager.process_transfer("test-pfd", test_request)
        
        self.assertEqual(result.status, TransferStatus.TRANSFERRED)
        self.assertEqual(result.transfer_id, test_request.transfer_id)
        
        # Check global metrics updated
        status = self.pfd_manager.get_comprehensive_status()
        self.assertEqual(status["global_metrics"]["total_transfers"], 1)
    
    async def test_pfd_not_found(self):
        """Test error when PFD not found."""
        test_request = DataTransferRequest(
            transfer_id="NONEXISTENT-001",
            source_system="test",
            destination_system="test",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=1024,
            data_hash="test123",
            content_type="application/json",
            timestamp=time.time(),
            metadata={}
        )
        
        with self.assertRaises(PFDException) as context:
            await self.pfd_manager.process_transfer("nonexistent-pfd", test_request)
        
        self.assertIn("not found", str(context.exception))
    
    async def test_security_summary(self):
        """Test security summary generation."""
        # Add PFD and process transfers
        await self.pfd_manager.add_pfd("security-test", self.outbound_config)
        
        # Process successful transfer
        success_request = DataTransferRequest(
            transfer_id="SUCCESS-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.HTTPS,
            classification="secret",
            data_size=1024,
            data_hash="success123",
            content_type="application/json",
            timestamp=time.time(),
            metadata={}
        )
        await self.pfd_manager.process_transfer("security-test", success_request)
        
        # Process blocked transfer
        blocked_request = DataTransferRequest(
            transfer_id="BLOCKED-001",
            source_system="secure-workstation-01",
            destination_system="external-server-01",
            protocol=ProtocolType.FTP,  # Not allowed
            classification="secret",
            data_size=1024,
            data_hash="blocked123",
            content_type="application/json",
            timestamp=time.time(),
            metadata={}
        )
        await self.pfd_manager.process_transfer("security-test", blocked_request)
        
        # Get security summary
        summary = self.pfd_manager.get_security_summary()
        
        self.assertEqual(summary["total_transfers"], 2)
        self.assertEqual(summary["total_blocked"], 1)
        self.assertEqual(summary["block_rate"], 0.5)
        self.assertEqual(summary["security_effectiveness"], 50.0)
        self.assertEqual(summary["compliance_status"], "compliant")
    
    def test_pfd_configuration_validation(self):
        """Test PFD configuration validation."""
        # Test valid configuration
        config = PFDConfiguration(
            diode_id="TEST-001",
            transfer_direction=TransferDirection.OUTBOUND,
            allowed_protocols=[ProtocolType.HTTPS],
            classification_level="secret",
            max_transfer_size=1024,
            enable_content_inspection=True,
            enable_malware_scanning=True,
            enable_steganography_detection=True,
            hardware_attestation_required=True,
            tempest_protection_enabled=True,
            monitoring_level="high"
        )
        
        self.assertEqual(config.diode_id, "TEST-001")
        self.assertEqual(config.transfer_direction, TransferDirection.OUTBOUND)
        self.assertEqual(config.allowed_protocols, [ProtocolType.HTTPS])
        self.assertEqual(config.classification_level, "secret")
        self.assertTrue(config.enable_content_inspection)
        self.assertTrue(config.enable_malware_scanning)
        self.assertTrue(config.enable_steganography_detection)
        self.assertTrue(config.hardware_attestation_required)
        self.assertTrue(config.tempest_protection_enabled)

if __name__ == '__main__':
    unittest.main()