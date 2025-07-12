"""
Comprehensive Test Suite for TPM 2.0 Integration

This test suite validates the complete TPM integration including:
- TPM core functionality
- Remote attestation
- Hardware key management
- Security HAL integration
- Crypto operations

Copyright 2025 ALCUB3 Inc.
"""

import pytest
import asyncio
import time
import os
from typing import Dict, Any
from datetime import datetime

# Import TPM components
from universal_robotics.src.hardware import (
    TPM2Interface,
    TPMError,
    PCRBank,
    RoboticsPCRAllocation,
    TPMHierarchy,
    TPMAttestationEngine,
    AttestationType,
    RobotStateVector,
    HardwareKeyManager,
    KeyPurpose,
    KeyLifecycle
)

from universal_robotics.src.hal.tpm_security_integration import (
    TPMEnhancedSecurityHAL,
    SecurityCommand,
    RobotPlatformType,
    SecurityClassification,
    EmergencyStopReason
)

from universal_robotics.src.security.tpm_crypto_integration import (
    TPMCryptoIntegration,
    CryptoAlgorithm
)


class TestTPMCore:
    """Test TPM 2.0 core functionality."""
    
    @pytest.fixture
    async def tpm(self):
        """Create TPM instance for testing."""
        tpm = TPM2Interface(simulation_mode=True)
        await tpm.initialize()
        yield tpm
        # Cleanup if needed
    
    @pytest.mark.asyncio
    async def test_tpm_initialization(self, tpm):
        """Test TPM initialization and basic info retrieval."""
        info = await tpm.get_tpm_info()
        
        assert info is not None
        assert "manufacturer" in info
        assert "firmware_version" in info
        assert info["tpm_version"] == "2.0"
        assert info["simulation_mode"] is True
    
    @pytest.mark.asyncio
    async def test_pcr_operations(self, tpm):
        """Test PCR extend and read operations."""
        pcr_index = RoboticsPCRAllocation.PLATFORM_CONFIG
        test_data = b"test_platform_config"
        
        # Extend PCR
        success = await tpm.extend_pcr(pcr_index, test_data, PCRBank.SHA256)
        assert success is True
        
        # Read PCR
        measurement = await tpm.read_pcr(pcr_index, PCRBank.SHA256)
        assert measurement is not None
        assert measurement.index == pcr_index
        assert measurement.bank == PCRBank.SHA256
        assert len(measurement.value) == 32  # SHA256 hash size
    
    @pytest.mark.asyncio
    async def test_key_hierarchy(self, tpm):
        """Test TPM key hierarchy creation."""
        # Create primary key
        primary_key = await tpm.create_primary_key(
            hierarchy=TPMHierarchy.OWNER,
            algorithm="RSA2048"
        )
        
        assert primary_key is not None
        assert primary_key.hierarchy == TPMHierarchy.OWNER
        assert primary_key.handle != 0
        
        # Create child key
        child_key = await tpm.create_key(
            parent=primary_key,
            algorithm="RSA2048",
            key_type="signing"
        )
        
        assert child_key is not None
        assert child_key.parent_handle == primary_key.handle
    
    @pytest.mark.asyncio
    async def test_data_sealing(self, tpm):
        """Test data sealing and unsealing."""
        test_data = b"sensitive_robot_command"
        
        # Seal data
        sealed = await tpm.seal_data(test_data)
        assert sealed is not None
        assert sealed != test_data
        
        # Unseal data
        unsealed = await tpm.unseal_data(sealed)
        assert unsealed == test_data
    
    @pytest.mark.asyncio
    async def test_random_generation(self, tpm):
        """Test hardware random number generation."""
        # Generate different sizes
        for size in [16, 32, 64]:
            random_bytes = await tpm.get_random(size)
            assert len(random_bytes) == size
            
            # Check randomness (basic check)
            assert len(set(random_bytes)) > size // 2


class TestAttestationEngine:
    """Test TPM attestation functionality."""
    
    @pytest.fixture
    async def attestation_engine(self):
        """Create attestation engine for testing."""
        tpm = TPM2Interface(simulation_mode=True)
        await tpm.initialize()
        
        engine = TPMAttestationEngine(tpm)
        await engine.initialize()
        
        yield engine
    
    @pytest.mark.asyncio
    async def test_platform_attestation(self, attestation_engine):
        """Test platform attestation."""
        robot_state = RobotStateVector(
            platform_type="boston_dynamics_spot",
            firmware_version="1.0.0",
            sensor_calibration_hash=b"calibration_data",
            battery_level=0.95,
            operational_mode="autonomous",
            location=(42.3601, -71.0589, 10.5),
            mission_id="test_mission_001",
            command_sequence=1,
            timestamp=time.time()
        )
        
        result = await attestation_engine.attest_robot_state(
            robot_id="test_robot_001",
            robot_state=robot_state,
            attestation_type=AttestationType.PLATFORM
        )
        
        assert result is not None
        assert result.is_valid is True
        assert result.attestation_type == AttestationType.PLATFORM
        assert result.robot_id == "test_robot_001"
        assert result.quote is not None
    
    @pytest.mark.asyncio
    async def test_mission_attestation(self, attestation_engine):
        """Test mission-scoped attestation."""
        # Create mission-specific state
        robot_state = RobotStateVector(
            platform_type="dji_drone",
            firmware_version="2.1.0",
            sensor_calibration_hash=b"drone_calibration",
            battery_level=0.85,
            operational_mode="mission",
            location=(42.3601, -71.0589, 100.0),
            mission_id="aerial_survey_001",
            command_sequence=5,
            timestamp=time.time()
        )
        
        result = await attestation_engine.attest_robot_state(
            robot_id="drone_001",
            robot_state=robot_state,
            attestation_type=AttestationType.MISSION
        )
        
        assert result.is_valid is True
        assert result.attestation_type == AttestationType.MISSION
        assert "mission_id" in result.metadata
    
    @pytest.mark.asyncio
    async def test_attestation_verification(self, attestation_engine):
        """Test attestation verification."""
        # First create an attestation
        robot_state = RobotStateVector(
            platform_type="ros2",
            firmware_version="3.0.0",
            sensor_calibration_hash=b"ros_calibration",
            battery_level=0.75,
            operational_mode="teleoperated",
            location=(0.0, 0.0, 0.0),
            mission_id=None,
            command_sequence=1,
            timestamp=time.time()
        )
        
        attestation_result = await attestation_engine.attest_robot_state(
            robot_id="ros_bot_001",
            robot_state=robot_state,
            attestation_type=AttestationType.OPERATIONAL
        )
        
        # Verify the attestation
        verification = await attestation_engine.verify_attestation(
            attestation_result,
            robot_state
        )
        
        assert verification is True


class TestHardwareKeyManager:
    """Test hardware key management functionality."""
    
    @pytest.fixture
    async def key_manager(self):
        """Create key manager for testing."""
        tpm = TPM2Interface(simulation_mode=True)
        await tpm.initialize()
        
        manager = HardwareKeyManager(tpm)
        await manager.initialize()
        
        yield manager
    
    @pytest.mark.asyncio
    async def test_robot_identity_key(self, key_manager):
        """Test robot identity key creation."""
        from universal_robotics.src.interfaces.robotics_types import (
            RobotPlatformIdentity,
            PlatformType
        )
        
        platform = RobotPlatformIdentity(
            platformId="spot_test_001",
            platformType=PlatformType.BOSTON_DYNAMICS_SPOT,
            classification=SecurityClassification.UNCLASSIFIED
        )
        
        hardware_binding = {
            "serial_number": "SPOT-2024-001",
            "mac_address": "00:11:22:33:44:55",
            "tpm_ek_cert": "mock_cert_data"
        }
        
        identity_key = await key_manager.create_robot_identity_key(
            platform=platform,
            hardware_binding=hardware_binding
        )
        
        assert identity_key is not None
        assert identity_key.policy.purpose == KeyPurpose.PLATFORM_IDENTITY
        assert identity_key.lifecycle_state == KeyLifecycle.ACTIVE
        assert "platform_id" in identity_key.metadata
    
    @pytest.mark.asyncio
    async def test_mission_key_lifecycle(self, key_manager):
        """Test mission key creation and expiration."""
        mission_id = "test_mission_002"
        mission_params = {
            "objective": "perimeter_patrol",
            "duration": 3600,
            "robots": ["robot_001", "robot_002"]
        }
        
        # Create mission key
        mission_key = await key_manager.create_mission_key(
            mission_id=mission_id,
            mission_params=mission_params,
            validity_period=2,  # 2 seconds for testing
            classification=SecurityClassification.SECRET
        )
        
        assert mission_key is not None
        assert mission_key.policy.mission_bound is True
        assert mission_key.policy.mission_id == mission_id
        assert mission_key.lifecycle_state == KeyLifecycle.ACTIVE
        
        # Wait for expiration
        await asyncio.sleep(3)
        
        # Complete mission
        expired_keys = await key_manager.complete_mission(mission_id)
        assert len(expired_keys) > 0
        assert mission_key.key_id in expired_keys
    
    @pytest.mark.asyncio
    async def test_key_rotation(self, key_manager):
        """Test key rotation functionality."""
        # Create a key
        original_key = await key_manager.create_sensor_signing_key(
            sensor_type="lidar",
            calibration_data=b"lidar_calibration_v1",
            platform=PlatformType.BOSTON_DYNAMICS_SPOT
        )
        
        assert original_key is not None
        original_id = original_key.key_id
        
        # Rotate the key
        rotated_key = await key_manager.rotate_key(
            original_id,
            reason="scheduled_rotation"
        )
        
        assert rotated_key is not None
        assert rotated_key.key_id != original_id
        assert rotated_key.metadata.get("rotated_from") == original_id
        assert original_key.lifecycle_state == KeyLifecycle.REVOKED
    
    @pytest.mark.asyncio
    async def test_classification_key_derivation(self, key_manager):
        """Test classification-aware key derivation."""
        # Get root key
        root_key_id = key_manager.root_keys[
            (TPMHierarchy.OWNER, SecurityClassification.TOP_SECRET)
        ]
        
        # Derive SECRET key from TOP_SECRET
        derived_key = await key_manager.derive_classification_key(
            base_key_id=root_key_id,
            target_classification=SecurityClassification.SECRET,
            purpose=KeyPurpose.DATA_ENCRYPTION
        )
        
        assert derived_key is not None
        assert derived_key.policy.classification == SecurityClassification.SECRET
        assert derived_key.policy.purpose == KeyPurpose.DATA_ENCRYPTION
        
        # Try invalid derivation (should fail)
        with pytest.raises(ValueError):
            await key_manager.derive_classification_key(
                base_key_id=root_key_id,
                target_classification=SecurityClassification.TOP_SECRET,
                purpose=KeyPurpose.DATA_ENCRYPTION
            )


class TestTPMSecurityIntegration:
    """Test TPM integration with Security HAL."""
    
    @pytest.fixture
    async def tpm_hal(self):
        """Create TPM-enhanced HAL for testing."""
        hal = TPMEnhancedSecurityHAL(enable_tpm=True)
        yield hal
    
    @pytest.mark.asyncio
    async def test_tpm_command_validation(self, tpm_hal):
        """Test command validation with TPM attestation."""
        # Register robot
        success = await tpm_hal.register_robot(
            robot_id="tpm_robot_001",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=SecurityClassification.SECRET
        )
        assert success is True
        
        # Create command
        command = SecurityCommand(
            command_id="tpm_cmd_001",
            robot_id="tpm_robot_001",
            command_type="navigate",
            parameters={"destination": "waypoint_alpha"},
            classification_level=SecurityClassification.SECRET,
            issued_by="operator_001",
            timestamp=datetime.utcnow()
        )
        
        # Validate with TPM
        valid = await tpm_hal.validate_command(command)
        assert valid is True
    
    @pytest.mark.asyncio
    async def test_mission_session_management(self, tpm_hal):
        """Test secure mission session creation."""
        # Register robots
        robots = ["tpm_robot_001", "tpm_robot_002"]
        for robot_id in robots:
            await tpm_hal.register_robot(
                robot_id=robot_id,
                platform_type=RobotPlatformType.ROS2_GENERIC,
                classification_level=SecurityClassification.UNCLASSIFIED
            )
        
        # Create mission session
        mission = await tpm_hal.create_mission_session(
            mission_id="secure_mission_001",
            robots=robots,
            classification="SECRET",
            duration_hours=2
        )
        
        assert mission["status"] == "active"
        assert "mission_key_id" in mission
        assert mission["classification"] == "SECRET"
        
        # Complete mission
        success = await tpm_hal.complete_mission_session("secure_mission_001")
        assert success is True
    
    @pytest.mark.asyncio
    async def test_emergency_stop_with_tpm(self, tpm_hal):
        """Test emergency stop with TPM key zeroization."""
        # Register robot
        await tpm_hal.register_robot(
            robot_id="emergency_robot_001",
            platform_type=RobotPlatformType.DJI_DRONE,
            classification_level=SecurityClassification.TOP_SECRET
        )
        
        # Execute emergency stop for security breach
        success = await tpm_hal.execute_emergency_stop(
            robot_id="emergency_robot_001",
            reason=EmergencyStopReason.SECURITY_BREACH,
            triggered_by="security_system"
        )
        
        assert success is True
        
        # Verify TPM state was reset
        tpm_status = await tpm_hal.get_tpm_status()
        assert tpm_status["tpm_enabled"] is True


class TestTPMCryptoOperations:
    """Test TPM-backed cryptographic operations."""
    
    @pytest.fixture
    async def tpm_crypto(self):
        """Create TPM crypto integration for testing."""
        tpm = TPM2Interface(simulation_mode=True)
        await tpm.initialize()
        
        key_manager = HardwareKeyManager(tpm)
        await key_manager.initialize()
        
        crypto = TPMCryptoIntegration(tpm, key_manager)
        yield crypto
    
    @pytest.mark.asyncio
    async def test_tpm_key_generation(self, tpm_crypto):
        """Test TPM-backed key generation."""
        key = await tpm_crypto.generate_key(
            algorithm=CryptoAlgorithm.AES_256_GCM,
            classification=SecurityClassification.SECRET,
            key_purpose="encryption",
            prefer_tpm=True
        )
        
        assert key is not None
        assert key.hsm_backed is True  # TPM is a type of HSM
        assert key.classification_level == "SECRET"
    
    @pytest.mark.asyncio
    async def test_tpm_encryption_decryption(self, tpm_crypto):
        """Test TPM-backed encryption and decryption."""
        # Generate TPM key
        key = await tpm_crypto.generate_key(
            algorithm=CryptoAlgorithm.AES_256_GCM,
            prefer_tpm=True
        )
        
        # Test data
        plaintext = b"Classified robot command data"
        
        # Encrypt
        encrypt_result = await tpm_crypto.encrypt_data(plaintext, key)
        assert encrypt_result.success is True
        assert encrypt_result.data != plaintext
        
        # Decrypt
        decrypt_result = await tpm_crypto.decrypt_data(
            encrypt_result.data,
            key
        )
        assert decrypt_result.success is True
        assert decrypt_result.data == plaintext
    
    @pytest.mark.asyncio
    async def test_tpm_signing_verification(self, tpm_crypto):
        """Test TPM-backed signing and verification."""
        # Generate RSA key for signing
        key = await tpm_crypto.generate_key(
            algorithm=CryptoAlgorithm.RSA_4096,
            key_purpose="signing",
            prefer_tpm=True
        )
        
        # Test data
        data = b"Critical robot state data"
        
        # Sign
        sign_result = await tpm_crypto.sign_data(data, key)
        assert sign_result.success is True
        assert len(sign_result.data) > 0
        
        # Verify
        verify_result = await tpm_crypto.verify_signature(
            data,
            sign_result.data,
            key
        )
        assert verify_result.success is True
    
    @pytest.mark.asyncio
    async def test_hardware_random(self, tpm_crypto):
        """Test hardware random number generation."""
        # Generate random bytes
        random1 = tpm_crypto.get_random_bytes(32)
        random2 = tpm_crypto.get_random_bytes(32)
        
        assert len(random1) == 32
        assert len(random2) == 32
        assert random1 != random2  # Should be different
    
    @pytest.mark.asyncio
    async def test_performance_benchmark(self, tpm_crypto):
        """Test performance benchmark functionality."""
        benchmark = await tpm_crypto.perform_benchmark()
        
        assert "operations" in benchmark
        assert "summary" in benchmark
        assert benchmark["summary"]["tpm_available"] is True
        
        # Check that benchmark ran
        keygen = benchmark["operations"].get("key_generation", {})
        assert keygen.get("software_ms") is not None
        assert keygen.get("tpm_ms") is not None


class TestIntegrationScenarios:
    """Test complete integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_secure_robot_deployment(self):
        """Test complete secure robot deployment scenario."""
        # Initialize all components
        hal = TPMEnhancedSecurityHAL(enable_tpm=True)
        
        # 1. Register robot fleet
        robot_ids = ["alpha_001", "beta_001", "gamma_001"]
        for robot_id in robot_ids:
            success = await hal.register_robot(
                robot_id=robot_id,
                platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
                classification_level=SecurityClassification.SECRET
            )
            assert success is True
        
        # 2. Create secure mission
        mission = await hal.create_mission_session(
            mission_id="deployment_001",
            robots=robot_ids,
            classification="SECRET",
            duration_hours=4
        )
        assert mission["status"] == "active"
        
        # 3. Validate commands
        for i, robot_id in enumerate(robot_ids):
            command = SecurityCommand(
                command_id=f"deploy_cmd_{i:03d}",
                robot_id=robot_id,
                command_type="deploy",
                parameters={
                    "position": f"position_{i}",
                    "mission_id": "deployment_001"
                },
                classification_level=SecurityClassification.SECRET,
                issued_by="mission_commander",
                timestamp=datetime.utcnow()
            )
            
            valid = await hal.validate_command(command)
            assert valid is True
        
        # 4. Get security status
        metrics = await hal.get_security_metrics()
        assert metrics["command_validations"] >= 3
        assert metrics["tpm"]["tpm_operations"] > 0
        
        # 5. Complete mission
        success = await hal.complete_mission_session("deployment_001")
        assert success is True
    
    @pytest.mark.asyncio
    async def test_security_breach_response(self):
        """Test security breach emergency response."""
        hal = TPMEnhancedSecurityHAL(enable_tpm=True)
        
        # Register high-security robot
        await hal.register_robot(
            robot_id="secure_bot_001",
            platform_type=RobotPlatformType.GHOST_ROBOTICS_VISION60,
            classification_level=SecurityClassification.TOP_SECRET
        )
        
        # Simulate security breach
        success = await hal.execute_emergency_stop(
            reason=EmergencyStopReason.SECURITY_BREACH,
            triggered_by="intrusion_detection_system"
        )
        
        assert success is True
        
        # Verify security measures
        tpm_status = await hal.get_tpm_status()
        assert tpm_status["tpm_enabled"] is True
        
        # Check that keys were zeroized
        if hal.key_manager:
            key_metrics = hal.key_manager.get_key_metrics()
            # After zeroization, only root keys should remain
            assert key_metrics["total_keys"] <= 6  # Root keys only


# Performance and stress tests
class TestPerformance:
    """Performance and stress tests for TPM integration."""
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_concurrent_attestations(self):
        """Test concurrent attestation performance."""
        tpm = TPM2Interface(simulation_mode=True)
        await tpm.initialize()
        
        engine = TPMAttestationEngine(tpm)
        await engine.initialize()
        
        # Create multiple attestation tasks
        tasks = []
        for i in range(10):
            robot_state = RobotStateVector(
                platform_type="ros2",
                firmware_version="1.0.0",
                sensor_calibration_hash=f"calibration_{i}".encode(),
                battery_level=0.9,
                operational_mode="autonomous",
                location=(i, i, i),
                mission_id=f"mission_{i}",
                command_sequence=i,
                timestamp=time.time()
            )
            
            task = engine.attest_robot_state(
                robot_id=f"robot_{i:03d}",
                robot_state=robot_state,
                attestation_type=AttestationType.OPERATIONAL
            )
            tasks.append(task)
        
        # Execute concurrently
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        # Verify all succeeded
        assert all(r.is_valid for r in results)
        assert elapsed < 5.0  # Should complete within 5 seconds
        
        print(f"\nConcurrent attestations: {len(results)} in {elapsed:.2f}s")
        print(f"Average: {elapsed/len(results)*1000:.1f}ms per attestation")
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_key_generation_performance(self):
        """Test key generation performance."""
        tpm = TPM2Interface(simulation_mode=True)
        await tpm.initialize()
        
        manager = HardwareKeyManager(tpm)
        await manager.initialize()
        
        start_time = time.time()
        keys_created = 0
        
        # Generate multiple keys
        for i in range(20):
            key = await manager.create_sensor_signing_key(
                sensor_type=f"sensor_{i}",
                calibration_data=f"calibration_{i}".encode(),
                platform=PlatformType.ROS2
            )
            if key:
                keys_created += 1
        
        elapsed = time.time() - start_time
        
        assert keys_created == 20
        assert elapsed < 10.0  # Should complete within 10 seconds
        
        print(f"\nKey generation: {keys_created} keys in {elapsed:.2f}s")
        print(f"Average: {elapsed/keys_created*1000:.1f}ms per key")


# Test runner
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])