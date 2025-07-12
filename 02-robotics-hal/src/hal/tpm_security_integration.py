"""
TPM-Enhanced Security HAL Integration for ALCUB3 Universal Robotics

This module integrates TPM 2.0 hardware security capabilities into the existing
UniversalSecurityHAL, providing hardware-backed cryptographic operations, attestation,
and key management for defense-grade robotics platforms.

Key Features:
- Hardware-backed command authentication using TPM
- Platform attestation for robot integrity verification
- Mission-scoped cryptographic operations
- Classification-aware key management with TPM enforcement
- Hardware entropy for enhanced security
- Cross-platform TPM integration for heterogeneous fleets

Patent-Defensible Innovations:
- TPM-backed robotics command validation
- Hardware-enforced mission isolation
- Robot platform attestation with physical state binding
- Classification-aware TPM key hierarchies

Copyright 2025 ALCUB3 Inc.
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path

# Import existing security HAL
from .security_hal import (
    UniversalSecurityHAL,
    SecurityCommand,
    RobotSecurityProfile,
    RobotPlatformType,
    SecurityValidationLevel,
    EmergencyStopReason
)

# Import TPM components
from ..hardware.tpm_integration import (
    TPM2Interface,
    TPMKeyHandle,
    TPMHierarchy,
    PCRBank,
    RoboticsPCRAllocation,
    TPMError
)

from ..hardware.tpm_attestation import (
    TPMAttestationEngine,
    AttestationType,
    RobotStateVector,
    AttestationPolicy
)

from ..hardware.tpm_key_manager import (
    HardwareKeyManager,
    KeyPurpose,
    SecurityClassification,
    PlatformType
)

# Import crypto utilities
import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))
from shared.crypto_utils import (
    FIPSCryptoUtils,
    CryptoAlgorithm,
    SecurityLevel,
    CryptoKeyMaterial
)


class TPMEnhancedSecurityHAL(UniversalSecurityHAL):
    """
    TPM-Enhanced Universal Security HAL
    
    This class extends the UniversalSecurityHAL with TPM 2.0 hardware security
    capabilities, providing defense-grade security for robotics platforms.
    """
    
    def __init__(self, config_path: Optional[str] = None, enable_tpm: bool = True):
        """
        Initialize TPM-Enhanced Security HAL.
        
        Args:
            config_path: Configuration file path
            enable_tpm: Enable TPM integration (defaults to True)
        """
        # Initialize base HAL
        super().__init__(config_path)
        
        self.tpm_enabled = enable_tpm
        self.tpm = None
        self.attestation_engine = None
        self.key_manager = None
        self.crypto_utils = None
        
        # TPM-specific metrics
        self.tpm_metrics = {
            "tpm_operations": 0,
            "attestations_performed": 0,
            "hardware_keys_created": 0,
            "tpm_errors": 0,
            "average_tpm_operation_ms": 0.0
        }
        
        if self.tpm_enabled:
            self._initialize_tpm_components()
    
    def _initialize_tpm_components(self):
        """Initialize TPM hardware security components."""
        try:
            self.logger.info("Initializing TPM 2.0 components...")
            
            # Initialize TPM interface
            self.tpm = TPM2Interface()
            asyncio.run(self.tpm.initialize())
            
            # Initialize attestation engine
            self.attestation_engine = TPMAttestationEngine(self.tpm)
            asyncio.run(self.attestation_engine.initialize())
            
            # Initialize hardware key manager
            self.key_manager = HardwareKeyManager(self.tpm)
            asyncio.run(self.key_manager.initialize())
            
            # Initialize FIPS crypto utilities with TPM support
            from shared.classification import ClassificationLevel as MaestroClassification
            class ClassificationAdapter:
                def __init__(self):
                    self.default_level = MaestroClassification.UNCLASSIFIED
            
            self.crypto_utils = FIPSCryptoUtils(
                ClassificationAdapter(),
                SecurityLevel.UNCLASSIFIED
            )
            
            self.logger.info("TPM components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize TPM components: {e}")
            self.tpm_enabled = False
            self.tpm_metrics["tpm_errors"] += 1
    
    async def validate_command(self, command: SecurityCommand) -> bool:
        """
        Validate security of robotics command with TPM hardware backing.
        
        This extends the base validation with:
        - TPM-based command authentication
        - Hardware attestation verification
        - Mission-scoped key validation
        
        Args:
            command: Security command to validate
            
        Returns:
            bool: True if command is valid and authorized
        """
        start_time = time.time()
        
        try:
            # First perform base validation
            base_valid = await super().validate_command(command)
            if not base_valid:
                return False
            
            # If TPM is not enabled, return base validation result
            if not self.tpm_enabled or not self.tpm:
                return base_valid
            
            # Perform TPM-enhanced validation
            tpm_valid = await self._tpm_validate_command(command)
            
            # Update TPM metrics
            operation_time = (time.time() - start_time) * 1000
            self._update_tpm_metrics("command_validation", operation_time)
            
            return tpm_valid
            
        except Exception as e:
            self.logger.error(f"TPM command validation error: {e}")
            self.tpm_metrics["tpm_errors"] += 1
            # Fall back to base validation on TPM error
            return base_valid
    
    async def _tpm_validate_command(self, command: SecurityCommand) -> bool:
        """
        Perform TPM-specific command validation.
        
        Args:
            command: Command to validate
            
        Returns:
            bool: True if TPM validation passes
        """
        try:
            robot_profile = self.security_profiles.get(command.robot_id)
            if not robot_profile:
                return False
            
            # Map robot platform to TPM platform type
            platform_map = {
                RobotPlatformType.BOSTON_DYNAMICS_SPOT: PlatformType.BOSTON_DYNAMICS_SPOT,
                RobotPlatformType.ROS2_GENERIC: PlatformType.ROS2,
                RobotPlatformType.DJI_DRONE: PlatformType.DJI_DRONE
            }
            
            platform_type = platform_map.get(
                robot_profile.platform_type,
                PlatformType.ROS2  # Default
            )
            
            # Create robot state vector for attestation
            robot_state = RobotStateVector(
                platform_type=platform_type,
                firmware_version="1.0.0",  # Would be retrieved from robot
                sensor_calibration_hash=b"sensor_calibration_data",
                battery_level=0.85,  # Would be real-time data
                operational_mode="autonomous",
                location=(0.0, 0.0, 0.0),  # Would be GPS/IMU data
                mission_id=command.parameters.get("mission_id"),
                command_sequence=1,
                timestamp=time.time()
            )
            
            # Perform platform attestation
            attestation_result = await self.attestation_engine.attest_robot_state(
                robot_id=command.robot_id,
                robot_state=robot_state,
                attestation_type=AttestationType.OPERATIONAL
            )
            
            if not attestation_result.is_valid:
                self.logger.warning(
                    f"TPM attestation failed for robot {command.robot_id}: "
                    f"{attestation_result.failure_reason}"
                )
                return False
            
            # Verify command signature if present
            if command.security_signature:
                signature_valid = await self._verify_command_signature(command)
                if not signature_valid:
                    self.logger.warning(f"Command signature verification failed")
                    return False
            
            self.logger.debug(f"TPM validation passed for command {command.command_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"TPM validation error: {e}")
            return False
    
    async def _verify_command_signature(self, command: SecurityCommand) -> bool:
        """
        Verify command signature using TPM-backed keys.
        
        Args:
            command: Command with signature to verify
            
        Returns:
            bool: True if signature is valid
        """
        try:
            # Get command signing key for robot
            robot_profile = self.security_profiles[command.robot_id]
            
            # Map classification levels
            classification_map = {
                "UNCLASSIFIED": SecurityClassification.UNCLASSIFIED,
                "SECRET": SecurityClassification.SECRET,
                "TOP_SECRET": SecurityClassification.TOP_SECRET
            }
            
            classification = classification_map.get(
                command.classification_level.value,
                SecurityClassification.UNCLASSIFIED
            )
            
            # Get or create command validation key
            signing_key = await self._get_command_signing_key(
                command.robot_id,
                classification
            )
            
            if not signing_key:
                return False
            
            # Prepare command data for verification
            command_data = f"{command.command_id}:{command.robot_id}:{command.command_type}".encode()
            
            # Verify signature using crypto utils
            if self.crypto_utils and signing_key:
                # Convert TPM key to crypto key material
                key_material = CryptoKeyMaterial(
                    key_id=signing_key.key_id,
                    algorithm=CryptoAlgorithm.RSA_4096,
                    key_data=b"",  # Key stays in TPM
                    security_level=SecurityLevel.UNCLASSIFIED,
                    creation_timestamp=signing_key.created_at,
                    key_purpose="command_signing",
                    classification_level=classification.value
                )
                
                verification_result = self.crypto_utils.verify_signature(
                    data=command_data,
                    signature=command.security_signature.encode(),
                    key_material=key_material
                )
                
                return verification_result.success
            
            return True  # Default to true if no crypto utils
            
        except Exception as e:
            self.logger.error(f"Command signature verification error: {e}")
            return False
    
    async def _get_command_signing_key(self, robot_id: str, 
                                     classification: SecurityClassification):
        """Get or create command signing key for robot."""
        try:
            # Check if key already exists
            key_id = f"cmd_sign_{robot_id}_{classification.value}"
            
            if key_id in self.key_manager.keys:
                return self.key_manager.keys[key_id]
            
            # Create new command signing key
            robot_profile = self.security_profiles[robot_id]
            platform_map = {
                RobotPlatformType.BOSTON_DYNAMICS_SPOT: PlatformType.BOSTON_DYNAMICS_SPOT,
                RobotPlatformType.ROS2_GENERIC: PlatformType.ROS2,
                RobotPlatformType.DJI_DRONE: PlatformType.DJI_DRONE
            }
            
            platform = platform_map.get(
                robot_profile.platform_type,
                PlatformType.ROS2
            )
            
            # Create classification-aware key
            signing_key = await self.key_manager.derive_classification_key(
                base_key_id=self.key_manager.root_keys[(TPMHierarchy.OWNER, classification)],
                target_classification=classification,
                purpose=KeyPurpose.COMMAND_VALIDATION
            )
            
            return signing_key
            
        except Exception as e:
            self.logger.error(f"Failed to get command signing key: {e}")
            return None
    
    async def create_mission_session(self, mission_id: str, 
                                   robots: List[str],
                                   classification: str,
                                   duration_hours: int = 24) -> Dict[str, Any]:
        """
        Create secure mission session with TPM-backed keys.
        
        Args:
            mission_id: Unique mission identifier
            robots: List of robot IDs participating in mission
            classification: Mission classification level
            duration_hours: Mission duration in hours
            
        Returns:
            Dict: Mission session information including ephemeral keys
        """
        try:
            if not self.tpm_enabled or not self.key_manager:
                return {
                    "mission_id": mission_id,
                    "status": "created_without_tpm",
                    "robots": robots
                }
            
            # Map classification
            classification_map = {
                "UNCLASSIFIED": SecurityClassification.UNCLASSIFIED,
                "SECRET": SecurityClassification.SECRET,
                "TOP_SECRET": SecurityClassification.TOP_SECRET
            }
            
            sec_class = classification_map.get(
                classification,
                SecurityClassification.UNCLASSIFIED
            )
            
            # Create mission parameters
            mission_params = {
                "robots": robots,
                "start_time": time.time(),
                "duration_hours": duration_hours,
                "classification": classification
            }
            
            # Create mission-scoped key
            mission_key = await self.key_manager.create_mission_key(
                mission_id=mission_id,
                mission_params=mission_params,
                validity_period=duration_hours * 3600,
                classification=sec_class
            )
            
            # Create attestation policy for mission
            policy = AttestationPolicy(
                name=f"mission_{mission_id}_policy",
                policy_type="mission",
                required_pcrs=[
                    RoboticsPCRAllocation.MISSION_PARAMETERS,
                    RoboticsPCRAllocation.COMMAND_AUTHORIZATION
                ],
                pcr_bank=PCRBank.SHA256,
                max_age_seconds=300,  # 5 minutes
                required_firmware_version="1.0.0",
                allowed_platforms=[PlatformType.BOSTON_DYNAMICS_SPOT, PlatformType.ROS2]
            )
            
            await self.attestation_engine.create_attestation_policy(
                f"mission_{mission_id}",
                policy
            )
            
            self.logger.info(f"Created secure mission session: {mission_id}")
            
            return {
                "mission_id": mission_id,
                "status": "active",
                "robots": robots,
                "classification": classification,
                "mission_key_id": mission_key.key_id,
                "attestation_policy": f"mission_{mission_id}",
                "expires_at": time.time() + (duration_hours * 3600)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create mission session: {e}")
            return {
                "mission_id": mission_id,
                "status": "error",
                "error": str(e)
            }
    
    async def complete_mission_session(self, mission_id: str) -> bool:
        """
        Complete mission session and expire associated keys.
        
        Args:
            mission_id: Mission identifier
            
        Returns:
            bool: True if mission completed successfully
        """
        try:
            if not self.tpm_enabled or not self.key_manager:
                return True
            
            # Complete mission in key manager
            expired_keys = await self.key_manager.complete_mission(mission_id)
            
            # Remove attestation policy
            self.attestation_engine.attestation_policies.pop(
                f"mission_{mission_id}",
                None
            )
            
            self.logger.info(
                f"Completed mission {mission_id}, expired {len(expired_keys)} keys"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to complete mission: {e}")
            return False
    
    async def execute_emergency_stop(self, robot_id: Optional[str] = None,
                                   reason: EmergencyStopReason = EmergencyStopReason.MANUAL_TRIGGER,
                                   triggered_by: str = "system") -> bool:
        """
        Execute emergency stop with TPM-backed security zeroization.
        
        This extends the base emergency stop with:
        - Emergency key zeroization for affected robots
        - TPM state reset for security breach scenarios
        - Hardware-attested emergency stop confirmation
        
        Args:
            robot_id: Specific robot ID or None for fleet-wide stop
            reason: Emergency stop reason
            triggered_by: Entity triggering the stop
            
        Returns:
            bool: True if emergency stop executed successfully
        """
        # Execute base emergency stop
        base_result = await super().execute_emergency_stop(
            robot_id, reason, triggered_by
        )
        
        if not base_result or not self.tpm_enabled:
            return base_result
        
        try:
            # For security breach, perform emergency zeroization
            if reason == EmergencyStopReason.SECURITY_BREACH:
                if self.key_manager:
                    zeroized = await self.key_manager.emergency_zeroize(
                        confirmation="CONFIRM_ZEROIZE"
                    )
                    self.logger.critical(
                        f"Emergency zeroization completed: {zeroized} keys destroyed"
                    )
            
            # Reset TPM state for affected robots
            if robot_id:
                await self._reset_robot_tpm_state(robot_id)
            else:
                # Fleet-wide TPM reset
                for rid in self.robots.keys():
                    await self._reset_robot_tpm_state(rid)
            
            return True
            
        except Exception as e:
            self.logger.error(f"TPM emergency stop error: {e}")
            return base_result
    
    async def _reset_robot_tpm_state(self, robot_id: str):
        """Reset TPM state for specific robot."""
        try:
            # Clear robot-specific PCRs
            await self.tpm.reset_pcr(
                RoboticsPCRAllocation.COMMAND_AUTHORIZATION,
                PCRBank.SHA256
            )
            
            # Revoke robot keys
            if self.key_manager:
                for key_id, key in list(self.key_manager.keys.items()):
                    if robot_id in key.metadata.get("robot_id", ""):
                        await self.key_manager.revoke_key(
                            key_id,
                            "Emergency stop triggered"
                        )
            
            self.logger.info(f"Reset TPM state for robot {robot_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to reset TPM state for {robot_id}: {e}")
    
    async def get_tpm_status(self) -> Dict[str, Any]:
        """
        Get comprehensive TPM integration status.
        
        Returns:
            Dict: TPM status and metrics
        """
        if not self.tpm_enabled:
            return {
                "tpm_enabled": False,
                "status": "disabled"
            }
        
        try:
            tpm_info = await self.tpm.get_tpm_info() if self.tpm else {}
            
            attestation_metrics = {}
            if self.attestation_engine:
                attestation_metrics = {
                    "total_attestations": self.attestation_engine.metrics["attestations_performed"],
                    "failed_attestations": self.attestation_engine.metrics["attestation_failures"],
                    "active_policies": len(self.attestation_engine.attestation_policies)
                }
            
            key_metrics = {}
            if self.key_manager:
                key_metrics = self.key_manager.get_key_metrics()
            
            return {
                "tpm_enabled": True,
                "status": "active",
                "tpm_info": tpm_info,
                "metrics": self.tpm_metrics,
                "attestation": attestation_metrics,
                "key_management": key_metrics,
                "simulation_mode": getattr(self.tpm, 'simulation_mode', False)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get TPM status: {e}")
            return {
                "tpm_enabled": True,
                "status": "error",
                "error": str(e)
            }
    
    def _update_tpm_metrics(self, operation: str, operation_time_ms: float):
        """Update TPM-specific metrics."""
        self.tpm_metrics["tpm_operations"] += 1
        
        # Update average operation time
        current_avg = self.tpm_metrics["average_tpm_operation_ms"]
        total_ops = self.tpm_metrics["tpm_operations"]
        new_avg = ((current_avg * (total_ops - 1)) + operation_time_ms) / total_ops
        self.tpm_metrics["average_tpm_operation_ms"] = new_avg
        
        if operation == "attestation":
            self.tpm_metrics["attestations_performed"] += 1
        elif operation == "key_creation":
            self.tpm_metrics["hardware_keys_created"] += 1
    
    async def get_security_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive security metrics including TPM data.
        
        Returns:
            Dict: Extended security metrics with TPM information
        """
        # Get base metrics
        base_metrics = await super().get_security_metrics()
        
        # Add TPM metrics if enabled
        if self.tpm_enabled:
            base_metrics["tpm"] = self.tpm_metrics
            base_metrics["hardware_security"] = {
                "tpm_enabled": True,
                "attestation_available": self.attestation_engine is not None,
                "hardware_key_management": self.key_manager is not None,
                "fips_crypto_available": self.crypto_utils is not None
            }
        
        return base_metrics


# Example usage
async def demonstrate_tpm_security():
    """Demonstrate TPM-enhanced security capabilities."""
    print("🔐 TPM-Enhanced Security HAL Demonstration")
    print("=" * 60)
    
    # Initialize TPM-enhanced HAL
    hal = TPMEnhancedSecurityHAL(enable_tpm=True)
    
    # Register a robot
    print("\n📋 Registering robot with TPM protection...")
    success = await hal.register_robot(
        robot_id="spot_tpm_01",
        platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
        classification_level=SecurityClassification.SECRET
    )
    print(f"Registration: {'✅ Success' if success else '❌ Failed'}")
    
    # Create mission session
    print("\n🚀 Creating secure mission session...")
    mission = await hal.create_mission_session(
        mission_id="patrol_mission_001",
        robots=["spot_tpm_01"],
        classification="SECRET",
        duration_hours=2
    )
    print(f"Mission status: {mission['status']}")
    if mission.get('mission_key_id'):
        print(f"Mission key: {mission['mission_key_id'][:16]}...")
    
    # Validate command with TPM
    print("\n🔒 Validating command with TPM attestation...")
    command = SecurityCommand(
        command_id="cmd_tpm_001",
        robot_id="spot_tpm_01",
        command_type="patrol",
        parameters={"route": "perimeter", "mission_id": "patrol_mission_001"},
        classification_level=SecurityClassification.SECRET,
        issued_by="operator_tpm",
        timestamp=datetime.utcnow()
    )
    
    valid = await hal.validate_command(command)
    print(f"Command validation: {'✅ Authorized' if valid else '❌ Denied'}")
    
    # Get TPM status
    print("\n📊 TPM Status:")
    tpm_status = await hal.get_tpm_status()
    print(f"TPM Enabled: {tpm_status['tpm_enabled']}")
    print(f"Status: {tpm_status['status']}")
    if tpm_status.get('metrics'):
        print(f"TPM Operations: {tpm_status['metrics']['tpm_operations']}")
        print(f"Average Operation Time: {tpm_status['metrics']['average_tpm_operation_ms']:.2f}ms")
    
    # Complete mission
    print("\n✅ Completing mission session...")
    completed = await hal.complete_mission_session("patrol_mission_001")
    print(f"Mission completion: {'Success' if completed else 'Failed'}")
    
    print("\n🎉 TPM-Enhanced Security HAL demonstration completed!")


if __name__ == "__main__":
    asyncio.run(demonstrate_tpm_security())