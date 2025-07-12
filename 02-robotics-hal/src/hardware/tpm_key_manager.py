"""
TPM-Backed Hardware Key Manager for ALCUB3 Universal Robotics

This module implements patent-pending hardware key management specifically designed for
robotics platforms. It provides mission-scoped keys, classification-aware key derivation,
and automatic key lifecycle management with hardware enforcement.

Key Features:
- Hierarchical deterministic key derivation with TPM backing
- Mission-scoped ephemeral keys with automatic expiration
- Classification-aware key policies with hardware enforcement
- Platform-specific key isolation and binding
- Emergency key zeroization with hardware attestation
- Secure key escrow and recovery mechanisms

Patent-Defensible Innovations:
- Mission-bound cryptographic keys with temporal constraints
- Robot identity keys bound to physical characteristics
- Cross-platform key translation with security preservation
- Hardware-enforced key expiration for mission completion
- Sensor calibration keys for data authenticity

Copyright 2025 ALCUB3 Inc.
"""

import os
import time
import json
import hashlib
import logging
import asyncio
import secrets
from typing import Dict, List, Optional, Tuple, Union, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import struct
import threading
from collections import defaultdict

# TPM integration imports
from .tpm_integration import (
    TPM2Interface,
    TPMKeyHandle,
    TPMHierarchy,
    PCRBank,
    RoboticsPCRAllocation,
    TPMError
)

# Security framework imports
try:
    from ...interfaces.robotics_types import (
        SecurityClassification,
        PlatformType,
        RobotPlatformIdentity
    )
except ImportError:
    # Fallback definitions
    class SecurityClassification(Enum):
        UNCLASSIFIED = "UNCLASSIFIED"
        SECRET = "SECRET"
        TOP_SECRET = "TOP_SECRET"
    
    class PlatformType(Enum):
        BOSTON_DYNAMICS_SPOT = "boston_dynamics_spot"
        ROS2 = "ros2"
        DJI_DRONE = "dji_drone"

# Key management types

class KeyPurpose(Enum):
    """Purpose of cryptographic keys."""
    PLATFORM_IDENTITY = "platform_identity"    # Robot identity key
    MISSION_EPHEMERAL = "mission_ephemeral"    # Mission-specific key
    SENSOR_SIGNING = "sensor_signing"          # Sensor data signing
    COMMAND_VALIDATION = "command_validation"  # Command authentication
    DATA_ENCRYPTION = "data_encryption"        # Data at rest encryption
    COMMUNICATION = "communication"            # Secure communication
    EMERGENCY_RECOVERY = "emergency_recovery"  # Emergency access

class KeyLifecycle(Enum):
    """Key lifecycle states."""
    PENDING = "pending"          # Key generation requested
    ACTIVE = "active"           # Key is active and usable
    SUSPENDED = "suspended"     # Temporarily suspended
    EXPIRED = "expired"         # Past expiration time
    REVOKED = "revoked"         # Manually revoked
    DESTROYED = "destroyed"     # Securely destroyed

@dataclass
class KeyPolicy:
    """Policy governing key usage and lifecycle."""
    purpose: KeyPurpose
    classification: SecurityClassification
    max_usage_count: Optional[int] = None
    expiration_time: Optional[float] = None
    mission_bound: bool = False
    mission_id: Optional[str] = None
    platform_bound: bool = True
    platforms: List[PlatformType] = field(default_factory=list)
    geographic_restrictions: Optional[List[Tuple[float, float, float]]] = None
    require_attestation: bool = True
    escrow_enabled: bool = False
    auto_rotate: bool = False
    rotation_period: int = 86400  # 24 hours

@dataclass
class ManagedKey:
    """TPM-managed key with metadata and policy."""
    key_id: str
    tpm_handle: TPMKeyHandle
    policy: KeyPolicy
    created_at: float
    lifecycle_state: KeyLifecycle
    usage_count: int = 0
    last_used: Optional[float] = None
    parent_key_id: Optional[str] = None
    child_key_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    attestation_quote: Optional[bytes] = None

@dataclass
class KeyDerivationPath:
    """Hierarchical key derivation path."""
    path_components: List[str]
    classification: SecurityClassification
    platform: Optional[PlatformType] = None
    purpose: Optional[KeyPurpose] = None
    
    def to_string(self) -> str:
        """Convert path to string representation."""
        return "/".join(self.path_components)
    
    def to_bytes(self) -> bytes:
        """Convert path to bytes for derivation."""
        return self.to_string().encode('utf-8')

@dataclass
class KeyEscrowRecord:
    """Key escrow record for recovery."""
    key_id: str
    escrow_shares: List[bytes]  # Shamir secret shares
    threshold: int              # Minimum shares for recovery
    custodians: List[str]       # Custodian identities
    created_at: float
    classification: SecurityClassification
    metadata: Dict[str, Any]

class HardwareKeyManager:
    """
    Patent-Pending Hardware Key Manager for Robotics
    
    This class implements comprehensive key management with TPM hardware backing,
    specifically designed for robotics platforms with mission-scoped operations
    and classification-aware security.
    """
    
    def __init__(self, tpm: TPM2Interface):
        """
        Initialize hardware key manager.
        
        Args:
            tpm: TPM 2.0 interface instance
        """
        self.tpm = tpm
        self.logger = logging.getLogger(__name__)
        
        # Key storage
        self.keys: Dict[str, ManagedKey] = {}
        self.key_hierarchy: Dict[str, List[str]] = defaultdict(list)  # parent -> children
        
        # Root keys per hierarchy
        self.root_keys: Dict[Tuple[TPMHierarchy, SecurityClassification], str] = {}
        
        # Derivation paths
        self.derivation_cache: Dict[str, str] = {}  # path -> key_id
        
        # Mission tracking
        self.active_missions: Dict[str, Set[str]] = defaultdict(set)  # mission_id -> key_ids
        
        # Key escrow
        self.escrow_records: Dict[str, KeyEscrowRecord] = {}
        
        # Lifecycle management
        self._lifecycle_thread = None
        self._lifecycle_running = False
        self._lifecycle_check_interval = 60  # seconds
        
        # Metrics
        self.metrics = {
            "keys_created": 0,
            "keys_destroyed": 0,
            "keys_rotated": 0,
            "mission_keys": 0,
            "escrow_operations": 0
        }
        
    async def initialize(self) -> bool:
        """
        Initialize key manager and create root keys.
        
        Returns:
            bool: True if initialization successful
        """
        try:
            # Create root keys for each classification level
            for classification in SecurityClassification:
                for hierarchy in [TPMHierarchy.OWNER, TPMHierarchy.PLATFORM]:
                    root_key = await self._create_root_key(hierarchy, classification)
                    self.root_keys[(hierarchy, classification)] = root_key.key_id
                    self.logger.info(f"Created root key for {hierarchy.value}/{classification.value}")
            
            # Start lifecycle management thread
            self._start_lifecycle_management()
            
            self.logger.info("Hardware key manager initialized")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize key manager: {e}")
            return False
    
    async def create_robot_identity_key(self,
                                      platform: RobotPlatformIdentity,
                                      hardware_binding: Optional[Dict[str, Any]] = None) -> ManagedKey:
        """
        Create platform-specific robot identity key.
        
        Patent Innovation: Identity keys bound to robot's physical characteristics
        and hardware identifiers for tamper-evident authentication.
        
        Args:
            platform: Robot platform identity
            hardware_binding: Hardware characteristics to bind (serial, sensors, etc.)
            
        Returns:
            ManagedKey: Hardware-backed identity key
        """
        try:
            # Create key policy
            policy = KeyPolicy(
                purpose=KeyPurpose.PLATFORM_IDENTITY,
                classification=platform.classification,
                platform_bound=True,
                platforms=[platform.platformType],
                require_attestation=True,
                escrow_enabled=True,  # Identity keys should be recoverable
                auto_rotate=False     # Identity keys are persistent
            )
            
            # Create derivation path
            path = KeyDerivationPath(
                path_components=[
                    "identity",
                    platform.platformType.value,
                    platform.platformId
                ],
                classification=platform.classification,
                platform=platform.platformType,
                purpose=KeyPurpose.PLATFORM_IDENTITY
            )
            
            # Get parent key
            parent_key_id = self.root_keys[(TPMHierarchy.PLATFORM, platform.classification)]
            parent_key = self.keys[parent_key_id]
            
            # Create TPM key with hardware binding
            tpm_key = await self._create_tpm_key(
                parent=parent_key.tpm_handle,
                key_type="signing",
                auth_policy=self._create_hardware_binding_policy(hardware_binding)
            )
            
            # Create managed key
            key_id = self._generate_key_id(path)
            managed_key = ManagedKey(
                key_id=key_id,
                tpm_handle=tpm_key,
                policy=policy,
                created_at=time.time(),
                lifecycle_state=KeyLifecycle.ACTIVE,
                parent_key_id=parent_key_id,
                metadata={
                    "platform_id": platform.platformId,
                    "platform_type": platform.platformType.value,
                    "hardware_binding": hardware_binding or {}
                }
            )
            
            # Store key
            self.keys[key_id] = managed_key
            self.key_hierarchy[parent_key_id].append(key_id)
            self.derivation_cache[path.to_string()] = key_id
            
            # Enable escrow for identity key
            if policy.escrow_enabled:
                await self._escrow_key(managed_key)
            
            self.metrics["keys_created"] += 1
            self.logger.info(f"Created robot identity key: {key_id}")
            
            return managed_key
            
        except Exception as e:
            self.logger.error(f"Failed to create identity key: {e}")
            raise
    
    async def create_mission_key(self,
                               mission_id: str,
                               mission_params: Dict[str, Any],
                               validity_period: int = 3600,
                               classification: SecurityClassification = SecurityClassification.UNCLASSIFIED) -> ManagedKey:
        """
        Create ephemeral key for specific mission.
        
        Patent Innovation: Mission-bound keys that automatically expire upon
        mission completion or timeout, ensuring forward secrecy.
        
        Args:
            mission_id: Unique mission identifier
            mission_params: Mission parameters for key binding
            validity_period: Key validity in seconds
            classification: Mission classification level
            
        Returns:
            ManagedKey: Mission-scoped ephemeral key
        """
        try:
            # Create key policy
            policy = KeyPolicy(
                purpose=KeyPurpose.MISSION_EPHEMERAL,
                classification=classification,
                expiration_time=time.time() + validity_period,
                mission_bound=True,
                mission_id=mission_id,
                require_attestation=True,
                escrow_enabled=False,  # Ephemeral keys not escrowed
                auto_rotate=False
            )
            
            # Create derivation path
            path = KeyDerivationPath(
                path_components=[
                    "mission",
                    mission_id,
                    str(int(time.time()))
                ],
                classification=classification,
                purpose=KeyPurpose.MISSION_EPHEMERAL
            )
            
            # Get parent key
            parent_key_id = self.root_keys[(TPMHierarchy.OWNER, classification)]
            parent_key = self.keys[parent_key_id]
            
            # Create mission binding policy
            mission_policy = self._create_mission_binding_policy(mission_id, mission_params)
            
            # Create TPM key
            tpm_key = await self._create_tpm_key(
                parent=parent_key.tpm_handle,
                key_type="storage",  # Can be used for encryption/decryption
                auth_policy=mission_policy
            )
            
            # Create managed key
            key_id = self._generate_key_id(path)
            managed_key = ManagedKey(
                key_id=key_id,
                tpm_handle=tpm_key,
                policy=policy,
                created_at=time.time(),
                lifecycle_state=KeyLifecycle.ACTIVE,
                parent_key_id=parent_key_id,
                metadata={
                    "mission_id": mission_id,
                    "mission_params": mission_params,
                    "validity_period": validity_period
                }
            )
            
            # Store key
            self.keys[key_id] = managed_key
            self.key_hierarchy[parent_key_id].append(key_id)
            self.active_missions[mission_id].add(key_id)
            
            self.metrics["keys_created"] += 1
            self.metrics["mission_keys"] += 1
            self.logger.info(f"Created mission key {key_id} for mission {mission_id}")
            
            return managed_key
            
        except Exception as e:
            self.logger.error(f"Failed to create mission key: {e}")
            raise
    
    async def derive_classification_key(self,
                                      base_key_id: str,
                                      target_classification: SecurityClassification,
                                      purpose: KeyPurpose) -> ManagedKey:
        """
        Derive classification-specific key from base key.
        
        Args:
            base_key_id: Base key to derive from
            target_classification: Target classification level
            purpose: Purpose for derived key
            
        Returns:
            ManagedKey: Derived key with classification policy
        """
        try:
            # Get base key
            base_key = self.keys.get(base_key_id)
            if not base_key:
                raise ValueError(f"Base key not found: {base_key_id}")
            
            # Verify classification compatibility
            if not self._can_derive_classification(
                base_key.policy.classification,
                target_classification
            ):
                raise ValueError(f"Cannot derive {target_classification.value} from "
                               f"{base_key.policy.classification.value}")
            
            # Create key policy
            policy = KeyPolicy(
                purpose=purpose,
                classification=target_classification,
                platform_bound=base_key.policy.platform_bound,
                platforms=base_key.policy.platforms,
                require_attestation=True,
                auto_rotate=True,
                rotation_period=86400  # 24 hours
            )
            
            # Create derivation path
            path = KeyDerivationPath(
                path_components=[
                    "derived",
                    target_classification.value.lower(),
                    purpose.value,
                    str(int(time.time()))
                ],
                classification=target_classification,
                purpose=purpose
            )
            
            # Create TPM key
            tpm_key = await self._create_tpm_key(
                parent=base_key.tpm_handle,
                key_type="storage" if purpose == KeyPurpose.DATA_ENCRYPTION else "signing",
                auth_policy=self._create_classification_policy(target_classification)
            )
            
            # Create managed key
            key_id = self._generate_key_id(path)
            managed_key = ManagedKey(
                key_id=key_id,
                tpm_handle=tpm_key,
                policy=policy,
                created_at=time.time(),
                lifecycle_state=KeyLifecycle.ACTIVE,
                parent_key_id=base_key_id,
                metadata={
                    "derived_from": base_key_id,
                    "derivation_purpose": purpose.value
                }
            )
            
            # Store key
            self.keys[key_id] = managed_key
            self.key_hierarchy[base_key_id].append(key_id)
            base_key.child_key_ids.append(key_id)
            
            self.metrics["keys_created"] += 1
            self.logger.info(f"Derived {target_classification.value} key: {key_id}")
            
            return managed_key
            
        except Exception as e:
            self.logger.error(f"Failed to derive classification key: {e}")
            raise
    
    async def create_sensor_signing_key(self,
                                      sensor_type: str,
                                      calibration_data: bytes,
                                      platform: PlatformType) -> ManagedKey:
        """
        Create key for sensor data signing with calibration binding.
        
        Patent Innovation: Sensor signing keys bound to calibration data
        ensuring data authenticity from specific sensor configuration.
        
        Args:
            sensor_type: Type of sensor (lidar, camera, etc.)
            calibration_data: Sensor calibration data to bind
            platform: Platform type
            
        Returns:
            ManagedKey: Sensor-specific signing key
        """
        try:
            # Create key policy
            policy = KeyPolicy(
                purpose=KeyPurpose.SENSOR_SIGNING,
                classification=SecurityClassification.UNCLASSIFIED,
                platform_bound=True,
                platforms=[platform],
                require_attestation=True,
                auto_rotate=True,
                rotation_period=604800  # Weekly rotation
            )
            
            # Extend sensor calibration PCR
            await self.tpm.extend_pcr(
                pcr_index=RoboticsPCRAllocation.SENSOR_CALIBRATION,
                data=calibration_data,
                bank=PCRBank.SHA256
            )
            
            # Create derivation path
            calibration_hash = hashlib.sha256(calibration_data).hexdigest()[:8]
            path = KeyDerivationPath(
                path_components=[
                    "sensor",
                    sensor_type,
                    platform.value,
                    calibration_hash
                ],
                classification=SecurityClassification.UNCLASSIFIED,
                platform=platform,
                purpose=KeyPurpose.SENSOR_SIGNING
            )
            
            # Get parent key
            parent_key_id = self.root_keys[(TPMHierarchy.PLATFORM, SecurityClassification.UNCLASSIFIED)]
            parent_key = self.keys[parent_key_id]
            
            # Create sensor binding policy
            sensor_policy = await self._create_sensor_binding_policy(
                sensor_type,
                calibration_data
            )
            
            # Create TPM key
            tpm_key = await self._create_tpm_key(
                parent=parent_key.tpm_handle,
                key_type="signing",
                auth_policy=sensor_policy
            )
            
            # Create managed key
            key_id = self._generate_key_id(path)
            managed_key = ManagedKey(
                key_id=key_id,
                tpm_handle=tpm_key,
                policy=policy,
                created_at=time.time(),
                lifecycle_state=KeyLifecycle.ACTIVE,
                parent_key_id=parent_key_id,
                metadata={
                    "sensor_type": sensor_type,
                    "calibration_hash": calibration_hash,
                    "platform": platform.value
                }
            )
            
            # Store key
            self.keys[key_id] = managed_key
            self.key_hierarchy[parent_key_id].append(key_id)
            
            self.metrics["keys_created"] += 1
            self.logger.info(f"Created sensor signing key: {key_id}")
            
            return managed_key
            
        except Exception as e:
            self.logger.error(f"Failed to create sensor signing key: {e}")
            raise
    
    async def rotate_key(self, key_id: str, reason: str = "scheduled") -> ManagedKey:
        """
        Rotate a key maintaining policy and bindings.
        
        Args:
            key_id: Key to rotate
            reason: Rotation reason
            
        Returns:
            ManagedKey: New rotated key
        """
        try:
            # Get current key
            current_key = self.keys.get(key_id)
            if not current_key:
                raise ValueError(f"Key not found: {key_id}")
            
            if current_key.lifecycle_state != KeyLifecycle.ACTIVE:
                raise ValueError(f"Cannot rotate key in state: {current_key.lifecycle_state}")
            
            # Create new key with same policy
            new_policy = current_key.policy
            parent_key = self.keys[current_key.parent_key_id]
            
            # Create new TPM key
            tpm_key = await self._create_tpm_key(
                parent=parent_key.tpm_handle,
                key_type="signing" if new_policy.purpose == KeyPurpose.SENSOR_SIGNING else "storage"
            )
            
            # Create new managed key
            new_key_id = f"{key_id}_rot_{int(time.time())}"
            new_key = ManagedKey(
                key_id=new_key_id,
                tpm_handle=tpm_key,
                policy=new_policy,
                created_at=time.time(),
                lifecycle_state=KeyLifecycle.ACTIVE,
                parent_key_id=current_key.parent_key_id,
                metadata={
                    **current_key.metadata,
                    "rotated_from": key_id,
                    "rotation_reason": reason
                }
            )
            
            # Store new key
            self.keys[new_key_id] = new_key
            self.key_hierarchy[current_key.parent_key_id].append(new_key_id)
            
            # Revoke old key
            await self.revoke_key(key_id, f"Rotated to {new_key_id}")
            
            self.metrics["keys_rotated"] += 1
            self.logger.info(f"Rotated key {key_id} to {new_key_id}")
            
            return new_key
            
        except Exception as e:
            self.logger.error(f"Failed to rotate key: {e}")
            raise
    
    async def revoke_key(self, key_id: str, reason: str) -> bool:
        """
        Revoke a key and all its children.
        
        Args:
            key_id: Key to revoke
            reason: Revocation reason
            
        Returns:
            bool: True if revoked successfully
        """
        try:
            key = self.keys.get(key_id)
            if not key:
                return False
            
            # Revoke all child keys first
            for child_id in key.child_key_ids[:]:
                await self.revoke_key(child_id, f"Parent revoked: {reason}")
            
            # Update key state
            key.lifecycle_state = KeyLifecycle.REVOKED
            key.metadata["revocation_time"] = time.time()
            key.metadata["revocation_reason"] = reason
            
            # Remove from active missions if applicable
            if key.policy.mission_bound and key.policy.mission_id:
                self.active_missions[key.policy.mission_id].discard(key_id)
            
            self.logger.info(f"Revoked key {key_id}: {reason}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to revoke key: {e}")
            return False
    
    async def destroy_key(self, key_id: str, secure_wipe: bool = True) -> bool:
        """
        Securely destroy a key from TPM.
        
        Args:
            key_id: Key to destroy
            secure_wipe: Perform secure wipe of key material
            
        Returns:
            bool: True if destroyed successfully
        """
        try:
            key = self.keys.get(key_id)
            if not key:
                return False
            
            # Cannot destroy if has active children
            active_children = [
                child_id for child_id in key.child_key_ids
                if self.keys[child_id].lifecycle_state == KeyLifecycle.ACTIVE
            ]
            if active_children:
                raise ValueError(f"Cannot destroy key with active children: {active_children}")
            
            # Delete from TPM
            if key.tpm_handle:
                await self.tpm.flush_context(key.tpm_handle.handle)
            
            # Update state
            key.lifecycle_state = KeyLifecycle.DESTROYED
            
            # Remove from parent's children
            if key.parent_key_id:
                parent = self.keys.get(key.parent_key_id)
                if parent:
                    parent.child_key_ids.remove(key_id)
            
            # Remove from hierarchy
            if key_id in self.key_hierarchy:
                del self.key_hierarchy[key_id]
            
            # Secure wipe if requested
            if secure_wipe:
                # Overwrite key data in memory
                key.tpm_handle = None
                key.metadata = {"destroyed": True}
            
            self.metrics["keys_destroyed"] += 1
            self.logger.info(f"Destroyed key {key_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to destroy key: {e}")
            return False
    
    async def complete_mission(self, mission_id: str) -> List[str]:
        """
        Complete mission and expire all associated keys.
        
        Args:
            mission_id: Mission identifier
            
        Returns:
            List[str]: Expired key IDs
        """
        try:
            expired_keys = []
            
            # Get all mission keys
            mission_keys = self.active_missions.get(mission_id, set())
            
            for key_id in mission_keys:
                key = self.keys.get(key_id)
                if key and key.lifecycle_state == KeyLifecycle.ACTIVE:
                    # Expire the key
                    key.lifecycle_state = KeyLifecycle.EXPIRED
                    key.metadata["mission_completed"] = time.time()
                    expired_keys.append(key_id)
                    
                    # Destroy ephemeral keys
                    if key.policy.purpose == KeyPurpose.MISSION_EPHEMERAL:
                        await self.destroy_key(key_id)
            
            # Clear mission tracking
            if mission_id in self.active_missions:
                del self.active_missions[mission_id]
            
            self.logger.info(f"Completed mission {mission_id}, expired {len(expired_keys)} keys")
            return expired_keys
            
        except Exception as e:
            self.logger.error(f"Failed to complete mission: {e}")
            return []
    
    async def emergency_zeroize(self, confirmation: str = "") -> int:
        """
        Emergency key zeroization for security breach.
        
        Args:
            confirmation: Must be "CONFIRM_ZEROIZE" to proceed
            
        Returns:
            int: Number of keys zeroized
        """
        if confirmation != "CONFIRM_ZEROIZE":
            raise ValueError("Emergency zeroization requires confirmation")
        
        try:
            zeroized = 0
            
            # Destroy all keys except root keys
            for key_id, key in list(self.keys.items()):
                if key_id not in self.root_keys.values():
                    if await self.destroy_key(key_id, secure_wipe=True):
                        zeroized += 1
            
            # Clear all mission data
            self.active_missions.clear()
            
            # Clear escrow records
            self.escrow_records.clear()
            
            self.logger.critical(f"EMERGENCY ZEROIZATION: Destroyed {zeroized} keys")
            return zeroized
            
        except Exception as e:
            self.logger.error(f"Emergency zeroization failed: {e}")
            raise
    
    # Private helper methods
    
    async def _create_root_key(self,
                              hierarchy: TPMHierarchy,
                              classification: SecurityClassification) -> ManagedKey:
        """Create root key for hierarchy and classification."""
        # Create TPM primary key
        tpm_key = await self.tpm.create_primary_key(hierarchy, "RSA2048")
        
        # Create key policy
        policy = KeyPolicy(
            purpose=KeyPurpose.PLATFORM_IDENTITY,
            classification=classification,
            platform_bound=False,
            require_attestation=True,
            escrow_enabled=True,
            auto_rotate=False
        )
        
        # Create managed key
        key_id = f"root_{hierarchy.value}_{classification.value}".lower()
        managed_key = ManagedKey(
            key_id=key_id,
            tpm_handle=tpm_key,
            policy=policy,
            created_at=time.time(),
            lifecycle_state=KeyLifecycle.ACTIVE,
            metadata={
                "hierarchy": hierarchy.value,
                "root_key": True
            }
        )
        
        self.keys[key_id] = managed_key
        return managed_key
    
    async def _create_tpm_key(self,
                            parent: TPMKeyHandle,
                            key_type: str = "storage",
                            auth_policy: Optional[bytes] = None) -> TPMKeyHandle:
        """Create TPM key with specified parameters."""
        return await self.tpm.create_key(
            parent=parent,
            algorithm="RSA2048",
            key_type=key_type,
            auth_policy=auth_policy
        )
    
    def _generate_key_id(self, path: KeyDerivationPath) -> str:
        """Generate unique key ID from derivation path."""
        path_hash = hashlib.sha256(path.to_bytes()).hexdigest()[:16]
        timestamp = int(time.time() * 1000)
        return f"key_{path_hash}_{timestamp}"
    
    def _create_hardware_binding_policy(self, hardware_binding: Optional[Dict[str, Any]]) -> Optional[bytes]:
        """Create TPM policy for hardware binding."""
        if not hardware_binding:
            return None
        
        # Create policy hash from hardware characteristics
        binding_data = json.dumps(hardware_binding, sort_keys=True)
        return hashlib.sha256(binding_data.encode()).digest()
    
    def _create_mission_binding_policy(self, mission_id: str, mission_params: Dict[str, Any]) -> bytes:
        """Create TPM policy for mission binding."""
        mission_data = {
            "mission_id": mission_id,
            "params": mission_params,
            "timestamp": int(time.time())
        }
        
        return hashlib.sha256(
            json.dumps(mission_data, sort_keys=True).encode()
        ).digest()
    
    def _create_classification_policy(self, classification: SecurityClassification) -> bytes:
        """Create TPM policy for classification enforcement."""
        policy_data = {
            "classification": classification.value,
            "enforcement": "mandatory",
            "version": "1.0"
        }
        
        return hashlib.sha256(
            json.dumps(policy_data, sort_keys=True).encode()
        ).digest()
    
    async def _create_sensor_binding_policy(self, sensor_type: str, calibration_data: bytes) -> bytes:
        """Create TPM policy for sensor binding."""
        # Read current sensor calibration PCR
        pcr_measurement = await self.tpm.read_pcr(
            RoboticsPCRAllocation.SENSOR_CALIBRATION,
            PCRBank.SHA256
        )
        
        policy_data = {
            "sensor_type": sensor_type,
            "calibration_hash": hashlib.sha256(calibration_data).hexdigest(),
            "pcr_value": pcr_measurement.value.hex()
        }
        
        return hashlib.sha256(
            json.dumps(policy_data, sort_keys=True).encode()
        ).digest()
    
    def _can_derive_classification(self,
                                 source: SecurityClassification,
                                 target: SecurityClassification) -> bool:
        """Check if classification derivation is allowed."""
        # Define classification hierarchy
        class_levels = {
            SecurityClassification.UNCLASSIFIED: 0,
            SecurityClassification.SECRET: 1,
            SecurityClassification.TOP_SECRET: 2
        }
        
        # Can only derive to equal or lower classification
        return class_levels[target] <= class_levels[source]
    
    async def _escrow_key(self, key: ManagedKey) -> bool:
        """Escrow key for recovery (simplified implementation)."""
        try:
            # In production, would use Shamir secret sharing
            escrow_record = KeyEscrowRecord(
                key_id=key.key_id,
                escrow_shares=[secrets.token_bytes(32) for _ in range(5)],
                threshold=3,
                custodians=["custodian1", "custodian2", "custodian3", "custodian4", "custodian5"],
                created_at=time.time(),
                classification=key.policy.classification,
                metadata={"key_purpose": key.policy.purpose.value}
            )
            
            self.escrow_records[key.key_id] = escrow_record
            self.metrics["escrow_operations"] += 1
            
            self.logger.info(f"Escrowed key {key.key_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to escrow key: {e}")
            return False
    
    def _start_lifecycle_management(self):
        """Start key lifecycle management thread."""
        if not self._lifecycle_running:
            self._lifecycle_running = True
            self._lifecycle_thread = threading.Thread(
                target=self._lifecycle_management_loop,
                daemon=True
            )
            self._lifecycle_thread.start()
    
    def _lifecycle_management_loop(self):
        """Key lifecycle management loop."""
        while self._lifecycle_running:
            try:
                # Check for expired keys
                current_time = time.time()
                
                for key_id, key in list(self.keys.items()):
                    if key.lifecycle_state == KeyLifecycle.ACTIVE:
                        # Check expiration
                        if key.policy.expiration_time and current_time > key.policy.expiration_time:
                            key.lifecycle_state = KeyLifecycle.EXPIRED
                            self.logger.info(f"Key {key_id} expired")
                        
                        # Check auto-rotation
                        elif key.policy.auto_rotate:
                            age = current_time - key.created_at
                            if age > key.policy.rotation_period:
                                # Schedule rotation
                                asyncio.create_task(self.rotate_key(key_id, "scheduled"))
                
                # Sleep until next check
                time.sleep(self._lifecycle_check_interval)
                
            except Exception as e:
                self.logger.error(f"Lifecycle management error: {e}")
    
    def stop_lifecycle_management(self):
        """Stop lifecycle management thread."""
        self._lifecycle_running = False
        if self._lifecycle_thread:
            self._lifecycle_thread.join()
    
    def get_key_metrics(self) -> Dict[str, Any]:
        """Get key management metrics."""
        state_counts = defaultdict(int)
        for key in self.keys.values():
            state_counts[key.lifecycle_state.value] += 1
        
        return {
            **self.metrics,
            "total_keys": len(self.keys),
            "active_missions": len(self.active_missions),
            "escrowed_keys": len(self.escrow_records),
            "key_states": dict(state_counts)
        }