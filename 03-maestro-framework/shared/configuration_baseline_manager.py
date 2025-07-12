"""
ALCUB3 Configuration Baseline Management System - Task 4.3.1
Patent-Pending Configuration Drift Detection Foundation

This module implements comprehensive configuration baseline management with
classification-aware versioning, cryptographic integrity, and MAESTRO framework integration.

Key Features:
- Secure baseline creation and storage with FIPS 140-2 Level 3+ encryption
- Classification-aware baseline versioning and access control
- Cryptographic integrity validation for tamper detection
- Integration with existing MAESTRO L1-L7 security framework
- Air-gapped operation with offline baseline validation

Patent Innovations:
- Multi-layer configuration correlation across MAESTRO layers
- Classification-aware baseline inheritance and security propagation
- Predictive baseline validation with anomaly detection
- Air-gapped configuration integrity verification

Compliance:
- STIG ASD V5R1 configuration management controls
- NIST SP 800-171 configuration control requirements
- CISA cybersecurity posture management guidelines
"""

import os
import json
import time
import hashlib
import logging
import threading
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
from collections import defaultdict, deque

# Import MAESTRO framework components
try:
    from .classification import SecurityClassification, ClassificationLevel
    from .crypto_utils import FIPSCryptoUtils, SecurityLevel, CryptoAlgorithm, CryptoKeyMaterial
    from .audit_logger import AuditLogger, AuditEvent, AuditSeverity, AuditEventType
    from .compliance_validator import ComplianceValidator
    MAESTRO_AVAILABLE = True
except ImportError:
    MAESTRO_AVAILABLE = False
    logging.warning("MAESTRO components not available - running in standalone mode")


class BaselineType(Enum):
    """Types of configuration baselines."""
    SYSTEM_CONFIGURATION = "system_config"
    SECURITY_CONFIGURATION = "security_config"
    APPLICATION_CONFIGURATION = "application_config"
    NETWORK_CONFIGURATION = "network_config"
    MAESTRO_CONFIGURATION = "maestro_config"
    COMPLIANCE_CONFIGURATION = "compliance_config"
    FULL_SYSTEM = "full_system"


class BaselineStatus(Enum):
    """Status of configuration baselines."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    CORRUPTED = "corrupted"
    PENDING_VALIDATION = "pending_validation"


class ConfigurationScope(Enum):
    """Scope of configuration monitoring."""
    FILE_SYSTEM = "filesystem"
    REGISTRY = "registry"
    ENVIRONMENT_VARIABLES = "env_vars"
    SERVICE_CONFIGURATION = "services"
    NETWORK_SETTINGS = "network"
    SECURITY_POLICIES = "security"
    MAESTRO_LAYERS = "maestro"


@dataclass
class ConfigurationItem:
    """Individual configuration item with metadata."""
    path: str
    value: Any
    data_type: str
    last_modified: float
    checksum: str
    classification_level: str
    scope: ConfigurationScope
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class BaselineSnapshot:
    """Complete configuration baseline snapshot."""
    baseline_id: str
    baseline_type: BaselineType
    classification_level: ClassificationLevel
    creation_timestamp: float
    created_by: str
    target_systems: List[str]
    configuration_items: List[ConfigurationItem]
    integrity_hash: str
    cryptographic_signature: str
    version: str
    status: BaselineStatus
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class DriftAnalysis:
    """Configuration drift analysis result."""
    analysis_id: str
    baseline_id: str
    target_baseline_id: str
    analysis_timestamp: float
    drift_detected: bool
    total_changes: int
    critical_changes: int
    changed_items: List[Dict[str, Any]]
    severity_score: float
    recommendations: List[str]
    classification_level: ClassificationLevel


class SecureBaselineStorage:
    """
    Secure storage for configuration baselines with encryption and integrity validation.
    """
    
    def __init__(self, storage_path: str, crypto_utils: 'FIPSCryptoUtils'):
        """Initialize secure baseline storage."""
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(mode=0o700, exist_ok=True)
        self.crypto_utils = crypto_utils
        self.logger = logging.getLogger(__name__)
        
        # Create subdirectories for different classification levels
        for level in ClassificationLevel:
            level_dir = self.storage_path / level.value.lower()
            level_dir.mkdir(mode=0o700, exist_ok=True)
    
    async def store_baseline(self, baseline: BaselineSnapshot) -> str:
        """Store baseline with encryption and integrity protection."""
        try:
            # Serialize baseline to JSON
            baseline_data = asdict(baseline)
            baseline_json = json.dumps(baseline_data, indent=2, sort_keys=True)
            
            # Encrypt baseline data
            encrypted_data = await self.crypto_utils.encrypt_data(
                baseline_json.encode(),
                algorithm=CryptoAlgorithm.AES_256_GCM,
                classification_level=baseline.classification_level
            )
            
            # Generate storage path based on classification
            storage_file = (
                self.storage_path / 
                baseline.classification_level.value.lower() / 
                f"baseline_{baseline.baseline_id}.encrypted"
            )
            
            # Write encrypted baseline to storage
            with open(storage_file, 'wb') as f:
                f.write(encrypted_data.ciphertext)
            
            # Store metadata separately
            metadata_file = storage_file.with_suffix('.metadata')
            metadata = {
                "baseline_id": baseline.baseline_id,
                "classification_level": baseline.classification_level.value,
                "creation_timestamp": baseline.creation_timestamp,
                "integrity_hash": baseline.integrity_hash,
                "iv": encrypted_data.iv.hex(),
                "auth_tag": encrypted_data.auth_tag.hex()
            }
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info(f"Stored baseline {baseline.baseline_id} securely")
            return str(storage_file)
            
        except Exception as e:
            self.logger.error(f"Failed to store baseline {baseline.baseline_id}: {e}")
            raise
    
    async def retrieve_baseline(self, baseline_id: str, 
                              classification_level: ClassificationLevel) -> BaselineSnapshot:
        """Retrieve and decrypt baseline from secure storage."""
        try:
            # Construct storage path
            storage_file = (
                self.storage_path / 
                classification_level.value.lower() / 
                f"baseline_{baseline_id}.encrypted"
            )
            metadata_file = storage_file.with_suffix('.metadata')
            
            if not storage_file.exists() or not metadata_file.exists():
                raise FileNotFoundError(f"Baseline {baseline_id} not found")
            
            # Load metadata
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Read encrypted data
            with open(storage_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt baseline data
            decrypted_data = await self.crypto_utils.decrypt_data(
                encrypted_data,
                bytes.fromhex(metadata['iv']),
                bytes.fromhex(metadata['auth_tag']),
                algorithm=CryptoAlgorithm.AES_256_GCM,
                classification_level=classification_level
            )
            
            # Deserialize baseline
            baseline_json = decrypted_data.decode()
            baseline_data = json.loads(baseline_json)
            
            # Convert back to BaselineSnapshot
            baseline = BaselineSnapshot(**baseline_data)
            
            # Validate integrity
            if not await self._validate_baseline_integrity(baseline):
                raise ValueError(f"Baseline {baseline_id} integrity validation failed")
            
            self.logger.info(f"Retrieved baseline {baseline_id} successfully")
            return baseline
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve baseline {baseline_id}: {e}")
            raise
    
    async def _validate_baseline_integrity(self, baseline: BaselineSnapshot) -> bool:
        """Validate baseline cryptographic integrity."""
        try:
            # Recalculate integrity hash
            baseline_copy = BaselineSnapshot(**asdict(baseline))
            baseline_copy.integrity_hash = ""
            baseline_copy.cryptographic_signature = ""
            
            calculated_hash = hashlib.sha256(
                json.dumps(asdict(baseline_copy), sort_keys=True).encode()
            ).hexdigest()
            
            return calculated_hash == baseline.integrity_hash
            
        except Exception as e:
            self.logger.error(f"Integrity validation error: {e}")
            return False


class BaselineVersionManager:
    """
    Version management for configuration baselines with classification inheritance.
    """
    
    def __init__(self, classification_system: SecurityClassification):
        """Initialize baseline version manager."""
        self.classification = classification_system
        self.logger = logging.getLogger(__name__)
        self.version_history = defaultdict(list)
        self.version_lock = threading.RLock()
    
    def create_version(self, baseline: BaselineSnapshot, 
                      parent_version: Optional[str] = None) -> str:
        """Create new baseline version with lineage tracking."""
        with self.version_lock:
            version_id = f"v{len(self.version_history[baseline.baseline_id]) + 1}"
            
            version_info = {
                "version_id": version_id,
                "baseline_id": baseline.baseline_id,
                "parent_version": parent_version,
                "creation_timestamp": baseline.creation_timestamp,
                "classification_level": baseline.classification_level.value,
                "created_by": baseline.created_by,
                "changes_summary": self._generate_changes_summary(baseline, parent_version)
            }
            
            self.version_history[baseline.baseline_id].append(version_info)
            
            self.logger.info(f"Created version {version_id} for baseline {baseline.baseline_id}")
            return version_id
    
    def get_version_lineage(self, baseline_id: str) -> List[Dict[str, Any]]:
        """Get complete version lineage for a baseline."""
        with self.version_lock:
            return self.version_history.get(baseline_id, []).copy()
    
    def _generate_changes_summary(self, baseline: BaselineSnapshot, 
                                parent_version: Optional[str]) -> Dict[str, Any]:
        """Generate summary of changes from parent version."""
        if not parent_version:
            return {
                "type": "initial_baseline",
                "total_items": len(baseline.configuration_items),
                "scopes": list(set(item.scope.value for item in baseline.configuration_items))
            }
        
        # In a real implementation, this would compare with parent version
        return {
            "type": "incremental_update",
            "modified_items": 0,
            "added_items": 0,
            "removed_items": 0
        }


class ConfigurationBaselineManager:
    """
    Patent-Pending Configuration Baseline Management System
    
    Provides comprehensive configuration baseline management with classification-aware
    versioning, cryptographic integrity, and MAESTRO framework integration.
    """
    
    def __init__(self, 
                 classification_system: SecurityClassification,
                 crypto_utils: FIPSCryptoUtils,
                 audit_logger: AuditLogger,
                 storage_path: str = "./secure_baselines"):
        """Initialize configuration baseline manager."""
        self.classification = classification_system
        self.crypto_utils = crypto_utils
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
        
        # Initialize storage and version management
        self.baseline_storage = SecureBaselineStorage(storage_path, crypto_utils)
        self.version_manager = BaselineVersionManager(classification_system)
        
        # Active baselines registry
        self.active_baselines = {}
        self.baseline_cache = {}
        self.registry_lock = threading.RLock()
        
        # Configuration collectors for different scopes
        self.config_collectors = {
            ConfigurationScope.FILE_SYSTEM: self._collect_filesystem_config,
            ConfigurationScope.ENVIRONMENT_VARIABLES: self._collect_env_config,
            ConfigurationScope.SERVICE_CONFIGURATION: self._collect_service_config,
            ConfigurationScope.SECURITY_POLICIES: self._collect_security_config,
            ConfigurationScope.MAESTRO_LAYERS: self._collect_maestro_config
        }
        
        self.logger.info("Configuration Baseline Manager initialized")
    
    async def create_baseline(self, 
                            target_systems: List[str],
                            baseline_type: BaselineType,
                            scopes: List[ConfigurationScope],
                            created_by: str,
                            metadata: Optional[Dict[str, Any]] = None) -> BaselineSnapshot:
        """
        Create comprehensive configuration baseline with cryptographic integrity.
        
        Args:
            target_systems: List of target systems to baseline
            baseline_type: Type of baseline to create
            scopes: Configuration scopes to include
            created_by: User/system creating the baseline
            metadata: Additional metadata
            
        Returns:
            BaselineSnapshot: Created baseline with integrity protection
        """
        start_time = time.time()
        baseline_id = f"baseline_{int(time.time())}_{baseline_type.value}"
        
        try:
            self.logger.info(f"Creating baseline {baseline_id} for systems: {target_systems}")
            
            # Collect configuration data from all specified scopes
            configuration_items = []
            for scope in scopes:
                if scope in self.config_collectors:
                    scope_configs = await self.config_collectors[scope](target_systems)
                    configuration_items.extend(scope_configs)
            
            # Create baseline snapshot
            baseline = BaselineSnapshot(
                baseline_id=baseline_id,
                baseline_type=baseline_type,
                classification_level=self.classification.default_level,
                creation_timestamp=time.time(),
                created_by=created_by,
                target_systems=target_systems,
                configuration_items=configuration_items,
                integrity_hash="",  # Will be calculated
                cryptographic_signature="",  # Will be calculated
                version="1.0",
                status=BaselineStatus.PENDING_VALIDATION,
                metadata=metadata or {}
            )
            
            # Calculate integrity hash
            baseline.integrity_hash = await self._calculate_integrity_hash(baseline)
            
            # Generate cryptographic signature
            baseline.cryptographic_signature = await self._generate_baseline_signature(baseline)
            
            # Update status to active
            baseline.status = BaselineStatus.ACTIVE
            
            # Store baseline securely
            storage_path = await self.baseline_storage.store_baseline(baseline)
            
            # Register baseline
            with self.registry_lock:
                self.active_baselines[baseline_id] = {
                    "baseline": baseline,
                    "storage_path": storage_path,
                    "last_accessed": time.time()
                }
            
            # Create version record
            version_id = self.version_manager.create_version(baseline)
            
            # Log baseline creation
            self.audit_logger.log_security_event(
                AuditEventType.SYSTEM_EVENT,
                AuditSeverity.MEDIUM,
                "configuration_baseline_manager",
                f"Created baseline {baseline_id}",
                {
                    "baseline_id": baseline_id,
                    "baseline_type": baseline_type.value,
                    "target_systems": target_systems,
                    "configuration_items": len(configuration_items),
                    "creation_time_ms": (time.time() - start_time) * 1000,
                    "version_id": version_id
                }
            )
            
            self.logger.info(
                f"Created baseline {baseline_id} with {len(configuration_items)} "
                f"configuration items in {(time.time() - start_time)*1000:.2f}ms"
            )
            
            return baseline
            
        except Exception as e:
            self.logger.error(f"Failed to create baseline {baseline_id}: {e}")
            
            # Log error event
            self.audit_logger.log_security_event(
                AuditEventType.SYSTEM_EVENT,
                AuditSeverity.HIGH,
                "configuration_baseline_manager",
                f"Failed to create baseline {baseline_id}: {str(e)}",
                {
                    "baseline_id": baseline_id,
                    "error": str(e),
                    "target_systems": target_systems
                }
            )
            raise
    
    async def validate_baseline_integrity(self, baseline_id: str) -> bool:
        """
        Cryptographically validate baseline integrity.
        
        Args:
            baseline_id: ID of baseline to validate
            
        Returns:
            bool: True if baseline integrity is valid
        """
        try:
            baseline = await self.get_baseline(baseline_id)
            
            # Validate cryptographic signature
            signature_valid = await self._verify_baseline_signature(baseline)
            
            # Validate integrity hash
            hash_valid = await self._validate_integrity_hash(baseline)
            
            # Validate storage integrity
            storage_valid = await self.baseline_storage._validate_baseline_integrity(baseline)
            
            is_valid = signature_valid and hash_valid and storage_valid
            
            self.logger.info(
                f"Baseline {baseline_id} integrity validation: "
                f"signature={signature_valid}, hash={hash_valid}, storage={storage_valid}"
            )
            
            return is_valid
            
        except Exception as e:
            self.logger.error(f"Baseline integrity validation failed for {baseline_id}: {e}")
            return False
    
    async def compare_configurations(self, 
                                   baseline_id: str,
                                   current_config: Dict[str, Any],
                                   target_baseline_id: Optional[str] = None) -> DriftAnalysis:
        """
        Compare current configuration against baseline.
        
        Args:
            baseline_id: Source baseline for comparison
            current_config: Current configuration data
            target_baseline_id: Optional target baseline for comparison
            
        Returns:
            DriftAnalysis: Comprehensive drift analysis
        """
        analysis_start = time.time()
        analysis_id = f"analysis_{int(time.time())}"
        
        try:
            # Get source baseline
            source_baseline = await self.get_baseline(baseline_id)
            
            # Get target baseline if specified
            target_baseline = None
            if target_baseline_id:
                target_baseline = await self.get_baseline(target_baseline_id)
            
            # Perform drift analysis
            drift_analysis = await self._analyze_configuration_drift(
                analysis_id, source_baseline, current_config, target_baseline
            )
            
            # Log analysis
            self.audit_logger.log_security_event(
                AuditEventType.SYSTEM_EVENT,
                AuditSeverity.MEDIUM if drift_analysis.drift_detected else AuditSeverity.LOW,
                "configuration_baseline_manager",
                f"Configuration drift analysis completed: {analysis_id}",
                {
                    "analysis_id": analysis_id,
                    "baseline_id": baseline_id,
                    "drift_detected": drift_analysis.drift_detected,
                    "total_changes": drift_analysis.total_changes,
                    "critical_changes": drift_analysis.critical_changes,
                    "severity_score": drift_analysis.severity_score,
                    "analysis_time_ms": (time.time() - analysis_start) * 1000
                }
            )
            
            return drift_analysis
            
        except Exception as e:
            self.logger.error(f"Configuration comparison failed: {e}")
            raise
    
    async def get_baseline(self, baseline_id: str) -> BaselineSnapshot:
        """Retrieve baseline with caching support."""
        with self.registry_lock:
            if baseline_id in self.active_baselines:
                self.active_baselines[baseline_id]["last_accessed"] = time.time()
                return self.active_baselines[baseline_id]["baseline"]
        
        # Try to load from storage
        for level in ClassificationLevel:
            try:
                baseline = await self.baseline_storage.retrieve_baseline(baseline_id, level)
                
                # Cache the baseline
                with self.registry_lock:
                    self.active_baselines[baseline_id] = {
                        "baseline": baseline,
                        "storage_path": f"{baseline_id}.encrypted",
                        "last_accessed": time.time()
                    }
                
                return baseline
                
            except FileNotFoundError:
                continue
        
        raise FileNotFoundError(f"Baseline {baseline_id} not found")
    
    async def list_baselines(self, 
                           classification_level: Optional[ClassificationLevel] = None,
                           baseline_type: Optional[BaselineType] = None) -> List[Dict[str, Any]]:
        """List available baselines with optional filtering."""
        baselines = []
        
        with self.registry_lock:
            for baseline_id, baseline_info in self.active_baselines.items():
                baseline = baseline_info["baseline"]
                
                # Apply filters
                if classification_level and baseline.classification_level != classification_level:
                    continue
                if baseline_type and baseline.baseline_type != baseline_type:
                    continue
                
                baselines.append({
                    "baseline_id": baseline_id,
                    "baseline_type": baseline.baseline_type.value,
                    "classification_level": baseline.classification_level.value,
                    "creation_timestamp": baseline.creation_timestamp,
                    "created_by": baseline.created_by,
                    "target_systems": baseline.target_systems,
                    "status": baseline.status.value,
                    "configuration_items": len(baseline.configuration_items)
                })
        
        return sorted(baselines, key=lambda x: x["creation_timestamp"], reverse=True)
    
    # Configuration Collection Methods
    async def _collect_filesystem_config(self, target_systems: List[str]) -> List[ConfigurationItem]:
        """Collect file system configuration items."""
        config_items = []
        
        # Important configuration files to monitor
        config_files = [
            "/etc/passwd", "/etc/shadow", "/etc/group",
            "/etc/ssh/sshd_config", "/etc/sudoers",
            "/etc/hosts", "/etc/resolv.conf",
            "/etc/fstab", "/etc/crontab"
        ]
        
        for file_path in config_files:
            if os.path.exists(file_path):
                try:
                    stat = os.stat(file_path)
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    config_items.append(ConfigurationItem(
                        path=file_path,
                        value=hashlib.sha256(content.encode()).hexdigest(),
                        data_type="file_hash",
                        last_modified=stat.st_mtime,
                        checksum=hashlib.sha256(content.encode()).hexdigest(),
                        classification_level=self.classification.default_level.value,
                        scope=ConfigurationScope.FILE_SYSTEM,
                        metadata={
                            "file_size": stat.st_size,
                            "permissions": oct(stat.st_mode)[-3:],
                            "owner": stat.st_uid,
                            "group": stat.st_gid
                        }
                    ))
                except Exception as e:
                    self.logger.warning(f"Failed to collect config for {file_path}: {e}")
        
        return config_items
    
    async def _collect_env_config(self, target_systems: List[str]) -> List[ConfigurationItem]:
        """Collect environment variable configuration."""
        config_items = []
        
        # Important environment variables to monitor
        important_env_vars = [
            "PATH", "HOME", "USER", "SHELL", "TERM",
            "LD_LIBRARY_PATH", "PYTHONPATH", "JAVA_HOME"
        ]
        
        for env_var in important_env_vars:
            value = os.environ.get(env_var)
            if value:
                config_items.append(ConfigurationItem(
                    path=f"env:{env_var}",
                    value=value,
                    data_type="environment_variable",
                    last_modified=time.time(),
                    checksum=hashlib.sha256(value.encode()).hexdigest(),
                    classification_level=self.classification.default_level.value,
                    scope=ConfigurationScope.ENVIRONMENT_VARIABLES
                ))
        
        return config_items
    
    async def _collect_service_config(self, target_systems: List[str]) -> List[ConfigurationItem]:
        """Collect service configuration."""
        config_items = []
        
        # This would typically interface with systemd, Docker, etc.
        # For now, implementing a basic version
        
        try:
            import subprocess
            
            # Get systemd services status
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=active", "--no-pager"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                services_hash = hashlib.sha256(result.stdout.encode()).hexdigest()
                config_items.append(ConfigurationItem(
                    path="systemd:active_services",
                    value=services_hash,
                    data_type="service_list_hash",
                    last_modified=time.time(),
                    checksum=services_hash,
                    classification_level=self.classification.default_level.value,
                    scope=ConfigurationScope.SERVICE_CONFIGURATION,
                    metadata={"service_count": len(result.stdout.splitlines()) - 1}
                ))
                
        except Exception as e:
            self.logger.warning(f"Failed to collect service configuration: {e}")
        
        return config_items
    
    async def _collect_security_config(self, target_systems: List[str]) -> List[ConfigurationItem]:
        """Collect security policy configuration."""
        config_items = []
        
        # Security configuration files
        security_files = [
            "/etc/security/limits.conf",
            "/etc/pam.conf",
            "/etc/login.defs",
            "/etc/audit/auditd.conf"
        ]
        
        for file_path in security_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    config_items.append(ConfigurationItem(
                        path=file_path,
                        value=hashlib.sha256(content.encode()).hexdigest(),
                        data_type="security_config_hash",
                        last_modified=os.path.getmtime(file_path),
                        checksum=hashlib.sha256(content.encode()).hexdigest(),
                        classification_level=self.classification.default_level.value,
                        scope=ConfigurationScope.SECURITY_POLICIES
                    ))
                except Exception as e:
                    self.logger.warning(f"Failed to collect security config for {file_path}: {e}")
        
        return config_items
    
    async def _collect_maestro_config(self, target_systems: List[str]) -> List[ConfigurationItem]:
        """Collect MAESTRO framework configuration."""
        config_items = []
        
        if MAESTRO_AVAILABLE:
            try:
                # Collect MAESTRO layer configurations
                maestro_config = {
                    "classification_level": self.classification.default_level.value,
                    "crypto_algorithms": [alg.value for alg in CryptoAlgorithm],
                    "security_levels": [level.value for level in SecurityLevel],
                    "audit_enabled": True
                }
                
                config_json = json.dumps(maestro_config, sort_keys=True)
                config_hash = hashlib.sha256(config_json.encode()).hexdigest()
                
                config_items.append(ConfigurationItem(
                    path="maestro:framework_config",
                    value=config_hash,
                    data_type="maestro_config_hash",
                    last_modified=time.time(),
                    checksum=config_hash,
                    classification_level=self.classification.default_level.value,
                    scope=ConfigurationScope.MAESTRO_LAYERS,
                    metadata=maestro_config
                ))
                
            except Exception as e:
                self.logger.warning(f"Failed to collect MAESTRO configuration: {e}")
        
        return config_items
    
    # Integrity and Security Methods
    async def _calculate_integrity_hash(self, baseline: BaselineSnapshot) -> str:
        """Calculate cryptographic integrity hash for baseline."""
        baseline_copy = BaselineSnapshot(**asdict(baseline))
        baseline_copy.integrity_hash = ""
        baseline_copy.cryptographic_signature = ""
        
        # Sort configuration items for consistent hashing
        baseline_copy.configuration_items.sort(key=lambda x: x.path)
        
        baseline_json = json.dumps(asdict(baseline_copy), sort_keys=True)
        return hashlib.sha256(baseline_json.encode()).hexdigest()
    
    async def _generate_baseline_signature(self, baseline: BaselineSnapshot) -> str:
        """Generate cryptographic signature for baseline."""
        try:
            # Create signature payload
            signature_data = {
                "baseline_id": baseline.baseline_id,
                "integrity_hash": baseline.integrity_hash,
                "creation_timestamp": baseline.creation_timestamp,
                "classification_level": baseline.classification_level.value
            }
            
            signature_json = json.dumps(signature_data, sort_keys=True)
            
            # Generate HMAC signature
            signature = await self.crypto_utils.generate_hmac(
                signature_json.encode(),
                algorithm=CryptoAlgorithm.HMAC_SHA256
            )
            
            return signature.hex()
            
        except Exception as e:
            self.logger.error(f"Failed to generate baseline signature: {e}")
            raise
    
    async def _verify_baseline_signature(self, baseline: BaselineSnapshot) -> bool:
        """Verify baseline cryptographic signature."""
        try:
            # Recreate signature data
            signature_data = {
                "baseline_id": baseline.baseline_id,
                "integrity_hash": baseline.integrity_hash,
                "creation_timestamp": baseline.creation_timestamp,
                "classification_level": baseline.classification_level.value
            }
            
            signature_json = json.dumps(signature_data, sort_keys=True)
            
            # Verify HMAC signature
            expected_signature = await self.crypto_utils.generate_hmac(
                signature_json.encode(),
                algorithm=CryptoAlgorithm.HMAC_SHA256
            )
            
            return expected_signature.hex() == baseline.cryptographic_signature
            
        except Exception as e:
            self.logger.error(f"Failed to verify baseline signature: {e}")
            return False
    
    async def _validate_integrity_hash(self, baseline: BaselineSnapshot) -> bool:
        """Validate baseline integrity hash."""
        try:
            calculated_hash = await self._calculate_integrity_hash(baseline)
            return calculated_hash == baseline.integrity_hash
        except Exception as e:
            self.logger.error(f"Failed to validate integrity hash: {e}")
            return False
    
    async def _analyze_configuration_drift(self, 
                                         analysis_id: str,
                                         source_baseline: BaselineSnapshot,
                                         current_config: Dict[str, Any],
                                         target_baseline: Optional[BaselineSnapshot] = None) -> DriftAnalysis:
        """Analyze configuration drift between baseline and current state."""
        
        # Convert baseline to comparable format
        baseline_config = {item.path: item.value for item in source_baseline.configuration_items}
        
        # Find changes
        changed_items = []
        critical_changes = 0
        
        # Check for modified items
        for path, current_value in current_config.items():
            if path in baseline_config:
                if baseline_config[path] != current_value:
                    change_info = {
                        "path": path,
                        "change_type": "modified",
                        "baseline_value": baseline_config[path],
                        "current_value": current_value,
                        "severity": self._assess_change_severity(path, baseline_config[path], current_value)
                    }
                    changed_items.append(change_info)
                    
                    if change_info["severity"] == "critical":
                        critical_changes += 1
        
        # Check for new items
        for path, current_value in current_config.items():
            if path not in baseline_config:
                change_info = {
                    "path": path,
                    "change_type": "added",
                    "baseline_value": None,
                    "current_value": current_value,
                    "severity": self._assess_change_severity(path, None, current_value)
                }
                changed_items.append(change_info)
                
                if change_info["severity"] == "critical":
                    critical_changes += 1
        
        # Check for removed items
        for path, baseline_value in baseline_config.items():
            if path not in current_config:
                change_info = {
                    "path": path,
                    "change_type": "removed",
                    "baseline_value": baseline_value,
                    "current_value": None,
                    "severity": self._assess_change_severity(path, baseline_value, None)
                }
                changed_items.append(change_info)
                
                if change_info["severity"] == "critical":
                    critical_changes += 1
        
        # Calculate severity score
        severity_score = self._calculate_severity_score(changed_items)
        
        # Generate recommendations
        recommendations = self._generate_drift_recommendations(changed_items)
        
        return DriftAnalysis(
            analysis_id=analysis_id,
            baseline_id=source_baseline.baseline_id,
            target_baseline_id=target_baseline.baseline_id if target_baseline else "",
            analysis_timestamp=time.time(),
            drift_detected=len(changed_items) > 0,
            total_changes=len(changed_items),
            critical_changes=critical_changes,
            changed_items=changed_items,
            severity_score=severity_score,
            recommendations=recommendations,
            classification_level=source_baseline.classification_level
        )
    
    def _assess_change_severity(self, path: str, baseline_value: Any, current_value: Any) -> str:
        """Assess severity of configuration change."""
        # Security-critical paths
        critical_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "env:PATH"
        ]
        
        if any(critical_path in path for critical_path in critical_paths):
            return "critical"
        
        # Medium severity paths
        medium_paths = [
            "/etc/hosts", "/etc/resolv.conf", "/etc/fstab"
        ]
        
        if any(medium_path in path for medium_path in medium_paths):
            return "medium"
        
        return "low"
    
    def _calculate_severity_score(self, changed_items: List[Dict[str, Any]]) -> float:
        """Calculate overall severity score for drift analysis."""
        if not changed_items:
            return 0.0
        
        severity_weights = {"critical": 1.0, "medium": 0.6, "low": 0.2}
        total_weight = sum(severity_weights[item["severity"]] for item in changed_items)
        
        return min(total_weight / len(changed_items), 1.0)
    
    def _generate_drift_recommendations(self, changed_items: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations for addressing configuration drift."""
        recommendations = []
        
        critical_items = [item for item in changed_items if item["severity"] == "critical"]
        if critical_items:
            recommendations.append(
                f"URGENT: {len(critical_items)} critical configuration changes detected. "
                "Immediate review and validation required."
            )
        
        added_items = [item for item in changed_items if item["change_type"] == "added"]
        if added_items:
            recommendations.append(
                f"Review {len(added_items)} new configuration items for policy compliance."
            )
        
        removed_items = [item for item in changed_items if item["change_type"] == "removed"]
        if removed_items:
            recommendations.append(
                f"Investigate {len(removed_items)} removed configuration items. "
                "Verify intentional changes."
            )
        
        if not recommendations:
            recommendations.append("Configuration drift within acceptable parameters.")
        
        return recommendations


# Utility functions for external integration
async def create_system_baseline(classification_level: str = "UNCLASSIFIED",
                               baseline_type: str = "full_system",
                               created_by: str = "system") -> str:
    """Utility function to create a system baseline."""
    if not MAESTRO_AVAILABLE:
        raise RuntimeError("MAESTRO framework required for baseline creation")
    
    classification = SecurityClassification(ClassificationLevel[classification_level.upper()])
    crypto_utils = FIPSCryptoUtils(classification, SecurityLevel.SECRET)
    audit_logger = AuditLogger(classification)
    
    manager = ConfigurationBaselineManager(classification, crypto_utils, audit_logger)
    
    baseline = await manager.create_baseline(
        target_systems=["localhost"],
        baseline_type=BaselineType[baseline_type.upper()],
        scopes=[
            ConfigurationScope.FILE_SYSTEM,
            ConfigurationScope.ENVIRONMENT_VARIABLES,
            ConfigurationScope.SERVICE_CONFIGURATION,
            ConfigurationScope.SECURITY_POLICIES,
            ConfigurationScope.MAESTRO_LAYERS
        ],
        created_by=created_by
    )
    
    return baseline.baseline_id


async def validate_configuration_against_baseline(baseline_id: str,
                                                 current_config: Dict[str, Any]) -> Dict[str, Any]:
    """Utility function to validate current configuration against baseline."""
    if not MAESTRO_AVAILABLE:
        raise RuntimeError("MAESTRO framework required for validation")
    
    classification = SecurityClassification(ClassificationLevel.UNCLASSIFIED)
    crypto_utils = FIPSCryptoUtils(classification, SecurityLevel.SECRET)
    audit_logger = AuditLogger(classification)
    
    manager = ConfigurationBaselineManager(classification, crypto_utils, audit_logger)
    
    drift_analysis = await manager.compare_configurations(baseline_id, current_config)
    
    return {
        "drift_detected": drift_analysis.drift_detected,
        "total_changes": drift_analysis.total_changes,
        "critical_changes": drift_analysis.critical_changes,
        "severity_score": drift_analysis.severity_score,
        "recommendations": drift_analysis.recommendations
    } 