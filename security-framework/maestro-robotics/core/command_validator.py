#!/usr/bin/env python3
"""
ALCUB3 MAESTRO Command Validation Pipeline
Patent-Pending Real-Time Command Validation for Defense Robotics

This module implements the command validation pipeline that intercepts,
validates, and transforms robotics commands with MAESTRO security controls.

Key Innovations:
- Real-time command interception and validation
- Multi-stage security validation pipeline
- Classification-aware command transformation
- Predictive threat assessment for commands
- Command execution audit trail with replay capability

Patent Applications:
- Real-time robotics command validation pipeline
- Predictive threat assessment for autonomous systems
- Classification-aware command transformation protocol
- Secure command replay and audit system
"""

import asyncio
import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import logging

# Import MAESTRO components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.crypto_utils import CryptoUtils
from shared.threat_detector import ThreatDetector
from shared.real_time_monitor import RealTimeMonitor


class ValidationStage(Enum):
    """Command validation pipeline stages."""
    AUTHENTICATION = "authentication"
    CLASSIFICATION = "classification"
    AUTHORIZATION = "authorization"
    THREAT_ASSESSMENT = "threat_assessment"
    POLICY_CHECK = "policy_check"
    TRANSFORM = "transform"
    SIGN = "sign"
    AUDIT = "audit"


class ValidationResult(Enum):
    """Validation stage results."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class ValidationContext:
    """Context passed through validation pipeline."""
    command_id: str
    raw_command: Dict[str, Any]
    issuer_id: str
    issuer_clearance: ClassificationLevel
    platform_id: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    validation_results: Dict[ValidationStage, ValidationResult] = field(default_factory=dict)
    stage_metrics: Dict[ValidationStage, float] = field(default_factory=dict)
    transformed_command: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None
    risk_score: float = 0.0
    threats_detected: List[str] = field(default_factory=list)


@dataclass
class PipelineMetrics:
    """Metrics for validation pipeline performance."""
    total_commands: int = 0
    passed_commands: int = 0
    failed_commands: int = 0
    warning_commands: int = 0
    average_validation_time_ms: float = 0.0
    stage_metrics: Dict[ValidationStage, Dict[str, float]] = field(default_factory=dict)
    recent_validations: deque = field(default_factory=lambda: deque(maxlen=1000))
    threat_detections: int = 0
    policy_violations: int = 0


class CommandValidationPipeline:
    """
    Command Validation Pipeline for MAESTRO Robotics Security.
    
    Provides multi-stage validation, transformation, and auditing
    for all robotics commands with real-time threat assessment.
    """
    
    def __init__(self,
                 classification_level: ClassificationLevel,
                 audit_logger: Optional[AuditLogger] = None,
                 enable_predictive: bool = True):
        """Initialize Command Validation Pipeline."""
        self.classification_level = classification_level
        self.logger = logging.getLogger("CommandValidationPipeline")
        
        # MAESTRO components
        self.audit_logger = audit_logger or AuditLogger(classification_level)
        self.crypto_utils = CryptoUtils()
        self.threat_detector = ThreatDetector(self.audit_logger)
        self.monitor = RealTimeMonitor(self.audit_logger)
        
        # Pipeline configuration
        self.enable_predictive = enable_predictive
        self.pipeline_stages = self._initialize_pipeline()
        self.stage_handlers = self._initialize_handlers()
        
        # Metrics and history
        self.metrics = PipelineMetrics()
        self.command_history: deque = deque(maxlen=10000)
        self.threat_patterns: Dict[str, int] = {}
        
        # Validation cache for performance
        self.validation_cache: Dict[str, Tuple[bool, float]] = {}
        self.cache_ttl = timedelta(minutes=5)
        
        self.logger.info("Command Validation Pipeline initialized")
    
    def _initialize_pipeline(self) -> List[ValidationStage]:
        """Initialize validation pipeline stages in order."""
        return [
            ValidationStage.AUTHENTICATION,
            ValidationStage.CLASSIFICATION,
            ValidationStage.AUTHORIZATION,
            ValidationStage.THREAT_ASSESSMENT,
            ValidationStage.POLICY_CHECK,
            ValidationStage.TRANSFORM,
            ValidationStage.SIGN,
            ValidationStage.AUDIT
        ]
    
    def _initialize_handlers(self) -> Dict[ValidationStage, Callable]:
        """Initialize stage-specific handlers."""
        return {
            ValidationStage.AUTHENTICATION: self._validate_authentication,
            ValidationStage.CLASSIFICATION: self._validate_classification,
            ValidationStage.AUTHORIZATION: self._validate_authorization,
            ValidationStage.THREAT_ASSESSMENT: self._assess_threats,
            ValidationStage.POLICY_CHECK: self._check_policies,
            ValidationStage.TRANSFORM: self._transform_command,
            ValidationStage.SIGN: self._sign_command,
            ValidationStage.AUDIT: self._audit_command
        }
    
    async def validate_command(self, 
                             command: Dict[str, Any],
                             issuer_id: str,
                             issuer_clearance: ClassificationLevel,
                             platform_id: str) -> Tuple[bool, Optional[Dict[str, Any]], ValidationContext]:
        """
        Validate command through the full pipeline.
        
        Returns:
            Tuple of (success, transformed_command, validation_context)
        """
        start_time = time.time()
        
        # Create validation context
        context = ValidationContext(
            command_id=self._generate_command_id(),
            raw_command=command,
            issuer_id=issuer_id,
            issuer_clearance=issuer_clearance,
            platform_id=platform_id,
            timestamp=datetime.utcnow()
        )
        
        # Check cache
        cache_key = self._generate_cache_key(command, issuer_id, platform_id)
        if cache_key in self.validation_cache:
            cached_result, cache_time = self.validation_cache[cache_key]
            if datetime.utcnow() - datetime.fromtimestamp(cache_time) < self.cache_ttl:
                self.logger.debug(f"Cache hit for command {context.command_id}")
                return cached_result, command if cached_result else None, context
        
        try:
            # Run through pipeline stages
            for stage in self.pipeline_stages:
                stage_start = time.time()
                
                handler = self.stage_handlers[stage]
                result = await handler(context)
                
                stage_time = (time.time() - stage_start) * 1000
                context.stage_metrics[stage] = stage_time
                context.validation_results[stage] = result
                
                # Update stage metrics
                self._update_stage_metrics(stage, result, stage_time)
                
                # Stop on failure
                if result == ValidationResult.FAIL:
                    self.logger.warning(f"Command {context.command_id} failed at stage {stage.value}")
                    break
            
            # Determine overall result
            success = all(
                result != ValidationResult.FAIL 
                for result in context.validation_results.values()
            )
            
            # Update metrics
            validation_time = (time.time() - start_time) * 1000
            self._update_pipeline_metrics(context, success, validation_time)
            
            # Cache result
            self.validation_cache[cache_key] = (success, time.time())
            
            # Store in history
            self.command_history.append({
                "context": context,
                "success": success,
                "timestamp": datetime.utcnow()
            })
            
            # Log result
            self.logger.info(
                f"Command {context.command_id} validation {'passed' if success else 'failed'} "
                f"in {validation_time:.2f}ms"
            )
            
            return success, context.transformed_command if success else None, context
            
        except Exception as e:
            self.logger.error(f"Pipeline error for command {context.command_id}: {e}")
            context.validation_results[ValidationStage.AUDIT] = ValidationResult.FAIL
            return False, None, context
    
    async def _validate_authentication(self, context: ValidationContext) -> ValidationResult:
        """Validate issuer authentication."""
        try:
            # Verify issuer identity
            if not context.issuer_id:
                return ValidationResult.FAIL
            
            # In production, this would verify against PKI/CAC
            # For now, simple validation
            if context.issuer_id.startswith("operator_") or context.issuer_id.startswith("system_"):
                return ValidationResult.PASS
            
            return ValidationResult.FAIL
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return ValidationResult.FAIL
    
    async def _validate_classification(self, context: ValidationContext) -> ValidationResult:
        """Validate classification levels."""
        try:
            # Extract command classification
            command_classification = ClassificationLevel(
                context.raw_command.get("classification", "UNCLASSIFIED")
            )
            
            context.metadata["command_classification"] = command_classification
            
            # Check issuer clearance
            if context.issuer_clearance.numeric_level < command_classification.numeric_level:
                self.logger.warning(
                    f"Issuer {context.issuer_id} clearance {context.issuer_clearance.value} "
                    f"insufficient for command classification {command_classification.value}"
                )
                return ValidationResult.FAIL
            
            # Check platform classification
            if command_classification.numeric_level > self.classification_level.numeric_level:
                self.logger.warning(
                    f"Command classification {command_classification.value} "
                    f"exceeds platform level {self.classification_level.value}"
                )
                return ValidationResult.FAIL
            
            return ValidationResult.PASS
            
        except Exception as e:
            self.logger.error(f"Classification validation error: {e}")
            return ValidationResult.FAIL
    
    async def _validate_authorization(self, context: ValidationContext) -> ValidationResult:
        """Validate command authorization."""
        try:
            command = context.raw_command
            command_type = command.get("command_type", "unknown")
            
            # Check if issuer is authorized for this command type
            # In production, this would check against access control lists
            restricted_commands = ["emergency_stop", "weapon_control", "override_safety"]
            
            if command_type in restricted_commands:
                # Check for additional authorization
                if not command.get("authorization_token"):
                    self.logger.warning(f"Missing authorization token for restricted command {command_type}")
                    return ValidationResult.FAIL
                
                # Verify token (simplified)
                token = command.get("authorization_token")
                if not token.startswith("AUTH_"):
                    return ValidationResult.FAIL
            
            return ValidationResult.PASS
            
        except Exception as e:
            self.logger.error(f"Authorization error: {e}")
            return ValidationResult.FAIL
    
    async def _assess_threats(self, context: ValidationContext) -> ValidationResult:
        """Assess threats in command."""
        try:
            # Prepare command data for threat assessment
            threat_data = {
                "command_type": context.raw_command.get("command_type", "unknown"),
                "parameters": context.raw_command.get("parameters", {}),
                "issuer": context.issuer_id,
                "platform": context.platform_id,
                "timestamp": context.timestamp.isoformat()
            }
            
            # Run threat detection
            threat_result = await self.threat_detector.analyze_robotics_command(threat_data)
            
            if threat_result.threat_detected:
                context.threats_detected.append(threat_result.threat_type)
                context.risk_score = threat_result.confidence
                self.metrics.threat_detections += 1
                
                # Update threat patterns
                self.threat_patterns[threat_result.threat_type] = \
                    self.threat_patterns.get(threat_result.threat_type, 0) + 1
                
                # High confidence threats fail validation
                if threat_result.confidence > 0.8:
                    return ValidationResult.FAIL
                else:
                    return ValidationResult.WARN
            
            # Predictive threat assessment
            if self.enable_predictive:
                predicted_risk = await self._predict_command_risk(context)
                context.risk_score = max(context.risk_score, predicted_risk)
                
                if predicted_risk > 0.7:
                    return ValidationResult.WARN
            
            return ValidationResult.PASS
            
        except Exception as e:
            self.logger.error(f"Threat assessment error: {e}")
            return ValidationResult.WARN
    
    async def _predict_command_risk(self, context: ValidationContext) -> float:
        """Predict command risk based on historical patterns."""
        try:
            # Analyze command patterns
            command_type = context.raw_command.get("command_type", "unknown")
            
            # Check historical threat patterns
            threat_frequency = self.threat_patterns.get(command_type, 0)
            total_commands = self.metrics.total_commands or 1
            
            # Calculate base risk
            base_risk = threat_frequency / total_commands
            
            # Adjust for command parameters
            parameters = context.raw_command.get("parameters", {})
            param_risk = 0.0
            
            # High-risk parameters
            if parameters.get("speed", 0) > 10:
                param_risk += 0.2
            if parameters.get("force", 0) > 100:
                param_risk += 0.3
            if parameters.get("autonomous_mode", False):
                param_risk += 0.2
            
            # Temporal risk (unusual timing)
            current_hour = datetime.utcnow().hour
            if current_hour < 6 or current_hour > 22:  # Off-hours
                param_risk += 0.1
            
            total_risk = min(1.0, base_risk + param_risk)
            return total_risk
            
        except Exception as e:
            self.logger.error(f"Risk prediction error: {e}")
            return 0.5  # Default medium risk
    
    async def _check_policies(self, context: ValidationContext) -> ValidationResult:
        """Check command against security policies."""
        try:
            # This would integrate with SecurityPolicyEngine
            # For now, basic policy checks
            
            command = context.raw_command
            command_type = command.get("command_type", "unknown")
            
            # Emergency stop policy
            if command_type == "emergency_stop":
                # Require elevated clearance
                if context.issuer_clearance.numeric_level < ClassificationLevel.SECRET.numeric_level:
                    self.metrics.policy_violations += 1
                    return ValidationResult.FAIL
            
            # Movement boundary policy
            if command_type in ["move", "navigate", "patrol"]:
                location = command.get("parameters", {}).get("destination", {})
                if self._check_boundary_violation(location):
                    self.metrics.policy_violations += 1
                    return ValidationResult.FAIL
            
            # Data transfer policy
            if command_type in ["upload", "download", "transfer"]:
                if not command.get("encrypted", False):
                    return ValidationResult.WARN
            
            return ValidationResult.PASS
            
        except Exception as e:
            self.logger.error(f"Policy check error: {e}")
            return ValidationResult.WARN
    
    def _check_boundary_violation(self, location: Dict[str, float]) -> bool:
        """Check if location violates operational boundaries."""
        # Simplified boundary check
        if not location:
            return False
        
        # Check distance from base
        lat = location.get("lat", 0)
        lon = location.get("lon", 0)
        
        # Simple distance check (production would use proper geofencing)
        base_lat, base_lon = 0, 0  # Base location
        distance = ((lat - base_lat) ** 2 + (lon - base_lon) ** 2) ** 0.5
        
        max_distance = 10  # km (simplified)
        return distance > max_distance
    
    async def _transform_command(self, context: ValidationContext) -> ValidationResult:
        """Transform command with security enhancements."""
        try:
            # Create transformed command
            transformed = dict(context.raw_command)
            
            # Add security metadata
            transformed["security_metadata"] = {
                "command_id": context.command_id,
                "validation_timestamp": context.timestamp.isoformat(),
                "issuer_id": context.issuer_id,
                "issuer_clearance": context.issuer_clearance.value,
                "classification": context.metadata.get("command_classification", ClassificationLevel.UNCLASSIFIED).value,
                "risk_score": context.risk_score,
                "threats_detected": context.threats_detected
            }
            
            # Add execution constraints based on risk
            if context.risk_score > 0.5:
                transformed["execution_constraints"] = {
                    "require_confirmation": True,
                    "max_retries": 1,
                    "timeout_seconds": 30
                }
            
            # Classification-based transformations
            command_classification = context.metadata.get("command_classification", ClassificationLevel.UNCLASSIFIED)
            if command_classification.numeric_level >= ClassificationLevel.SECRET.numeric_level:
                # Add additional security for classified commands
                transformed["security_metadata"]["require_secure_channel"] = True
                transformed["security_metadata"]["audit_level"] = "detailed"
            
            context.transformed_command = transformed
            return ValidationResult.PASS
            
        except Exception as e:
            self.logger.error(f"Command transformation error: {e}")
            return ValidationResult.FAIL
    
    async def _sign_command(self, context: ValidationContext) -> ValidationResult:
        """Sign validated command."""
        try:
            if not context.transformed_command:
                return ValidationResult.FAIL
            
            # Create signature data
            sign_data = {
                "command_id": context.command_id,
                "command_hash": self._hash_command(context.transformed_command),
                "timestamp": context.timestamp.isoformat(),
                "issuer_id": context.issuer_id,
                "platform_id": context.platform_id
            }
            
            # Generate signature (simplified - production would use real crypto)
            signature_string = json.dumps(sign_data, sort_keys=True)
            signature = f"MAESTRO_SIG_{hashlib.sha256(signature_string.encode()).hexdigest()[:16]}"
            
            context.signature = signature
            context.transformed_command["signature"] = signature
            
            return ValidationResult.PASS
            
        except Exception as e:
            self.logger.error(f"Command signing error: {e}")
            return ValidationResult.FAIL
    
    async def _audit_command(self, context: ValidationContext) -> ValidationResult:
        """Audit command validation."""
        try:
            # Prepare audit data
            audit_data = {
                "command_id": context.command_id,
                "command_type": context.raw_command.get("command_type", "unknown"),
                "issuer_id": context.issuer_id,
                "platform_id": context.platform_id,
                "validation_results": {
                    stage.value: result.value 
                    for stage, result in context.validation_results.items()
                },
                "stage_metrics": {
                    stage.value: time_ms
                    for stage, time_ms in context.stage_metrics.items()
                },
                "risk_score": context.risk_score,
                "threats_detected": context.threats_detected,
                "total_validation_time_ms": sum(context.stage_metrics.values())
            }
            
            # Log to audit system
            classification = context.metadata.get("command_classification", ClassificationLevel.UNCLASSIFIED)
            await self.audit_logger.log_event(
                "COMMAND_VALIDATION_PIPELINE",
                audit_data,
                classification=classification
            )
            
            return ValidationResult.PASS
            
        except Exception as e:
            self.logger.error(f"Audit logging error: {e}")
            return ValidationResult.WARN  # Don't fail validation for audit errors
    
    def _generate_command_id(self) -> str:
        """Generate unique command ID."""
        timestamp = int(time.time() * 1000000)
        return f"CMD_{timestamp}"
    
    def _generate_cache_key(self, command: Dict[str, Any], 
                          issuer_id: str, platform_id: str) -> str:
        """Generate cache key for command."""
        key_data = {
            "command_type": command.get("command_type", ""),
            "parameters": sorted(command.get("parameters", {}).items()),
            "issuer": issuer_id,
            "platform": platform_id
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _hash_command(self, command: Dict[str, Any]) -> str:
        """Generate hash of command for integrity."""
        command_string = json.dumps(command, sort_keys=True)
        return hashlib.sha256(command_string.encode()).hexdigest()
    
    def _update_stage_metrics(self, stage: ValidationStage, 
                            result: ValidationResult, time_ms: float):
        """Update metrics for specific stage."""
        if stage not in self.metrics.stage_metrics:
            self.metrics.stage_metrics[stage] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "average_time_ms": 0.0
            }
        
        stage_metrics = self.metrics.stage_metrics[stage]
        stage_metrics["total"] += 1
        
        if result == ValidationResult.PASS:
            stage_metrics["passed"] += 1
        elif result == ValidationResult.FAIL:
            stage_metrics["failed"] += 1
        elif result == ValidationResult.WARN:
            stage_metrics["warnings"] += 1
        
        # Update average time
        total = stage_metrics["total"]
        avg_time = stage_metrics["average_time_ms"]
        stage_metrics["average_time_ms"] = ((avg_time * (total - 1)) + time_ms) / total
    
    def _update_pipeline_metrics(self, context: ValidationContext, 
                               success: bool, validation_time: float):
        """Update overall pipeline metrics."""
        self.metrics.total_commands += 1
        
        if success:
            self.metrics.passed_commands += 1
        else:
            self.metrics.failed_commands += 1
        
        # Check for warnings
        if any(result == ValidationResult.WARN for result in context.validation_results.values()):
            self.metrics.warning_commands += 1
        
        # Update average time
        total = self.metrics.total_commands
        avg_time = self.metrics.average_validation_time_ms
        self.metrics.average_validation_time_ms = ((avg_time * (total - 1)) + validation_time) / total
        
        # Store recent validation
        self.metrics.recent_validations.append({
            "command_id": context.command_id,
            "success": success,
            "time_ms": validation_time,
            "timestamp": datetime.utcnow()
        })
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive pipeline metrics."""
        return {
            "total_commands": self.metrics.total_commands,
            "passed_commands": self.metrics.passed_commands,
            "failed_commands": self.metrics.failed_commands,
            "warning_commands": self.metrics.warning_commands,
            "success_rate": (self.metrics.passed_commands / max(1, self.metrics.total_commands)) * 100,
            "average_validation_time_ms": self.metrics.average_validation_time_ms,
            "threat_detections": self.metrics.threat_detections,
            "policy_violations": self.metrics.policy_violations,
            "stage_metrics": {
                stage.value: metrics
                for stage, metrics in self.metrics.stage_metrics.items()
            },
            "threat_patterns": dict(self.threat_patterns),
            "cache_size": len(self.validation_cache),
            "history_size": len(self.command_history)
        }
    
    def get_command_history(self, 
                          limit: int = 100,
                          platform_id: Optional[str] = None,
                          success_only: bool = False) -> List[Dict[str, Any]]:
        """Get recent command history."""
        history = list(self.command_history)
        
        # Filter by platform
        if platform_id:
            history = [h for h in history if h["context"].platform_id == platform_id]
        
        # Filter by success
        if success_only:
            history = [h for h in history if h["success"]]
        
        # Return most recent
        return history[-limit:]
    
    def clear_cache(self):
        """Clear validation cache."""
        self.validation_cache.clear()
        self.logger.info("Validation cache cleared")
    
    async def replay_command(self, command_id: str) -> Optional[Tuple[bool, ValidationContext]]:
        """Replay a previously validated command for analysis."""
        # Find command in history
        for entry in self.command_history:
            if entry["context"].command_id == command_id:
                context = entry["context"]
                
                # Re-run validation
                success, _, new_context = await self.validate_command(
                    context.raw_command,
                    context.issuer_id,
                    context.issuer_clearance,
                    context.platform_id
                )
                
                return success, new_context
        
        return None