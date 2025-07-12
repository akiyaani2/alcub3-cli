#!/usr/bin/env python3
"""
ALCUB3 Behavioral Security Integration with MAESTRO Framework
Defense-Grade Security Integration for Behavioral Analysis

This module integrates the behavioral analysis engine with the MAESTRO L1-L3
security framework, providing classification-aware behavioral monitoring,
threat detection, and automated security response.

Key Features:
- MAESTRO L1-L3 security layer integration
- Classification-aware behavioral analysis (U/S/TS)
- Behavioral threat detection and classification
- Automated security response triggers
- Audit logging and compliance validation
- Byzantine fault-tolerant behavioral consensus

Author: ALCUB3 Development Team
Classification: For Official Use Only
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid
from pathlib import Path
import sys

# Import security framework components
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "02-security-maestro" / "src"))

from shared.classification import ClassificationLevel, ClassificationHandler
from shared.audit_logger import AuditLogger
from shared.threat_detector import ThreatDetector, ThreatLevel, ThreatType
from l1_physical.tpm_attestation import TPMAttestation, AttestationResult
from l2_network.secure_channel import SecureChannel, ChannelSecurity
from l3_agent.security_monitoring_dashboard import SecurityMonitoringDashboard, SecurityEvent

# Import behavioral analysis components
from .behavioral_analyzer import (
    BehavioralAnalysisEngine, BehavioralAnomaly, BehavioralAnomalyType,
    BehavioralFeature, BehavioralPattern, BehavioralPatternType
)
from .real_time_behavioral_monitor import RealTimeBehavioralMonitor, ProcessingPriority
from .cross_platform_correlator import CrossPlatformBehavioralCorrelator, RobotPlatformType

logger = logging.getLogger(__name__)


class BehavioralThreatLevel(Enum):
    """Behavioral threat severity levels."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class BehavioralSecurityEvent(Enum):
    """Types of behavioral security events."""
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    COORDINATED_ATTACK = "coordinated_attack"
    INSIDER_THREAT = "insider_threat"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    COMPROMISED_ROBOT = "compromised_robot"
    SWARM_INFILTRATION = "swarm_infiltration"
    ADAPTIVE_ADVERSARY = "adaptive_adversary"
    BEHAVIORAL_MASQUERADE = "behavioral_masquerade"


@dataclass
class BehavioralSecurityContext:
    """Security context for behavioral analysis."""
    classification_level: ClassificationLevel
    security_domain: str
    mission_context: Optional[str] = None
    
    # Security constraints
    data_retention_period: timedelta = timedelta(days=30)
    sharing_restrictions: List[str] = field(default_factory=list)
    access_controls: Dict[str, str] = field(default_factory=dict)
    
    # Compliance requirements
    audit_requirements: List[str] = field(default_factory=list)
    regulatory_frameworks: List[str] = field(default_factory=list)
    
    def is_authorized_access(self, user_clearance: ClassificationLevel) -> bool:
        """Check if user has authorized access to this security context."""
        return user_clearance.value >= self.classification_level.value


@dataclass
class BehavioralThreat:
    """Represents a detected behavioral threat."""
    threat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: BehavioralSecurityEvent = BehavioralSecurityEvent.ANOMALOUS_BEHAVIOR
    threat_level: BehavioralThreatLevel = BehavioralThreatLevel.MEDIUM
    
    # Threat details
    affected_robots: List[str] = field(default_factory=list)
    behavioral_anomalies: List[BehavioralAnomaly] = field(default_factory=list)
    confidence: float = 0.0
    
    # Security context
    security_context: Optional[BehavioralSecurityContext] = None
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    
    # Temporal information
    first_detected: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    
    # Attribution and context
    potential_attack_vector: Optional[str] = None
    indicators_of_compromise: List[str] = field(default_factory=list)
    kill_chain_stage: Optional[str] = None
    
    # Response information
    automated_response: bool = False
    response_actions: List[str] = field(default_factory=list)
    mitigation_status: str = "pending"
    
    def to_security_event(self) -> SecurityEvent:
        """Convert to MAESTRO security event."""
        return SecurityEvent(
            event_type=f"behavioral_{self.threat_type.value}",
            severity=self.threat_level.value,
            description=f"Behavioral threat detected: {self.threat_type.value}",
            affected_assets=self.affected_robots,
            timestamp=self.first_detected,
            classification=self.classification_level,
            metadata={
                'threat_id': self.threat_id,
                'confidence': self.confidence,
                'anomaly_count': len(self.behavioral_anomalies),
                'attack_vector': self.potential_attack_vector,
                'indicators': self.indicators_of_compromise
            }
        )


class BehavioralSecurityAnalyzer:
    """Analyzes behavioral data for security threats."""
    
    def __init__(self, classification_handler: ClassificationHandler):
        self.classification_handler = classification_handler
        self.threat_patterns = self._initialize_threat_patterns()
        self.attack_signatures = self._initialize_attack_signatures()
        
    def _initialize_threat_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize behavioral threat patterns."""
        return {
            'coordinated_attack': {
                'description': 'Multiple robots exhibiting coordinated anomalous behavior',
                'indicators': ['synchronized_movement', 'coordinated_communication', 'timing_correlation'],
                'threshold': 0.8,
                'min_robots': 3
            },
            'insider_threat': {
                'description': 'Authorized robot exhibiting suspicious behavior',
                'indicators': ['privilege_escalation', 'data_exfiltration', 'policy_violation'],
                'threshold': 0.7,
                'behavioral_changes': ['communication_pattern_change', 'access_pattern_change']
            },
            'behavioral_drift': {
                'description': 'Gradual change in behavioral patterns',
                'indicators': ['baseline_deviation', 'performance_degradation', 'error_rate_increase'],
                'threshold': 0.6,
                'time_window': timedelta(hours=24)
            },
            'swarm_infiltration': {
                'description': 'Unauthorized robot joining swarm',
                'indicators': ['authentication_anomaly', 'behavioral_mismatch', 'communication_anomaly'],
                'threshold': 0.9,
                'verification_required': True
            },
            'adaptive_adversary': {
                'description': 'Attacker adapting to defensive measures',
                'indicators': ['evasion_techniques', 'behavior_mimicry', 'detection_avoidance'],
                'threshold': 0.8,
                'learning_indicators': True
            }
        }
    
    def _initialize_attack_signatures(self) -> Dict[str, List[str]]:
        """Initialize attack signatures for behavioral analysis."""
        return {
            'replay_attack': ['repetitive_patterns', 'timestamp_anomalies', 'sequence_violations'],
            'man_in_the_middle': ['communication_delays', 'message_modification', 'routing_anomalies'],
            'denial_of_service': ['resource_exhaustion', 'communication_flooding', 'task_overload'],
            'data_poisoning': ['sensor_manipulation', 'data_corruption', 'learning_interference'],
            'model_evasion': ['adversarial_inputs', 'confidence_manipulation', 'decision_boundary_probing']
        }
    
    async def analyze_behavioral_threat(self, 
                                      anomalies: List[BehavioralAnomaly],
                                      security_context: BehavioralSecurityContext) -> List[BehavioralThreat]:
        """Analyze behavioral anomalies for security threats."""
        threats = []
        
        # Group anomalies by type and affected robots
        anomaly_groups = self._group_anomalies(anomalies)
        
        # Analyze each group for threat patterns
        for group_key, group_anomalies in anomaly_groups.items():
            threat = await self._analyze_anomaly_group(group_anomalies, security_context)
            if threat:
                threats.append(threat)
        
        # Look for coordinated threats across groups
        coordinated_threats = await self._detect_coordinated_threats(anomalies, security_context)
        threats.extend(coordinated_threats)
        
        return threats
    
    def _group_anomalies(self, anomalies: List[BehavioralAnomaly]) -> Dict[str, List[BehavioralAnomaly]]:
        """Group anomalies by similarity and affected robots."""
        groups = {}
        
        for anomaly in anomalies:
            # Group by anomaly type and robots
            group_key = f"{anomaly.anomaly_type.value}_{','.join(sorted(anomaly.affected_robots))}"
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(anomaly)
        
        return groups
    
    async def _analyze_anomaly_group(self, 
                                   anomalies: List[BehavioralAnomaly],
                                   security_context: BehavioralSecurityContext) -> Optional[BehavioralThreat]:
        """Analyze a group of anomalies for threat patterns."""
        if not anomalies:
            return None
        
        # Calculate aggregate metrics
        avg_confidence = sum(a.confidence for a in anomalies) / len(anomalies)
        max_severity = max(a.severity for a in anomalies)
        affected_robots = list(set(robot for anomaly in anomalies for robot in anomaly.affected_robots))
        
        # Determine threat type and level
        threat_type = self._classify_threat_type(anomalies)
        threat_level = self._calculate_threat_level(anomalies, security_context)
        
        # Create threat if above threshold
        if avg_confidence > 0.5 and threat_level != BehavioralThreatLevel.INFORMATIONAL:
            threat = BehavioralThreat(
                threat_type=threat_type,
                threat_level=threat_level,
                affected_robots=affected_robots,
                behavioral_anomalies=anomalies,
                confidence=avg_confidence,
                security_context=security_context,
                classification_level=security_context.classification_level
            )
            
            # Add threat-specific indicators
            threat.indicators_of_compromise = self._extract_indicators(anomalies)
            threat.potential_attack_vector = self._identify_attack_vector(anomalies)
            
            return threat
        
        return None
    
    def _classify_threat_type(self, anomalies: List[BehavioralAnomaly]) -> BehavioralSecurityEvent:
        """Classify the type of behavioral threat."""
        # Count anomaly types
        anomaly_types = [a.anomaly_type for a in anomalies]
        
        # Check for coordinated behavior
        if len(set(a.affected_robots[0] for a in anomalies if a.affected_robots)) > 1:
            return BehavioralSecurityEvent.COORDINATED_ATTACK
        
        # Check for specific patterns
        if any(a.anomaly_type == BehavioralAnomalyType.ADAPTIVE_ATTACK for a in anomalies):
            return BehavioralSecurityEvent.ADAPTIVE_ADVERSARY
        
        if any(a.anomaly_type == BehavioralAnomalyType.BEHAVIORAL_DEGRADATION for a in anomalies):
            return BehavioralSecurityEvent.BEHAVIORAL_DRIFT
        
        # Default to anomalous behavior
        return BehavioralSecurityEvent.ANOMALOUS_BEHAVIOR
    
    def _calculate_threat_level(self, 
                              anomalies: List[BehavioralAnomaly],
                              security_context: BehavioralSecurityContext) -> BehavioralThreatLevel:
        """Calculate threat level based on anomalies and security context."""
        # Base threat level on anomaly severity
        max_severity = max(a.severity for a in anomalies)
        avg_confidence = sum(a.confidence for a in anomalies) / len(anomalies)
        
        # Adjust based on classification level
        classification_multiplier = {
            ClassificationLevel.UNCLASSIFIED: 1.0,
            ClassificationLevel.CONFIDENTIAL: 1.2,
            ClassificationLevel.SECRET: 1.5,
            ClassificationLevel.TOP_SECRET: 2.0
        }.get(security_context.classification_level, 1.0)
        
        # Calculate threat score
        threat_score = 0.0
        
        if max_severity == "critical":
            threat_score = 1.0
        elif max_severity == "high":
            threat_score = 0.8
        elif max_severity == "medium":
            threat_score = 0.6
        else:
            threat_score = 0.4
        
        # Adjust by confidence and classification
        adjusted_score = threat_score * avg_confidence * classification_multiplier
        
        # Map to threat levels
        if adjusted_score >= 0.9:
            return BehavioralThreatLevel.EMERGENCY
        elif adjusted_score >= 0.8:
            return BehavioralThreatLevel.CRITICAL
        elif adjusted_score >= 0.6:
            return BehavioralThreatLevel.HIGH
        elif adjusted_score >= 0.4:
            return BehavioralThreatLevel.MEDIUM
        elif adjusted_score >= 0.2:
            return BehavioralThreatLevel.LOW
        else:
            return BehavioralThreatLevel.INFORMATIONAL
    
    def _extract_indicators(self, anomalies: List[BehavioralAnomaly]) -> List[str]:
        """Extract indicators of compromise from anomalies."""
        indicators = []
        
        for anomaly in anomalies:
            # Add anomaly-specific indicators
            indicators.append(f"behavioral_anomaly_{anomaly.anomaly_type.value}")
            
            # Add feature-specific indicators
            for feature, contribution in anomaly.feature_contributions.items():
                if contribution > 0.7:
                    indicators.append(f"high_contribution_{feature}")
        
        return list(set(indicators))
    
    def _identify_attack_vector(self, anomalies: List[BehavioralAnomaly]) -> Optional[str]:
        """Identify potential attack vector from anomalies."""
        # Analyze anomaly patterns to identify attack vectors
        anomaly_types = [a.anomaly_type for a in anomalies]
        
        if BehavioralAnomalyType.CROSS_MODAL_INCONSISTENCY in anomaly_types:
            return "sensor_manipulation"
        
        if BehavioralAnomalyType.TEMPORAL_ANOMALY in anomaly_types:
            return "timing_attack"
        
        if BehavioralAnomalyType.COORDINATED_ANOMALY in anomaly_types:
            return "coordinated_compromise"
        
        return "unknown"
    
    async def _detect_coordinated_threats(self, 
                                        anomalies: List[BehavioralAnomaly],
                                        security_context: BehavioralSecurityContext) -> List[BehavioralThreat]:
        """Detect coordinated threats across multiple robots."""
        threats = []
        
        # Group anomalies by time window
        time_groups = self._group_by_time_window(anomalies, timedelta(seconds=30))
        
        for time_window, window_anomalies in time_groups.items():
            # Check for coordinated behavior
            if len(window_anomalies) > 2:
                affected_robots = list(set(robot for anomaly in window_anomalies for robot in anomaly.affected_robots))
                
                if len(affected_robots) > 1:
                    # Create coordinated threat
                    threat = BehavioralThreat(
                        threat_type=BehavioralSecurityEvent.COORDINATED_ATTACK,
                        threat_level=BehavioralThreatLevel.HIGH,
                        affected_robots=affected_robots,
                        behavioral_anomalies=window_anomalies,
                        confidence=0.8,
                        security_context=security_context,
                        classification_level=security_context.classification_level,
                        potential_attack_vector="coordinated_compromise"
                    )
                    
                    threats.append(threat)
        
        return threats
    
    def _group_by_time_window(self, 
                            anomalies: List[BehavioralAnomaly],
                            window_size: timedelta) -> Dict[datetime, List[BehavioralAnomaly]]:
        """Group anomalies by time window."""
        groups = {}
        
        for anomaly in anomalies:
            # Round timestamp to window
            window_start = datetime.fromtimestamp(
                int(anomaly.timestamp.timestamp() / window_size.total_seconds()) * window_size.total_seconds()
            )
            
            if window_start not in groups:
                groups[window_start] = []
            groups[window_start].append(anomaly)
        
        return groups


class BehavioralSecurityIntegration:
    """
    Main integration class for behavioral security with MAESTRO framework.
    
    Features:
    - MAESTRO L1-L3 security integration
    - Classification-aware behavioral analysis
    - Automated threat detection and response
    - Audit logging and compliance
    """
    
    def __init__(self, 
                 classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED,
                 security_domain: str = "behavioral_analysis"):
        
        self.classification_level = classification_level
        self.security_domain = security_domain
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize security components
        self.classification_handler = ClassificationHandler(classification_level)
        self.audit_logger = AuditLogger(security_domain)
        self.threat_detector = ThreatDetector()
        
        # Initialize behavioral components
        self.behavioral_analyzer = BehavioralSecurityAnalyzer(self.classification_handler)
        self.behavioral_engine = BehavioralAnalysisEngine(classification_level=classification_level)
        self.real_time_monitor = RealTimeBehavioralMonitor()
        
        # Security context
        self.security_context = BehavioralSecurityContext(
            classification_level=classification_level,
            security_domain=security_domain
        )
        
        # Threat tracking
        self.active_threats: Dict[str, BehavioralThreat] = {}
        self.threat_history: List[BehavioralThreat] = []
        
        # Integration with MAESTRO layers
        self.security_dashboard = None
        self.tpm_attestation = None
        self.secure_channels = {}
        
        # Performance metrics
        self.security_metrics = {
            'threats_detected': 0,
            'threats_mitigated': 0,
            'false_positives': 0,
            'response_time_ms': [],
            'classification_violations': 0
        }
        
        self.logger.info(f"Behavioral security integration initialized for {security_domain}")
    
    async def initialize_maestro_integration(self, 
                                           dashboard: SecurityMonitoringDashboard,
                                           tpm_attestation: Optional[TPMAttestation] = None):
        """Initialize integration with MAESTRO components."""
        self.security_dashboard = dashboard
        self.tpm_attestation = tpm_attestation
        
        # Register behavioral threat handlers
        await self._register_threat_handlers()
        
        # Start security monitoring
        await self._start_security_monitoring()
        
        self.logger.info("MAESTRO integration initialized")
    
    async def _register_threat_handlers(self):
        """Register behavioral threat handlers with MAESTRO."""
        if self.security_dashboard:
            # Register behavioral threat types
            for threat_type in BehavioralSecurityEvent:
                await self.security_dashboard.register_threat_type(
                    threat_type.value,
                    self._handle_behavioral_threat
                )
    
    async def _start_security_monitoring(self):
        """Start security monitoring tasks."""
        # Start background tasks
        asyncio.create_task(self._threat_monitoring_task())
        asyncio.create_task(self._audit_logging_task())
        asyncio.create_task(self._classification_validation_task())
    
    async def analyze_behavioral_security(self, 
                                        robot_id: str,
                                        sensor_data: Dict[str, Any],
                                        user_clearance: ClassificationLevel) -> Optional[BehavioralThreat]:
        """
        Analyze behavioral data for security threats.
        
        Args:
            robot_id: Robot identifier
            sensor_data: Sensor data to analyze
            user_clearance: User's security clearance level
            
        Returns:
            Detected threat or None
        """
        start_time = datetime.now()
        
        try:
            # Verify user authorization
            if not self.security_context.is_authorized_access(user_clearance):
                await self.audit_logger.log_event(
                    "UNAUTHORIZED_ACCESS_ATTEMPT",
                    classification=self.classification_level,
                    details={
                        'robot_id': robot_id,
                        'user_clearance': user_clearance.value,
                        'required_clearance': self.classification_level.value
                    }
                )
                self.security_metrics['classification_violations'] += 1
                return None
            
            # Extract behavioral features
            features = await self.behavioral_engine.extract_behavioral_features(robot_id, sensor_data)
            
            # Detect behavioral anomalies
            anomalies = await self.behavioral_engine.detect_behavioral_anomalies(robot_id, features)
            
            # Analyze for security threats
            threats = await self.behavioral_analyzer.analyze_behavioral_threat(anomalies, self.security_context)
            
            # Process detected threats
            for threat in threats:
                await self._process_threat(threat)
            
            # Update performance metrics
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.security_metrics['response_time_ms'].append(processing_time)
            
            # Return highest priority threat
            if threats:
                return max(threats, key=lambda t: t.threat_level.value)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in behavioral security analysis: {e}")
            await self.audit_logger.log_event(
                "BEHAVIORAL_SECURITY_ERROR",
                classification=self.classification_level,
                details={'error': str(e), 'robot_id': robot_id}
            )
            return None
    
    async def _process_threat(self, threat: BehavioralThreat):
        """Process a detected behavioral threat."""
        try:
            # Store threat
            self.active_threats[threat.threat_id] = threat
            self.threat_history.append(threat)
            self.security_metrics['threats_detected'] += 1
            
            # Log threat
            await self.audit_logger.log_event(
                "BEHAVIORAL_THREAT_DETECTED",
                classification=threat.classification_level,
                details={
                    'threat_id': threat.threat_id,
                    'threat_type': threat.threat_type.value,
                    'threat_level': threat.threat_level.value,
                    'affected_robots': threat.affected_robots,
                    'confidence': threat.confidence
                }
            )
            
            # Send to security dashboard
            if self.security_dashboard:
                security_event = threat.to_security_event()
                await self.security_dashboard.process_security_event(security_event)
            
            # Trigger automated response if needed
            if threat.threat_level in [BehavioralThreatLevel.CRITICAL, BehavioralThreatLevel.EMERGENCY]:
                await self._trigger_automated_response(threat)
            
        except Exception as e:
            self.logger.error(f"Error processing threat: {e}")
    
    async def _trigger_automated_response(self, threat: BehavioralThreat):
        """Trigger automated response to high-priority threats."""
        try:
            response_actions = []
            
            # Determine response based on threat type
            if threat.threat_type == BehavioralSecurityEvent.COORDINATED_ATTACK:
                response_actions.extend([
                    "isolate_affected_robots",
                    "increase_monitoring_frequency",
                    "activate_Byzantine_defenses"
                ])
            
            elif threat.threat_type == BehavioralSecurityEvent.COMPROMISED_ROBOT:
                response_actions.extend([
                    "quarantine_robot",
                    "revoke_access_credentials",
                    "initiate_forensic_analysis"
                ])
            
            elif threat.threat_type == BehavioralSecurityEvent.SWARM_INFILTRATION:
                response_actions.extend([
                    "verify_all_robot_identities",
                    "strengthen_authentication",
                    "activate_intrusion_detection"
                ])
            
            # Execute response actions
            for action in response_actions:
                await self._execute_response_action(action, threat)
            
            # Update threat status
            threat.automated_response = True
            threat.response_actions = response_actions
            threat.mitigation_status = "in_progress"
            
            # Log response
            await self.audit_logger.log_event(
                "AUTOMATED_RESPONSE_TRIGGERED",
                classification=threat.classification_level,
                details={
                    'threat_id': threat.threat_id,
                    'response_actions': response_actions
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error in automated response: {e}")
    
    async def _execute_response_action(self, action: str, threat: BehavioralThreat):
        """Execute a specific response action."""
        try:
            if action == "isolate_affected_robots":
                # Isolate robots by restricting their communication
                for robot_id in threat.affected_robots:
                    await self._isolate_robot(robot_id)
            
            elif action == "increase_monitoring_frequency":
                # Increase monitoring frequency for affected robots
                for robot_id in threat.affected_robots:
                    await self.real_time_monitor.process_sensor_data(
                        robot_id, {}, ProcessingPriority.CRITICAL
                    )
            
            elif action == "activate_Byzantine_defenses":
                # Activate Byzantine fault tolerance mechanisms
                await self._activate_byzantine_defenses(threat)
            
            # Add more response actions as needed
            
        except Exception as e:
            self.logger.error(f"Error executing response action {action}: {e}")
    
    async def _isolate_robot(self, robot_id: str):
        """Isolate a robot from the network."""
        # Implementation would depend on specific network architecture
        self.logger.info(f"Isolating robot {robot_id} due to security threat")
    
    async def _activate_byzantine_defenses(self, threat: BehavioralThreat):
        """Activate Byzantine fault tolerance defenses."""
        # Implementation would integrate with existing Byzantine defense systems
        self.logger.info(f"Activating Byzantine defenses for threat {threat.threat_id}")
    
    async def _threat_monitoring_task(self):
        """Background task for threat monitoring."""
        while True:
            try:
                # Check for threat escalation
                for threat_id, threat in self.active_threats.items():
                    if threat.threat_level == BehavioralThreatLevel.EMERGENCY:
                        # Escalate to security dashboard
                        if self.security_dashboard:
                            await self.security_dashboard.escalate_threat(threat_id)
                
                # Clean up old threats
                cutoff_time = datetime.now() - timedelta(hours=24)
                expired_threats = [
                    threat_id for threat_id, threat in self.active_threats.items()
                    if threat.first_detected < cutoff_time and threat.mitigation_status == "completed"
                ]
                
                for threat_id in expired_threats:
                    del self.active_threats[threat_id]
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in threat monitoring task: {e}")
                await asyncio.sleep(30)
    
    async def _audit_logging_task(self):
        """Background task for audit logging."""
        while True:
            try:
                # Log periodic security metrics
                await self.audit_logger.log_event(
                    "BEHAVIORAL_SECURITY_METRICS",
                    classification=self.classification_level,
                    details=self.security_metrics
                )
                
                await asyncio.sleep(300)  # Log every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in audit logging task: {e}")
                await asyncio.sleep(300)
    
    async def _classification_validation_task(self):
        """Background task for classification validation."""
        while True:
            try:
                # Validate classification levels of stored data
                for threat in self.active_threats.values():
                    if threat.classification_level != self.classification_level:
                        # Handle classification mismatch
                        await self._handle_classification_mismatch(threat)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in classification validation task: {e}")
                await asyncio.sleep(60)
    
    async def _handle_classification_mismatch(self, threat: BehavioralThreat):
        """Handle classification level mismatches."""
        self.logger.warning(f"Classification mismatch for threat {threat.threat_id}")
        self.security_metrics['classification_violations'] += 1
        
        # Log the mismatch
        await self.audit_logger.log_event(
            "CLASSIFICATION_MISMATCH",
            classification=max(threat.classification_level, self.classification_level),
            details={
                'threat_id': threat.threat_id,
                'threat_classification': threat.classification_level.value,
                'system_classification': self.classification_level.value
            }
        )
    
    async def _handle_behavioral_threat(self, event: SecurityEvent):
        """Handle behavioral threat events from MAESTRO."""
        # This would be called by the MAESTRO framework
        self.logger.info(f"Handling behavioral threat event: {event.event_type}")
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics."""
        avg_response_time = sum(self.security_metrics['response_time_ms']) / len(self.security_metrics['response_time_ms']) if self.security_metrics['response_time_ms'] else 0
        
        return {
            'threats_detected': self.security_metrics['threats_detected'],
            'threats_mitigated': self.security_metrics['threats_mitigated'],
            'false_positives': self.security_metrics['false_positives'],
            'avg_response_time_ms': avg_response_time,
            'classification_violations': self.security_metrics['classification_violations'],
            'active_threats': len(self.active_threats),
            'threat_history_size': len(self.threat_history),
            'classification_level': self.classification_level.value,
            'security_domain': self.security_domain
        }
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of current threat landscape."""
        threat_levels = {}
        threat_types = {}
        
        for threat in self.active_threats.values():
            # Count by threat level
            level = threat.threat_level.value
            threat_levels[level] = threat_levels.get(level, 0) + 1
            
            # Count by threat type
            threat_type = threat.threat_type.value
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return {
            'active_threats': len(self.active_threats),
            'threat_levels': threat_levels,
            'threat_types': threat_types,
            'highest_threat_level': max([t.threat_level.value for t in self.active_threats.values()], default='informational'),
            'last_threat_detected': max([t.first_detected for t in self.active_threats.values()], default=datetime.min).isoformat() if self.active_threats else None
        }


# Example usage and testing
async def demo_behavioral_security_integration():
    """Demonstrate behavioral security integration."""
    
    # Initialize integration
    integration = BehavioralSecurityIntegration(
        classification_level=ClassificationLevel.CONFIDENTIAL,
        security_domain="robotics_behavioral_analysis"
    )
    
    # Simulate behavioral security analysis
    robot_id = "secure_robot_001"
    sensor_data = {
        'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
        'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
        'communication': {'message_frequency': 10.0, 'response_time': 0.1},  # Suspicious values
        'power': {'consumption': 500.0}  # Abnormal power consumption
    }
    
    try:
        # Analyze for threats
        print("Analyzing behavioral security...")
        threat = await integration.analyze_behavioral_security(
            robot_id, sensor_data, ClassificationLevel.CONFIDENTIAL
        )
        
        if threat:
            print(f"Threat detected: {threat.threat_type.value} with {threat.threat_level.value} level")
            print(f"Affected robots: {threat.affected_robots}")
            print(f"Confidence: {threat.confidence:.3f}")
        else:
            print("No threats detected")
        
        # Get security metrics
        metrics = integration.get_security_metrics()
        print(f"Security metrics: {metrics}")
        
        # Get threat summary
        threat_summary = await integration.get_threat_summary()
        print(f"Threat summary: {threat_summary}")
        
        return True
        
    except Exception as e:
        print(f"Demo failed: {e}")
        return False


if __name__ == "__main__":
    # Run demo
    asyncio.run(demo_behavioral_security_integration())