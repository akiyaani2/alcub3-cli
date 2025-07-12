#!/usr/bin/env python3
"""
ALCUB3 Zero-Trust Integration Layer
Unified orchestration of all zero-trust components with MAESTRO framework

This module provides the integration layer that:
- Orchestrates all zero-trust components
- Integrates with existing MAESTRO L1-L3 layers
- Provides unified API for zero-trust operations
- Manages component lifecycle and dependencies
- Enables cross-component policy enforcement

Patent-Pending Integration:
- Unified zero-trust orchestration
- Cross-layer security correlation
- Adaptive security posture management
- Real-time threat response coordination
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from pathlib import Path
import json

# Import zero-trust components
from zero_trust import (
    MicrosegmentationEngine,
    ContinuousVerificationSystem,
    IdentityAccessControl,
    DeviceTrustScorer,
    ZeroTrustPolicyEngine,
    ZeroTrustNetworkGateway
)

# Import MAESTRO components
import sys
sys.path.append(str(Path(__file__).parent.parent))

from classification import ClassificationLevel
from audit_logger import AuditLogger
from exceptions import SecurityError
from real_time_monitor import RealTimeMonitor
from clearance_access_control import ClearanceAccessControl
from crypto_utils import CryptoUtils
from hsm_integration import HSMIntegration
from protocol_filtering_diodes import ProtocolFilteringDiode

# Import additional shared components
from jit_privilege_engine import JITPrivilegeEngine
from mtls_manager import MTLSManager

logger = logging.getLogger(__name__)


class SecurityPosture(Enum):
    """Overall security posture levels."""
    BASELINE = "baseline"
    ELEVATED = "elevated"
    HIGH_ALERT = "high_alert"
    LOCKDOWN = "lockdown"
    EMERGENCY = "emergency"


class ComponentStatus(Enum):
    """Component operational status."""
    INITIALIZING = "initializing"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    MAINTENANCE = "maintenance"


@dataclass
class ComponentHealth:
    """Health status of a zero-trust component."""
    component_name: str
    status: ComponentStatus
    last_check: datetime
    metrics: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class SecurityEvent:
    """Security event from zero-trust components."""
    event_id: str
    timestamp: datetime
    component: str
    event_type: str
    severity: str  # low, medium, high, critical
    classification: ClassificationLevel
    details: Dict[str, Any]
    response_actions: List[str] = field(default_factory=list)


@dataclass
class ZeroTrustContext:
    """Unified context for zero-trust decisions."""
    request_id: str
    timestamp: datetime
    # Subject context
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    # Network context
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    network_zone: Optional[str] = None
    # Resource context
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    action: Optional[str] = None
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    # Risk context
    risk_score: float = 0.0
    trust_score: float = 0.0
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class ZeroTrustOrchestrator:
    """
    Master orchestrator for all zero-trust components.
    
    This class provides unified management and coordination of all
    zero-trust security components with MAESTRO framework integration.
    """
    
    def __init__(
        self,
        orchestrator_id: str,
        audit_logger: AuditLogger,
        monitor: Optional[RealTimeMonitor] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the zero-trust orchestrator.
        
        Args:
            orchestrator_id: Unique orchestrator identifier
            audit_logger: Audit logger for security events
            monitor: Real-time monitoring system
            config: Configuration parameters
        """
        self.orchestrator_id = orchestrator_id
        self.audit_logger = audit_logger
        self.monitor = monitor
        self.config = config or {}
        
        # Initialize components
        self.components: Dict[str, Any] = {}
        self.component_health: Dict[str, ComponentHealth] = {}
        
        # Security posture
        self.security_posture = SecurityPosture.BASELINE
        self.posture_thresholds = {
            SecurityPosture.ELEVATED: 30,     # Risk score threshold
            SecurityPosture.HIGH_ALERT: 50,
            SecurityPosture.LOCKDOWN: 70,
            SecurityPosture.EMERGENCY: 85
        }
        
        # Event handling
        self.security_events: List[SecurityEvent] = []
        self.event_handlers: Dict[str, List[Callable]] = {}
        
        # Cross-component correlation
        self.correlation_rules: List[Dict[str, Any]] = []
        self.active_incidents: Dict[str, Dict[str, Any]] = {}
        
        # Performance metrics
        self.metrics = {
            'requests_processed': 0,
            'avg_decision_time_ms': 0.0,
            'security_events': 0,
            'posture_changes': 0,
            'component_failures': 0
        }
        
        # Background tasks
        self._running = False
        self._health_check_task = None
        self._correlation_task = None
        
        logger.info("Zero-trust orchestrator %s initialized", orchestrator_id)
    
    async def initialize(self):
        """Initialize all zero-trust components."""
        try:
            # Create shared dependencies
            crypto_utils = CryptoUtils()
            hsm = HSMIntegration() if self.config.get('enable_hsm', True) else None
            pfd = ProtocolFilteringDiode(
                diode_id="zt_pfd",
                audit_logger=self.audit_logger
            ) if self.config.get('enable_pfd', False) else None
            
            # Initialize microsegmentation engine
            logger.info("Initializing microsegmentation engine...")
            self.components['microsegmentation'] = MicrosegmentationEngine(
                audit_logger=self.audit_logger,
                monitor=self.monitor,
                enable_hardware_acceleration=self.config.get('hardware_acceleration', True)
            )
            
            # Initialize continuous verification
            logger.info("Initializing continuous verification system...")
            self.components['continuous_verification'] = ContinuousVerificationSystem(
                audit_logger=self.audit_logger,
                monitor=self.monitor,
                ml_model_path=self.config.get('ml_model_path'),
                challenge_threshold=self.config.get('challenge_threshold', 60.0)
            )
            
            # Initialize identity access control
            logger.info("Initializing identity access control...")
            self.components['identity_access'] = IdentityAccessControl(
                audit_logger=self.audit_logger,
                enable_policy_cache=self.config.get('enable_policy_cache', True)
            )
            
            # Initialize device trust scorer
            logger.info("Initializing device trust scorer...")
            self.components['device_trust'] = DeviceTrustScorer(
                audit_logger=self.audit_logger,
                hsm_integration=hsm,
                monitor=self.monitor,
                attestation_ca_path=self.config.get('attestation_ca_path')
            )
            
            # Initialize policy engine
            logger.info("Initializing zero-trust policy engine...")
            self.components['policy_engine'] = ZeroTrustPolicyEngine(
                audit_logger=self.audit_logger,
                monitor=self.monitor,
                enable_caching=self.config.get('enable_policy_cache', True)
            )
            
            # Initialize network gateway
            logger.info("Initializing zero-trust network gateway...")
            self.components['network_gateway'] = ZeroTrustNetworkGateway(
                gateway_id=f"gw_{self.orchestrator_id}",
                audit_logger=self.audit_logger,
                crypto_utils=crypto_utils,
                pfd=pfd,
                monitor=self.monitor
            )
            
            # Initialize MAESTRO integrations
            await self._initialize_maestro_integrations()
            
            # Set all components as healthy initially
            for component_name in self.components:
                self.component_health[component_name] = ComponentHealth(
                    component_name=component_name,
                    status=ComponentStatus.HEALTHY,
                    last_check=datetime.utcnow()
                )
            
            # Start background tasks
            self._running = True
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            self._correlation_task = asyncio.create_task(self._correlation_loop())
            
            # Load correlation rules
            await self._load_correlation_rules()
            
            # Audit log
            await self.audit_logger.log_event(
                "ZERO_TRUST_ORCHESTRATOR_INITIALIZED",
                classification=ClassificationLevel.UNCLASSIFIED,
                details={
                    'orchestrator_id': self.orchestrator_id,
                    'components': list(self.components.keys()),
                    'initial_posture': self.security_posture.value
                }
            )
            
            logger.info("Zero-trust orchestrator initialization complete")
            
        except Exception as e:
            logger.error("Failed to initialize orchestrator: %s", str(e))
            raise SecurityError(f"Orchestrator initialization failed: {str(e)}")
    
    async def _initialize_maestro_integrations(self):
        """Initialize integrations with existing MAESTRO components."""
        # JIT Privilege Engine integration
        if 'jit_privilege' in self.config.get('maestro_integrations', []):
            self.components['jit_privilege'] = JITPrivilegeEngine(
                audit_logger=self.audit_logger
            )
        
        # mTLS Manager integration
        if 'mtls' in self.config.get('maestro_integrations', []):
            self.components['mtls_manager'] = MTLSManager(
                audit_logger=self.audit_logger
            )
        
        # Clearance Access Control integration
        self.components['clearance_control'] = ClearanceAccessControl()
    
    async def evaluate_access(
        self,
        context: ZeroTrustContext
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate access request through all zero-trust components.
        
        Args:
            context: Unified zero-trust context
            
        Returns:
            Tuple of (allowed, decision_details)
        """
        start_time = time.time()
        decision_details = {
            'request_id': context.request_id,
            'timestamp': datetime.utcnow().isoformat(),
            'components_consulted': [],
            'risk_factors': [],
            'decision_factors': []
        }
        
        try:
            # 1. Check device trust
            if context.device_id:
                device_trust = await self._evaluate_device_trust(context)
                decision_details['device_trust_score'] = device_trust
                decision_details['components_consulted'].append('device_trust')
                
                if device_trust < 40:  # Low trust
                    decision_details['risk_factors'].append('Low device trust')
                    context.risk_score += 20
            
            # 2. Verify continuous authentication
            if context.session_id:
                session_valid, auth_methods = await self._verify_session(context)
                decision_details['session_valid'] = session_valid
                decision_details['components_consulted'].append('continuous_verification')
                
                if not session_valid:
                    decision_details['decision_factors'].append('Invalid session')
                    return False, decision_details
                
                if auth_methods:
                    decision_details['required_auth_methods'] = [
                        method.value for method in auth_methods
                    ]
            
            # 3. Check microsegmentation
            if context.source_ip and context.destination_ip:
                segment_allowed = await self._check_microsegmentation(context)
                decision_details['segment_allowed'] = segment_allowed
                decision_details['components_consulted'].append('microsegmentation')
                
                if not segment_allowed:
                    decision_details['decision_factors'].append('Segmentation policy denied')
                    return False, decision_details
            
            # 4. Evaluate identity-based access
            if context.user_id and context.resource_id:
                identity_decision = await self._evaluate_identity_access(context)
                decision_details['identity_decision'] = identity_decision
                decision_details['components_consulted'].append('identity_access')
                
                if identity_decision != 'permit':
                    decision_details['decision_factors'].append('Identity access denied')
                    return False, decision_details
            
            # 5. Check zero-trust policies
            policy_decision = await self._evaluate_policies(context)
            decision_details['policy_decision'] = policy_decision
            decision_details['components_consulted'].append('policy_engine')
            
            if policy_decision == 'deny':
                decision_details['decision_factors'].append('Policy denied access')
                return False, decision_details
            
            # 6. Calculate overall risk score
            overall_risk = context.risk_score
            decision_details['overall_risk_score'] = overall_risk
            
            # 7. Check security posture
            if overall_risk > self._get_posture_risk_threshold():
                decision_details['decision_factors'].append(
                    f'Risk exceeds threshold for {self.security_posture.value} posture'
                )
                return False, decision_details
            
            # Access allowed
            decision_details['decision'] = 'allow'
            decision_details['decision_factors'].append('All checks passed')
            
            # Update metrics
            self.metrics['requests_processed'] += 1
            decision_time = (time.time() - start_time) * 1000
            self._update_avg_decision_time(decision_time)
            
            # Audit log
            await self.audit_logger.log_event(
                "ZERO_TRUST_ACCESS_DECISION",
                classification=context.classification,
                details={
                    'request_id': context.request_id,
                    'decision': 'allow',
                    'risk_score': overall_risk,
                    'decision_time_ms': decision_time
                }
            )
            
            return True, decision_details
            
        except Exception as e:
            logger.error("Error evaluating access: %s", str(e))
            decision_details['error'] = str(e)
            decision_details['decision'] = 'deny'
            return False, decision_details
    
    async def _evaluate_device_trust(self, context: ZeroTrustContext) -> float:
        """Evaluate device trust score."""
        device_trust = self.components.get('device_trust')
        if not device_trust:
            return 50.0  # Default medium trust
        
        try:
            trust_score = await device_trust.calculate_trust_score(context.device_id)
            return trust_score.overall_score
        except Exception as e:
            logger.error("Device trust evaluation failed: %s", str(e))
            return 0.0
    
    async def _verify_session(
        self,
        context: ZeroTrustContext
    ) -> Tuple[bool, Optional[List[Any]]]:
        """Verify continuous authentication session."""
        continuous_verification = self.components.get('continuous_verification')
        if not continuous_verification:
            return True, None
        
        try:
            activity_data = {
                'access_rate': context.metadata.get('access_rate', 10),
                'data_volume': context.metadata.get('data_volume', 0),
                'privileged_operations': context.metadata.get('privileged_ops', 0)
            }
            
            return await continuous_verification.verify_session(
                context.session_id,
                activity_data
            )
        except Exception as e:
            logger.error("Session verification failed: %s", str(e))
            return False, None
    
    async def _check_microsegmentation(self, context: ZeroTrustContext) -> bool:
        """Check microsegmentation policy."""
        microsegmentation = self.components.get('microsegmentation')
        if not microsegmentation:
            return True
        
        try:
            allowed, reason = await microsegmentation.process_packet(
                source_ip=context.source_ip,
                destination_ip=context.destination_ip,
                protocol=context.metadata.get('protocol', 'tcp'),
                port=context.metadata.get('port', 443),
                classification=context.classification
            )
            return allowed
        except Exception as e:
            logger.error("Microsegmentation check failed: %s", str(e))
            return False
    
    async def _evaluate_identity_access(self, context: ZeroTrustContext) -> str:
        """Evaluate identity-based access control."""
        identity_access = self.components.get('identity_access')
        if not identity_access:
            return 'permit'
        
        try:
            # Build ABAC context
            from zero_trust.identity_access_control import (
                Subject, Resource, Action, Environment
            )
            
            subject = Subject(
                id=context.user_id,
                type='user',
                clearance_level=context.metadata.get('clearance_level')
            )
            
            resource = Resource(
                id=context.resource_id,
                type=context.resource_type or 'unknown',
                classification=context.classification
            )
            
            action = Action(
                id=context.action or 'access',
                type=context.action or 'read'
            )
            
            environment = Environment(
                source_ip=context.source_ip,
                device_trust_score=context.trust_score / 100.0,
                network_zone=context.network_zone,
                session_id=context.session_id
            )
            
            response = await identity_access.evaluate_access(
                subject, resource, action, environment
            )
            
            return response.decision.value
            
        except Exception as e:
            logger.error("Identity access evaluation failed: %s", str(e))
            return 'deny'
    
    async def _evaluate_policies(self, context: ZeroTrustContext) -> str:
        """Evaluate zero-trust policies."""
        policy_engine = self.components.get('policy_engine')
        if not policy_engine:
            return 'allow'
        
        try:
            # Build policy context
            policy_context = {
                'subject': {'id': context.user_id},
                'resource': {'id': context.resource_id, 'type': context.resource_type},
                'action': {'type': context.action},
                'network': {'zone': context.network_zone, 'source_ip': context.source_ip},
                'device': {'id': context.device_id, 'trust_score': context.trust_score},
                'classification': context.classification
            }
            
            policies = await policy_engine.evaluate_policies(policy_context)
            
            # Get highest priority decision
            if policies:
                return policies[0][1].value
            else:
                return 'deny'  # Default deny
                
        except Exception as e:
            logger.error("Policy evaluation failed: %s", str(e))
            return 'deny'
    
    def _get_posture_risk_threshold(self) -> float:
        """Get risk threshold for current security posture."""
        base_thresholds = {
            SecurityPosture.BASELINE: 70,
            SecurityPosture.ELEVATED: 60,
            SecurityPosture.HIGH_ALERT: 40,
            SecurityPosture.LOCKDOWN: 20,
            SecurityPosture.EMERGENCY: 10
        }
        return base_thresholds.get(self.security_posture, 50)
    
    async def update_security_posture(self, new_posture: SecurityPosture, reason: str):
        """Update the overall security posture."""
        old_posture = self.security_posture
        self.security_posture = new_posture
        self.metrics['posture_changes'] += 1
        
        # Notify all components of posture change
        for component_name, component in self.components.items():
            if hasattr(component, 'update_security_posture'):
                try:
                    await component.update_security_posture(new_posture)
                except Exception as e:
                    logger.error("Failed to update posture for %s: %s",
                               component_name, str(e))
        
        # Create security event
        event = SecurityEvent(
            event_id=f"posture_change_{time.time()}",
            timestamp=datetime.utcnow(),
            component='orchestrator',
            event_type='posture_change',
            severity='high',
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'old_posture': old_posture.value,
                'new_posture': new_posture.value,
                'reason': reason
            }
        )
        
        await self._handle_security_event(event)
        
        # Audit log
        await self.audit_logger.log_event(
            "ZERO_TRUST_POSTURE_CHANGE",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'old_posture': old_posture.value,
                'new_posture': new_posture.value,
                'reason': reason
            }
        )
        
        logger.info("Security posture changed from %s to %s: %s",
                   old_posture.value, new_posture.value, reason)
    
    async def _handle_security_event(self, event: SecurityEvent):
        """Handle a security event from any component."""
        self.security_events.append(event)
        self.metrics['security_events'] += 1
        
        # Trim old events
        if len(self.security_events) > 10000:
            self.security_events = self.security_events[-10000:]
        
        # Call registered handlers
        handlers = self.event_handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error("Event handler error: %s", str(e))
        
        # Check for correlation
        await self._correlate_event(event)
        
        # Monitor high severity events
        if event.severity in ['high', 'critical']:
            if self.monitor:
                await self.monitor.record_event(
                    'security.zero_trust.high_severity_event',
                    {
                        'event_type': event.event_type,
                        'component': event.component,
                        'severity': event.severity
                    }
                )
    
    async def _correlate_event(self, event: SecurityEvent):
        """Correlate event with other recent events."""
        # Simple correlation based on time window and event patterns
        time_window = timedelta(minutes=5)
        recent_events = [
            e for e in self.security_events
            if (event.timestamp - e.timestamp) < time_window
        ]
        
        # Check correlation rules
        for rule in self.correlation_rules:
            if self._match_correlation_rule(event, recent_events, rule):
                await self._create_incident(event, recent_events, rule)
    
    def _match_correlation_rule(
        self,
        event: SecurityEvent,
        recent_events: List[SecurityEvent],
        rule: Dict[str, Any]
    ) -> bool:
        """Check if events match a correlation rule."""
        # Simplified correlation matching
        required_count = rule.get('event_count', 1)
        event_types = rule.get('event_types', [])
        
        matching_events = [
            e for e in recent_events
            if e.event_type in event_types
        ]
        
        return len(matching_events) >= required_count
    
    async def _create_incident(
        self,
        trigger_event: SecurityEvent,
        related_events: List[SecurityEvent],
        rule: Dict[str, Any]
    ):
        """Create a security incident from correlated events."""
        incident_id = f"incident_{time.time()}"
        
        incident = {
            'incident_id': incident_id,
            'created_at': datetime.utcnow(),
            'trigger_event': trigger_event.event_id,
            'related_events': [e.event_id for e in related_events],
            'rule_name': rule.get('name', 'unknown'),
            'severity': rule.get('severity', 'high'),
            'auto_response': rule.get('auto_response', [])
        }
        
        self.active_incidents[incident_id] = incident
        
        # Execute auto-response actions
        for action in incident['auto_response']:
            await self._execute_response_action(action, incident)
        
        logger.warning("Security incident created: %s", incident_id)
    
    async def _execute_response_action(self, action: str, incident: Dict[str, Any]):
        """Execute an automated response action."""
        logger.info("Executing response action: %s for incident %s",
                   action, incident['incident_id'])
        
        if action == 'elevate_posture':
            if self.security_posture == SecurityPosture.BASELINE:
                await self.update_security_posture(
                    SecurityPosture.ELEVATED,
                    f"Automated response to incident {incident['incident_id']}"
                )
        
        elif action == 'block_source':
            # Would implement network blocking
            pass
        
        elif action == 'force_reauth':
            # Would force re-authentication for affected sessions
            pass
    
    async def _health_check_loop(self):
        """Background task to monitor component health."""
        while self._running:
            try:
                for component_name, component in self.components.items():
                    health = await self._check_component_health(
                        component_name, component
                    )
                    
                    old_status = self.component_health.get(
                        component_name, ComponentHealth(
                            component_name=component_name,
                            status=ComponentStatus.INITIALIZING,
                            last_check=datetime.utcnow()
                        )
                    ).status
                    
                    self.component_health[component_name] = health
                    
                    # Handle status changes
                    if health.status != old_status:
                        if health.status == ComponentStatus.FAILED:
                            self.metrics['component_failures'] += 1
                            await self._handle_component_failure(
                                component_name, health
                            )
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error("Health check error: %s", str(e))
    
    async def _check_component_health(
        self,
        component_name: str,
        component: Any
    ) -> ComponentHealth:
        """Check health of a specific component."""
        health = ComponentHealth(
            component_name=component_name,
            status=ComponentStatus.HEALTHY,
            last_check=datetime.utcnow()
        )
        
        try:
            # Get component statistics
            if hasattr(component, 'get_statistics'):
                stats = component.get_statistics()
                health.metrics.update(stats)
            
            # Component-specific health checks
            if component_name == 'microsegmentation':
                if stats.get('avg_decision_time_ms', 0) > 10:
                    health.warnings.append("High decision latency")
                    health.status = ComponentStatus.DEGRADED
            
            elif component_name == 'continuous_verification':
                if stats.get('challenged_sessions', 0) > stats.get('active_sessions', 1) * 0.5:
                    health.warnings.append("High challenge rate")
                    health.status = ComponentStatus.DEGRADED
            
            elif component_name == 'device_trust':
                if stats.get('untrusted_devices', 0) > stats.get('devices_registered', 1) * 0.2:
                    health.warnings.append("High untrusted device ratio")
                    health.status = ComponentStatus.DEGRADED
            
        except Exception as e:
            health.status = ComponentStatus.FAILED
            health.errors.append(str(e))
        
        return health
    
    async def _handle_component_failure(
        self,
        component_name: str,
        health: ComponentHealth
    ):
        """Handle component failure."""
        event = SecurityEvent(
            event_id=f"component_failure_{time.time()}",
            timestamp=datetime.utcnow(),
            component='orchestrator',
            event_type='component_failure',
            severity='critical',
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'component': component_name,
                'errors': health.errors
            }
        )
        
        await self._handle_security_event(event)
        
        # Attempt recovery
        logger.error("Component %s failed, attempting recovery...", component_name)
        # Recovery logic would go here
    
    async def _correlation_loop(self):
        """Background task for event correlation."""
        while self._running:
            try:
                # Periodic correlation analysis
                await asyncio.sleep(60)  # Run every minute
                
                # Clean up old incidents
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                old_incidents = [
                    incident_id for incident_id, incident in self.active_incidents.items()
                    if incident['created_at'] < cutoff_time
                ]
                
                for incident_id in old_incidents:
                    del self.active_incidents[incident_id]
                
            except Exception as e:
                logger.error("Correlation loop error: %s", str(e))
    
    async def _load_correlation_rules(self):
        """Load event correlation rules."""
        # Default correlation rules
        self.correlation_rules = [
            {
                'name': 'repeated_auth_failures',
                'event_types': ['auth_failure', 'challenge_failed'],
                'event_count': 5,
                'time_window_minutes': 5,
                'severity': 'high',
                'auto_response': ['elevate_posture']
            },
            {
                'name': 'network_scanning',
                'event_types': ['segmentation_violation', 'policy_violation'],
                'event_count': 10,
                'time_window_minutes': 2,
                'severity': 'critical',
                'auto_response': ['block_source', 'elevate_posture']
            },
            {
                'name': 'privilege_escalation_attempt',
                'event_types': ['privilege_denied', 'identity_access_denied'],
                'event_count': 3,
                'time_window_minutes': 10,
                'severity': 'high',
                'auto_response': ['force_reauth']
            }
        ]
    
    def _update_avg_decision_time(self, decision_time_ms: float):
        """Update average decision time metric."""
        current_avg = self.metrics['avg_decision_time_ms']
        total_requests = self.metrics['requests_processed']
        
        # Calculate running average
        self.metrics['avg_decision_time_ms'] = (
            (current_avg * (total_requests - 1) + decision_time_ms) / total_requests
        )
    
    def register_event_handler(self, event_type: str, handler: Callable):
        """Register a handler for specific event types."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    async def stop(self):
        """Stop the orchestrator and all components."""
        self._running = False
        
        # Cancel background tasks
        if self._health_check_task:
            self._health_check_task.cancel()
        if self._correlation_task:
            self._correlation_task.cancel()
        
        # Stop all components
        for component_name, component in self.components.items():
            if hasattr(component, 'stop'):
                try:
                    await component.stop()
                except Exception as e:
                    logger.error("Error stopping %s: %s", component_name, str(e))
        
        await self.audit_logger.log_event(
            "ZERO_TRUST_ORCHESTRATOR_STOPPED",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'orchestrator_id': self.orchestrator_id,
                'total_requests': self.metrics['requests_processed'],
                'total_events': self.metrics['security_events']
            }
        )
        
        logger.info("Zero-trust orchestrator stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status."""
        return {
            'orchestrator_id': self.orchestrator_id,
            'security_posture': self.security_posture.value,
            'component_health': {
                name: {
                    'status': health.status.value,
                    'last_check': health.last_check.isoformat(),
                    'warnings': health.warnings,
                    'errors': health.errors
                }
                for name, health in self.component_health.items()
            },
            'active_incidents': len(self.active_incidents),
            'metrics': self.metrics
        }