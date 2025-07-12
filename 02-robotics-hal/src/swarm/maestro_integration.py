#!/usr/bin/env python3
"""
ALCUB3 Swarm MAESTRO Security Integration
Integrates swarm intelligence with MAESTRO L1-L3 security framework

This module provides comprehensive security integration for swarm operations
including hardware attestation, network security, and application controls.
"""

import asyncio
import time
import uuid
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

# Import security framework components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.real_time_monitor import RealTimeSecurityMonitor
from shared.mtls_manager import MTLSManager
from shared.crypto_utils import CryptoUtils
from shared.hsm_integration import HSMInterface

# Import HAL components
sys.path.append(str(Path(__file__).parent.parent))
from hal.tpm_security_integration import TPMSecurityIntegration
from hal.security_hal import SecurityHAL

# Import swarm components
from .distributed_task_allocator import SwarmTask, SwarmMember, DistributedTaskAllocator
from .consensus_protocol import EnhancedConsensusProtocol, CryptoCredentials
from .secure_p2p_network import SecureSwarmNetwork

logger = logging.getLogger(__name__)


class MAESTROLayer(Enum):
    """MAESTRO security layers."""
    L1_PHYSICAL = "L1_PHYSICAL"      # Hardware/TPM attestation
    L2_NETWORK = "L2_NETWORK"        # Network security/mTLS
    L3_APPLICATION = "L3_APPLICATION" # Application controls


class SecurityViolationType(Enum):
    """Types of security violations."""
    ATTESTATION_FAILURE = "attestation_failure"
    CLASSIFICATION_BREACH = "classification_breach"
    UNAUTHORIZED_TASK = "unauthorized_task"
    CONSENSUS_MANIPULATION = "consensus_manipulation"
    NETWORK_INTRUSION = "network_intrusion"
    RESOURCE_ABUSE = "resource_abuse"


@dataclass
class SwarmSecurityPolicy:
    """Security policy for swarm operations."""
    policy_id: str
    name: str
    classification_level: ClassificationLevel
    layer: MAESTROLayer
    rules: List[Dict[str, Any]]
    enforcement_mode: str  # "strict", "permissive", "monitor"
    created_at: datetime
    updated_at: datetime
    
    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Evaluate policy against context."""
        for rule in self.rules:
            if not self._evaluate_rule(rule, context):
                return False, rule.get('violation_message', 'Policy violation')
        return True, None
    
    def _evaluate_rule(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate individual rule."""
        rule_type = rule.get('type')
        
        if rule_type == 'classification_check':
            required_level = ClassificationLevel[rule['required_level']]
            context_level = context.get('classification_level', ClassificationLevel.UNCLASSIFIED)
            return context_level.value >= required_level.value
        
        elif rule_type == 'capability_required':
            required_caps = set(rule['capabilities'])
            context_caps = set(context.get('capabilities', []))
            return required_caps.issubset(context_caps)
        
        elif rule_type == 'attestation_required':
            return context.get('attestation_valid', False)
        
        elif rule_type == 'network_zone':
            allowed_zones = set(rule['allowed_zones'])
            context_zone = context.get('network_zone', 'unknown')
            return context_zone in allowed_zones
        
        return True


@dataclass
class SecurityIncident:
    """Security incident record."""
    incident_id: str
    violation_type: SecurityViolationType
    severity: str  # "critical", "high", "medium", "low"
    affected_members: List[str]
    task_id: Optional[str]
    details: Dict[str, Any]
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    response_actions: List[str] = field(default_factory=list)


class L1PhysicalSecurity:
    """Layer 1: Physical/Hardware Security Integration."""
    
    def __init__(self, tpm_integration: Optional[TPMSecurityIntegration] = None):
        self.tpm = tpm_integration
        self.attestation_cache: Dict[str, Dict[str, Any]] = {}
        self.attestation_validity = timedelta(minutes=30)
        
    async def attest_swarm_member(self, member: SwarmMember) -> Tuple[bool, Dict[str, Any]]:
        """Perform hardware attestation for swarm member."""
        # Check cache
        cached = self.attestation_cache.get(member.member_id)
        if cached:
            if datetime.now() - cached['timestamp'] < self.attestation_validity:
                return cached['valid'], cached['details']
        
        # Perform attestation
        if self.tpm:
            try:
                # Generate attestation quote
                nonce = uuid.uuid4().bytes
                quote = await self.tpm.generate_attestation_quote(nonce)
                
                # Verify quote
                is_valid = await self.tpm.verify_attestation_quote(quote, nonce)
                
                # Get platform measurements
                measurements = await self.tpm.get_platform_measurements()
                
                attestation_result = {
                    'valid': is_valid,
                    'timestamp': datetime.now(),
                    'details': {
                        'quote_hash': hashlib.sha256(quote).hexdigest(),
                        'platform_measurements': measurements,
                        'tpm_version': self.tpm.get_tpm_version()
                    }
                }
                
                # Cache result
                self.attestation_cache[member.member_id] = attestation_result
                
                return is_valid, attestation_result['details']
                
            except Exception as e:
                logger.error("TPM attestation failed for %s: %s", member.member_id, e)
                return False, {'error': str(e)}
        
        # Fallback if no TPM
        return True, {'warning': 'No TPM available, attestation bypassed'}
    
    async def verify_secure_boot(self, member_id: str) -> bool:
        """Verify secure boot status."""
        if self.tpm:
            return await self.tpm.verify_secure_boot_status()
        return True
    
    async def seal_task_data(self, task: SwarmTask, pcr_policy: List[int]) -> bytes:
        """Seal sensitive task data to TPM."""
        if self.tpm:
            task_data = json.dumps({
                'task_id': task.task_id,
                'classification': task.classification.value,
                'payload': task.payload
            }).encode()
            
            return await self.tpm.seal_data(task_data, pcr_policy)
        
        # Fallback encryption
        crypto = CryptoUtils()
        return crypto.encrypt(json.dumps(task.payload).encode())


class L2NetworkSecurity:
    """Layer 2: Network Security Integration."""
    
    def __init__(self, mtls_manager: MTLSManager):
        self.mtls = mtls_manager
        self.network_zones: Dict[str, Set[str]] = {
            'classified': set(),
            'unclassified': set(),
            'dmz': set()
        }
        self.connection_audit: deque = deque(maxlen=10000)
    
    async def establish_secure_channel(
        self,
        source_member: str,
        target_member: str,
        classification: ClassificationLevel
    ) -> Tuple[bool, Optional[str]]:
        """Establish mTLS channel between swarm members."""
        # Verify certificates
        source_cert_valid = await self.mtls.verify_client_certificate(source_member)
        target_cert_valid = await self.mtls.verify_client_certificate(target_member)
        
        if not source_cert_valid or not target_cert_valid:
            return False, "Certificate validation failed"
        
        # Check network zone compatibility
        source_zone = self._get_member_zone(source_member)
        target_zone = self._get_member_zone(target_member)
        
        if not self._can_communicate(source_zone, target_zone, classification):
            return False, f"Network zone policy violation: {source_zone} -> {target_zone}"
        
        # Establish channel
        channel_id = f"{source_member}:{target_member}:{uuid.uuid4()}"
        
        # Audit connection
        self.connection_audit.append({
            'channel_id': channel_id,
            'source': source_member,
            'target': target_member,
            'classification': classification.value,
            'timestamp': datetime.now(),
            'source_zone': source_zone,
            'target_zone': target_zone
        })
        
        return True, channel_id
    
    def _get_member_zone(self, member_id: str) -> str:
        """Get network zone for member."""
        for zone, members in self.network_zones.items():
            if member_id in members:
                return zone
        return 'unknown'
    
    def _can_communicate(
        self,
        source_zone: str,
        target_zone: str,
        classification: ClassificationLevel
    ) -> bool:
        """Check if communication is allowed between zones."""
        # Classified data cannot flow to unclassified zones
        if classification in [ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET]:
            if target_zone == 'unclassified':
                return False
        
        # DMZ can only communicate with specific zones
        if source_zone == 'dmz' and target_zone == 'classified':
            return False
        
        return True
    
    async def monitor_network_anomalies(
        self,
        network_metrics: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Monitor for network security anomalies."""
        anomalies = []
        
        # Check for unusual traffic patterns
        if network_metrics.get('packet_rate', 0) > 10000:
            anomalies.append({
                'type': 'high_packet_rate',
                'severity': 'medium',
                'details': network_metrics
            })
        
        # Check for unauthorized connections
        recent_connections = list(self.connection_audit)[-100:]
        unauthorized = [
            conn for conn in recent_connections
            if conn['source_zone'] == 'unknown' or conn['target_zone'] == 'unknown'
        ]
        
        if unauthorized:
            anomalies.append({
                'type': 'unauthorized_connections',
                'severity': 'high',
                'count': len(unauthorized),
                'samples': unauthorized[:5]
            })
        
        return anomalies


class L3ApplicationSecurity:
    """Layer 3: Application Security Controls."""
    
    def __init__(self, security_hal: SecurityHAL):
        self.security_hal = security_hal
        self.task_authorization_cache: Dict[str, bool] = {}
        self.capability_registry: Dict[str, Set[str]] = {}
        self.rate_limits: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
    
    async def authorize_task_execution(
        self,
        task: SwarmTask,
        member: SwarmMember
    ) -> Tuple[bool, Optional[str]]:
        """Authorize task execution at application layer."""
        # Check classification clearance
        if member.classification_clearance.value < task.classification.value:
            return False, "Insufficient classification clearance"
        
        # Verify required capabilities
        member_caps = {cap.capability_id for cap in member.capabilities}
        missing_caps = set(task.required_capabilities) - member_caps
        
        if missing_caps:
            return False, f"Missing capabilities: {missing_caps}"
        
        # Check rate limits
        if not self._check_rate_limit(member.member_id, task.task_type):
            return False, "Rate limit exceeded"
        
        # Application-specific authorization
        auth_context = {
            'task_id': task.task_id,
            'task_type': task.task_type,
            'member_id': member.member_id,
            'classification': task.classification
        }
        
        authorized = await self.security_hal.authorize_operation(
            'task_execution',
            auth_context
        )
        
        # Cache result
        cache_key = f"{task.task_id}:{member.member_id}"
        self.task_authorization_cache[cache_key] = authorized
        
        return authorized, None if authorized else "HAL authorization denied"
    
    def _check_rate_limit(self, member_id: str, task_type: str) -> bool:
        """Check rate limits for task execution."""
        key = f"{member_id}:{task_type}"
        now = datetime.now()
        
        # Add current request
        self.rate_limits[key].append(now)
        
        # Count requests in last minute
        one_minute_ago = now - timedelta(minutes=1)
        recent_requests = sum(
            1 for ts in self.rate_limits[key]
            if ts > one_minute_ago
        )
        
        # Task type specific limits
        limits = {
            'emergency': 100,  # High limit for emergency tasks
            'consensus': 50,
            'allocation': 30,
            'default': 20
        }
        
        limit = limits.get(task_type, limits['default'])
        return recent_requests <= limit
    
    async def validate_consensus_participation(
        self,
        member_id: str,
        consensus_context: Dict[str, Any]
    ) -> bool:
        """Validate member can participate in consensus."""
        # Check if member is registered
        if member_id not in self.capability_registry:
            return False
        
        # Verify consensus capabilities
        member_caps = self.capability_registry.get(member_id, set())
        if 'consensus_voting' not in member_caps:
            return False
        
        # Additional validation through HAL
        return await self.security_hal.validate_consensus_member(
            member_id,
            consensus_context
        )


class SwarmMAESTROIntegration:
    """
    Complete MAESTRO security integration for swarm intelligence.
    
    Integrates all three layers:
    - L1: Hardware attestation and TPM
    - L2: Network security and mTLS
    - L3: Application controls and authorization
    """
    
    def __init__(
        self,
        tpm_integration: Optional[TPMSecurityIntegration],
        mtls_manager: MTLSManager,
        security_hal: SecurityHAL,
        audit_logger: AuditLogger,
        monitor: RealTimeSecurityMonitor
    ):
        # MAESTRO layers
        self.l1_security = L1PhysicalSecurity(tpm_integration)
        self.l2_security = L2NetworkSecurity(mtls_manager)
        self.l3_security = L3ApplicationSecurity(security_hal)
        
        # Core services
        self.audit_logger = audit_logger
        self.monitor = monitor
        
        # Policy management
        self.security_policies: Dict[str, SwarmSecurityPolicy] = {}
        self.active_incidents: Dict[str, SecurityIncident] = {}
        
        # Integration with swarm components
        self.task_allocator: Optional[DistributedTaskAllocator] = None
        self.consensus_protocol: Optional[EnhancedConsensusProtocol] = None
        self.p2p_network: Optional[SecureSwarmNetwork] = None
        
        # Metrics
        self.security_metrics = {
            'attestations_performed': 0,
            'attestations_failed': 0,
            'secure_channels_established': 0,
            'policy_violations': 0,
            'incidents_detected': 0,
            'incidents_resolved': 0
        }
        
        logger.info("MAESTRO security integration initialized")
    
    def set_swarm_components(
        self,
        allocator: DistributedTaskAllocator,
        consensus: EnhancedConsensusProtocol,
        network: SecureSwarmNetwork
    ):
        """Set references to swarm components."""
        self.task_allocator = allocator
        self.consensus_protocol = consensus
        self.p2p_network = network
    
    async def secure_member_registration(
        self,
        member: SwarmMember
    ) -> Tuple[bool, Optional[str]]:
        """Securely register a swarm member with full MAESTRO validation."""
        try:
            # L1: Hardware attestation
            attested, attestation_details = await self.l1_security.attest_swarm_member(member)
            
            if not attested:
                self.security_metrics['attestations_failed'] += 1
                await self._create_incident(
                    SecurityViolationType.ATTESTATION_FAILURE,
                    "high",
                    [member.member_id],
                    {'attestation_details': attestation_details}
                )
                return False, "Hardware attestation failed"
            
            self.security_metrics['attestations_performed'] += 1
            
            # L2: Network zone assignment
            network_zone = self._determine_network_zone(member.classification_clearance)
            self.l2_security.network_zones[network_zone].add(member.member_id)
            
            # L3: Capability registration
            capability_ids = {cap.capability_id for cap in member.capabilities}
            self.l3_security.capability_registry[member.member_id] = capability_ids
            
            # Create crypto credentials for consensus
            private_key, public_key = self._generate_member_keys()
            credentials = CryptoCredentials(
                member_id=member.member_id,
                private_key=private_key,
                public_key=public_key,
                classification_level=member.classification_clearance
            )
            
            # Register with consensus protocol
            if self.consensus_protocol:
                self.consensus_protocol.credentials[member.member_id] = credentials
            
            # Audit successful registration
            await self.audit_logger.log_event(
                "SWARM_MEMBER_SECURE_REGISTRATION",
                classification=member.classification_clearance,
                details={
                    'member_id': member.member_id,
                    'attestation_valid': attested,
                    'network_zone': network_zone,
                    'capabilities': list(capability_ids)
                }
            )
            
            # Monitor registration
            await self.monitor.track_metric(
                'swarm_member_registrations',
                1,
                {
                    'classification': member.classification_clearance.value,
                    'platform_type': member.platform_type.value
                }
            )
            
            return True, None
            
        except Exception as e:
            logger.error("Secure member registration failed: %s", e)
            return False, f"Registration error: {str(e)}"
    
    async def secure_task_allocation(
        self,
        task: SwarmTask,
        proposed_member_id: str
    ) -> Tuple[bool, Optional[str]]:
        """Validate task allocation through MAESTRO layers."""
        member = None
        if self.task_allocator:
            member = self.task_allocator.swarm_members.get(proposed_member_id)
        
        if not member:
            return False, "Unknown member"
        
        # L3: Application authorization
        authorized, auth_reason = await self.l3_security.authorize_task_execution(
            task, member
        )
        
        if not authorized:
            await self._create_incident(
                SecurityViolationType.UNAUTHORIZED_TASK,
                "medium",
                [proposed_member_id],
                {
                    'task_id': task.task_id,
                    'reason': auth_reason
                }
            )
            return False, auth_reason
        
        # L1: Verify current attestation
        attested, _ = await self.l1_security.attest_swarm_member(member)
        if not attested:
            return False, "Member attestation expired or invalid"
        
        # Apply security policies
        for policy in self.security_policies.values():
            if policy.layer == MAESTROLayer.L3_APPLICATION:
                context = {
                    'task_type': task.task_type,
                    'classification_level': task.classification,
                    'member_id': proposed_member_id,
                    'capabilities': [cap.capability_id for cap in member.capabilities]
                }
                
                passed, violation_msg = policy.evaluate(context)
                if not passed:
                    self.security_metrics['policy_violations'] += 1
                    return False, f"Policy violation: {violation_msg}"
        
        # Seal sensitive task data if classified
        if task.classification in [ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET]:
            pcr_policy = [0, 1, 2, 3, 7]  # Boot measurements
            sealed_data = await self.l1_security.seal_task_data(task, pcr_policy)
            task.payload['sealed_data'] = sealed_data.hex()
        
        return True, None
    
    async def secure_consensus_round(
        self,
        task_id: str,
        participants: List[str]
    ) -> Tuple[bool, Optional[str]]:
        """Secure a consensus round with MAESTRO validation."""
        # Verify all participants
        for participant_id in participants:
            # L3: Validate consensus participation
            valid = await self.l3_security.validate_consensus_participation(
                participant_id,
                {'task_id': task_id}
            )
            
            if not valid:
                await self._create_incident(
                    SecurityViolationType.CONSENSUS_MANIPULATION,
                    "high",
                    [participant_id],
                    {
                        'task_id': task_id,
                        'reason': 'Invalid consensus participant'
                    }
                )
                return False, f"Invalid participant: {participant_id}"
        
        # L2: Establish secure channels between participants
        for i in range(len(participants)):
            for j in range(i + 1, len(participants)):
                success, channel = await self.l2_security.establish_secure_channel(
                    participants[i],
                    participants[j],
                    ClassificationLevel.UNCLASSIFIED  # Consensus metadata
                )
                
                if not success:
                    return False, f"Failed to establish secure channel: {channel}"
                
                self.security_metrics['secure_channels_established'] += 1
        
        return True, None
    
    async def handle_security_violation(
        self,
        violation_type: SecurityViolationType,
        context: Dict[str, Any]
    ):
        """Handle detected security violations."""
        severity = self._determine_severity(violation_type, context)
        affected_members = context.get('affected_members', [])
        
        # Create incident
        incident = await self._create_incident(
            violation_type,
            severity,
            affected_members,
            context
        )
        
        # Take response actions based on violation type
        if violation_type == SecurityViolationType.ATTESTATION_FAILURE:
            # Isolate member
            for member_id in affected_members:
                await self._isolate_member(member_id)
        
        elif violation_type == SecurityViolationType.CLASSIFICATION_BREACH:
            # Revoke task and audit
            task_id = context.get('task_id')
            if task_id and self.task_allocator:
                # TODO: Implement task revocation
                pass
        
        elif violation_type == SecurityViolationType.CONSENSUS_MANIPULATION:
            # Invalidate consensus round
            if self.consensus_protocol:
                await self.consensus_protocol._initiate_view_change()
        
        # Alert monitor
        await self.monitor.raise_alert(
            f"Security violation: {violation_type.value}",
            severity,
            context
        )
    
    def _determine_network_zone(self, classification: ClassificationLevel) -> str:
        """Determine network zone based on classification."""
        if classification in [ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET]:
            return 'classified'
        return 'unclassified'
    
    def _generate_member_keys(self):
        """Generate cryptographic keys for member."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def _determine_severity(
        self,
        violation_type: SecurityViolationType,
        context: Dict[str, Any]
    ) -> str:
        """Determine incident severity."""
        # Critical violations
        if violation_type in [
            SecurityViolationType.CLASSIFICATION_BREACH,
            SecurityViolationType.NETWORK_INTRUSION
        ]:
            return "critical"
        
        # High severity
        if violation_type in [
            SecurityViolationType.ATTESTATION_FAILURE,
            SecurityViolationType.CONSENSUS_MANIPULATION
        ]:
            return "high"
        
        # Check context for elevation
        if context.get('classification', ClassificationLevel.UNCLASSIFIED) == ClassificationLevel.TOP_SECRET:
            return "critical"
        
        return "medium"
    
    async def _create_incident(
        self,
        violation_type: SecurityViolationType,
        severity: str,
        affected_members: List[str],
        details: Dict[str, Any]
    ) -> SecurityIncident:
        """Create and record security incident."""
        incident = SecurityIncident(
            incident_id=str(uuid.uuid4()),
            violation_type=violation_type,
            severity=severity,
            affected_members=affected_members,
            task_id=details.get('task_id'),
            details=details,
            detected_at=datetime.now()
        )
        
        self.active_incidents[incident.incident_id] = incident
        self.security_metrics['incidents_detected'] += 1
        
        # Audit incident
        await self.audit_logger.log_event(
            "SECURITY_INCIDENT_CREATED",
            classification=ClassificationLevel.SECRET,  # Security incidents are classified
            details={
                'incident_id': incident.incident_id,
                'type': violation_type.value,
                'severity': severity,
                'affected_count': len(affected_members)
            }
        )
        
        return incident
    
    async def _isolate_member(self, member_id: str):
        """Isolate a compromised swarm member."""
        logger.warning("Isolating compromised member: %s", member_id)
        
        # Remove from network zones
        for zone_members in self.l2_security.network_zones.values():
            zone_members.discard(member_id)
        
        # Revoke capabilities
        if member_id in self.l3_security.capability_registry:
            del self.l3_security.capability_registry[member_id]
        
        # Remove from consensus
        if self.consensus_protocol:
            self.consensus_protocol.current_view.faulty_members.add(member_id)
        
        # Audit isolation
        await self.audit_logger.log_event(
            "SWARM_MEMBER_ISOLATED",
            classification=ClassificationLevel.SECRET,
            details={'member_id': member_id, 'reason': 'Security violation'}
        )
    
    async def periodic_security_audit(self):
        """Perform periodic security audit of swarm."""
        audit_results = {
            'timestamp': datetime.now(),
            'members_audited': 0,
            'violations_found': 0,
            'attestations_renewed': 0
        }
        
        if self.task_allocator:
            for member_id, member in self.task_allocator.swarm_members.items():
                audit_results['members_audited'] += 1
                
                # Re-attest members
                attested, _ = await self.l1_security.attest_swarm_member(member)
                if attested:
                    audit_results['attestations_renewed'] += 1
                else:
                    audit_results['violations_found'] += 1
                    await self._isolate_member(member_id)
        
        # Check for stale incidents
        for incident in list(self.active_incidents.values()):
            if not incident.resolved_at:
                age = datetime.now() - incident.detected_at
                if age > timedelta(hours=24):
                    logger.warning("Stale incident detected: %s", incident.incident_id)
        
        # Log audit results
        await self.audit_logger.log_event(
            "SWARM_SECURITY_AUDIT",
            classification=ClassificationLevel.UNCLASSIFIED,
            details=audit_results
        )
        
        return audit_results
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics."""
        return {
            'maestro_integration': {
                'l1_attestations': {
                    'performed': self.security_metrics['attestations_performed'],
                    'failed': self.security_metrics['attestations_failed'],
                    'success_rate': (
                        self.security_metrics['attestations_performed'] /
                        max(1, self.security_metrics['attestations_performed'] + 
                            self.security_metrics['attestations_failed'])
                    )
                },
                'l2_network': {
                    'secure_channels': self.security_metrics['secure_channels_established'],
                    'zones': {
                        zone: len(members)
                        for zone, members in self.l2_security.network_zones.items()
                    }
                },
                'l3_application': {
                    'registered_members': len(self.l3_security.capability_registry),
                    'policy_violations': self.security_metrics['policy_violations']
                }
            },
            'incidents': {
                'total_detected': self.security_metrics['incidents_detected'],
                'active': len(self.active_incidents),
                'resolved': self.security_metrics['incidents_resolved'],
                'by_type': self._count_incidents_by_type(),
                'by_severity': self._count_incidents_by_severity()
            },
            'policies': {
                'total': len(self.security_policies),
                'by_layer': self._count_policies_by_layer()
            }
        }
    
    def _count_incidents_by_type(self) -> Dict[str, int]:
        """Count incidents by violation type."""
        counts = defaultdict(int)
        for incident in self.active_incidents.values():
            counts[incident.violation_type.value] += 1
        return dict(counts)
    
    def _count_incidents_by_severity(self) -> Dict[str, int]:
        """Count incidents by severity."""
        counts = defaultdict(int)
        for incident in self.active_incidents.values():
            counts[incident.severity] += 1
        return dict(counts)
    
    def _count_policies_by_layer(self) -> Dict[str, int]:
        """Count policies by MAESTRO layer."""
        counts = defaultdict(int)
        for policy in self.security_policies.values():
            counts[policy.layer.value] += 1
        return dict(counts)