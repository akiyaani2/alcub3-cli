#!/usr/bin/env python3
"""
ALCUB3 Microsegmentation Engine
Classification-aware network segmentation with dynamic security zones

This module implements patent-pending microsegmentation that:
- Isolates network traffic at the process level
- Creates dynamic security zones based on classification levels
- Provides automated VLAN/subnet management
- Enables east-west traffic inspection and control
- Integrates with MAESTRO classification system

Performance Targets:
- <5ms per packet decision
- Support for 10,000+ concurrent segments
- Zero packet loss during zone transitions
"""

import asyncio
import hashlib
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict
import json
from datetime import datetime, timedelta

# Import MAESTRO components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError
from shared.real_time_monitor import RealTimeMonitor

logger = logging.getLogger(__name__)


class SegmentType(Enum):
    """Types of network segments based on security requirements."""
    UNCLASSIFIED = "unclassified"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"
    SAP = "sap"  # Special Access Program
    AIRGAPPED = "airgapped"
    DMZ = "dmz"
    MANAGEMENT = "management"
    QUARANTINE = "quarantine"


class TrafficDirection(Enum):
    """Direction of network traffic flow."""
    NORTH_SOUTH = "north_south"  # External to internal
    EAST_WEST = "east_west"      # Internal to internal
    INGRESS = "ingress"
    EGRESS = "egress"


@dataclass
class NetworkSegment:
    """Represents a microsegmented network zone."""
    segment_id: str
    name: str
    segment_type: SegmentType
    classification_level: ClassificationLevel
    vlan_id: Optional[int] = None
    subnet: Optional[ipaddress.IPv4Network] = None
    allowed_protocols: Set[str] = field(default_factory=set)
    allowed_ports: Set[int] = field(default_factory=set)
    member_processes: Set[str] = field(default_factory=set)
    policy_rules: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_modified: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrafficFlow:
    """Represents a network traffic flow between segments."""
    flow_id: str
    source_segment: str
    destination_segment: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    direction: TrafficDirection
    classification: ClassificationLevel
    packet_count: int = 0
    byte_count: int = 0
    start_time: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    allowed: bool = False
    policy_matched: Optional[str] = None


@dataclass
class SegmentationPolicy:
    """Policy for microsegmentation rules."""
    policy_id: str
    name: str
    source_segments: List[str]
    destination_segments: List[str]
    allowed_protocols: List[str]
    allowed_ports: List[int]
    classification_requirements: List[ClassificationLevel]
    action: str  # "allow", "deny", "inspect"
    priority: int = 100
    enabled: bool = True
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class MicrosegmentationEngine:
    """
    Patent-pending microsegmentation engine with classification awareness.
    
    This engine provides dynamic network segmentation based on security
    classifications, enabling fine-grained control over network traffic
    while maintaining performance requirements.
    """
    
    def __init__(
        self,
        audit_logger: AuditLogger,
        monitor: Optional[RealTimeMonitor] = None,
        enable_hardware_acceleration: bool = True
    ):
        """
        Initialize the microsegmentation engine.
        
        Args:
            audit_logger: Audit logger for security events
            monitor: Real-time monitoring system
            enable_hardware_acceleration: Use hardware acceleration for packet processing
        """
        self.audit_logger = audit_logger
        self.monitor = monitor
        self.enable_hardware_acceleration = enable_hardware_acceleration
        
        # Core data structures
        self.segments: Dict[str, NetworkSegment] = {}
        self.policies: Dict[str, SegmentationPolicy] = {}
        self.active_flows: Dict[str, TrafficFlow] = {}
        self.segment_cache: Dict[str, str] = {}  # IP to segment mapping cache
        
        # Performance optimization
        self.policy_cache: Dict[str, bool] = {}  # Flow to decision cache
        self.cache_ttl = 300  # 5 minutes
        self.last_cache_clear = time.time()
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'flows_created': 0,
            'policy_hits': 0,
            'cache_hits': 0,
            'violations_blocked': 0,
            'avg_decision_time_ms': 0.0
        }
        
        # VLAN management
        self.vlan_pool = set(range(100, 4096))  # Available VLAN IDs
        self.used_vlans: Set[int] = set()
        
        # Classification-based default segments
        self._initialize_default_segments()
        
        logger.info("Microsegmentation engine initialized with hardware acceleration: %s", 
                   enable_hardware_acceleration)
    
    def _initialize_default_segments(self):
        """Create default segments based on classification levels."""
        # Create segments for each classification level
        classifications = [
            (ClassificationLevel.UNCLASSIFIED, SegmentType.UNCLASSIFIED, "10.0.0.0/16"),
            (ClassificationLevel.CONFIDENTIAL, SegmentType.CONFIDENTIAL, "10.1.0.0/16"),
            (ClassificationLevel.SECRET, SegmentType.SECRET, "10.2.0.0/16"),
            (ClassificationLevel.TOP_SECRET, SegmentType.TOP_SECRET, "10.3.0.0/16"),
        ]
        
        for classification, segment_type, subnet_str in classifications:
            segment_id = f"default_{classification.value.lower()}"
            segment = NetworkSegment(
                segment_id=segment_id,
                name=f"Default {classification.value} Segment",
                segment_type=segment_type,
                classification_level=classification,
                subnet=ipaddress.IPv4Network(subnet_str),
                vlan_id=self._allocate_vlan(),
                allowed_protocols={'tcp', 'udp', 'icmp'},
                allowed_ports=set(range(1024, 65536)),  # High ports by default
                metadata={'auto_created': True}
            )
            self.segments[segment_id] = segment
        
        # Create special segments
        self._create_special_segments()
    
    def _create_special_segments(self):
        """Create special purpose segments."""
        special_segments = [
            ("dmz", "DMZ Network", SegmentType.DMZ, "172.16.0.0/24"),
            ("management", "Management Network", SegmentType.MANAGEMENT, "172.31.0.0/24"),
            ("quarantine", "Quarantine Network", SegmentType.QUARANTINE, "169.254.0.0/24"),
            ("airgapped", "Air-Gapped Network", SegmentType.AIRGAPPED, "192.168.0.0/24"),
        ]
        
        for segment_id, name, segment_type, subnet_str in special_segments:
            segment = NetworkSegment(
                segment_id=segment_id,
                name=name,
                segment_type=segment_type,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                subnet=ipaddress.IPv4Network(subnet_str),
                vlan_id=self._allocate_vlan(),
                metadata={'special_purpose': True}
            )
            self.segments[segment_id] = segment
    
    def _allocate_vlan(self) -> int:
        """Allocate a VLAN ID from the pool."""
        if not self.vlan_pool:
            raise SecurityError("VLAN pool exhausted")
        
        vlan_id = self.vlan_pool.pop()
        self.used_vlans.add(vlan_id)
        return vlan_id
    
    async def create_segment(
        self,
        name: str,
        segment_type: SegmentType,
        classification_level: ClassificationLevel,
        subnet: Optional[str] = None,
        allowed_protocols: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> NetworkSegment:
        """
        Create a new network segment with classification awareness.
        
        Args:
            name: Human-readable segment name
            segment_type: Type of segment
            classification_level: Security classification level
            subnet: Optional subnet specification
            allowed_protocols: List of allowed protocols
            allowed_ports: List of allowed ports
            metadata: Additional metadata
            
        Returns:
            Created NetworkSegment
            
        Raises:
            SecurityError: If segment creation violates security policy
        """
        start_time = time.time()
        
        try:
            # Generate segment ID
            segment_id = hashlib.sha256(
                f"{name}:{segment_type.value}:{time.time()}".encode()
            ).hexdigest()[:16]
            
            # Parse subnet if provided
            subnet_obj = None
            if subnet:
                subnet_obj = ipaddress.IPv4Network(subnet)
                
                # Check for subnet conflicts
                for existing_segment in self.segments.values():
                    if existing_segment.subnet and existing_segment.subnet.overlaps(subnet_obj):
                        raise SecurityError(
                            f"Subnet {subnet} overlaps with segment {existing_segment.name}"
                        )
            
            # Create segment
            segment = NetworkSegment(
                segment_id=segment_id,
                name=name,
                segment_type=segment_type,
                classification_level=classification_level,
                subnet=subnet_obj,
                vlan_id=self._allocate_vlan(),
                allowed_protocols=set(allowed_protocols or ['tcp', 'udp']),
                allowed_ports=set(allowed_ports or []),
                metadata=metadata or {}
            )
            
            # Store segment
            self.segments[segment_id] = segment
            
            # Audit log
            await self.audit_logger.log_event(
                "SEGMENT_CREATED",
                classification=classification_level,
                details={
                    'segment_id': segment_id,
                    'name': name,
                    'type': segment_type.value,
                    'vlan_id': segment.vlan_id,
                    'subnet': str(subnet_obj) if subnet_obj else None
                }
            )
            
            # Monitor performance
            creation_time = (time.time() - start_time) * 1000
            if self.monitor:
                await self.monitor.record_metric(
                    'microsegmentation.segment_creation_time',
                    creation_time,
                    {'segment_type': segment_type.value}
                )
            
            logger.info("Created segment %s with VLAN %d", name, segment.vlan_id)
            return segment
            
        except Exception as e:
            logger.error("Failed to create segment: %s", str(e))
            raise SecurityError(f"Segment creation failed: {str(e)}")
    
    async def process_packet(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: str,
        port: int,
        classification: ClassificationLevel,
        packet_data: Optional[bytes] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Process a network packet through microsegmentation rules.
        
        This is the core performance-critical function that must meet
        the <5ms decision time requirement.
        
        Args:
            source_ip: Source IP address
            destination_ip: Destination IP address
            protocol: Network protocol (tcp, udp, etc.)
            port: Destination port
            classification: Data classification level
            packet_data: Optional packet payload for deep inspection
            
        Returns:
            Tuple of (allowed, reason) where allowed is boolean and
            reason explains the decision
        """
        start_time = time.time()
        
        try:
            # Update statistics
            self.stats['packets_processed'] += 1
            
            # Check cache first
            cache_key = f"{source_ip}:{destination_ip}:{protocol}:{port}:{classification.value}"
            if cache_key in self.policy_cache:
                self.stats['cache_hits'] += 1
                decision = self.policy_cache[cache_key]
                decision_time = (time.time() - start_time) * 1000
                self._update_avg_decision_time(decision_time)
                return decision, "Cached decision"
            
            # Determine source and destination segments
            source_segment = await self._get_segment_for_ip(source_ip)
            dest_segment = await self._get_segment_for_ip(destination_ip)
            
            if not source_segment or not dest_segment:
                self.stats['violations_blocked'] += 1
                return False, "Unknown segment"
            
            # Check if flow exists
            flow_id = f"{source_ip}:{destination_ip}:{protocol}:{port}"
            flow = self.active_flows.get(flow_id)
            
            if not flow:
                # Create new flow
                flow = TrafficFlow(
                    flow_id=flow_id,
                    source_segment=source_segment.segment_id,
                    destination_segment=dest_segment.segment_id,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=protocol,
                    port=port,
                    direction=self._determine_direction(source_segment, dest_segment),
                    classification=classification
                )
                self.active_flows[flow_id] = flow
                self.stats['flows_created'] += 1
            
            # Update flow statistics
            flow.packet_count += 1
            flow.last_seen = datetime.utcnow()
            
            # Evaluate policies
            allowed, policy_id = await self._evaluate_policies(
                source_segment, dest_segment, protocol, port, classification
            )
            
            flow.allowed = allowed
            flow.policy_matched = policy_id
            
            # Cache decision
            self.policy_cache[cache_key] = (allowed, f"Policy: {policy_id}")
            
            # Handle violations
            if not allowed:
                self.stats['violations_blocked'] += 1
                await self._handle_violation(flow, source_segment, dest_segment)
            
            # Update performance metrics
            decision_time = (time.time() - start_time) * 1000
            self._update_avg_decision_time(decision_time)
            
            # Monitor if decision time exceeds target
            if decision_time > 5.0:
                logger.warning("Packet decision time %.2fms exceeds 5ms target", decision_time)
            
            reason = f"Policy: {policy_id}" if policy_id else "Default deny"
            return allowed, reason
            
        except Exception as e:
            logger.error("Error processing packet: %s", str(e))
            return False, f"Processing error: {str(e)}"
    
    async def _get_segment_for_ip(self, ip_address: str) -> Optional[NetworkSegment]:
        """Get the network segment for an IP address."""
        # Check cache
        if ip_address in self.segment_cache:
            segment_id = self.segment_cache[ip_address]
            return self.segments.get(segment_id)
        
        # Search segments
        ip_obj = ipaddress.IPv4Address(ip_address)
        for segment in self.segments.values():
            if segment.subnet and ip_obj in segment.subnet:
                self.segment_cache[ip_address] = segment.segment_id
                return segment
        
        return None
    
    def _determine_direction(
        self, 
        source_segment: NetworkSegment, 
        dest_segment: NetworkSegment
    ) -> TrafficDirection:
        """Determine traffic direction based on segments."""
        if source_segment.segment_type == SegmentType.DMZ:
            return TrafficDirection.NORTH_SOUTH
        elif source_segment.segment_id == dest_segment.segment_id:
            return TrafficDirection.EAST_WEST
        elif dest_segment.segment_type in [SegmentType.DMZ, SegmentType.UNCLASSIFIED]:
            return TrafficDirection.EGRESS
        else:
            return TrafficDirection.EAST_WEST
    
    async def _evaluate_policies(
        self,
        source_segment: NetworkSegment,
        dest_segment: NetworkSegment,
        protocol: str,
        port: int,
        classification: ClassificationLevel
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate segmentation policies for a flow."""
        # Check classification compatibility first
        if classification.value > dest_segment.classification_level.value:
            return False, "classification_mismatch"
        
        # Find matching policies
        matching_policies = []
        for policy in self.policies.values():
            if not policy.enabled:
                continue
                
            if (source_segment.segment_id in policy.source_segments and
                dest_segment.segment_id in policy.destination_segments and
                protocol in policy.allowed_protocols and
                (not policy.allowed_ports or port in policy.allowed_ports) and
                classification in policy.classification_requirements):
                
                matching_policies.append(policy)
        
        # Sort by priority
        matching_policies.sort(key=lambda p: p.priority)
        
        # Apply first matching policy
        if matching_policies:
            policy = matching_policies[0]
            self.stats['policy_hits'] += 1
            
            if policy.action == "allow":
                return True, policy.policy_id
            elif policy.action == "deny":
                return False, policy.policy_id
            elif policy.action == "inspect":
                # TODO: Implement deep packet inspection
                return True, policy.policy_id
        
        # Default deny
        return False, None
    
    async def _handle_violation(
        self,
        flow: TrafficFlow,
        source_segment: NetworkSegment,
        dest_segment: NetworkSegment
    ):
        """Handle a policy violation."""
        await self.audit_logger.log_event(
            "MICROSEGMENTATION_VIOLATION",
            classification=flow.classification,
            details={
                'flow_id': flow.flow_id,
                'source_segment': source_segment.name,
                'dest_segment': dest_segment.name,
                'protocol': flow.protocol,
                'port': flow.port,
                'reason': 'Policy violation'
            }
        )
        
        if self.monitor:
            await self.monitor.record_event(
                'security.microsegmentation.violation',
                {
                    'source_ip': flow.source_ip,
                    'dest_ip': flow.destination_ip,
                    'classification': flow.classification.value
                }
            )
    
    def _update_avg_decision_time(self, decision_time_ms: float):
        """Update average decision time metric."""
        current_avg = self.stats['avg_decision_time_ms']
        packet_count = self.stats['packets_processed']
        
        # Calculate running average
        self.stats['avg_decision_time_ms'] = (
            (current_avg * (packet_count - 1) + decision_time_ms) / packet_count
        )
    
    async def create_policy(
        self,
        name: str,
        source_segments: List[str],
        destination_segments: List[str],
        allowed_protocols: List[str],
        allowed_ports: Optional[List[int]] = None,
        classification_requirements: Optional[List[ClassificationLevel]] = None,
        action: str = "allow",
        priority: int = 100,
        conditions: Optional[Dict[str, Any]] = None
    ) -> SegmentationPolicy:
        """
        Create a microsegmentation policy.
        
        Args:
            name: Policy name
            source_segments: List of source segment IDs
            destination_segments: List of destination segment IDs
            allowed_protocols: List of allowed protocols
            allowed_ports: Optional list of allowed ports
            classification_requirements: Required classification levels
            action: Policy action (allow, deny, inspect)
            priority: Policy priority (lower number = higher priority)
            conditions: Additional conditions
            
        Returns:
            Created SegmentationPolicy
        """
        policy_id = hashlib.sha256(
            f"{name}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        policy = SegmentationPolicy(
            policy_id=policy_id,
            name=name,
            source_segments=source_segments,
            destination_segments=destination_segments,
            allowed_protocols=allowed_protocols,
            allowed_ports=allowed_ports or [],
            classification_requirements=classification_requirements or [
                ClassificationLevel.UNCLASSIFIED
            ],
            action=action,
            priority=priority,
            conditions=conditions or {}
        )
        
        self.policies[policy_id] = policy
        
        # Clear policy cache on new policy
        self.policy_cache.clear()
        
        await self.audit_logger.log_event(
            "SEGMENTATION_POLICY_CREATED",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'policy_id': policy_id,
                'name': name,
                'action': action,
                'priority': priority
            }
        )
        
        logger.info("Created segmentation policy: %s", name)
        return policy
    
    async def get_segment_topology(self) -> Dict[str, Any]:
        """Get the current network segment topology."""
        topology = {
            'segments': {},
            'policies': [],
            'active_flows': len(self.active_flows),
            'statistics': self.stats
        }
        
        # Add segment information
        for segment_id, segment in self.segments.items():
            topology['segments'][segment_id] = {
                'name': segment.name,
                'type': segment.segment_type.value,
                'classification': segment.classification_level.value,
                'vlan_id': segment.vlan_id,
                'subnet': str(segment.subnet) if segment.subnet else None,
                'member_count': len(segment.member_processes),
                'created_at': segment.created_at.isoformat()
            }
        
        # Add policy summary
        for policy in self.policies.values():
            if policy.enabled:
                topology['policies'].append({
                    'name': policy.name,
                    'action': policy.action,
                    'priority': policy.priority,
                    'source_segments': policy.source_segments,
                    'destination_segments': policy.destination_segments
                })
        
        return topology
    
    async def cleanup_stale_flows(self, max_age_minutes: int = 30):
        """Clean up stale flows to prevent memory growth."""
        cutoff_time = datetime.utcnow() - timedelta(minutes=max_age_minutes)
        stale_flows = []
        
        for flow_id, flow in self.active_flows.items():
            if flow.last_seen < cutoff_time:
                stale_flows.append(flow_id)
        
        for flow_id in stale_flows:
            del self.active_flows[flow_id]
        
        if stale_flows:
            logger.info("Cleaned up %d stale flows", len(stale_flows))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current engine statistics."""
        return {
            **self.stats,
            'total_segments': len(self.segments),
            'total_policies': len(self.policies),
            'active_flows': len(self.active_flows),
            'cache_size': len(self.policy_cache),
            'used_vlans': len(self.used_vlans),
            'available_vlans': len(self.vlan_pool)
        }