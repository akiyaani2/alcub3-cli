#!/usr/bin/env python3
"""
ALCUB3 Swarm Consensus Integration
Integrates Byzantine fault-tolerant consensus with swarm task allocation

This module connects the PBFT consensus engine with the distributed task
allocator, providing a complete swarm intelligence platform.
"""

import asyncio
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.real_time_monitor import RealTimeSecurityMonitor

# Import swarm components
from .distributed_task_allocator import (
    DistributedTaskAllocator, SwarmTask, SwarmMember,
    TaskStatus, TaskPriority, SwarmConfiguration
)
from .consensus_engine import (
    ByzantineFaultTolerantEngine, PBFTRequest, PBFTMessage,
    MessageType, CryptoCredentials
)
from .byzantine_defense import ByzantineDefenseSystem, AttackType
from .partition_tolerance import PartitionTolerantProtocol, PartitionState
from .consensus_optimization import PerformanceOptimizer
from .formal_verification import FormalVerifier, ProtocolState
from .secure_p2p_network import SecureSwarmNetwork, PeerInfo
from .maestro_integration import SwarmMAESTROIntegration

logger = logging.getLogger(__name__)


class ConsensusOperation(Enum):
    """Types of consensus operations."""
    TASK_ALLOCATION = "task_allocation"
    STATE_UPDATE = "state_update"
    MEMBER_REGISTRATION = "member_registration"
    CONFIGURATION_CHANGE = "configuration_change"
    EMERGENCY_RESPONSE = "emergency_response"


@dataclass
class SwarmConsensusRequest:
    """Request for swarm consensus."""
    operation: ConsensusOperation
    data: Dict[str, Any]
    priority: TaskPriority
    classification: ClassificationLevel
    requester_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_pbft_request(self) -> PBFTRequest:
        """Convert to PBFT request."""
        return PBFTRequest(
            request_id=str(uuid.uuid4()),
            client_id=self.requester_id,
            operation=self.operation.value,
            data=self.data,
            classification=self.classification,
            timestamp=self.timestamp,
            timeout=timedelta(seconds=30 if self.priority != TaskPriority.CRITICAL else 10)
        )


class SwarmConsensusIntegration:
    """
    Integrates Byzantine consensus with swarm task allocation.
    
    Provides:
    - Consensus-based task allocation decisions
    - Byzantine-tolerant swarm coordination
    - Integration with all security layers
    - Performance optimization
    - Formal verification
    """
    
    def __init__(
        self,
        node_id: str,
        swarm_config: SwarmConfiguration,
        audit_logger: AuditLogger,
        monitor: RealTimeSecurityMonitor
    ):
        self.node_id = node_id
        self.swarm_config = swarm_config
        self.audit_logger = audit_logger
        self.monitor = monitor
        
        # Core components
        self.task_allocator: Optional[DistributedTaskAllocator] = None
        self.consensus_engine: Optional[ByzantineFaultTolerantEngine] = None
        self.defense_system: Optional[ByzantineDefenseSystem] = None
        self.partition_protocol: Optional[PartitionTolerantProtocol] = None
        self.performance_optimizer: Optional[PerformanceOptimizer] = None
        self.formal_verifier: Optional[FormalVerifier] = None
        self.p2p_network: Optional[SecureSwarmNetwork] = None
        self.maestro_integration: Optional[SwarmMAESTROIntegration] = None
        
        # State tracking
        self.consensus_decisions: Dict[str, Any] = {}
        self.pending_operations: deque = deque()
        self.operation_results: Dict[str, Any] = {}
        
        # Metrics
        self.integration_metrics = {
            'total_consensus_operations': 0,
            'successful_operations': 0,
            'failed_operations': 0,
            'average_consensus_time_ms': 0.0,
            'task_allocation_decisions': 0,
            'byzantine_incidents': 0
        }
        
        logger.info("Swarm Consensus Integration initialized for node %s", node_id)
    
    async def initialize_components(
        self,
        swarm_members: Dict[str, SwarmMember],
        node_credentials: Dict[str, CryptoCredentials],
        classification_level: ClassificationLevel
    ):
        """Initialize all integrated components."""
        logger.info("Initializing swarm consensus components...")
        
        # Initialize task allocator
        self.task_allocator = DistributedTaskAllocator(
            self.swarm_config,
            self.audit_logger
        )
        
        # Register swarm members
        for member in swarm_members.values():
            await self.task_allocator.register_swarm_member(member)
        
        # Initialize consensus engine
        self.consensus_engine = ByzantineFaultTolerantEngine(
            self.node_id,
            node_credentials,
            classification_level,
            self.audit_logger
        )
        
        # Initialize defense system
        self.defense_system = ByzantineDefenseSystem(self.audit_logger)
        
        # Initialize partition tolerance
        self.partition_protocol = PartitionTolerantProtocol(
            self.node_id,
            len(swarm_members),
            classification_level,
            self.audit_logger
        )
        
        # Initialize performance optimizer
        self.performance_optimizer = PerformanceOptimizer(num_workers=4)
        
        # Initialize formal verifier
        self.formal_verifier = FormalVerifier()
        
        # Set up message handlers
        await self._setup_message_handlers()
        
        logger.info("All components initialized successfully")
    
    async def _setup_message_handlers(self):
        """Set up handlers for different message types."""
        # P2P network handlers
        if self.p2p_network:
            self.p2p_network.register_handler(
                MessageType.PRE_PREPARE,
                self._handle_consensus_message
            )
            self.p2p_network.register_handler(
                MessageType.PREPARE,
                self._handle_consensus_message
            )
            self.p2p_network.register_handler(
                MessageType.COMMIT,
                self._handle_consensus_message
            )
    
    async def request_task_allocation_consensus(
        self,
        task: SwarmTask,
        candidate_members: List[str]
    ) -> Tuple[bool, Optional[str]]:
        """Request consensus on task allocation."""
        # Create consensus request
        request = SwarmConsensusRequest(
            operation=ConsensusOperation.TASK_ALLOCATION,
            data={
                'task_id': task.task_id,
                'task_type': task.task_type,
                'required_capabilities': task.required_capabilities,
                'priority': task.priority.value,
                'classification': task.classification.value,
                'candidates': candidate_members,
                'constraints': task.constraints
            },
            priority=task.priority,
            classification=task.classification,
            requester_id=self.node_id
        )
        
        # Check if can make progress (partition tolerance)
        can_progress, reason = self.partition_protocol.can_make_progress()
        if not can_progress:
            logger.warning("Cannot achieve consensus: %s", reason)
            return False, None
        
        # Convert to PBFT request
        pbft_request = request.to_pbft_request()
        
        # Apply performance optimizations
        if self.performance_optimizer.check_fast_path_eligible(pbft_request):
            # Try fast path
            result = await self.performance_optimizer.execute_fast_path(
                pbft_request,
                self._execute_task_allocation
            )
            if result:
                return True, result.get('allocated_to')
        
        # Normal consensus path
        start_time = time.time()
        
        # Submit to consensus engine
        success, result = await self.consensus_engine.submit_request(pbft_request)
        
        consensus_time = (time.time() - start_time) * 1000
        
        # Update metrics
        self.integration_metrics['total_consensus_operations'] += 1
        if success:
            self.integration_metrics['successful_operations'] += 1
            self.integration_metrics['task_allocation_decisions'] += 1
        else:
            self.integration_metrics['failed_operations'] += 1
        
        # Update average consensus time
        total_ops = self.integration_metrics['total_consensus_operations']
        avg_time = self.integration_metrics['average_consensus_time_ms']
        self.integration_metrics['average_consensus_time_ms'] = (
            (avg_time * (total_ops - 1) + consensus_time) / total_ops
        )
        
        # Record formal verification state
        self._record_verification_state('task_allocation', success)
        
        if success and result:
            allocated_to = result.get('allocated_to')
            
            # Record consensus decision
            self.consensus_decisions[task.task_id] = {
                'allocated_to': allocated_to,
                'consensus_time_ms': consensus_time,
                'timestamp': datetime.now()
            }
            
            # Audit log
            await self.audit_logger.log_event(
                "CONSENSUS_TASK_ALLOCATION",
                classification=task.classification,
                details={
                    'task_id': task.task_id,
                    'allocated_to': allocated_to,
                    'consensus_time_ms': consensus_time,
                    'candidates': candidate_members
                }
            )
            
            return True, allocated_to
        
        return False, None
    
    async def _execute_task_allocation(
        self,
        request: PBFTRequest,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute task allocation decision."""
        data = request.data
        task_id = data['task_id']
        candidates = data['candidates']
        
        # Use task allocator to find best candidate
        # In real implementation, would reconstruct SwarmTask
        best_candidate = candidates[0] if candidates else None
        
        if best_candidate:
            # Perform actual allocation
            self.task_allocator.task_assignments[task_id] = best_candidate
            
            return {
                'status': 'success',
                'task_id': task_id,
                'allocated_to': best_candidate,
                'timestamp': datetime.now().isoformat()
            }
        
        return {
            'status': 'failed',
            'task_id': task_id,
            'reason': 'No suitable candidate'
        }
    
    async def handle_byzantine_behavior(
        self,
        node_id: str,
        behavior_type: str,
        evidence: Dict[str, Any]
    ):
        """Handle detected Byzantine behavior."""
        # Record in defense system
        await self.defense_system.record_node_behavior(node_id, {
            'behavior_type': behavior_type,
            'evidence': evidence,
            'detected_by': self.node_id
        })
        
        # Check if message should be allowed
        allowed, reason = self.defense_system.check_message_allowed(node_id)
        
        if not allowed:
            logger.warning("Blocking messages from %s: %s", node_id, reason)
            
            # Update metrics
            self.integration_metrics['byzantine_incidents'] += 1
            
            # Notify consensus engine
            await self.consensus_engine._handle_byzantine_fault(node_id, reason)
    
    async def _handle_consensus_message(self, sender_id: str, message: Dict[str, Any]):
        """Handle incoming consensus message."""
        # Check Byzantine defense
        allowed, reason = self.defense_system.check_message_allowed(sender_id)
        if not allowed:
            logger.debug("Dropping message from %s: %s", sender_id, reason)
            return
        
        # Convert to PBFT message
        # In real implementation, would properly deserialize
        pbft_message = PBFTMessage(
            message_type=MessageType[message['type']],
            view_number=message['view'],
            sequence_number=message['sequence'],
            digest=message['digest'],
            node_id=sender_id,
            signature=bytes.fromhex(message['signature']),
            timestamp=datetime.fromisoformat(message['timestamp'])
        )
        
        # Process through consensus engine
        await self.consensus_engine.process_message(pbft_message)
        
        # Record behavior for analysis
        await self.defense_system.record_node_behavior(sender_id, {
            'message_type': message['type'],
            'view': message['view'],
            'sequence': message['sequence']
        })
    
    def _record_verification_state(self, operation: str, success: bool):
        """Record state for formal verification."""
        state = ProtocolState(
            view_number=self.consensus_engine.current_view.view_number,
            sequence_number=self.consensus_engine.sequence_number,
            phase=self.consensus_engine.phase.value,
            num_nodes=self.consensus_engine.current_view.num_nodes,
            num_faulty=len(self.consensus_engine.current_view.faulty_nodes),
            node_states={
                self.node_id: "decided" if success else "failed"
            }
        )
        
        self.formal_verifier.record_state(state)
    
    async def handle_network_partition(self, reachable_nodes: Set[str]):
        """Handle network partition event."""
        all_nodes = set(self.task_allocator.swarm_members.keys())
        
        # Update partition protocol
        await self.partition_protocol.update_network_state(
            reachable_nodes,
            all_nodes
        )
        
        # Check if can continue
        can_continue, reason = self.partition_protocol.can_make_progress()
        
        if not can_continue:
            logger.warning("Partition prevents consensus: %s", reason)
            
            # Switch to degraded mode
            if self.partition_protocol.partition_state == PartitionState.SPLIT:
                await self.partition_protocol.handle_partition_timeout()
    
    async def optimize_consensus_performance(self):
        """Optimize consensus performance based on metrics."""
        # Get current performance data
        consensus_metrics = self.consensus_engine.get_consensus_metrics()
        
        performance_data = {
            'avg_latency_ms': consensus_metrics['average_latency_ms'],
            'throughput_rps': consensus_metrics['throughput_rps'],
            'cpu_usage': 0.5  # Would get from system monitoring
        }
        
        # Auto-tune parameters
        await self.performance_optimizer.auto_tune_parameters(performance_data)
        
        # Adapt consensus parameters
        await self.consensus_engine.adapt_parameters()
        
        # Update partition timeout if needed
        partition_metrics = self.partition_protocol.get_partition_metrics()
        if partition_metrics['partition_risk']['average'] > 0.7:
            # High partition risk - reduce timeouts
            self.consensus_engine.adaptive_params.view_change_timeout = timedelta(seconds=3)
    
    def generate_consensus_proof(self) -> Dict[str, Any]:
        """Generate formal proof of consensus correctness."""
        return self.formal_verifier.generate_correctness_proof()
    
    def get_integration_metrics(self) -> Dict[str, Any]:
        """Get comprehensive integration metrics."""
        metrics = {
            'integration': self.integration_metrics.copy(),
            'consensus': self.consensus_engine.get_consensus_metrics() if self.consensus_engine else {},
            'defense': self.defense_system.get_defense_metrics() if self.defense_system else {},
            'partition': self.partition_protocol.get_partition_metrics() if self.partition_protocol else {},
            'optimization': self.performance_optimizer.get_optimization_metrics() if self.performance_optimizer else {},
            'verification': self.formal_verifier.get_verification_report() if self.formal_verifier else {}
        }
        
        # Calculate integrated success rate
        if metrics['integration']['total_consensus_operations'] > 0:
            metrics['integration']['success_rate'] = (
                metrics['integration']['successful_operations'] /
                metrics['integration']['total_consensus_operations']
            )
        
        return metrics
    
    async def emergency_consensus(self, emergency_action: str, targets: List[str]):
        """Fast consensus for emergency actions."""
        request = SwarmConsensusRequest(
            operation=ConsensusOperation.EMERGENCY_RESPONSE,
            data={
                'action': emergency_action,
                'targets': targets,
                'timestamp': datetime.now().isoformat()
            },
            priority=TaskPriority.CRITICAL,
            classification=ClassificationLevel.UNCLASSIFIED,
            requester_id=self.node_id
        )
        
        # Use fast path for emergency
        pbft_request = request.to_pbft_request()
        
        # Reduce timeout for emergency
        pbft_request.timeout = timedelta(seconds=5)
        
        # Execute with highest priority
        success, result = await self.consensus_engine.submit_request(pbft_request)
        
        if success:
            logger.info("Emergency consensus achieved for action: %s", emergency_action)
        else:
            logger.error("Emergency consensus failed!")
        
        return success, result
    
    async def shutdown(self):
        """Gracefully shutdown integration."""
        logger.info("Shutting down Swarm Consensus Integration...")
        
        # Save metrics
        final_report = {
            'metrics': self.get_integration_metrics(),
            'consensus_proof': self.generate_consensus_proof(),
            'shutdown_time': datetime.now().isoformat()
        }
        
        logger.info("Final integration report: %s", final_report)
        
        # Shutdown components
        if self.consensus_engine:
            await self.consensus_engine.shutdown()
        
        if self.performance_optimizer:
            self.performance_optimizer.shutdown()
        
        if self.task_allocator:
            await self.task_allocator.shutdown()