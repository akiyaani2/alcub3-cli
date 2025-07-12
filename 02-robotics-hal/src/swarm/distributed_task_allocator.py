#!/usr/bin/env python3
"""
ALCUB3 Distributed Task Allocator
Core engine for swarm intelligence task distribution with Byzantine fault tolerance

This module implements the foundational distributed task allocation system
for swarm robotics with defense-grade security and reliability.
"""

import asyncio
import time
import uuid
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import heapq

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.crypto_utils import CryptoUtils

# Import HAL components
sys.path.append(str(Path(__file__).parent.parent))
from hal.platform_adapter import PlatformType, SecurityState

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REALLOCATING = "reallocating"


class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = 1  # Emergency/safety critical
    HIGH = 2      # Mission critical
    MEDIUM = 3    # Standard operations
    LOW = 4       # Background tasks


class ConsensusPhase(Enum):
    """Byzantine consensus protocol phases."""
    PREPARE = "prepare"
    COMMIT = "commit"
    CONFIRM = "confirm"
    VIEW_CHANGE = "view_change"


@dataclass
class SwarmCapability:
    """Capability descriptor for swarm members."""
    capability_id: str
    category: str  # sensor, actuator, compute, communication
    specifications: Dict[str, Any]
    performance_metrics: Dict[str, float]
    classification_level: ClassificationLevel


@dataclass
class SwarmTask:
    """Task representation for swarm allocation."""
    task_id: str
    task_type: str
    required_capabilities: List[str]
    priority: TaskPriority
    classification: ClassificationLevel
    payload: Dict[str, Any]
    constraints: Dict[str, Any]  # time, location, resource constraints
    created_at: datetime
    deadline: Optional[datetime] = None
    status: TaskStatus = TaskStatus.PENDING
    assigned_to: Optional[str] = None
    allocation_history: List[Tuple[str, datetime]] = field(default_factory=list)
    execution_metrics: Dict[str, Any] = field(default_factory=dict)
    consensus_proof: Optional[str] = None
    
    def calculate_urgency(self) -> float:
        """Calculate task urgency score for prioritization."""
        base_score = self.priority.value * 10
        
        # Add deadline urgency
        if self.deadline:
            time_remaining = (self.deadline - datetime.now()).total_seconds()
            if time_remaining > 0:
                deadline_factor = 100 / max(time_remaining / 60, 1)  # Minutes
                base_score += deadline_factor
        
        # Classification multiplier
        classification_multiplier = {
            ClassificationLevel.TOP_SECRET: 2.0,
            ClassificationLevel.SECRET: 1.5,
            ClassificationLevel.UNCLASSIFIED: 1.0
        }.get(self.classification, 1.0)
        
        return base_score * classification_multiplier


@dataclass
class SwarmMember:
    """Swarm member representation."""
    member_id: str
    platform_type: PlatformType
    capabilities: List[SwarmCapability]
    classification_clearance: ClassificationLevel
    current_load: float  # 0.0 to 1.0
    reliability_score: float  # 0.0 to 1.0 based on historical performance
    location: Optional[Dict[str, float]] = None  # lat, lon, alt
    last_heartbeat: datetime = field(default_factory=datetime.now)
    active_tasks: Set[str] = field(default_factory=set)
    completed_tasks: int = 0
    failed_tasks: int = 0
    consensus_weight: float = 1.0  # Voting weight in consensus
    is_byzantine: bool = False  # For testing/simulation
    
    def can_execute_task(self, task: SwarmTask) -> bool:
        """Check if member can execute given task."""
        # Check classification clearance
        if self.classification_clearance.value < task.classification.value:
            return False
        
        # Check required capabilities
        member_capabilities = {cap.capability_id for cap in self.capabilities}
        if not all(req in member_capabilities for req in task.required_capabilities):
            return False
        
        # Check load constraints
        if self.current_load > 0.8:  # 80% load threshold
            return False
        
        return True
    
    def calculate_suitability_score(self, task: SwarmTask) -> float:
        """Calculate how suitable this member is for the task."""
        if not self.can_execute_task(task):
            return 0.0
        
        # Base score from reliability
        score = self.reliability_score * 100
        
        # Adjust for current load (prefer less loaded members)
        score *= (1.0 - self.current_load)
        
        # Bonus for matching classification level
        if self.classification_clearance == task.classification:
            score *= 1.2
        
        # Consider location if task has location constraints
        if 'location' in task.constraints and self.location:
            task_loc = task.constraints['location']
            distance = ((self.location['lat'] - task_loc['lat'])**2 + 
                       (self.location['lon'] - task_loc['lon'])**2)**0.5
            score *= max(0.1, 1.0 - distance / 100)  # Reduce score by distance
        
        return score


@dataclass
class TaskAllocationResult:
    """Result of task allocation process."""
    task_id: str
    allocated_to: str
    allocation_score: float
    consensus_achieved: bool
    consensus_proof: str
    allocation_time_ms: float
    participating_members: List[str]
    dissenting_members: List[str] = field(default_factory=list)


@dataclass
class ConsensusMessage:
    """Message for consensus protocol."""
    message_id: str
    phase: ConsensusPhase
    sender_id: str
    task_id: str
    proposed_allocation: str
    view_number: int
    signature: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SwarmConfiguration:
    """Configuration for swarm operations."""
    min_consensus_ratio: float = 0.67  # 2/3 for Byzantine fault tolerance
    max_allocation_time_ms: float = 50.0
    heartbeat_interval_seconds: float = 1.0
    task_timeout_seconds: float = 300.0
    enable_predictive_allocation: bool = True
    enable_load_balancing: bool = True
    max_retries: int = 3
    byzantine_fault_threshold: float = 0.33
    classification_weight_multipliers: Dict[ClassificationLevel, float] = field(
        default_factory=lambda: {
            ClassificationLevel.TOP_SECRET: 3.0,
            ClassificationLevel.SECRET: 2.0,
            ClassificationLevel.UNCLASSIFIED: 1.0
        }
    )


class ConsensusProtocol:
    """Byzantine fault-tolerant consensus protocol for task allocation."""
    
    def __init__(self, swarm_members: Dict[str, SwarmMember], config: SwarmConfiguration):
        self.members = swarm_members
        self.config = config
        self.view_number = 0
        self.current_leader = None
        self.consensus_log = deque(maxlen=1000)
        self.crypto = CryptoUtils()
        self._select_leader()
    
    def _select_leader(self):
        """Select leader based on reliability and classification."""
        eligible_members = [
            (m.reliability_score * m.consensus_weight, m.member_id, m)
            for m in self.members.values()
            if not m.is_byzantine
        ]
        if eligible_members:
            eligible_members.sort(reverse=True)
            self.current_leader = eligible_members[0][1]
    
    async def achieve_consensus(
        self, 
        task: SwarmTask, 
        proposed_allocation: str
    ) -> Tuple[bool, str, List[str]]:
        """
        Achieve Byzantine fault-tolerant consensus on task allocation.
        
        Returns:
            Tuple of (consensus_achieved, consensus_proof, participating_members)
        """
        start_time = time.time()
        
        # Phase 1: Prepare
        prepare_votes = await self._prepare_phase(task, proposed_allocation)
        
        if len(prepare_votes) < self._required_votes():
            return False, "", []
        
        # Phase 2: Commit
        commit_votes = await self._commit_phase(task, proposed_allocation, prepare_votes)
        
        if len(commit_votes) < self._required_votes():
            return False, "", []
        
        # Phase 3: Confirm
        confirmation = await self._confirm_phase(task, proposed_allocation, commit_votes)
        
        # Generate consensus proof
        consensus_proof = self._generate_consensus_proof(
            task, proposed_allocation, prepare_votes, commit_votes, confirmation
        )
        
        # Log consensus achievement
        self.consensus_log.append({
            'task_id': task.task_id,
            'allocation': proposed_allocation,
            'view': self.view_number,
            'duration_ms': (time.time() - start_time) * 1000,
            'timestamp': datetime.now()
        })
        
        return True, consensus_proof, list(commit_votes.keys())
    
    def _required_votes(self) -> int:
        """Calculate required votes for consensus."""
        total_weight = sum(
            m.consensus_weight * self.config.classification_weight_multipliers.get(
                m.classification_clearance, 1.0
            )
            for m in self.members.values()
        )
        return int(total_weight * self.config.min_consensus_ratio)
    
    async def _prepare_phase(
        self, 
        task: SwarmTask, 
        proposed_allocation: str
    ) -> Dict[str, ConsensusMessage]:
        """Execute prepare phase of consensus."""
        prepare_msg = ConsensusMessage(
            message_id=str(uuid.uuid4()),
            phase=ConsensusPhase.PREPARE,
            sender_id=self.current_leader,
            task_id=task.task_id,
            proposed_allocation=proposed_allocation,
            view_number=self.view_number,
            signature=self._sign_message(task.task_id, proposed_allocation),
            timestamp=datetime.now()
        )
        
        # Simulate message broadcast and vote collection
        votes = {}
        for member_id, member in self.members.items():
            if member.can_execute_task(task) and not member.is_byzantine:
                # Weighted vote based on classification
                weight = self.config.classification_weight_multipliers.get(
                    member.classification_clearance, 1.0
                )
                if member.consensus_weight * weight > 0:
                    votes[member_id] = prepare_msg
        
        return votes
    
    async def _commit_phase(
        self, 
        task: SwarmTask,
        proposed_allocation: str,
        prepare_votes: Dict[str, ConsensusMessage]
    ) -> Dict[str, ConsensusMessage]:
        """Execute commit phase of consensus."""
        commit_votes = {}
        
        for member_id in prepare_votes:
            commit_msg = ConsensusMessage(
                message_id=str(uuid.uuid4()),
                phase=ConsensusPhase.COMMIT,
                sender_id=member_id,
                task_id=task.task_id,
                proposed_allocation=proposed_allocation,
                view_number=self.view_number,
                signature=self._sign_message(task.task_id, proposed_allocation),
                timestamp=datetime.now()
            )
            commit_votes[member_id] = commit_msg
        
        return commit_votes
    
    async def _confirm_phase(
        self,
        task: SwarmTask,
        proposed_allocation: str,
        commit_votes: Dict[str, ConsensusMessage]
    ) -> Dict[str, ConsensusMessage]:
        """Execute confirm phase of consensus."""
        confirmations = {}
        
        for member_id in commit_votes:
            confirm_msg = ConsensusMessage(
                message_id=str(uuid.uuid4()),
                phase=ConsensusPhase.CONFIRM,
                sender_id=member_id,
                task_id=task.task_id,
                proposed_allocation=proposed_allocation,
                view_number=self.view_number,
                signature=self._sign_message(task.task_id, proposed_allocation),
                timestamp=datetime.now()
            )
            confirmations[member_id] = confirm_msg
        
        return confirmations
    
    def _sign_message(self, task_id: str, allocation: str) -> str:
        """Generate signature for consensus message."""
        data = f"{task_id}:{allocation}:{self.view_number}".encode()
        return hashlib.sha256(data).hexdigest()
    
    def _generate_consensus_proof(
        self,
        task: SwarmTask,
        allocation: str,
        prepare_votes: Dict[str, ConsensusMessage],
        commit_votes: Dict[str, ConsensusMessage],
        confirmations: Dict[str, ConsensusMessage]
    ) -> str:
        """Generate cryptographic proof of consensus."""
        proof_data = {
            'task_id': task.task_id,
            'allocation': allocation,
            'view_number': self.view_number,
            'prepare_votes': len(prepare_votes),
            'commit_votes': len(commit_votes),
            'confirmations': len(confirmations),
            'timestamp': datetime.now().isoformat(),
            'signatures': [
                v.signature for v in commit_votes.values()
            ][:10]  # Include first 10 signatures
        }
        
        proof_json = json.dumps(proof_data, sort_keys=True)
        return hashlib.sha256(proof_json.encode()).hexdigest()


class DistributedTaskAllocator:
    """
    Core distributed task allocation engine for swarm robotics.
    
    This class implements the main task allocation logic with:
    - Byzantine fault-tolerant consensus
    - Dynamic load balancing
    - Predictive task allocation
    - Classification-aware routing
    - Real-time performance optimization
    """
    
    def __init__(
        self,
        config: SwarmConfiguration,
        audit_logger: Optional[AuditLogger] = None
    ):
        self.config = config
        self.audit_logger = audit_logger or AuditLogger()
        
        # Core data structures
        self.swarm_members: Dict[str, SwarmMember] = {}
        self.task_queue: List[SwarmTask] = []  # Min-heap by urgency
        self.active_allocations: Dict[str, TaskAllocationResult] = {}
        self.allocation_history: deque = deque(maxlen=10000)
        
        # Consensus protocol
        self.consensus_protocol: Optional[ConsensusProtocol] = None
        
        # Performance tracking
        self.allocation_metrics = {
            'total_allocations': 0,
            'successful_allocations': 0,
            'failed_allocations': 0,
            'average_allocation_time_ms': 0.0,
            'consensus_failures': 0
        }
        
        # Thread pool for parallel operations
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()
        
        logger.info("Distributed Task Allocator initialized with config: %s", config)
    
    async def register_swarm_member(self, member: SwarmMember) -> bool:
        """Register a new swarm member."""
        async with self._lock:
            self.swarm_members[member.member_id] = member
            
            # Reinitialize consensus protocol with new member
            if len(self.swarm_members) > 0:
                self.consensus_protocol = ConsensusProtocol(
                    self.swarm_members, self.config
                )
            
            await self.audit_logger.log_event(
                "SWARM_MEMBER_REGISTERED",
                classification=member.classification_clearance,
                details={
                    'member_id': member.member_id,
                    'platform_type': member.platform_type.value,
                    'capabilities': [c.capability_id for c in member.capabilities]
                }
            )
            
            logger.info("Registered swarm member: %s", member.member_id)
            return True
    
    async def submit_task(self, task: SwarmTask) -> bool:
        """Submit a task for allocation."""
        async with self._lock:
            # Add to priority queue
            heapq.heappush(self.task_queue, (-task.calculate_urgency(), task))
            
            await self.audit_logger.log_event(
                "TASK_SUBMITTED",
                classification=task.classification,
                details={
                    'task_id': task.task_id,
                    'task_type': task.task_type,
                    'priority': task.priority.value,
                    'required_capabilities': task.required_capabilities
                }
            )
            
            # Trigger immediate allocation for critical tasks
            if task.priority == TaskPriority.CRITICAL:
                asyncio.create_task(self._allocate_task(task))
            
            return True
    
    async def allocate_tasks(self) -> List[TaskAllocationResult]:
        """Main task allocation loop - allocate all pending tasks."""
        results = []
        
        while self.task_queue:
            _, task = heapq.heappop(self.task_queue)
            
            if task.status != TaskStatus.PENDING:
                continue
            
            result = await self._allocate_task(task)
            if result:
                results.append(result)
        
        return results
    
    async def _allocate_task(self, task: SwarmTask) -> Optional[TaskAllocationResult]:
        """Allocate a single task to the most suitable swarm member."""
        start_time = time.time()
        
        # Find suitable members
        candidates = self._find_suitable_members(task)
        
        if not candidates:
            logger.warning("No suitable members found for task %s", task.task_id)
            task.status = TaskStatus.FAILED
            return None
        
        # Select best candidate
        best_member_id, best_score = candidates[0]
        
        # Achieve consensus on allocation
        if self.consensus_protocol:
            consensus_achieved, proof, participants = await self.consensus_protocol.achieve_consensus(
                task, best_member_id
            )
            
            if not consensus_achieved:
                logger.error("Failed to achieve consensus for task %s", task.task_id)
                self.allocation_metrics['consensus_failures'] += 1
                task.status = TaskStatus.FAILED
                return None
        else:
            # No consensus needed with single member
            consensus_achieved = True
            proof = "single-member-allocation"
            participants = [best_member_id]
        
        # Execute allocation
        task.status = TaskStatus.ASSIGNED
        task.assigned_to = best_member_id
        task.consensus_proof = proof
        task.allocation_history.append((best_member_id, datetime.now()))
        
        # Update member state
        member = self.swarm_members[best_member_id]
        member.active_tasks.add(task.task_id)
        member.current_load = min(1.0, member.current_load + 0.1)  # Increase load
        
        # Create allocation result
        allocation_time_ms = (time.time() - start_time) * 1000
        result = TaskAllocationResult(
            task_id=task.task_id,
            allocated_to=best_member_id,
            allocation_score=best_score,
            consensus_achieved=consensus_achieved,
            consensus_proof=proof,
            allocation_time_ms=allocation_time_ms,
            participating_members=participants
        )
        
        # Update metrics
        self.allocation_metrics['total_allocations'] += 1
        self.allocation_metrics['successful_allocations'] += 1
        self.allocation_metrics['average_allocation_time_ms'] = (
            (self.allocation_metrics['average_allocation_time_ms'] * 
             (self.allocation_metrics['total_allocations'] - 1) + 
             allocation_time_ms) / self.allocation_metrics['total_allocations']
        )
        
        # Store result
        self.active_allocations[task.task_id] = result
        self.allocation_history.append(result)
        
        # Audit log
        await self.audit_logger.log_event(
            "TASK_ALLOCATED",
            classification=task.classification,
            details={
                'task_id': task.task_id,
                'allocated_to': best_member_id,
                'allocation_score': best_score,
                'allocation_time_ms': allocation_time_ms,
                'consensus_proof': proof
            }
        )
        
        logger.info(
            "Task %s allocated to %s in %.2fms (score: %.2f)",
            task.task_id, best_member_id, allocation_time_ms, best_score
        )
        
        return result
    
    def _find_suitable_members(self, task: SwarmTask) -> List[Tuple[str, float]]:
        """Find suitable swarm members for a task, sorted by suitability."""
        candidates = []
        
        for member_id, member in self.swarm_members.items():
            if member.can_execute_task(task):
                score = member.calculate_suitability_score(task)
                if score > 0:
                    candidates.append((member_id, score))
        
        # Sort by score (highest first)
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        return candidates
    
    async def handle_task_completion(
        self, 
        task_id: str, 
        member_id: str,
        success: bool,
        metrics: Optional[Dict[str, Any]] = None
    ):
        """Handle task completion notification from swarm member."""
        async with self._lock:
            if task_id not in self.active_allocations:
                logger.warning("Unknown task completion: %s", task_id)
                return
            
            # Update task status
            allocation = self.active_allocations[task_id]
            task = next((t for _, t in self.task_queue if t.task_id == task_id), None)
            
            if task:
                task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
                task.execution_metrics = metrics or {}
            
            # Update member state
            member = self.swarm_members.get(member_id)
            if member:
                member.active_tasks.discard(task_id)
                member.current_load = max(0.0, member.current_load - 0.1)
                
                if success:
                    member.completed_tasks += 1
                    member.reliability_score = min(
                        1.0, 
                        member.reliability_score * 0.95 + 0.05
                    )
                else:
                    member.failed_tasks += 1
                    member.reliability_score = max(
                        0.0,
                        member.reliability_score * 0.9
                    )
            
            # Audit log
            await self.audit_logger.log_event(
                "TASK_COMPLETED" if success else "TASK_FAILED",
                classification=task.classification if task else ClassificationLevel.UNCLASSIFIED,
                details={
                    'task_id': task_id,
                    'member_id': member_id,
                    'success': success,
                    'metrics': metrics
                }
            )
    
    async def reallocate_failed_tasks(self):
        """Reallocate tasks that have failed or timed out."""
        tasks_to_reallocate = []
        
        async with self._lock:
            current_time = datetime.now()
            
            for task_id, allocation in self.active_allocations.items():
                task = next((t for _, t in self.task_queue if t.task_id == task_id), None)
                
                if not task:
                    continue
                
                # Check for timeout
                if task.status == TaskStatus.ASSIGNED:
                    time_elapsed = (current_time - task.allocation_history[-1][1]).total_seconds()
                    if time_elapsed > self.config.task_timeout_seconds:
                        tasks_to_reallocate.append(task)
                
                # Check for failed tasks that can be retried
                elif task.status == TaskStatus.FAILED:
                    if len(task.allocation_history) < self.config.max_retries:
                        tasks_to_reallocate.append(task)
        
        # Reallocate tasks
        for task in tasks_to_reallocate:
            task.status = TaskStatus.REALLOCATING
            await self.submit_task(task)
            logger.info("Reallocating task %s (attempt %d)", 
                       task.task_id, len(task.allocation_history) + 1)
    
    async def get_swarm_status(self) -> Dict[str, Any]:
        """Get current swarm status and metrics."""
        async with self._lock:
            return {
                'swarm_size': len(self.swarm_members),
                'active_members': sum(
                    1 for m in self.swarm_members.values() 
                    if m.active_tasks
                ),
                'total_capabilities': sum(
                    len(m.capabilities) 
                    for m in self.swarm_members.values()
                ),
                'pending_tasks': len([
                    t for _, t in self.task_queue 
                    if t.status == TaskStatus.PENDING
                ]),
                'active_tasks': len(self.active_allocations),
                'allocation_metrics': self.allocation_metrics.copy(),
                'average_member_load': sum(
                    m.current_load for m in self.swarm_members.values()
                ) / max(1, len(self.swarm_members)),
                'consensus_protocol_active': self.consensus_protocol is not None
            }
    
    async def shutdown(self):
        """Gracefully shutdown the task allocator."""
        logger.info("Shutting down Distributed Task Allocator...")
        
        # Cancel any pending allocations
        for task in self.task_queue:
            if task[1].status == TaskStatus.PENDING:
                task[1].status = TaskStatus.CANCELLED
        
        # Clean up executor
        self.executor.shutdown(wait=True)
        
        # Final metrics log
        logger.info("Final allocation metrics: %s", self.allocation_metrics)