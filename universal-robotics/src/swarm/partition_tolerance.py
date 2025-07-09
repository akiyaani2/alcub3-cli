#!/usr/bin/env python3
"""
ALCUB3 Network Partition Tolerance System
Advanced partition detection, handling, and recovery for swarm consensus

This module implements sophisticated network partition tolerance mechanisms
including detection algorithms, quorum management, and state reconciliation.
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
import numpy as np
import networkx as nx
from scipy.cluster.hierarchy import linkage, fcluster

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class PartitionState(Enum):
    """Network partition states."""
    CONNECTED = "connected"           # Fully connected network
    PARTIAL = "partial"              # Some nodes unreachable
    SPLIT = "split"                  # Network split into partitions
    HEALING = "healing"              # Partition recovery in progress
    DEGRADED = "degraded"            # Operating with reduced nodes


class ReconciliationStrategy(Enum):
    """Strategies for reconciling divergent states."""
    LATEST_TIMESTAMP = "latest_timestamp"     # Use most recent state
    HIGHEST_SEQUENCE = "highest_sequence"     # Use highest sequence number
    MAJORITY_VOTE = "majority_vote"          # Vote on conflicting states
    WEIGHTED_MERGE = "weighted_merge"        # Weight by partition size
    CLASSIFICATION_PRIORITY = "classification_priority"  # Higher classification wins


@dataclass
class NetworkPartition:
    """Represents a network partition."""
    partition_id: str
    detected_at: datetime
    nodes: Set[str]
    reachability_matrix: Dict[str, Set[str]]  # Who can reach whom
    partition_leader: Optional[str] = None
    state_digest: Optional[str] = None
    sequence_range: Tuple[int, int] = (0, 0)
    is_primary: bool = False  # Has quorum
    
    @property
    def size(self) -> int:
        """Number of nodes in partition."""
        return len(self.nodes)
    
    def can_reach(self, node_a: str, node_b: str) -> bool:
        """Check if node_a can reach node_b within partition."""
        return node_b in self.reachability_matrix.get(node_a, set())
    
    def is_fully_connected(self) -> bool:
        """Check if all nodes in partition can reach each other."""
        for node in self.nodes:
            reachable = self.reachability_matrix.get(node, set())
            if not self.nodes.issubset(reachable | {node}):
                return False
        return True


@dataclass
class PartitionEvent:
    """Network partition event."""
    event_id: str
    event_type: str  # "split", "merge", "node_join", "node_leave"
    timestamp: datetime
    affected_nodes: Set[str]
    old_partitions: List[str]
    new_partitions: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateConflict:
    """Represents a state conflict between partitions."""
    conflict_id: str
    sequence_number: int
    partition_states: Dict[str, Any]  # partition_id -> state
    resolution_strategy: ReconciliationStrategy
    resolved_state: Optional[Any] = None
    resolution_timestamp: Optional[datetime] = None


class NetworkTopologyMonitor:
    """Monitors network topology and detects partitions."""
    
    def __init__(self, heartbeat_interval: timedelta = timedelta(seconds=1)):
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_interval * 3
        
        # Node connectivity tracking
        self.last_heartbeats: Dict[str, Dict[str, datetime]] = defaultdict(dict)
        self.connectivity_graph = nx.Graph()
        self.latency_matrix: Dict[Tuple[str, str], float] = {}
        
        # Historical data
        self.connectivity_history: deque = deque(maxlen=1000)
        self.partition_events: List[PartitionEvent] = []
    
    def record_heartbeat(self, from_node: str, to_node: str, latency_ms: float):
        """Record successful heartbeat between nodes."""
        now = datetime.now()
        self.last_heartbeats[from_node][to_node] = now
        self.latency_matrix[(from_node, to_node)] = latency_ms
        
        # Update graph
        self.connectivity_graph.add_edge(from_node, to_node, weight=latency_ms)
        
        # Record in history
        self.connectivity_history.append({
            'from': from_node,
            'to': to_node,
            'latency': latency_ms,
            'timestamp': now
        })
    
    def detect_partitions(self, all_nodes: Set[str]) -> List[NetworkPartition]:
        """Detect network partitions based on connectivity."""
        now = datetime.now()
        partitions = []
        
        # Build current connectivity graph
        current_graph = nx.Graph()
        current_graph.add_nodes_from(all_nodes)
        
        # Add edges based on recent heartbeats
        for from_node in all_nodes:
            for to_node in all_nodes:
                if from_node != to_node:
                    last_heartbeat = self.last_heartbeats.get(from_node, {}).get(to_node)
                    if last_heartbeat and now - last_heartbeat < self.heartbeat_timeout:
                        current_graph.add_edge(from_node, to_node)
        
        # Find connected components (partitions)
        components = list(nx.connected_components(current_graph))
        
        for i, component in enumerate(components):
            # Build reachability matrix for partition
            reachability = {}
            for node in component:
                reachable = set()
                for other in component:
                    if node != other and nx.has_path(current_graph, node, other):
                        reachable.add(other)
                reachability[node] = reachable
            
            partition = NetworkPartition(
                partition_id=f"partition_{i}_{uuid.uuid4().hex[:8]}",
                detected_at=now,
                nodes=set(component),
                reachability_matrix=reachability
            )
            
            partitions.append(partition)
        
        return partitions
    
    def predict_partition_risk(self, all_nodes: Set[str]) -> Dict[str, float]:
        """Predict risk of partition for each node pair."""
        risk_scores = {}
        
        for node_a in all_nodes:
            for node_b in all_nodes:
                if node_a < node_b:  # Avoid duplicates
                    # Calculate risk based on:
                    # 1. Recent heartbeat failures
                    # 2. Increasing latency
                    # 3. Historical partition events
                    
                    risk = 0.0
                    
                    # Check heartbeat recency
                    last_hb = self.last_heartbeats.get(node_a, {}).get(node_b)
                    if not last_hb:
                        risk += 0.3
                    else:
                        age = (datetime.now() - last_hb).total_seconds()
                        risk += min(0.5, age / self.heartbeat_timeout.total_seconds())
                    
                    # Check latency trend
                    recent_latencies = [
                        h['latency'] for h in self.connectivity_history
                        if (h['from'] == node_a and h['to'] == node_b) or
                           (h['from'] == node_b and h['to'] == node_a)
                    ][-10:]
                    
                    if len(recent_latencies) > 5:
                        # Calculate trend
                        latency_increase = np.polyfit(range(len(recent_latencies)), recent_latencies, 1)[0]
                        if latency_increase > 0:
                            risk += min(0.3, latency_increase / 100)
                    
                    risk_scores[(node_a, node_b)] = min(1.0, risk)
        
        return risk_scores


class PartitionTolerantProtocol:
    """
    Network partition tolerant consensus protocol.
    
    Features:
    - Partition detection and tracking
    - Quorum management across partitions
    - State reconciliation after partition healing
    - Eventual consistency guarantees
    - Classification-aware partition handling
    """
    
    def __init__(
        self,
        node_id: str,
        total_nodes: int,
        classification_level: ClassificationLevel,
        audit_logger: AuditLogger
    ):
        self.node_id = node_id
        self.total_nodes = total_nodes
        self.classification_level = classification_level
        self.audit_logger = audit_logger
        
        # Partition management
        self.current_partition: Optional[NetworkPartition] = None
        self.known_partitions: Dict[str, NetworkPartition] = {}
        self.partition_state = PartitionState.CONNECTED
        
        # Topology monitoring
        self.topology_monitor = NetworkTopologyMonitor()
        
        # State management
        self.partition_states: Dict[str, Dict[int, Any]] = defaultdict(dict)  # partition_id -> sequence -> state
        self.state_conflicts: List[StateConflict] = []
        self.reconciliation_queue: deque = deque()
        
        # Quorum tracking
        self.partition_quorums: Dict[str, int] = {}  # partition_id -> node count
        self.global_quorum_size = (total_nodes // 3) * 2 + 1
        
        # Configuration
        self.partition_timeout = timedelta(minutes=5)
        self.reconciliation_batch_size = 100
        self.max_divergence_allowed = 1000  # Max sequence number difference
        
        # Metrics
        self.partition_metrics = {
            'total_partitions': 0,
            'partition_duration_sum': 0.0,
            'successful_reconciliations': 0,
            'failed_reconciliations': 0,
            'state_conflicts_resolved': 0
        }
        
        logger.info("Partition Tolerant Protocol initialized for node %s", node_id)
    
    async def update_network_state(self, reachable_nodes: Set[str], all_nodes: Set[str]):
        """Update network state based on reachability."""
        # Record heartbeats for reachable nodes
        for node in reachable_nodes:
            if node != self.node_id:
                self.topology_monitor.record_heartbeat(
                    self.node_id, node, 
                    np.random.uniform(5, 50)  # Simulated latency
                )
        
        # Detect partitions
        partitions = self.topology_monitor.detect_partitions(all_nodes)
        
        # Find our partition
        my_partition = None
        for partition in partitions:
            if self.node_id in partition.nodes:
                my_partition = partition
                break
        
        if not my_partition:
            logger.error("Node %s not found in any partition!", self.node_id)
            return
        
        # Check if partition changed
        if not self.current_partition or self.current_partition.nodes != my_partition.nodes:
            await self._handle_partition_change(my_partition, partitions)
        
        self.current_partition = my_partition
        
        # Update partition state
        if len(partitions) == 1 and partitions[0].size == self.total_nodes:
            self.partition_state = PartitionState.CONNECTED
        elif len(partitions) > 1:
            self.partition_state = PartitionState.SPLIT
        else:
            self.partition_state = PartitionState.PARTIAL
    
    async def _handle_partition_change(
        self,
        new_partition: NetworkPartition,
        all_partitions: List[NetworkPartition]
    ):
        """Handle network partition change."""
        old_partition_id = self.current_partition.partition_id if self.current_partition else None
        
        # Determine partition leadership
        new_partition.partition_leader = self._elect_partition_leader(new_partition)
        
        # Check if partition has quorum
        new_partition.is_primary = new_partition.size >= self.global_quorum_size
        
        # Create partition event
        event = PartitionEvent(
            event_id=str(uuid.uuid4()),
            event_type="split" if len(all_partitions) > 1 else "merge",
            timestamp=datetime.now(),
            affected_nodes=new_partition.nodes,
            old_partitions=[old_partition_id] if old_partition_id else [],
            new_partitions=[p.partition_id for p in all_partitions]
        )
        
        self.topology_monitor.partition_events.append(event)
        self.partition_metrics['total_partitions'] += 1
        
        # Store partition info
        self.known_partitions[new_partition.partition_id] = new_partition
        
        # If merging partitions, initiate reconciliation
        if event.event_type == "merge" and len(event.old_partitions) > 1:
            await self._initiate_reconciliation(event.old_partitions)
        
        # Audit log
        await self.audit_logger.log_event(
            "NETWORK_PARTITION_CHANGE",
            classification=self.classification_level,
            details={
                'event_type': event.event_type,
                'partition_id': new_partition.partition_id,
                'partition_size': new_partition.size,
                'has_quorum': new_partition.is_primary,
                'leader': new_partition.partition_leader
            }
        )
        
        logger.warning("Partition change: %s -> %s (size: %d, quorum: %s)",
                      old_partition_id, new_partition.partition_id,
                      new_partition.size, new_partition.is_primary)
    
    def _elect_partition_leader(self, partition: NetworkPartition) -> str:
        """Elect leader for a partition using deterministic algorithm."""
        # Sort nodes by:
        # 1. Classification level (descending)
        # 2. Node ID (for determinism)
        
        candidates = []
        for node in partition.nodes:
            # In real implementation, would look up node classification
            # For now, use hash of node_id as pseudo-classification
            classification_value = hash(node) % 3  # 0=UNCLASSIFIED, 1=SECRET, 2=TOP_SECRET
            candidates.append((classification_value, node))
        
        candidates.sort(reverse=True)
        return candidates[0][1] if candidates else None
    
    def can_make_progress(self) -> Tuple[bool, str]:
        """Check if current partition can make consensus progress."""
        if not self.current_partition:
            return False, "No partition information"
        
        if self.partition_state == PartitionState.CONNECTED:
            return True, "Network fully connected"
        
        if self.current_partition.is_primary:
            return True, f"Partition has quorum ({self.current_partition.size}/{self.total_nodes})"
        
        # Check if we have classification-based quorum
        if self.classification_level == ClassificationLevel.TOP_SECRET:
            # TS nodes can continue with fewer nodes
            ts_quorum = max(3, self.total_nodes // 4)
            if self.current_partition.size >= ts_quorum:
                return True, "Classification-based quorum met"
        
        return False, f"Insufficient nodes for quorum ({self.current_partition.size}/{self.global_quorum_size})"
    
    async def record_partition_state(self, sequence_number: int, state: Any):
        """Record state for current partition."""
        if not self.current_partition:
            return
        
        partition_id = self.current_partition.partition_id
        self.partition_states[partition_id][sequence_number] = state
        
        # Update partition's sequence range
        if partition_id in self.known_partitions:
            min_seq = min(self.partition_states[partition_id].keys())
            max_seq = max(self.partition_states[partition_id].keys())
            self.known_partitions[partition_id].sequence_range = (min_seq, max_seq)
            
            # Calculate state digest
            state_data = json.dumps(
                sorted(self.partition_states[partition_id].items()),
                sort_keys=True
            )
            self.known_partitions[partition_id].state_digest = hashlib.sha256(
                state_data.encode()
            ).hexdigest()
    
    async def _initiate_reconciliation(self, partition_ids: List[str]):
        """Initiate state reconciliation between partitions."""
        logger.info("Initiating reconciliation for partitions: %s", partition_ids)
        
        # Collect states from all partitions
        partition_sequences = {}
        for pid in partition_ids:
            if pid in self.partition_states:
                partition_sequences[pid] = set(self.partition_states[pid].keys())
        
        if not partition_sequences:
            return
        
        # Find overlapping and unique sequences
        all_sequences = set()
        for sequences in partition_sequences.values():
            all_sequences.update(sequences)
        
        # Check each sequence for conflicts
        for sequence in sorted(all_sequences):
            states_by_partition = {}
            
            for pid in partition_ids:
                if sequence in self.partition_states[pid]:
                    states_by_partition[pid] = self.partition_states[pid][sequence]
            
            if len(set(str(s) for s in states_by_partition.values())) > 1:
                # Conflict detected
                conflict = StateConflict(
                    conflict_id=str(uuid.uuid4()),
                    sequence_number=sequence,
                    partition_states=states_by_partition,
                    resolution_strategy=self._select_resolution_strategy(states_by_partition)
                )
                
                self.state_conflicts.append(conflict)
                self.reconciliation_queue.append(conflict)
        
        # Process reconciliation queue
        await self._process_reconciliation_queue()
    
    def _select_resolution_strategy(self, partition_states: Dict[str, Any]) -> ReconciliationStrategy:
        """Select appropriate reconciliation strategy."""
        # Check if any partition had classification priority
        has_classified = any(
            self.known_partitions.get(pid, NetworkPartition(
                "", datetime.now(), set(), {}
            )).partition_leader and
            hash(self.known_partitions[pid].partition_leader) % 3 > 0
            for pid in partition_states
        )
        
        if has_classified and self.classification_level != ClassificationLevel.UNCLASSIFIED:
            return ReconciliationStrategy.CLASSIFICATION_PRIORITY
        
        # Check partition sizes
        partition_sizes = [
            len(self.known_partitions.get(pid, NetworkPartition(
                "", datetime.now(), set(), {}
            )).nodes)
            for pid in partition_states
        ]
        
        if max(partition_sizes) > sum(partition_sizes) * 0.6:
            return ReconciliationStrategy.MAJORITY_VOTE
        
        # Default to latest timestamp
        return ReconciliationStrategy.LATEST_TIMESTAMP
    
    async def _process_reconciliation_queue(self):
        """Process pending reconciliations."""
        processed = 0
        
        while self.reconciliation_queue and processed < self.reconciliation_batch_size:
            conflict = self.reconciliation_queue.popleft()
            
            try:
                resolved_state = await self._resolve_conflict(conflict)
                conflict.resolved_state = resolved_state
                conflict.resolution_timestamp = datetime.now()
                
                self.partition_metrics['successful_reconciliations'] += 1
                self.partition_metrics['state_conflicts_resolved'] += 1
                
                # Apply resolved state
                if self.current_partition:
                    self.partition_states[self.current_partition.partition_id][
                        conflict.sequence_number
                    ] = resolved_state
                
                processed += 1
                
            except Exception as e:
                logger.error("Failed to resolve conflict %s: %s", conflict.conflict_id, e)
                self.partition_metrics['failed_reconciliations'] += 1
                
                # Re-queue for retry
                self.reconciliation_queue.append(conflict)
    
    async def _resolve_conflict(self, conflict: StateConflict) -> Any:
        """Resolve a state conflict using selected strategy."""
        strategy = conflict.resolution_strategy
        states = conflict.partition_states
        
        if strategy == ReconciliationStrategy.LATEST_TIMESTAMP:
            # Use state with latest timestamp
            latest_time = None
            latest_state = None
            
            for state in states.values():
                if isinstance(state, dict) and 'timestamp' in state:
                    timestamp = datetime.fromisoformat(state['timestamp'])
                    if not latest_time or timestamp > latest_time:
                        latest_time = timestamp
                        latest_state = state
            
            return latest_state or list(states.values())[0]
        
        elif strategy == ReconciliationStrategy.HIGHEST_SEQUENCE:
            # Already at specific sequence, return any
            return list(states.values())[0]
        
        elif strategy == ReconciliationStrategy.MAJORITY_VOTE:
            # Count occurrences of each state
            state_counts = defaultdict(int)
            state_map = {}
            
            for state in states.values():
                state_str = json.dumps(state, sort_keys=True)
                state_counts[state_str] += 1
                state_map[state_str] = state
            
            # Return most common state
            majority_state_str = max(state_counts, key=state_counts.get)
            return state_map[majority_state_str]
        
        elif strategy == ReconciliationStrategy.WEIGHTED_MERGE:
            # Weight by partition size
            weighted_states = []
            
            for pid, state in states.items():
                partition = self.known_partitions.get(pid)
                weight = partition.size if partition else 1
                weighted_states.append((weight, state))
            
            # Return state from largest partition
            weighted_states.sort(reverse=True)
            return weighted_states[0][1]
        
        elif strategy == ReconciliationStrategy.CLASSIFICATION_PRIORITY:
            # Highest classification wins
            classified_states = []
            
            for pid, state in states.items():
                partition = self.known_partitions.get(pid)
                if partition and partition.partition_leader:
                    # Use leader's classification (simulated)
                    classification = hash(partition.partition_leader) % 3
                    classified_states.append((classification, state))
            
            if classified_states:
                classified_states.sort(reverse=True)
                return classified_states[0][1]
            
            return list(states.values())[0]
        
        # Fallback
        return list(states.values())[0]
    
    def estimate_partition_duration(self) -> Optional[timedelta]:
        """Estimate how long current partition will last."""
        if self.partition_state == PartitionState.CONNECTED:
            return timedelta(0)
        
        # Analyze historical partition events
        recent_events = [
            e for e in self.topology_monitor.partition_events
            if e.timestamp > datetime.now() - timedelta(hours=24)
        ]
        
        if not recent_events:
            return None
        
        # Calculate average partition duration
        durations = []
        for i in range(len(recent_events) - 1):
            if recent_events[i].event_type == "split" and recent_events[i+1].event_type == "merge":
                duration = recent_events[i+1].timestamp - recent_events[i].timestamp
                durations.append(duration.total_seconds())
        
        if durations:
            avg_duration = np.mean(durations)
            return timedelta(seconds=avg_duration)
        
        return None
    
    def get_partition_metrics(self) -> Dict[str, Any]:
        """Get partition tolerance metrics."""
        metrics = self.partition_metrics.copy()
        
        # Add current state info
        metrics['current_state'] = self.partition_state.value
        metrics['current_partition_size'] = self.current_partition.size if self.current_partition else 0
        metrics['has_quorum'] = self.current_partition.is_primary if self.current_partition else False
        metrics['known_partitions'] = len(self.known_partitions)
        metrics['pending_reconciliations'] = len(self.reconciliation_queue)
        metrics['unresolved_conflicts'] = len([c for c in self.state_conflicts if not c.resolved_state])
        
        # Calculate average partition duration
        if metrics['total_partitions'] > 0:
            metrics['avg_partition_duration_s'] = metrics['partition_duration_sum'] / metrics['total_partitions']
        else:
            metrics['avg_partition_duration_s'] = 0
        
        # Partition risk assessment
        if self.topology_monitor and self.current_partition:
            risk_scores = self.topology_monitor.predict_partition_risk(self.current_partition.nodes)
            if risk_scores:
                metrics['partition_risk'] = {
                    'average': np.mean(list(risk_scores.values())),
                    'max': max(risk_scores.values()),
                    'high_risk_pairs': sum(1 for r in risk_scores.values() if r > 0.7)
                }
        
        return metrics
    
    async def handle_partition_timeout(self):
        """Handle partition timeout - switch to degraded mode."""
        if self.partition_state != PartitionState.SPLIT:
            return
        
        if not self.current_partition:
            return
        
        # Check partition age
        partition_age = datetime.now() - self.current_partition.detected_at
        
        if partition_age > self.partition_timeout:
            logger.warning("Partition timeout reached, switching to degraded mode")
            self.partition_state = PartitionState.DEGRADED
            
            # Adjust consensus parameters for degraded operation
            # In real implementation, would signal consensus engine
            
            await self.audit_logger.log_event(
                "PARTITION_TIMEOUT",
                classification=self.classification_level,
                details={
                    'partition_id': self.current_partition.partition_id,
                    'partition_age_s': partition_age.total_seconds(),
                    'partition_size': self.current_partition.size
                }
            )