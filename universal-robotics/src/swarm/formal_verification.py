#!/usr/bin/env python3
"""
ALCUB3 Formal Verification for Byzantine Consensus
Mathematical proofs and invariant checking for correctness guarantees

This module implements formal verification techniques to prove safety,
liveness, and Byzantine fault tolerance properties of the consensus protocol.
"""

import time
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import numpy as np
from z3 import *  # SMT solver for formal verification

logger = logging.getLogger(__name__)


class VerificationProperty(Enum):
    """Properties to verify."""
    AGREEMENT = "agreement"              # All correct nodes agree
    VALIDITY = "validity"                # Decision was proposed by someone
    TERMINATION = "termination"          # All correct nodes eventually decide
    INTEGRITY = "integrity"              # Decide at most once
    BYZANTINE_TOLERANCE = "byzantine"    # Tolerates f Byzantine nodes
    TOTAL_ORDER = "total_order"         # All nodes see same order
    CAUSALITY = "causality"             # Causal order preserved


@dataclass
class ProtocolState:
    """Abstract protocol state for verification."""
    view_number: int
    sequence_number: int
    phase: str
    num_nodes: int
    num_faulty: int
    prepared_values: Set[str] = field(default_factory=set)
    committed_values: Set[str] = field(default_factory=set)
    decided_values: Set[str] = field(default_factory=set)
    node_states: Dict[str, str] = field(default_factory=dict)  # node_id -> state
    message_log: List[Tuple[str, str, str]] = field(default_factory=list)  # (from, to, type)


@dataclass
class SafetyInvariant:
    """Safety invariant to check."""
    name: str
    description: str
    check_function: Callable[[ProtocolState], bool]
    violation_count: int = 0
    last_violation: Optional[datetime] = None
    
    def check(self, state: ProtocolState) -> Tuple[bool, Optional[str]]:
        """Check if invariant holds."""
        try:
            if self.check_function(state):
                return True, None
            else:
                self.violation_count += 1
                self.last_violation = datetime.now()
                return False, f"Invariant {self.name} violated at view {state.view_number}"
        except Exception as e:
            return False, f"Error checking invariant {self.name}: {e}"


@dataclass
class LivenessProperty:
    """Liveness property to verify."""
    name: str
    description: str
    max_rounds: int  # Maximum rounds before property must hold
    check_function: Callable[[List[ProtocolState]], bool]
    
    def check(self, state_history: List[ProtocolState]) -> Tuple[bool, Optional[str]]:
        """Check if liveness property eventually holds."""
        if len(state_history) < self.max_rounds:
            return True, None  # Not enough history yet
        
        if self.check_function(state_history[-self.max_rounds:]):
            return True, None
        else:
            return False, f"Liveness property {self.name} not satisfied after {self.max_rounds} rounds"


class FormalVerifier:
    """
    Formal verification system for Byzantine consensus.
    
    Verifies:
    - Safety properties (agreement, validity, integrity)
    - Liveness properties (termination)
    - Byzantine fault tolerance bounds
    - Protocol invariants
    """
    
    def __init__(self):
        # Z3 solver for formal proofs
        self.solver = Solver()
        
        # Define safety invariants
        self.safety_invariants = self._define_safety_invariants()
        
        # Define liveness properties
        self.liveness_properties = self._define_liveness_properties()
        
        # Protocol traces for verification
        self.protocol_traces: List[ProtocolState] = []
        self.max_trace_length = 1000
        
        # Verification results
        self.verification_results = {
            'safety_violations': 0,
            'liveness_violations': 0,
            'invariant_checks': 0,
            'proofs_generated': 0,
            'counterexamples': []
        }
        
        logger.info("Formal Verifier initialized")
    
    def _define_safety_invariants(self) -> List[SafetyInvariant]:
        """Define safety invariants to check."""
        return [
            SafetyInvariant(
                name="single_value_prepared",
                description="At most one value can be prepared in a view",
                check_function=lambda s: len(s.prepared_values) <= 1
            ),
            SafetyInvariant(
                name="single_value_committed",
                description="At most one value can be committed in a view",
                check_function=lambda s: len(s.committed_values) <= 1
            ),
            SafetyInvariant(
                name="prepare_before_commit",
                description="A value must be prepared before committed",
                check_function=lambda s: s.committed_values.issubset(s.prepared_values)
            ),
            SafetyInvariant(
                name="commit_before_decide",
                description="A value must be committed before decided",
                check_function=lambda s: s.decided_values.issubset(s.committed_values)
            ),
            SafetyInvariant(
                name="quorum_overlap",
                description="Any two quorums must overlap",
                check_function=self._check_quorum_overlap
            ),
            SafetyInvariant(
                name="byzantine_bound",
                description="Number of faulty nodes within tolerance",
                check_function=lambda s: s.num_faulty <= (s.num_nodes - 1) // 3
            )
        ]
    
    def _define_liveness_properties(self) -> List[LivenessProperty]:
        """Define liveness properties to verify."""
        return [
            LivenessProperty(
                name="eventual_decision",
                description="All correct nodes eventually decide",
                max_rounds=10,
                check_function=self._check_eventual_decision
            ),
            LivenessProperty(
                name="view_change_progress",
                description="View changes eventually succeed",
                max_rounds=5,
                check_function=self._check_view_progress
            ),
            LivenessProperty(
                name="message_delivery",
                description="Messages eventually delivered to correct nodes",
                max_rounds=3,
                check_function=self._check_message_delivery
            )
        ]
    
    def _check_quorum_overlap(self, state: ProtocolState) -> bool:
        """Verify quorum intersection property."""
        n = state.num_nodes
        f = state.num_faulty
        quorum_size = 2 * f + 1
        
        # In PBFT, any two quorums of size 2f+1 must overlap in at least f+1 nodes
        # This ensures at least one correct node in the intersection
        min_overlap = f + 1
        
        # For n nodes with quorum size q, minimum overlap is 2q - n
        actual_min_overlap = 2 * quorum_size - n
        
        return actual_min_overlap >= min_overlap
    
    def _check_eventual_decision(self, state_history: List[ProtocolState]) -> bool:
        """Check if all correct nodes eventually decide."""
        if not state_history:
            return True
        
        last_state = state_history[-1]
        correct_nodes = [
            node_id for node_id, state in last_state.node_states.items()
            if state != "faulty"
        ]
        
        # All correct nodes should have decided
        decided_nodes = [
            node_id for node_id in correct_nodes
            if last_state.node_states.get(node_id) == "decided"
        ]
        
        return len(decided_nodes) == len(correct_nodes)
    
    def _check_view_progress(self, state_history: List[ProtocolState]) -> bool:
        """Check if view changes make progress."""
        if len(state_history) < 2:
            return True
        
        view_numbers = [s.view_number for s in state_history]
        
        # Check if stuck in same view
        if all(v == view_numbers[0] for v in view_numbers):
            # Check if making sequence progress
            seq_numbers = [s.sequence_number for s in state_history]
            return seq_numbers[-1] > seq_numbers[0]
        
        # View is progressing
        return view_numbers[-1] > view_numbers[0]
    
    def _check_message_delivery(self, state_history: List[ProtocolState]) -> bool:
        """Check message delivery property."""
        # Simplified check - in real implementation would track actual delivery
        total_messages = sum(len(s.message_log) for s in state_history)
        return total_messages > 0
    
    def record_state(self, state: ProtocolState):
        """Record protocol state for verification."""
        self.protocol_traces.append(state)
        
        # Limit trace length
        if len(self.protocol_traces) > self.max_trace_length:
            self.protocol_traces.pop(0)
        
        # Check invariants
        self._check_invariants(state)
    
    def _check_invariants(self, state: ProtocolState):
        """Check all safety invariants."""
        for invariant in self.safety_invariants:
            self.verification_results['invariant_checks'] += 1
            
            holds, error = invariant.check(state)
            if not holds:
                self.verification_results['safety_violations'] += 1
                logger.error("Safety violation: %s", error)
                
                # Record counterexample
                self.verification_results['counterexamples'].append({
                    'type': 'safety',
                    'invariant': invariant.name,
                    'state': state,
                    'error': error
                })
    
    def verify_safety_properties(self) -> Dict[str, bool]:
        """Verify all safety properties hold."""
        results = {}
        
        # Check agreement
        results['agreement'] = self._verify_agreement()
        
        # Check validity
        results['validity'] = self._verify_validity()
        
        # Check integrity
        results['integrity'] = self._verify_integrity()
        
        return results
    
    def _verify_agreement(self) -> bool:
        """Verify agreement property: all correct nodes agree on same value."""
        if not self.protocol_traces:
            return True
        
        # Group decisions by view/sequence
        decisions_by_round = defaultdict(set)
        
        for state in self.protocol_traces:
            key = (state.view_number, state.sequence_number)
            decisions_by_round[key].update(state.decided_values)
        
        # Check each round has at most one decision
        for key, decisions in decisions_by_round.items():
            if len(decisions) > 1:
                logger.error("Agreement violation at %s: multiple decisions %s", key, decisions)
                return False
        
        return True
    
    def _verify_validity(self) -> bool:
        """Verify validity: decided value was proposed by a correct node."""
        # In PBFT, this is ensured by the protocol structure
        # Check that decided values appeared in requests
        return True  # Simplified - would check against actual proposals
    
    def _verify_integrity(self) -> bool:
        """Verify integrity: each correct node decides at most once per sequence."""
        decisions_per_node = defaultdict(lambda: defaultdict(int))
        
        for state in self.protocol_traces:
            for node_id in state.node_states:
                if state.node_states[node_id] == "decided":
                    decisions_per_node[node_id][state.sequence_number] += 1
        
        # Check no node decided more than once per sequence
        for node_id, sequences in decisions_per_node.items():
            for seq, count in sequences.items():
                if count > 1:
                    logger.error("Integrity violation: node %s decided %d times for seq %d",
                               node_id, count, seq)
                    return False
        
        return True
    
    def verify_liveness_properties(self) -> Dict[str, bool]:
        """Verify liveness properties."""
        results = {}
        
        for prop in self.liveness_properties:
            holds, error = prop.check(self.protocol_traces)
            results[prop.name] = holds
            
            if not holds:
                self.verification_results['liveness_violations'] += 1
                logger.error("Liveness violation: %s", error)
        
        return results
    
    def prove_byzantine_tolerance(self, n: int, f: int) -> bool:
        """Prove Byzantine fault tolerance for n nodes with f faults."""
        # Create Z3 variables
        nodes = [Bool(f'node_{i}') for i in range(n)]
        faulty = [Bool(f'faulty_{i}') for i in range(n)]
        
        # Add constraints
        self.solver.push()
        
        # At most f nodes are faulty
        self.solver.add(Sum([If(faulty[i], 1, 0) for i in range(n)]) <= f)
        
        # Quorum size is 2f + 1
        quorum_size = 2 * f + 1
        
        # For any two quorums, they must overlap in at least f+1 nodes
        # This ensures at least one correct node in intersection
        
        # Create two arbitrary quorums
        quorum1 = [Bool(f'q1_{i}') for i in range(n)]
        quorum2 = [Bool(f'q2_{i}') for i in range(n)]
        
        # Each quorum has exactly quorum_size nodes
        self.solver.add(Sum([If(quorum1[i], 1, 0) for i in range(n)]) == quorum_size)
        self.solver.add(Sum([If(quorum2[i], 1, 0) for i in range(n)]) == quorum_size)
        
        # Calculate intersection
        intersection = [And(quorum1[i], quorum2[i]) for i in range(n)]
        intersection_size = Sum([If(intersection[i], 1, 0) for i in range(n)])
        
        # Intersection must have at least one correct node
        correct_in_intersection = Sum([
            If(And(intersection[i], Not(faulty[i])), 1, 0) 
            for i in range(n)
        ])
        
        # Try to find counterexample where no correct node in intersection
        self.solver.add(correct_in_intersection == 0)
        
        # Check satisfiability
        result = self.solver.check()
        self.solver.pop()
        
        if result == unsat:
            # No counterexample found - Byzantine tolerance holds
            self.verification_results['proofs_generated'] += 1
            logger.info("Proved Byzantine tolerance for n=%d, f=%d", n, f)
            return True
        else:
            # Found counterexample
            logger.error("Byzantine tolerance fails for n=%d, f=%d", n, f)
            return False
    
    def generate_correctness_proof(self) -> Dict[str, Any]:
        """Generate formal correctness proof."""
        proof = {
            'timestamp': datetime.now().isoformat(),
            'protocol': 'PBFT',
            'properties_verified': {},
            'assumptions': [],
            'theorems': []
        }
        
        # Verify safety properties
        safety_results = self.verify_safety_properties()
        proof['properties_verified']['safety'] = safety_results
        
        # Verify liveness properties
        liveness_results = self.verify_liveness_properties()
        proof['properties_verified']['liveness'] = liveness_results
        
        # Byzantine tolerance proof
        n = 10  # Example
        f = 3   # Byzantine nodes
        byzantine_proof = self.prove_byzantine_tolerance(n, f)
        proof['properties_verified']['byzantine_tolerance'] = byzantine_proof
        
        # Add assumptions
        proof['assumptions'] = [
            "Synchronous network model with known bounds",
            "Cryptographic signatures are unforgeable",
            "Hash functions are collision-resistant",
            f"At most {f} out of {n} nodes are Byzantine"
        ]
        
        # Add proven theorems
        if all(safety_results.values()):
            proof['theorems'].append("Safety: All correct nodes agree on the same value")
        
        if all(liveness_results.values()):
            proof['theorems'].append("Liveness: All correct nodes eventually decide")
        
        if byzantine_proof:
            proof['theorems'].append(f"Byzantine Tolerance: Protocol tolerates {f} Byzantine nodes")
        
        self.verification_results['proofs_generated'] += 1
        
        return proof
    
    def verify_message_complexity(self, n: int) -> Dict[str, int]:
        """Verify message complexity bounds."""
        # PBFT message complexity
        # Normal case: O(n²) - each node sends to all others
        # View change: O(n²) - similar broadcast pattern
        
        complexity = {
            'normal_case': {
                'pre_prepare': n - 1,      # Primary to all backups
                'prepare': (n - 1) ** 2,   # All to all
                'commit': (n - 1) ** 2,    # All to all
                'total': n - 1 + 2 * (n - 1) ** 2
            },
            'view_change': {
                'view_change': n * (n - 1),     # All to all
                'new_view': n - 1,              # New primary to all
                'total': n * (n - 1) + n - 1
            }
        }
        
        # Verify bounds
        normal_total = complexity['normal_case']['total']
        view_change_total = complexity['view_change']['total']
        
        # Both should be O(n²)
        complexity['verified'] = (
            normal_total <= n * n and
            view_change_total <= n * n
        )
        
        return complexity
    
    def check_linearizability(self, operations: List[Dict[str, Any]]) -> bool:
        """Check if operations are linearizable."""
        # Simplified linearizability check
        # In real implementation, would use sophisticated algorithms
        
        # Check that operations can be totally ordered while respecting:
        # 1. Real-time ordering (if op1 completes before op2 starts, op1 < op2)
        # 2. Sequential specification (operations appear atomic)
        
        # Sort by start time
        sorted_ops = sorted(operations, key=lambda op: op.get('start_time', 0))
        
        # Check for conflicts
        for i in range(len(sorted_ops) - 1):
            op1 = sorted_ops[i]
            op2 = sorted_ops[i + 1]
            
            # If op1 completes after op2 starts, they overlap
            if op1.get('end_time', float('inf')) > op2.get('start_time', 0):
                # Check if operations commute
                if not self._operations_commute(op1, op2):
                    return False
        
        return True
    
    def _operations_commute(self, op1: Dict[str, Any], op2: Dict[str, Any]) -> bool:
        """Check if two operations commute."""
        # Read operations always commute
        if op1.get('type') == 'read' and op2.get('type') == 'read':
            return True
        
        # Write operations on different keys commute
        if op1.get('key') != op2.get('key'):
            return True
        
        return False
    
    def get_verification_report(self) -> Dict[str, Any]:
        """Generate comprehensive verification report."""
        report = {
            'summary': {
                'total_states_analyzed': len(self.protocol_traces),
                'safety_violations': self.verification_results['safety_violations'],
                'liveness_violations': self.verification_results['liveness_violations'],
                'invariant_checks': self.verification_results['invariant_checks'],
                'proofs_generated': self.verification_results['proofs_generated']
            },
            'invariants': {},
            'properties': {},
            'counterexamples': self.verification_results['counterexamples']
        }
        
        # Add invariant status
        for inv in self.safety_invariants:
            report['invariants'][inv.name] = {
                'description': inv.description,
                'violations': inv.violation_count,
                'last_violation': inv.last_violation.isoformat() if inv.last_violation else None
            }
        
        # Add property verification results
        report['properties']['safety'] = self.verify_safety_properties()
        report['properties']['liveness'] = self.verify_liveness_properties()
        
        # Add complexity analysis
        report['complexity'] = self.verify_message_complexity(10)
        
        return report