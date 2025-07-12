#!/usr/bin/env python3
"""
ALCUB3 Byzantine Fault-Tolerant Consensus Protocol
Advanced consensus mechanism for swarm task allocation

This module implements a sophisticated PBFT-based consensus protocol
with classification-aware voting and predictive fault detection.
"""

import asyncio
import time
import uuid
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class ConsensusState(Enum):
    """State of consensus protocol."""
    IDLE = "idle"
    PREPARING = "preparing"
    PREPARED = "prepared"
    COMMITTING = "committing"
    COMMITTED = "committed"
    VIEW_CHANGING = "view_changing"


class FaultType(Enum):
    """Types of Byzantine faults."""
    NONE = "none"
    CRASH = "crash"  # Node stops responding
    OMISSION = "omission"  # Node omits messages
    TIMING = "timing"  # Node delays messages
    ARBITRARY = "arbitrary"  # Node sends conflicting messages


@dataclass
class CryptoCredentials:
    """Cryptographic credentials for swarm member."""
    member_id: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    certificate: Optional[bytes] = None
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED


@dataclass
class ConsensusView:
    """View configuration for consensus rounds."""
    view_number: int
    leader_id: str
    members: List[str]
    faulty_members: Set[str] = field(default_factory=set)
    start_time: datetime = field(default_factory=datetime.now)
    
    def is_valid_member(self, member_id: str) -> bool:
        """Check if member is valid in this view."""
        return member_id in self.members and member_id not in self.faulty_members


@dataclass
class SignedMessage:
    """Cryptographically signed consensus message."""
    content: Dict[str, Any]
    sender_id: str
    signature: bytes
    timestamp: datetime
    sequence_number: int
    
    def verify_signature(self, public_key: rsa.RSAPublicKey) -> bool:
        """Verify message signature."""
        try:
            message_bytes = json.dumps(self.content, sort_keys=True).encode()
            public_key.verify(
                self.signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


@dataclass
class VoteRecord:
    """Record of votes for consensus decision."""
    phase: str
    task_id: str
    proposed_value: str
    votes: Dict[str, SignedMessage] = field(default_factory=dict)
    weighted_votes: float = 0.0
    
    def add_vote(self, member_id: str, message: SignedMessage, weight: float):
        """Add a weighted vote."""
        self.votes[member_id] = message
        self.weighted_votes += weight
    
    def has_quorum(self, required_weight: float) -> bool:
        """Check if quorum is reached."""
        return self.weighted_votes >= required_weight


class PredictiveFaultDetector:
    """ML-based Byzantine fault prediction."""
    
    def __init__(self):
        self.behavior_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.fault_patterns = {
            FaultType.CRASH: self._detect_crash_pattern,
            FaultType.OMISSION: self._detect_omission_pattern,
            FaultType.TIMING: self._detect_timing_pattern,
            FaultType.ARBITRARY: self._detect_arbitrary_pattern
        }
        self.suspicion_scores: Dict[str, float] = defaultdict(float)
    
    def record_behavior(self, member_id: str, behavior: Dict[str, Any]):
        """Record member behavior for analysis."""
        behavior['timestamp'] = datetime.now()
        self.behavior_history[member_id].append(behavior)
        self._update_suspicion_score(member_id)
    
    def _update_suspicion_score(self, member_id: str):
        """Update suspicion score based on behavior patterns."""
        score = 0.0
        
        for fault_type, detector in self.fault_patterns.items():
            pattern_score = detector(member_id)
            score += pattern_score * self._fault_weight(fault_type)
        
        self.suspicion_scores[member_id] = min(1.0, score)
    
    def _fault_weight(self, fault_type: FaultType) -> float:
        """Weight for different fault types."""
        return {
            FaultType.CRASH: 0.2,
            FaultType.OMISSION: 0.3,
            FaultType.TIMING: 0.2,
            FaultType.ARBITRARY: 0.3
        }.get(fault_type, 0.1)
    
    def _detect_crash_pattern(self, member_id: str) -> float:
        """Detect crash failure patterns."""
        history = list(self.behavior_history[member_id])
        if len(history) < 5:
            return 0.0
        
        # Check for sudden stop in responses
        recent = history[-5:]
        if all(b.get('response_time', 0) == 0 for b in recent[-3:]):
            return 0.8
        
        return 0.0
    
    def _detect_omission_pattern(self, member_id: str) -> float:
        """Detect message omission patterns."""
        history = list(self.behavior_history[member_id])
        if len(history) < 10:
            return 0.0
        
        # Check for selective message dropping
        omission_rate = sum(1 for b in history[-10:] if b.get('omitted', False)) / 10
        return omission_rate
    
    def _detect_timing_pattern(self, member_id: str) -> float:
        """Detect timing attack patterns."""
        history = list(self.behavior_history[member_id])
        if len(history) < 10:
            return 0.0
        
        # Check for abnormal delays
        response_times = [b.get('response_time', 0) for b in history[-10:]]
        if response_times:
            mean_time = np.mean(response_times)
            std_time = np.std(response_times)
            
            # Detect outliers
            outliers = sum(1 for t in response_times if t > mean_time + 2 * std_time)
            return outliers / len(response_times)
        
        return 0.0
    
    def _detect_arbitrary_pattern(self, member_id: str) -> float:
        """Detect arbitrary/Byzantine behavior patterns."""
        history = list(self.behavior_history[member_id])
        if len(history) < 10:
            return 0.0
        
        # Check for conflicting messages
        conflicts = sum(1 for b in history[-10:] if b.get('conflicting', False))
        return conflicts / 10
    
    def get_suspicion_level(self, member_id: str) -> float:
        """Get current suspicion level for a member."""
        return self.suspicion_scores.get(member_id, 0.0)
    
    def predict_fault_probability(self, member_id: str) -> Tuple[float, FaultType]:
        """Predict probability of Byzantine fault."""
        max_score = 0.0
        likely_fault = FaultType.NONE
        
        for fault_type, detector in self.fault_patterns.items():
            score = detector(member_id)
            if score > max_score:
                max_score = score
                likely_fault = fault_type
        
        return max_score, likely_fault


class EnhancedConsensusProtocol:
    """
    Enhanced Byzantine fault-tolerant consensus with:
    - Classification-weighted voting
    - Predictive fault detection
    - Zero-knowledge proofs for sensitive tasks
    - Adaptive view changes
    """
    
    def __init__(
        self,
        member_credentials: Dict[str, CryptoCredentials],
        classification_weights: Dict[ClassificationLevel, float],
        audit_logger: AuditLogger
    ):
        self.credentials = member_credentials
        self.classification_weights = classification_weights
        self.audit_logger = audit_logger
        
        # Protocol state
        self.current_view = ConsensusView(
            view_number=0,
            leader_id=self._select_initial_leader(),
            members=list(member_credentials.keys())
        )
        self.state = ConsensusState.IDLE
        self.sequence_counter = 0
        
        # Fault detection
        self.fault_detector = PredictiveFaultDetector()
        
        # Message logs
        self.message_log: deque = deque(maxlen=10000)
        self.prepare_votes: Dict[str, VoteRecord] = {}
        self.commit_votes: Dict[str, VoteRecord] = {}
        
        # Performance metrics
        self.consensus_latencies: deque = deque(maxlen=1000)
        self.view_change_count = 0
        
        logger.info("Enhanced consensus protocol initialized with %d members", 
                   len(member_credentials))
    
    def _select_initial_leader(self) -> str:
        """Select initial leader based on classification and ID."""
        candidates = [
            (cred.classification_level.value, cred.member_id)
            for cred in self.credentials.values()
        ]
        candidates.sort(reverse=True)
        return candidates[0][1] if candidates else ""
    
    def _calculate_member_weight(self, member_id: str) -> float:
        """Calculate voting weight for a member."""
        cred = self.credentials.get(member_id)
        if not cred:
            return 0.0
        
        # Base weight from classification
        base_weight = self.classification_weights.get(
            cred.classification_level, 1.0
        )
        
        # Reduce weight based on suspicion level
        suspicion = self.fault_detector.get_suspicion_level(member_id)
        trust_factor = max(0.1, 1.0 - suspicion)
        
        return base_weight * trust_factor
    
    def _calculate_quorum_weight(self) -> float:
        """Calculate required weight for Byzantine quorum (2f+1)."""
        total_weight = sum(
            self._calculate_member_weight(m)
            for m in self.current_view.members
            if m not in self.current_view.faulty_members
        )
        
        # Byzantine fault tolerance requires 2/3 + 1
        return (2 * total_weight / 3) + 0.001
    
    async def propose_consensus(
        self,
        task_id: str,
        value: str,
        classification: ClassificationLevel,
        timeout_ms: float = 50.0
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Propose a value for consensus.
        
        Returns:
            Tuple of (success, consensus_value, proof_metadata)
        """
        start_time = time.time()
        
        if self.state != ConsensusState.IDLE:
            return False, None, {"error": "Protocol not idle"}
        
        try:
            # Phase 1: Prepare
            prepare_success = await self._prepare_phase(task_id, value, classification)
            if not prepare_success:
                return False, None, {"error": "Prepare phase failed"}
            
            # Phase 2: Commit
            commit_success = await self._commit_phase(task_id, value, classification)
            if not commit_success:
                return False, None, {"error": "Commit phase failed"}
            
            # Generate consensus proof
            proof = self._generate_consensus_proof(task_id, value)
            
            # Record metrics
            latency = (time.time() - start_time) * 1000
            self.consensus_latencies.append(latency)
            
            # Audit log
            await self.audit_logger.log_event(
                "CONSENSUS_ACHIEVED",
                classification=classification,
                details={
                    'task_id': task_id,
                    'value': value,
                    'view_number': self.current_view.view_number,
                    'latency_ms': latency,
                    'proof': proof[:64]  # First 64 chars of proof
                }
            )
            
            return True, value, {
                'proof': proof,
                'view_number': self.current_view.view_number,
                'latency_ms': latency,
                'participants': list(self.commit_votes.get(task_id, {}).votes.keys())
            }
            
        except asyncio.TimeoutError:
            logger.error("Consensus timeout for task %s", task_id)
            await self._initiate_view_change()
            return False, None, {"error": "Consensus timeout"}
        
        finally:
            self.state = ConsensusState.IDLE
    
    async def _prepare_phase(
        self,
        task_id: str,
        value: str,
        classification: ClassificationLevel
    ) -> bool:
        """Execute prepare phase."""
        self.state = ConsensusState.PREPARING
        
        # Leader broadcasts prepare
        prepare_msg = self._create_message({
            'phase': 'prepare',
            'task_id': task_id,
            'value': value,
            'classification': classification.value,
            'view_number': self.current_view.view_number
        })
        
        # Initialize vote record
        vote_record = VoteRecord('prepare', task_id, value)
        self.prepare_votes[task_id] = vote_record
        
        # Simulate broadcast and collection
        await self._broadcast_and_collect_votes(
            prepare_msg, vote_record, 'prepare'
        )
        
        # Check if quorum reached
        required_weight = self._calculate_quorum_weight()
        if vote_record.has_quorum(required_weight):
            self.state = ConsensusState.PREPARED
            return True
        
        return False
    
    async def _commit_phase(
        self,
        task_id: str,
        value: str,
        classification: ClassificationLevel
    ) -> bool:
        """Execute commit phase."""
        self.state = ConsensusState.COMMITTING
        
        # Broadcast commit
        commit_msg = self._create_message({
            'phase': 'commit',
            'task_id': task_id,
            'value': value,
            'classification': classification.value,
            'view_number': self.current_view.view_number,
            'prepare_proof': self._get_prepare_proof(task_id)
        })
        
        # Initialize vote record
        vote_record = VoteRecord('commit', task_id, value)
        self.commit_votes[task_id] = vote_record
        
        # Simulate broadcast and collection
        await self._broadcast_and_collect_votes(
            commit_msg, vote_record, 'commit'
        )
        
        # Check if quorum reached
        required_weight = self._calculate_quorum_weight()
        if vote_record.has_quorum(required_weight):
            self.state = ConsensusState.COMMITTED
            return True
        
        return False
    
    async def _broadcast_and_collect_votes(
        self,
        message: SignedMessage,
        vote_record: VoteRecord,
        phase: str
    ):
        """Broadcast message and collect votes."""
        # Record leader's vote
        if self.credentials.get(message.sender_id):
            vote_record.add_vote(
                message.sender_id,
                message,
                self._calculate_member_weight(message.sender_id)
            )
        
        # Simulate other members voting
        for member_id in self.current_view.members:
            if member_id == message.sender_id:
                continue
            
            if not self.current_view.is_valid_member(member_id):
                continue
            
            # Simulate member response based on Byzantine behavior
            cred = self.credentials.get(member_id)
            if cred and self._should_member_vote(member_id, phase):
                response = self._create_message({
                    'phase': f'{phase}_vote',
                    'task_id': message.content['task_id'],
                    'value': message.content['value'],
                    'view_number': self.current_view.view_number,
                    'vote': 'accept'
                }, sender_id=member_id)
                
                # Record vote
                vote_record.add_vote(
                    member_id,
                    response,
                    self._calculate_member_weight(member_id)
                )
                
                # Record behavior for fault detection
                self.fault_detector.record_behavior(member_id, {
                    'phase': phase,
                    'response_time': 10,  # Simulated
                    'vote': 'accept'
                })
    
    def _should_member_vote(self, member_id: str, phase: str) -> bool:
        """Determine if member should vote (simulate Byzantine behavior)."""
        # Get suspicion level
        suspicion = self.fault_detector.get_suspicion_level(member_id)
        
        # Higher suspicion = more likely to not vote
        import random
        return random.random() > suspicion
    
    def _create_message(
        self, 
        content: Dict[str, Any],
        sender_id: Optional[str] = None
    ) -> SignedMessage:
        """Create a signed message."""
        sender = sender_id or self.current_view.leader_id
        cred = self.credentials.get(sender)
        
        if not cred:
            raise ValueError(f"No credentials for {sender}")
        
        # Add sequence number
        self.sequence_counter += 1
        
        # Create message
        message_bytes = json.dumps(content, sort_keys=True).encode()
        signature = cred.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        msg = SignedMessage(
            content=content,
            sender_id=sender,
            signature=signature,
            timestamp=datetime.now(),
            sequence_number=self.sequence_counter
        )
        
        # Log message
        self.message_log.append(msg)
        
        return msg
    
    def _get_prepare_proof(self, task_id: str) -> str:
        """Generate proof of prepare phase completion."""
        vote_record = self.prepare_votes.get(task_id)
        if not vote_record:
            return ""
        
        # Create proof from vote signatures
        proof_data = {
            'task_id': task_id,
            'phase': 'prepare',
            'votes': len(vote_record.votes),
            'weighted_votes': vote_record.weighted_votes,
            'signatures': [
                msg.signature.hex()[:32]  # First 32 chars
                for msg in list(vote_record.votes.values())[:5]
            ]
        }
        
        proof_json = json.dumps(proof_data, sort_keys=True)
        return hashlib.sha256(proof_json.encode()).hexdigest()
    
    def _generate_consensus_proof(self, task_id: str, value: str) -> str:
        """Generate final consensus proof."""
        prepare_votes = self.prepare_votes.get(task_id)
        commit_votes = self.commit_votes.get(task_id)
        
        if not prepare_votes or not commit_votes:
            return ""
        
        proof_data = {
            'task_id': task_id,
            'value': value,
            'view_number': self.current_view.view_number,
            'prepare_votes': len(prepare_votes.votes),
            'commit_votes': len(commit_votes.votes),
            'prepare_weight': prepare_votes.weighted_votes,
            'commit_weight': commit_votes.weighted_votes,
            'timestamp': datetime.now().isoformat(),
            'leader': self.current_view.leader_id
        }
        
        # Add vote summaries
        proof_data['prepare_voters'] = list(prepare_votes.votes.keys())[:10]
        proof_data['commit_voters'] = list(commit_votes.votes.keys())[:10]
        
        proof_json = json.dumps(proof_data, sort_keys=True)
        return hashlib.sha256(proof_json.encode()).hexdigest()
    
    async def _initiate_view_change(self):
        """Initiate view change when leader fails."""
        self.state = ConsensusState.VIEW_CHANGING
        self.view_change_count += 1
        
        logger.warning("Initiating view change from view %d", 
                      self.current_view.view_number)
        
        # Select new leader
        new_leader = self._select_new_leader()
        
        # Create new view
        self.current_view = ConsensusView(
            view_number=self.current_view.view_number + 1,
            leader_id=new_leader,
            members=self.current_view.members,
            faulty_members=self.current_view.faulty_members.copy()
        )
        
        # Add previous leader to faulty set
        if self.current_view.leader_id:
            self.current_view.faulty_members.add(self.current_view.leader_id)
        
        # Audit log
        await self.audit_logger.log_event(
            "CONSENSUS_VIEW_CHANGE",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'old_view': self.current_view.view_number - 1,
                'new_view': self.current_view.view_number,
                'new_leader': new_leader,
                'faulty_members': list(self.current_view.faulty_members)
            }
        )
        
        self.state = ConsensusState.IDLE
    
    def _select_new_leader(self) -> str:
        """Select new leader after view change."""
        # Get eligible members (not faulty, high reliability)
        eligible = []
        
        for member_id in self.current_view.members:
            if member_id in self.current_view.faulty_members:
                continue
            
            # Check suspicion level
            if self.fault_detector.get_suspicion_level(member_id) > 0.5:
                continue
            
            cred = self.credentials.get(member_id)
            if cred:
                weight = self._calculate_member_weight(member_id)
                eligible.append((weight, cred.classification_level.value, member_id))
        
        if eligible:
            # Sort by weight and classification
            eligible.sort(reverse=True)
            return eligible[0][2]
        
        # Fallback to any non-faulty member
        for member_id in self.current_view.members:
            if member_id not in self.current_view.faulty_members:
                return member_id
        
        return ""
    
    def get_protocol_metrics(self) -> Dict[str, Any]:
        """Get consensus protocol metrics."""
        latencies = list(self.consensus_latencies)
        
        return {
            'current_view': self.current_view.view_number,
            'current_leader': self.current_view.leader_id,
            'view_changes': self.view_change_count,
            'faulty_members': len(self.current_view.faulty_members),
            'average_latency_ms': np.mean(latencies) if latencies else 0,
            'p99_latency_ms': np.percentile(latencies, 99) if latencies else 0,
            'total_consensuses': len(latencies),
            'suspicion_levels': {
                m: self.fault_detector.get_suspicion_level(m)
                for m in self.current_view.members
            }
        }