#!/usr/bin/env python3
"""
ALCUB3 Byzantine Defense System
Advanced attack detection and mitigation for swarm consensus

This module implements sophisticated Byzantine attack detection,
game-theoretic defense mechanisms, and adaptive response strategies.
"""

import asyncio
import time
import uuid
import hashlib
import json
import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import numpy as np
from scipy import stats

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of Byzantine attacks."""
    DOUBLE_VOTING = "double_voting"          # Voting for multiple values
    EQUIVOCATION = "equivocation"            # Sending different messages to different nodes
    TIMING_ATTACK = "timing_attack"          # Delaying messages strategically
    CENSORSHIP = "censorship"                # Dropping specific messages
    SYBIL_ATTACK = "sybil_attack"           # Creating fake identities
    COLLUSION = "collusion"                  # Coordinated attack by multiple nodes
    REPLAY_ATTACK = "replay_attack"          # Replaying old messages
    STATE_CORRUPTION = "state_corruption"    # Corrupting local state
    FLOODING = "flooding"                    # Overwhelming with messages
    FORK_ATTACK = "fork_attack"             # Creating blockchain forks


class DefenseStrategy(Enum):
    """Defense strategies against attacks."""
    ISOLATE = "isolate"                      # Isolate the attacker
    PENALIZE = "penalize"                    # Economic penalty
    RATE_LIMIT = "rate_limit"                # Limit message rate
    BLACKLIST = "blacklist"                  # Permanent exclusion
    QUARANTINE = "quarantine"                # Temporary isolation
    REPUTATION_REDUCE = "reputation_reduce"   # Lower reputation score
    VIEW_CHANGE = "view_change"              # Force view change
    ALERT = "alert"                          # Alert operators
    ADAPT_PROTOCOL = "adapt_protocol"        # Change protocol parameters
    COUNTER_ATTACK = "counter_attack"        # Active countermeasures


@dataclass
class AttackPattern:
    """Pattern representing a Byzantine attack."""
    pattern_id: str
    attack_type: AttackType
    indicators: List[str]  # Observable indicators
    confidence_threshold: float  # Min confidence to trigger
    severity: str  # low, medium, high, critical
    recommended_defenses: List[DefenseStrategy]
    
    def matches(self, behaviors: List[Dict[str, Any]]) -> Tuple[bool, float]:
        """Check if behaviors match this attack pattern."""
        matches = 0
        for behavior in behaviors:
            for indicator in self.indicators:
                if self._check_indicator(behavior, indicator):
                    matches += 1
        
        confidence = matches / (len(self.indicators) * len(behaviors)) if behaviors else 0
        return confidence >= self.confidence_threshold, confidence
    
    def _check_indicator(self, behavior: Dict[str, Any], indicator: str) -> bool:
        """Check if behavior matches indicator."""
        # Simplified pattern matching - in production would use regex or ML
        if indicator == "multiple_votes_same_round":
            return behavior.get('vote_count', 0) > 1
        elif indicator == "conflicting_messages":
            return behavior.get('conflict_detected', False)
        elif indicator == "abnormal_delay":
            return behavior.get('delay_ms', 0) > 1000
        elif indicator == "message_dropping":
            return behavior.get('dropped_messages', 0) > 0
        elif indicator == "rapid_message_rate":
            return behavior.get('message_rate', 0) > 100
        return False


@dataclass
class NodeReputation:
    """Reputation tracking for a node."""
    node_id: str
    reputation_score: float = 100.0  # 0-100
    successful_consensuses: int = 0
    failed_consensuses: int = 0
    detected_attacks: int = 0
    false_positives: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
    penalty_history: List[Tuple[datetime, float, str]] = field(default_factory=list)
    
    def update_score(self, delta: float, reason: str):
        """Update reputation score."""
        old_score = self.reputation_score
        self.reputation_score = max(0.0, min(100.0, self.reputation_score + delta))
        self.last_updated = datetime.now()
        
        if delta < 0:
            self.penalty_history.append((datetime.now(), abs(delta), reason))
        
        logger.debug("Updated reputation for %s: %.2f -> %.2f (%s)",
                    self.node_id, old_score, self.reputation_score, reason)
    
    def calculate_trust_factor(self) -> float:
        """Calculate trust factor (0.0 to 1.0)."""
        # Base trust from reputation
        base_trust = self.reputation_score / 100.0
        
        # Success rate factor
        total_consensuses = self.successful_consensuses + self.failed_consensuses
        if total_consensuses > 0:
            success_rate = self.successful_consensuses / total_consensuses
            base_trust *= (0.5 + 0.5 * success_rate)
        
        # Penalty for detected attacks
        if self.detected_attacks > 0:
            attack_penalty = 1.0 / (1.0 + self.detected_attacks * 0.1)
            base_trust *= attack_penalty
        
        return base_trust


@dataclass
class GameTheoreticState:
    """Game theoretic state for Byzantine defense."""
    node_payoffs: Dict[str, float] = field(default_factory=dict)
    cooperation_history: Dict[str, List[bool]] = field(default_factory=lambda: defaultdict(list))
    punishment_rounds: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    forgiveness_threshold: int = 10
    punishment_duration: int = 5
    
    def calculate_payoff(self, node_id: str, cooperated: bool, others_cooperated: float) -> float:
        """Calculate payoff using prisoner's dilemma dynamics."""
        # Payoff matrix (cooperate, defect):
        # Both cooperate: (3, 3)
        # One defects: (5, 0)
        # Both defect: (1, 1)
        
        if cooperated:
            return 3 * others_cooperated  # Reward for cooperation
        else:
            return 5 * others_cooperated + 1 * (1 - others_cooperated)  # Temptation to defect
    
    def should_punish(self, node_id: str) -> bool:
        """Determine if node should be punished (Tit-for-Tat with forgiveness)."""
        history = self.cooperation_history.get(node_id, [])
        
        if not history:
            return False  # Start with cooperation
        
        # Check recent defections
        recent_defections = sum(1 for cooperated in history[-self.forgiveness_threshold:] if not cooperated)
        
        # Punish if too many recent defections
        return recent_defections > self.forgiveness_threshold // 2


class ByzantineDefenseSystem:
    """
    Advanced Byzantine defense system with attack detection and mitigation.
    
    Features:
    - Multi-modal attack detection
    - Game-theoretic punishment strategies
    - Reputation-based trust management
    - Adaptive defense mechanisms
    - Economic incentives for honest behavior
    """
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        
        # Attack detection
        self.attack_patterns = self._initialize_attack_patterns()
        self.behavior_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.detected_attacks: Dict[str, List[Tuple[AttackType, datetime]]] = defaultdict(list)
        
        # Reputation management
        self.node_reputations: Dict[str, NodeReputation] = {}
        self.reputation_decay_rate = 0.01  # Per hour
        self.reputation_recovery_rate = 0.1  # Per successful consensus
        
        # Game theory
        self.game_state = GameTheoreticState()
        
        # Defense mechanisms
        self.active_defenses: Dict[str, List[DefenseStrategy]] = defaultdict(list)
        self.blacklisted_nodes: Set[str] = set()
        self.quarantined_nodes: Dict[str, datetime] = {}  # node_id -> end_time
        self.rate_limits: Dict[str, Tuple[int, datetime]] = {}  # node_id -> (count, window_start)
        
        # Attack statistics
        self.attack_stats = {
            'total_attacks_detected': 0,
            'attacks_by_type': defaultdict(int),
            'attacks_mitigated': 0,
            'false_positives': 0
        }
        
        # Thresholds and parameters
        self.detection_window = timedelta(minutes=5)
        self.quarantine_duration = timedelta(hours=1)
        self.rate_limit_window = timedelta(seconds=10)
        self.rate_limit_max = 100
        
        logger.info("Byzantine Defense System initialized")
    
    def _initialize_attack_patterns(self) -> List[AttackPattern]:
        """Initialize known attack patterns."""
        return [
            AttackPattern(
                pattern_id="double_voting",
                attack_type=AttackType.DOUBLE_VOTING,
                indicators=["multiple_votes_same_round", "conflicting_messages"],
                confidence_threshold=0.8,
                severity="high",
                recommended_defenses=[DefenseStrategy.ISOLATE, DefenseStrategy.PENALIZE]
            ),
            AttackPattern(
                pattern_id="timing_attack",
                attack_type=AttackType.TIMING_ATTACK,
                indicators=["abnormal_delay", "selective_delays", "deadline_manipulation"],
                confidence_threshold=0.7,
                severity="medium",
                recommended_defenses=[DefenseStrategy.RATE_LIMIT, DefenseStrategy.ADAPT_PROTOCOL]
            ),
            AttackPattern(
                pattern_id="flooding",
                attack_type=AttackType.FLOODING,
                indicators=["rapid_message_rate", "duplicate_messages", "resource_exhaustion"],
                confidence_threshold=0.9,
                severity="high",
                recommended_defenses=[DefenseStrategy.RATE_LIMIT, DefenseStrategy.QUARANTINE]
            ),
            AttackPattern(
                pattern_id="collusion",
                attack_type=AttackType.COLLUSION,
                indicators=["coordinated_voting", "synchronized_delays", "message_correlation"],
                confidence_threshold=0.85,
                severity="critical",
                recommended_defenses=[DefenseStrategy.VIEW_CHANGE, DefenseStrategy.BLACKLIST]
            ),
            AttackPattern(
                pattern_id="equivocation",
                attack_type=AttackType.EQUIVOCATION,
                indicators=["conflicting_messages", "target_specific_messages", "hash_mismatches"],
                confidence_threshold=0.9,
                severity="high",
                recommended_defenses=[DefenseStrategy.ISOLATE, DefenseStrategy.REPUTATION_REDUCE]
            )
        ]
    
    async def record_node_behavior(self, node_id: str, behavior: Dict[str, Any]):
        """Record node behavior for analysis."""
        behavior['timestamp'] = datetime.now()
        behavior['node_id'] = node_id
        
        self.behavior_history[node_id].append(behavior)
        
        # Initialize reputation if needed
        if node_id not in self.node_reputations:
            self.node_reputations[node_id] = NodeReputation(node_id=node_id)
        
        # Analyze for attacks
        await self._analyze_behavior(node_id)
    
    async def _analyze_behavior(self, node_id: str):
        """Analyze recent behavior for attack patterns."""
        # Get recent behaviors
        recent_behaviors = list(self.behavior_history[node_id])
        if len(recent_behaviors) < 5:
            return  # Not enough data
        
        # Filter to detection window
        cutoff_time = datetime.now() - self.detection_window
        window_behaviors = [
            b for b in recent_behaviors
            if b['timestamp'] > cutoff_time
        ]
        
        # Check each attack pattern
        for pattern in self.attack_patterns:
            matched, confidence = pattern.matches(window_behaviors)
            
            if matched:
                await self._handle_detected_attack(
                    node_id, pattern.attack_type, confidence, pattern
                )
    
    async def _handle_detected_attack(
        self,
        node_id: str,
        attack_type: AttackType,
        confidence: float,
        pattern: AttackPattern
    ):
        """Handle a detected attack."""
        logger.warning("Attack detected: %s from node %s (confidence: %.2f)",
                      attack_type.value, node_id, confidence)
        
        # Record attack
        self.detected_attacks[node_id].append((attack_type, datetime.now()))
        self.attack_stats['total_attacks_detected'] += 1
        self.attack_stats['attacks_by_type'][attack_type] += 1
        
        # Update reputation
        reputation = self.node_reputations[node_id]
        penalty = self._calculate_reputation_penalty(attack_type, confidence)
        reputation.update_score(-penalty, f"Detected {attack_type.value}")
        reputation.detected_attacks += 1
        
        # Apply defenses
        defenses = await self._select_defenses(node_id, pattern, confidence)
        for defense in defenses:
            await self._apply_defense(node_id, defense, attack_type)
        
        # Update game state
        self.game_state.cooperation_history[node_id].append(False)
        
        # Audit log
        await self.audit_logger.log_event(
            "BYZANTINE_ATTACK_DETECTED",
            classification=ClassificationLevel.SECRET,
            details={
                'node_id': node_id,
                'attack_type': attack_type.value,
                'confidence': confidence,
                'severity': pattern.severity,
                'defenses_applied': [d.value for d in defenses]
            }
        )
    
    def _calculate_reputation_penalty(self, attack_type: AttackType, confidence: float) -> float:
        """Calculate reputation penalty for detected attack."""
        base_penalties = {
            AttackType.DOUBLE_VOTING: 20.0,
            AttackType.EQUIVOCATION: 25.0,
            AttackType.TIMING_ATTACK: 10.0,
            AttackType.CENSORSHIP: 15.0,
            AttackType.SYBIL_ATTACK: 50.0,
            AttackType.COLLUSION: 40.0,
            AttackType.REPLAY_ATTACK: 15.0,
            AttackType.STATE_CORRUPTION: 30.0,
            AttackType.FLOODING: 20.0,
            AttackType.FORK_ATTACK: 35.0
        }
        
        base_penalty = base_penalties.get(attack_type, 10.0)
        return base_penalty * confidence
    
    async def _select_defenses(
        self,
        node_id: str,
        pattern: AttackPattern,
        confidence: float
    ) -> List[DefenseStrategy]:
        """Select appropriate defenses based on attack and node history."""
        defenses = []
        
        # Start with recommended defenses
        defenses.extend(pattern.recommended_defenses)
        
        # Add based on severity
        if pattern.severity == "critical":
            defenses.append(DefenseStrategy.ALERT)
            if confidence > 0.95:
                defenses.append(DefenseStrategy.BLACKLIST)
        
        # Add based on reputation
        reputation = self.node_reputations[node_id]
        if reputation.reputation_score < 30:
            defenses.append(DefenseStrategy.QUARANTINE)
        
        # Add based on repeat offenses
        recent_attacks = [
            a for a, t in self.detected_attacks[node_id]
            if t > datetime.now() - timedelta(hours=24)
        ]
        if len(recent_attacks) > 3:
            defenses.append(DefenseStrategy.BLACKLIST)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_defenses = []
        for defense in defenses:
            if defense not in seen:
                seen.add(defense)
                unique_defenses.append(defense)
        
        return unique_defenses
    
    async def _apply_defense(
        self,
        node_id: str,
        defense: DefenseStrategy,
        attack_type: AttackType
    ):
        """Apply a specific defense strategy."""
        self.active_defenses[node_id].append(defense)
        
        if defense == DefenseStrategy.ISOLATE:
            # Immediate isolation - reject all messages
            logger.info("Isolating node %s", node_id)
            # Implementation would update network layer
            
        elif defense == DefenseStrategy.PENALIZE:
            # Economic penalty
            penalty = self.game_state.calculate_payoff(node_id, False, 0.0)
            self.game_state.node_payoffs[node_id] = self.game_state.node_payoffs.get(node_id, 0) - penalty
            
        elif defense == DefenseStrategy.RATE_LIMIT:
            # Apply rate limiting
            self.rate_limits[node_id] = (0, datetime.now())
            logger.info("Rate limiting node %s to %d messages per %s",
                       node_id, self.rate_limit_max, self.rate_limit_window)
            
        elif defense == DefenseStrategy.BLACKLIST:
            # Permanent exclusion
            self.blacklisted_nodes.add(node_id)
            logger.warning("Blacklisted node %s", node_id)
            
        elif defense == DefenseStrategy.QUARANTINE:
            # Temporary isolation
            self.quarantined_nodes[node_id] = datetime.now() + self.quarantine_duration
            logger.info("Quarantined node %s until %s",
                       node_id, self.quarantined_nodes[node_id])
            
        elif defense == DefenseStrategy.REPUTATION_REDUCE:
            # Additional reputation penalty
            self.node_reputations[node_id].update_score(-10, "Defense penalty")
            
        elif defense == DefenseStrategy.VIEW_CHANGE:
            # Trigger view change in consensus
            logger.info("Requesting view change due to Byzantine behavior")
            # Implementation would signal consensus engine
            
        elif defense == DefenseStrategy.ALERT:
            # Alert operators
            await self._send_security_alert(node_id, attack_type)
            
        elif defense == DefenseStrategy.ADAPT_PROTOCOL:
            # Adapt protocol parameters
            await self._adapt_protocol_parameters(attack_type)
            
        elif defense == DefenseStrategy.COUNTER_ATTACK:
            # Active countermeasures (honeypot, deception)
            await self._deploy_countermeasures(node_id, attack_type)
        
        self.attack_stats['attacks_mitigated'] += 1
    
    async def _send_security_alert(self, node_id: str, attack_type: AttackType):
        """Send security alert to operators."""
        alert = {
            'alert_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'node_id': node_id,
            'attack_type': attack_type.value,
            'reputation_score': self.node_reputations[node_id].reputation_score,
            'recent_attacks': len([
                a for a, t in self.detected_attacks[node_id]
                if t > datetime.now() - timedelta(hours=1)
            ])
        }
        
        logger.critical("SECURITY ALERT: %s", json.dumps(alert))
        
        # In production, would send to monitoring system
    
    async def _adapt_protocol_parameters(self, attack_type: AttackType):
        """Adapt protocol parameters based on attack."""
        adaptations = {
            AttackType.TIMING_ATTACK: {
                'timeout_multiplier': 0.8,  # Reduce timeouts
                'batch_size_delta': -5       # Smaller batches
            },
            AttackType.FLOODING: {
                'rate_limit_reduction': 0.5,  # Halve rate limits
                'message_buffer_reduction': 0.7
            },
            AttackType.COLLUSION: {
                'quorum_increase': 1,  # Require one more vote
                'view_change_speedup': 0.5
            }
        }
        
        if attack_type in adaptations:
            params = adaptations[attack_type]
            logger.info("Adapting protocol parameters for %s: %s",
                       attack_type.value, params)
            # Implementation would update consensus engine
    
    async def _deploy_countermeasures(self, node_id: str, attack_type: AttackType):
        """Deploy active countermeasures."""
        if attack_type == AttackType.SYBIL_ATTACK:
            # Deploy Sybil detection honeypot
            logger.info("Deploying Sybil honeypot for %s", node_id)
            # Create fake identities to detect Sybil behavior
            
        elif attack_type == AttackType.TIMING_ATTACK:
            # Deploy timing deception
            logger.info("Deploying timing deception against %s", node_id)
            # Send fake timing signals to confuse attacker
    
    def check_message_allowed(self, node_id: str) -> Tuple[bool, Optional[str]]:
        """Check if message from node is allowed."""
        # Check blacklist
        if node_id in self.blacklisted_nodes:
            return False, "Node is blacklisted"
        
        # Check quarantine
        if node_id in self.quarantined_nodes:
            if datetime.now() < self.quarantined_nodes[node_id]:
                return False, "Node is quarantined"
            else:
                # Quarantine expired
                del self.quarantined_nodes[node_id]
        
        # Check rate limit
        if node_id in self.rate_limits:
            count, window_start = self.rate_limits[node_id]
            
            if datetime.now() - window_start > self.rate_limit_window:
                # New window
                self.rate_limits[node_id] = (1, datetime.now())
            else:
                # Check limit
                if count >= self.rate_limit_max:
                    return False, "Rate limit exceeded"
                else:
                    self.rate_limits[node_id] = (count + 1, window_start)
        
        return True, None
    
    async def record_consensus_result(
        self,
        node_id: str,
        success: bool,
        consensus_time_ms: float
    ):
        """Record consensus participation result."""
        if node_id not in self.node_reputations:
            self.node_reputations[node_id] = NodeReputation(node_id=node_id)
        
        reputation = self.node_reputations[node_id]
        
        if success:
            reputation.successful_consensuses += 1
            reputation.update_score(
                self.reputation_recovery_rate,
                "Successful consensus participation"
            )
            
            # Update game state
            self.game_state.cooperation_history[node_id].append(True)
            
            # Calculate and store payoff
            others_cooperation = self._calculate_average_cooperation()
            payoff = self.game_state.calculate_payoff(node_id, True, others_cooperation)
            self.game_state.node_payoffs[node_id] = self.game_state.node_payoffs.get(node_id, 0) + payoff
            
        else:
            reputation.failed_consensuses += 1
            reputation.update_score(-2, "Failed consensus")
            self.game_state.cooperation_history[node_id].append(False)
        
        # Check for punishment/forgiveness
        if self.game_state.should_punish(node_id):
            if node_id not in self.game_state.punishment_rounds:
                logger.info("Starting punishment for node %s", node_id)
                self.game_state.punishment_rounds[node_id] = self.game_state.punishment_duration
        else:
            if node_id in self.game_state.punishment_rounds:
                self.game_state.punishment_rounds[node_id] -= 1
                if self.game_state.punishment_rounds[node_id] <= 0:
                    logger.info("Ending punishment for node %s", node_id)
                    del self.game_state.punishment_rounds[node_id]
    
    def _calculate_average_cooperation(self) -> float:
        """Calculate average cooperation rate across all nodes."""
        total_cooperation = 0
        total_history = 0
        
        for history in self.game_state.cooperation_history.values():
            if history:
                total_cooperation += sum(history)
                total_history += len(history)
        
        return total_cooperation / total_history if total_history > 0 else 0.5
    
    async def apply_reputation_decay(self):
        """Apply periodic reputation decay."""
        for reputation in self.node_reputations.values():
            # Decay towards neutral (50)
            if reputation.reputation_score > 50:
                reputation.update_score(-self.reputation_decay_rate, "Time decay")
            elif reputation.reputation_score < 50:
                reputation.update_score(self.reputation_decay_rate, "Time recovery")
    
    def get_node_trust_factor(self, node_id: str) -> float:
        """Get trust factor for a node."""
        if node_id in self.blacklisted_nodes:
            return 0.0
        
        if node_id in self.quarantined_nodes:
            if datetime.now() < self.quarantined_nodes[node_id]:
                return 0.1  # Minimal trust during quarantine
        
        if node_id in self.node_reputations:
            return self.node_reputations[node_id].calculate_trust_factor()
        
        return 0.5  # Default trust for new nodes
    
    def get_defense_metrics(self) -> Dict[str, Any]:
        """Get defense system metrics."""
        return {
            'attack_statistics': dict(self.attack_stats),
            'blacklisted_nodes': len(self.blacklisted_nodes),
            'quarantined_nodes': len(self.quarantined_nodes),
            'rate_limited_nodes': len(self.rate_limits),
            'average_reputation': np.mean([
                r.reputation_score for r in self.node_reputations.values()
            ]) if self.node_reputations else 50.0,
            'cooperation_rate': self._calculate_average_cooperation(),
            'nodes_under_punishment': len(self.game_state.punishment_rounds),
            'total_payoffs': sum(self.game_state.node_payoffs.values())
        }
    
    async def analyze_attack_trends(self) -> Dict[str, Any]:
        """Analyze attack trends for predictive defense."""
        trends = {
            'attack_frequency': {},
            'attack_timing': {},
            'attacker_patterns': {},
            'vulnerability_assessment': {}
        }
        
        # Analyze attack frequency by type
        for attack_type in AttackType:
            count = self.attack_stats['attacks_by_type'].get(attack_type, 0)
            trends['attack_frequency'][attack_type.value] = count
        
        # Analyze attack timing patterns
        all_attacks = []
        for node_id, attacks in self.detected_attacks.items():
            for attack_type, timestamp in attacks:
                all_attacks.append({
                    'node_id': node_id,
                    'type': attack_type.value,
                    'hour': timestamp.hour,
                    'weekday': timestamp.weekday()
                })
        
        if all_attacks:
            # Find peak attack hours
            attack_hours = [a['hour'] for a in all_attacks]
            if attack_hours:
                peak_hour = max(set(attack_hours), key=attack_hours.count)
                trends['attack_timing']['peak_hour'] = peak_hour
            
            # Find most active attackers
            attacker_counts = defaultdict(int)
            for attack in all_attacks:
                attacker_counts[attack['node_id']] += 1
            
            top_attackers = sorted(
                attacker_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            trends['attacker_patterns']['top_attackers'] = [
                {'node_id': node_id, 'attack_count': count}
                for node_id, count in top_attackers
            ]
        
        # Vulnerability assessment
        total_nodes = len(self.node_reputations)
        if total_nodes > 0:
            low_reputation_nodes = sum(
                1 for r in self.node_reputations.values()
                if r.reputation_score < 30
            )
            trends['vulnerability_assessment']['at_risk_nodes'] = low_reputation_nodes
            trends['vulnerability_assessment']['risk_percentage'] = (
                low_reputation_nodes / total_nodes * 100
            )
        
        return trends
    
    def export_reputation_report(self) -> List[Dict[str, Any]]:
        """Export reputation report for all nodes."""
        report = []
        
        for node_id, reputation in self.node_reputations.items():
            report.append({
                'node_id': node_id,
                'reputation_score': reputation.reputation_score,
                'trust_factor': reputation.calculate_trust_factor(),
                'successful_consensuses': reputation.successful_consensuses,
                'failed_consensuses': reputation.failed_consensuses,
                'detected_attacks': reputation.detected_attacks,
                'is_blacklisted': node_id in self.blacklisted_nodes,
                'is_quarantined': node_id in self.quarantined_nodes,
                'under_punishment': node_id in self.game_state.punishment_rounds,
                'total_payoff': self.game_state.node_payoffs.get(node_id, 0)
            })
        
        # Sort by reputation score
        report.sort(key=lambda x: x['reputation_score'], reverse=True)
        
        return report