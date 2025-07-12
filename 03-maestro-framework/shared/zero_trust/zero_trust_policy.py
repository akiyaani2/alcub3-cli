#!/usr/bin/env python3
"""
ALCUB3 Zero-Trust Policy Engine
Centralized policy management with conflict resolution and simulation

This module implements patent-pending policy engine that:
- Manages zero-trust policies across all components
- Resolves policy conflicts intelligently
- Simulates policy changes before deployment
- Distributes policies in real-time
- Integrates with MAESTRO framework

Performance Targets:
- <1ms policy evaluation
- <100ms policy distribution
- Support for 100,000+ policies
"""

import asyncio
import hashlib
import logging
import time
import json
import yaml
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from collections import defaultdict, OrderedDict
from pathlib import Path
import re
from abc import ABC, abstractmethod

# Import MAESTRO components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError, PolicyError
from shared.real_time_monitor import RealTimeMonitor

logger = logging.getLogger(__name__)


class PolicyType(Enum):
    """Types of zero-trust policies."""
    NETWORK = "network"
    IDENTITY = "identity"
    DEVICE = "device"
    APPLICATION = "application"
    DATA = "data"
    COMPOSITE = "composite"


class PolicyScope(Enum):
    """Policy application scope."""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    DEPARTMENT = "department"
    TEAM = "team"
    USER = "user"
    DEVICE = "device"
    NETWORK_ZONE = "network_zone"


class ConflictResolution(Enum):
    """Policy conflict resolution strategies."""
    DENY_OVERRIDES = "deny_overrides"
    PERMIT_OVERRIDES = "permit_overrides"
    FIRST_APPLICABLE = "first_applicable"
    PRIORITY_BASED = "priority_based"
    MOST_RESTRICTIVE = "most_restrictive"
    LEAST_RESTRICTIVE = "least_restrictive"


class PolicyAction(Enum):
    """Policy action types."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_MFA = "require_mfa"
    REQUIRE_ENCRYPTION = "require_encryption"
    LOG_ONLY = "log_only"
    REDIRECT = "redirect"
    QUARANTINE = "quarantine"
    RATE_LIMIT = "rate_limit"


@dataclass
class PolicyCondition:
    """Condition for policy evaluation."""
    field: str
    operator: str
    value: Any
    case_sensitive: bool = True
    negate: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyTarget:
    """Target specification for a policy."""
    subjects: List[str] = field(default_factory=list)  # User/service IDs or patterns
    resources: List[str] = field(default_factory=list)  # Resource IDs or patterns
    actions: List[str] = field(default_factory=list)  # Action types
    networks: List[str] = field(default_factory=list)  # Network zones/CIDRs
    devices: List[str] = field(default_factory=list)  # Device IDs or types
    classifications: List[ClassificationLevel] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyRule:
    """Zero-trust policy rule."""
    rule_id: str
    name: str
    description: str
    policy_type: PolicyType
    scope: PolicyScope
    target: PolicyTarget
    conditions: List[PolicyCondition]
    action: PolicyAction
    priority: int = 100
    enabled: bool = True
    effective_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    version: int = 1
    parent_policy: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "system"
    last_modified: datetime = field(default_factory=datetime.utcnow)
    modified_by: str = "system"


@dataclass
class PolicySet:
    """Collection of related policies."""
    set_id: str
    name: str
    description: str
    policies: List[str] = field(default_factory=list)  # Policy rule IDs
    conflict_resolution: ConflictResolution = ConflictResolution.DENY_OVERRIDES
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyConflict:
    """Detected policy conflict."""
    conflict_id: str
    policy1_id: str
    policy2_id: str
    conflict_type: str
    description: str
    resolution_applied: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PolicySimulation:
    """Policy simulation result."""
    simulation_id: str
    timestamp: datetime
    scenario: Dict[str, Any]
    affected_policies: List[str]
    decisions: List[Dict[str, Any]]
    conflicts_detected: List[PolicyConflict]
    performance_metrics: Dict[str, float]
    recommendations: List[str]


class PolicyEvaluator(ABC):
    """Abstract base class for policy evaluators."""
    
    @abstractmethod
    async def evaluate(
        self,
        policy: PolicyRule,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate if policy applies to context."""
        pass


class ZeroTrustPolicyEngine:
    """
    Patent-pending zero-trust policy engine with advanced management.
    
    This engine provides centralized policy management with intelligent
    conflict resolution, simulation capabilities, and real-time distribution.
    """
    
    def __init__(
        self,
        audit_logger: AuditLogger,
        monitor: Optional[RealTimeMonitor] = None,
        default_conflict_resolution: ConflictResolution = ConflictResolution.DENY_OVERRIDES,
        enable_caching: bool = True
    ):
        """
        Initialize the policy engine.
        
        Args:
            audit_logger: Audit logger for policy events
            monitor: Real-time monitoring system
            default_conflict_resolution: Default conflict resolution strategy
            enable_caching: Enable policy evaluation caching
        """
        self.audit_logger = audit_logger
        self.monitor = monitor
        self.default_conflict_resolution = default_conflict_resolution
        self.enable_caching = enable_caching
        
        # Policy storage
        self.policies: Dict[str, PolicyRule] = {}
        self.policy_sets: Dict[str, PolicySet] = {}
        self.policy_index: Dict[PolicyType, Set[str]] = defaultdict(set)
        
        # Policy hierarchy
        self.policy_hierarchy: Dict[str, Set[str]] = defaultdict(set)
        
        # Conflict tracking
        self.conflicts: List[PolicyConflict] = []
        self.conflict_matrix: Dict[Tuple[str, str], PolicyConflict] = {}
        
        # Evaluation cache
        self.evaluation_cache: Dict[str, Tuple[Any, datetime]] = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Policy evaluators
        self.evaluators: Dict[PolicyType, PolicyEvaluator] = {}
        self._register_default_evaluators()
        
        # Policy distribution
        self.policy_subscribers: List[Callable] = []
        self.distribution_queue: asyncio.Queue = asyncio.Queue()
        
        # Statistics
        self.stats = {
            'policies_created': 0,
            'policies_evaluated': 0,
            'conflicts_detected': 0,
            'conflicts_resolved': 0,
            'simulations_run': 0,
            'cache_hits': 0,
            'avg_evaluation_time_ms': 0.0,
            'avg_distribution_time_ms': 0.0
        }
        
        # Initialize default policies
        self._initialize_default_policies()
        
        logger.info("Zero-trust policy engine initialized")
    
    def _register_default_evaluators(self):
        """Register default policy evaluators."""
        self.evaluators[PolicyType.NETWORK] = NetworkPolicyEvaluator()
        self.evaluators[PolicyType.IDENTITY] = IdentityPolicyEvaluator()
        self.evaluators[PolicyType.DEVICE] = DevicePolicyEvaluator()
        self.evaluators[PolicyType.APPLICATION] = ApplicationPolicyEvaluator()
        self.evaluators[PolicyType.DATA] = DataPolicyEvaluator()
        self.evaluators[PolicyType.COMPOSITE] = CompositePolicyEvaluator()
    
    def _initialize_default_policies(self):
        """Create default zero-trust policies."""
        # Default deny-all policy
        default_deny = PolicyRule(
            rule_id="default_deny_all",
            name="Default Deny All",
            description="Deny all access by default (zero-trust principle)",
            policy_type=PolicyType.COMPOSITE,
            scope=PolicyScope.GLOBAL,
            target=PolicyTarget(),  # Empty target matches all
            conditions=[],  # No conditions means always applies
            action=PolicyAction.DENY,
            priority=999999,  # Lowest priority
            metadata={'system_policy': True}
        )
        self.policies[default_deny.rule_id] = default_deny
        self.policy_index[PolicyType.COMPOSITE].add(default_deny.rule_id)
        
        # Require MFA for privileged actions
        mfa_policy = PolicyRule(
            rule_id="require_mfa_privileged",
            name="Require MFA for Privileged Actions",
            description="Require multi-factor authentication for all privileged operations",
            policy_type=PolicyType.IDENTITY,
            scope=PolicyScope.GLOBAL,
            target=PolicyTarget(
                actions=["admin.*", "write.*", "delete.*", "modify.*"]
            ),
            conditions=[
                PolicyCondition(
                    field="user.privilege_level",
                    operator="greater_than",
                    value=5
                )
            ],
            action=PolicyAction.REQUIRE_MFA,
            priority=100,
            metadata={'system_policy': True}
        )
        self.policies[mfa_policy.rule_id] = mfa_policy
        self.policy_index[PolicyType.IDENTITY].add(mfa_policy.rule_id)
        
        # Require encryption for classified data
        encryption_policy = PolicyRule(
            rule_id="require_encryption_classified",
            name="Require Encryption for Classified Data",
            description="Require encryption for all classified data operations",
            policy_type=PolicyType.DATA,
            scope=PolicyScope.GLOBAL,
            target=PolicyTarget(
                classifications=[
                    ClassificationLevel.CONFIDENTIAL,
                    ClassificationLevel.SECRET,
                    ClassificationLevel.TOP_SECRET
                ]
            ),
            conditions=[],
            action=PolicyAction.REQUIRE_ENCRYPTION,
            priority=50,
            metadata={'system_policy': True}
        )
        self.policies[encryption_policy.rule_id] = encryption_policy
        self.policy_index[PolicyType.DATA].add(encryption_policy.rule_id)
    
    async def create_policy(
        self,
        name: str,
        description: str,
        policy_type: PolicyType,
        scope: PolicyScope,
        target: PolicyTarget,
        conditions: List[PolicyCondition],
        action: PolicyAction,
        priority: int = 100,
        effective_date: Optional[datetime] = None,
        expiration_date: Optional[datetime] = None,
        created_by: str = "system",
        metadata: Optional[Dict[str, Any]] = None
    ) -> PolicyRule:
        """
        Create a new policy rule.
        
        Args:
            name: Policy name
            description: Policy description
            policy_type: Type of policy
            scope: Policy scope
            target: Policy target specification
            conditions: Policy conditions
            action: Policy action
            priority: Policy priority (lower = higher priority)
            effective_date: When policy becomes effective
            expiration_date: When policy expires
            created_by: Policy creator
            metadata: Additional metadata
            
        Returns:
            Created PolicyRule
        """
        # Generate policy ID
        rule_id = hashlib.sha256(
            f"{name}:{policy_type.value}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Create policy rule
        policy = PolicyRule(
            rule_id=rule_id,
            name=name,
            description=description,
            policy_type=policy_type,
            scope=scope,
            target=target,
            conditions=conditions,
            action=action,
            priority=priority,
            effective_date=effective_date,
            expiration_date=expiration_date,
            created_by=created_by,
            metadata=metadata or {}
        )
        
        # Validate policy
        if not await self._validate_policy(policy):
            raise PolicyError(f"Policy validation failed: {name}")
        
        # Check for conflicts
        conflicts = await self._detect_conflicts(policy)
        if conflicts:
            for conflict in conflicts:
                self.conflicts.append(conflict)
                self.conflict_matrix[(policy.rule_id, conflict.policy2_id)] = conflict
                self.stats['conflicts_detected'] += 1
        
        # Store policy
        self.policies[rule_id] = policy
        self.policy_index[policy_type].add(rule_id)
        self.stats['policies_created'] += 1
        
        # Clear evaluation cache
        if self.enable_caching:
            self.evaluation_cache.clear()
        
        # Audit log
        await self.audit_logger.log_event(
            "ZERO_TRUST_POLICY_CREATED",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'policy_id': rule_id,
                'name': name,
                'type': policy_type.value,
                'scope': scope.value,
                'action': action.value,
                'priority': priority,
                'conflicts_detected': len(conflicts)
            }
        )
        
        # Distribute policy
        await self._distribute_policy(policy, 'created')
        
        logger.info("Created policy %s with %d conflicts", name, len(conflicts))
        return policy
    
    async def _validate_policy(self, policy: PolicyRule) -> bool:
        """Validate policy rule."""
        # Check for valid targets
        if not any([
            policy.target.subjects,
            policy.target.resources,
            policy.target.actions,
            policy.target.networks,
            policy.target.devices,
            policy.target.classifications
        ]):
            # Empty target is allowed for global policies
            if policy.scope != PolicyScope.GLOBAL:
                logger.warning("Non-global policy %s has empty target", policy.name)
                return False
        
        # Validate conditions
        for condition in policy.conditions:
            if not self._validate_condition(condition):
                return False
        
        # Check expiration
        if policy.expiration_date and policy.expiration_date < datetime.utcnow():
            logger.warning("Policy %s has already expired", policy.name)
            return False
        
        return True
    
    def _validate_condition(self, condition: PolicyCondition) -> bool:
        """Validate a policy condition."""
        valid_operators = [
            'equals', 'not_equals', 'contains', 'not_contains',
            'starts_with', 'ends_with', 'matches', 'greater_than',
            'less_than', 'in', 'not_in', 'exists', 'not_exists'
        ]
        
        if condition.operator not in valid_operators:
            logger.warning("Invalid operator: %s", condition.operator)
            return False
        
        return True
    
    async def _detect_conflicts(self, policy: PolicyRule) -> List[PolicyConflict]:
        """Detect conflicts with existing policies."""
        conflicts = []
        
        # Check policies of the same type
        for policy_id in self.policy_index[policy.policy_type]:
            existing_policy = self.policies[policy_id]
            
            # Skip if same policy
            if existing_policy.rule_id == policy.rule_id:
                continue
            
            # Check for overlapping targets
            if self._targets_overlap(policy.target, existing_policy.target):
                # Check for conflicting actions
                if self._actions_conflict(policy.action, existing_policy.action):
                    conflict = PolicyConflict(
                        conflict_id=hashlib.sha256(
                            f"{policy.rule_id}:{existing_policy.rule_id}".encode()
                        ).hexdigest()[:16],
                        policy1_id=policy.rule_id,
                        policy2_id=existing_policy.rule_id,
                        conflict_type="action_conflict",
                        description=f"Policies have conflicting actions: {policy.action.value} vs {existing_policy.action.value}",
                        resolution_applied=self._determine_resolution(policy, existing_policy)
                    )
                    conflicts.append(conflict)
        
        return conflicts
    
    def _targets_overlap(self, target1: PolicyTarget, target2: PolicyTarget) -> bool:
        """Check if two policy targets overlap."""
        # Check each target dimension
        overlaps = []
        
        # Subjects
        if target1.subjects and target2.subjects:
            overlaps.append(self._lists_overlap(target1.subjects, target2.subjects))
        
        # Resources
        if target1.resources and target2.resources:
            overlaps.append(self._lists_overlap(target1.resources, target2.resources))
        
        # Actions
        if target1.actions and target2.actions:
            overlaps.append(self._lists_overlap(target1.actions, target2.actions))
        
        # Networks
        if target1.networks and target2.networks:
            overlaps.append(self._networks_overlap(target1.networks, target2.networks))
        
        # Devices
        if target1.devices and target2.devices:
            overlaps.append(self._lists_overlap(target1.devices, target2.devices))
        
        # Classifications
        if target1.classifications and target2.classifications:
            overlaps.append(bool(set(target1.classifications) & set(target2.classifications)))
        
        # Targets overlap if any dimension overlaps (or both are empty)
        return any(overlaps) if overlaps else True
    
    def _lists_overlap(self, list1: List[str], list2: List[str]) -> bool:
        """Check if two lists overlap, considering wildcards."""
        for item1 in list1:
            for item2 in list2:
                if self._patterns_match(item1, item2):
                    return True
        return False
    
    def _patterns_match(self, pattern1: str, pattern2: str) -> bool:
        """Check if two patterns match."""
        # Convert wildcards to regex
        regex1 = pattern1.replace('*', '.*').replace('?', '.')
        regex2 = pattern2.replace('*', '.*').replace('?', '.')
        
        # Check if either pattern matches the other
        return (re.match(regex1, pattern2) is not None or 
                re.match(regex2, pattern1) is not None)
    
    def _networks_overlap(self, networks1: List[str], networks2: List[str]) -> bool:
        """Check if network specifications overlap."""
        # Simplified - in production would parse CIDR notation
        return self._lists_overlap(networks1, networks2)
    
    def _actions_conflict(self, action1: PolicyAction, action2: PolicyAction) -> bool:
        """Check if two actions conflict."""
        # Define conflicting action pairs
        conflicts = {
            (PolicyAction.ALLOW, PolicyAction.DENY),
            (PolicyAction.DENY, PolicyAction.ALLOW),
            (PolicyAction.ALLOW, PolicyAction.QUARANTINE),
            (PolicyAction.QUARANTINE, PolicyAction.ALLOW)
        }
        
        return (action1, action2) in conflicts or (action2, action1) in conflicts
    
    def _determine_resolution(
        self,
        policy1: PolicyRule,
        policy2: PolicyRule
    ) -> str:
        """Determine how to resolve a conflict."""
        # Use priority-based resolution by default
        if policy1.priority < policy2.priority:
            return f"Policy {policy1.rule_id} takes precedence (higher priority)"
        elif policy2.priority < policy1.priority:
            return f"Policy {policy2.rule_id} takes precedence (higher priority)"
        else:
            # Same priority - use creation time
            if policy1.created_at < policy2.created_at:
                return f"Policy {policy1.rule_id} takes precedence (created earlier)"
            else:
                return f"Policy {policy2.rule_id} takes precedence (created earlier)"
    
    async def evaluate_policies(
        self,
        context: Dict[str, Any],
        policy_types: Optional[List[PolicyType]] = None
    ) -> List[Tuple[PolicyRule, PolicyAction]]:
        """
        Evaluate applicable policies for a given context.
        
        Args:
            context: Evaluation context with subject, resource, action, etc.
            policy_types: Specific policy types to evaluate (None = all)
            
        Returns:
            List of (policy, action) tuples for applicable policies
        """
        start_time = time.time()
        
        # Check cache
        if self.enable_caching:
            cache_key = self._generate_cache_key(context)
            if cache_key in self.evaluation_cache:
                cached_result, cache_time = self.evaluation_cache[cache_key]
                if (datetime.utcnow() - cache_time).total_seconds() < self.cache_ttl:
                    self.stats['cache_hits'] += 1
                    return cached_result
        
        # Determine policy types to evaluate
        types_to_evaluate = policy_types or list(PolicyType)
        
        # Collect applicable policies
        applicable_policies = []
        
        for policy_type in types_to_evaluate:
            for policy_id in self.policy_index[policy_type]:
                policy = self.policies[policy_id]
                
                # Skip disabled policies
                if not policy.enabled:
                    continue
                
                # Check effective dates
                now = datetime.utcnow()
                if policy.effective_date and now < policy.effective_date:
                    continue
                if policy.expiration_date and now > policy.expiration_date:
                    continue
                
                # Evaluate policy
                evaluator = self.evaluators.get(policy_type)
                if evaluator:
                    applies, reason = await evaluator.evaluate(policy, context)
                    if applies:
                        applicable_policies.append((policy, policy.action))
        
        # Sort by priority (lower number = higher priority)
        applicable_policies.sort(key=lambda x: x[0].priority)
        
        # Apply conflict resolution
        resolved_policies = await self._resolve_conflicts(applicable_policies, context)
        
        # Update statistics
        self.stats['policies_evaluated'] += len(self.policies)
        evaluation_time = (time.time() - start_time) * 1000
        self._update_avg_evaluation_time(evaluation_time)
        
        # Cache result
        if self.enable_caching and resolved_policies:
            cache_key = self._generate_cache_key(context)
            self.evaluation_cache[cache_key] = (resolved_policies, datetime.utcnow())
        
        # Monitor if evaluation is slow
        if evaluation_time > 1.0:
            logger.warning("Policy evaluation took %.2fms (exceeds 1ms target)", evaluation_time)
        
        return resolved_policies
    
    def _generate_cache_key(self, context: Dict[str, Any]) -> str:
        """Generate cache key for evaluation context."""
        # Extract key fields
        key_parts = [
            context.get('subject', {}).get('id', ''),
            context.get('resource', {}).get('id', ''),
            context.get('action', {}).get('type', ''),
            context.get('network', {}).get('zone', ''),
            str(context.get('classification', ''))
        ]
        
        return hashlib.sha256(":".join(key_parts).encode()).hexdigest()
    
    async def _resolve_conflicts(
        self,
        policies: List[Tuple[PolicyRule, PolicyAction]],
        context: Dict[str, Any]
    ) -> List[Tuple[PolicyRule, PolicyAction]]:
        """Resolve conflicts among applicable policies."""
        if len(policies) <= 1:
            return policies
        
        # Group by action
        action_groups = defaultdict(list)
        for policy, action in policies:
            action_groups[action].append(policy)
        
        # Check for conflicts
        if PolicyAction.ALLOW in action_groups and PolicyAction.DENY in action_groups:
            self.stats['conflicts_resolved'] += 1
            
            # Apply conflict resolution strategy
            if self.default_conflict_resolution == ConflictResolution.DENY_OVERRIDES:
                # Any deny overrides all allows
                return [(p, PolicyAction.DENY) for p in action_groups[PolicyAction.DENY]]
            
            elif self.default_conflict_resolution == ConflictResolution.PERMIT_OVERRIDES:
                # Any allow overrides all denies
                return [(p, PolicyAction.ALLOW) for p in action_groups[PolicyAction.ALLOW]]
            
            elif self.default_conflict_resolution == ConflictResolution.PRIORITY_BASED:
                # Already sorted by priority, take first
                return [policies[0]]
            
            elif self.default_conflict_resolution == ConflictResolution.MOST_RESTRICTIVE:
                # Deny is most restrictive
                return [(p, PolicyAction.DENY) for p in action_groups[PolicyAction.DENY]]
            
            elif self.default_conflict_resolution == ConflictResolution.LEAST_RESTRICTIVE:
                # Allow is least restrictive
                return [(p, PolicyAction.ALLOW) for p in action_groups[PolicyAction.ALLOW]]
        
        # No conflict, return all policies
        return policies
    
    async def simulate_policy_change(
        self,
        new_policy: PolicyRule,
        test_scenarios: List[Dict[str, Any]]
    ) -> PolicySimulation:
        """
        Simulate the impact of adding or modifying a policy.
        
        Args:
            new_policy: New or modified policy to simulate
            test_scenarios: List of test scenarios to evaluate
            
        Returns:
            PolicySimulation with results
        """
        simulation_start = time.time()
        
        # Create simulation ID
        simulation_id = hashlib.sha256(
            f"sim:{new_policy.rule_id}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Temporarily add policy
        original_policy = None
        if new_policy.rule_id in self.policies:
            original_policy = self.policies[new_policy.rule_id]
        
        self.policies[new_policy.rule_id] = new_policy
        self.policy_index[new_policy.policy_type].add(new_policy.rule_id)
        
        # Clear cache for simulation
        if self.enable_caching:
            self.evaluation_cache.clear()
        
        # Run scenarios
        decisions = []
        affected_policies = set()
        
        for scenario in test_scenarios:
            # Evaluate with new policy
            applicable = await self.evaluate_policies(scenario)
            
            decision = {
                'scenario': scenario,
                'applicable_policies': [
                    {'policy_id': p.rule_id, 'action': a.value}
                    for p, a in applicable
                ],
                'final_decision': applicable[0][1].value if applicable else 'deny'
            }
            decisions.append(decision)
            
            # Track affected policies
            for policy, _ in applicable:
                affected_policies.add(policy.rule_id)
        
        # Detect new conflicts
        new_conflicts = await self._detect_conflicts(new_policy)
        
        # Calculate performance metrics
        total_evaluation_time = (time.time() - simulation_start) * 1000
        avg_scenario_time = total_evaluation_time / len(test_scenarios) if test_scenarios else 0
        
        # Generate recommendations
        recommendations = []
        if new_conflicts:
            recommendations.append(f"Policy creates {len(new_conflicts)} new conflicts")
        if avg_scenario_time > 1.0:
            recommendations.append("Policy evaluation exceeds 1ms target")
        if len(affected_policies) > 10:
            recommendations.append(f"Policy affects {len(affected_policies)} existing policies")
        
        # Restore original state
        if original_policy:
            self.policies[new_policy.rule_id] = original_policy
        else:
            del self.policies[new_policy.rule_id]
            self.policy_index[new_policy.policy_type].discard(new_policy.rule_id)
        
        # Create simulation result
        simulation = PolicySimulation(
            simulation_id=simulation_id,
            timestamp=datetime.utcnow(),
            scenario={'new_policy': new_policy.rule_id, 'scenarios_count': len(test_scenarios)},
            affected_policies=list(affected_policies),
            decisions=decisions,
            conflicts_detected=new_conflicts,
            performance_metrics={
                'total_time_ms': total_evaluation_time,
                'avg_scenario_time_ms': avg_scenario_time,
                'scenarios_evaluated': len(test_scenarios)
            },
            recommendations=recommendations
        )
        
        self.stats['simulations_run'] += 1
        
        # Audit log
        await self.audit_logger.log_event(
            "ZERO_TRUST_POLICY_SIMULATION",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'simulation_id': simulation_id,
                'policy_id': new_policy.rule_id,
                'scenarios_count': len(test_scenarios),
                'conflicts_detected': len(new_conflicts),
                'affected_policies': len(affected_policies)
            }
        )
        
        logger.info("Completed policy simulation %s with %d scenarios",
                   simulation_id, len(test_scenarios))
        
        return simulation
    
    async def _distribute_policy(self, policy: PolicyRule, event_type: str):
        """Distribute policy update to subscribers."""
        if not self.policy_subscribers:
            return
        
        distribution_start = time.time()
        
        # Create distribution event
        event = {
            'event_type': event_type,
            'policy_id': policy.rule_id,
            'policy': {
                'name': policy.name,
                'type': policy.policy_type.value,
                'action': policy.action.value,
                'priority': policy.priority,
                'enabled': policy.enabled
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Notify all subscribers
        tasks = []
        for subscriber in self.policy_subscribers:
            if asyncio.iscoroutinefunction(subscriber):
                tasks.append(subscriber(event))
            else:
                # Wrap sync callbacks
                tasks.append(asyncio.create_task(asyncio.to_thread(subscriber, event)))
        
        # Wait for all notifications
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Update metrics
        distribution_time = (time.time() - distribution_start) * 1000
        self._update_avg_distribution_time(distribution_time)
        
        if distribution_time > 100:
            logger.warning("Policy distribution took %.2fms (exceeds 100ms target)",
                         distribution_time)
    
    def subscribe_to_updates(self, callback: Callable):
        """Subscribe to policy update notifications."""
        self.policy_subscribers.append(callback)
        logger.debug("Added policy update subscriber")
    
    def _update_avg_evaluation_time(self, evaluation_time_ms: float):
        """Update average evaluation time metric."""
        current_avg = self.stats['avg_evaluation_time_ms']
        total_evaluations = self.stats.get('total_evaluations', 0)
        
        # Calculate running average
        self.stats['avg_evaluation_time_ms'] = (
            (current_avg * total_evaluations + evaluation_time_ms) / (total_evaluations + 1)
        )
        self.stats['total_evaluations'] = total_evaluations + 1
    
    def _update_avg_distribution_time(self, distribution_time_ms: float):
        """Update average distribution time metric."""
        current_avg = self.stats['avg_distribution_time_ms']
        total_distributions = self.stats.get('total_distributions', 0)
        
        # Calculate running average
        self.stats['avg_distribution_time_ms'] = (
            (current_avg * total_distributions + distribution_time_ms) / (total_distributions + 1)
        )
        self.stats['total_distributions'] = total_distributions + 1
    
    async def export_policies(self, format: str = 'json') -> str:
        """Export all policies in specified format."""
        policies_data = []
        
        for policy in self.policies.values():
            policy_dict = {
                'rule_id': policy.rule_id,
                'name': policy.name,
                'description': policy.description,
                'type': policy.policy_type.value,
                'scope': policy.scope.value,
                'action': policy.action.value,
                'priority': policy.priority,
                'enabled': policy.enabled,
                'created_at': policy.created_at.isoformat(),
                'created_by': policy.created_by
            }
            policies_data.append(policy_dict)
        
        if format == 'json':
            return json.dumps(policies_data, indent=2)
        elif format == 'yaml':
            return yaml.dump(policies_data, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current engine statistics."""
        return {
            **self.stats,
            'total_policies': len(self.policies),
            'policies_by_type': {
                policy_type.value: len(self.policy_index[policy_type])
                for policy_type in PolicyType
            },
            'total_conflicts': len(self.conflicts),
            'cache_size': len(self.evaluation_cache),
            'subscribers': len(self.policy_subscribers)
        }


# Policy evaluator implementations

class NetworkPolicyEvaluator(PolicyEvaluator):
    """Evaluator for network policies."""
    
    async def evaluate(
        self,
        policy: PolicyRule,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate network policy."""
        # Check if network context exists
        network_info = context.get('network', {})
        if not network_info:
            return False, "No network context"
        
        # Check network targets
        if policy.target.networks:
            current_network = network_info.get('zone', network_info.get('cidr', ''))
            if not any(self._match_network(current_network, target) 
                      for target in policy.target.networks):
                return False, "Network does not match target"
        
        # Evaluate conditions
        for condition in policy.conditions:
            if not self._evaluate_condition(condition, context):
                return False, f"Condition failed: {condition.field}"
        
        return True, None
    
    def _match_network(self, network: str, target: str) -> bool:
        """Check if network matches target pattern."""
        # Simplified - in production would handle CIDR notation
        return target == '*' or network == target or network.startswith(target)
    
    def _evaluate_condition(
        self,
        condition: PolicyCondition,
        context: Dict[str, Any]
    ) -> bool:
        """Evaluate a single condition."""
        # Get value from context
        value = self._get_value(condition.field, context)
        if value is None and condition.operator != 'not_exists':
            return False
        
        # Evaluate based on operator
        expected = condition.value
        
        if condition.operator == 'equals':
            result = value == expected
        elif condition.operator == 'not_equals':
            result = value != expected
        elif condition.operator == 'exists':
            result = value is not None
        elif condition.operator == 'not_exists':
            result = value is None
        else:
            result = False
        
        return not result if condition.negate else result
    
    def _get_value(self, field: str, context: Dict[str, Any]) -> Any:
        """Get value from context using dot notation."""
        parts = field.split('.')
        current = context
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current


class IdentityPolicyEvaluator(PolicyEvaluator):
    """Evaluator for identity policies."""
    
    async def evaluate(
        self,
        policy: PolicyRule,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate identity policy."""
        subject = context.get('subject', {})
        if not subject:
            return False, "No subject context"
        
        # Check subject targets
        if policy.target.subjects:
            subject_id = subject.get('id', '')
            if not any(self._match_pattern(subject_id, target) 
                      for target in policy.target.subjects):
                return False, "Subject does not match target"
        
        # Check action targets
        if policy.target.actions:
            action = context.get('action', {}).get('type', '')
            if not any(self._match_pattern(action, target) 
                      for target in policy.target.actions):
                return False, "Action does not match target"
        
        # Evaluate conditions
        evaluator = NetworkPolicyEvaluator()  # Reuse condition evaluation logic
        for condition in policy.conditions:
            if not evaluator._evaluate_condition(condition, context):
                return False, f"Condition failed: {condition.field}"
        
        return True, None
    
    def _match_pattern(self, value: str, pattern: str) -> bool:
        """Match value against pattern with wildcards."""
        regex = pattern.replace('*', '.*').replace('?', '.')
        return re.match(f"^{regex}$", value) is not None


class DevicePolicyEvaluator(PolicyEvaluator):
    """Evaluator for device policies."""
    
    async def evaluate(
        self,
        policy: PolicyRule,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate device policy."""
        device = context.get('device', {})
        if not device:
            return False, "No device context"
        
        # Check device targets
        if policy.target.devices:
            device_id = device.get('id', device.get('type', ''))
            if not any(self._match_device(device_id, target) 
                      for target in policy.target.devices):
                return False, "Device does not match target"
        
        # Evaluate conditions
        evaluator = NetworkPolicyEvaluator()
        for condition in policy.conditions:
            if not evaluator._evaluate_condition(condition, context):
                return False, f"Condition failed: {condition.field}"
        
        return True, None
    
    def _match_device(self, device: str, target: str) -> bool:
        """Match device against target."""
        return target == '*' or device == target or device.startswith(target)


class ApplicationPolicyEvaluator(PolicyEvaluator):
    """Evaluator for application policies."""
    
    async def evaluate(
        self,
        policy: PolicyRule,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate application policy."""
        # Check resource targets
        if policy.target.resources:
            resource = context.get('resource', {})
            resource_id = resource.get('id', resource.get('type', ''))
            
            identity_eval = IdentityPolicyEvaluator()
            if not any(identity_eval._match_pattern(resource_id, target) 
                      for target in policy.target.resources):
                return False, "Resource does not match target"
        
        # Evaluate conditions
        evaluator = NetworkPolicyEvaluator()
        for condition in policy.conditions:
            if not evaluator._evaluate_condition(condition, context):
                return False, f"Condition failed: {condition.field}"
        
        return True, None


class DataPolicyEvaluator(PolicyEvaluator):
    """Evaluator for data policies."""
    
    async def evaluate(
        self,
        policy: PolicyRule,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate data policy."""
        # Check classification targets
        if policy.target.classifications:
            data_class = context.get('classification')
            if not data_class:
                return False, "No classification context"
            
            if isinstance(data_class, str):
                try:
                    data_class = ClassificationLevel[data_class.upper()]
                except KeyError:
                    return False, f"Invalid classification: {data_class}"
            
            if data_class not in policy.target.classifications:
                return False, "Classification does not match target"
        
        # Evaluate conditions
        evaluator = NetworkPolicyEvaluator()
        for condition in policy.conditions:
            if not evaluator._evaluate_condition(condition, context):
                return False, f"Condition failed: {condition.field}"
        
        return True, None


class CompositePolicyEvaluator(PolicyEvaluator):
    """Evaluator for composite policies."""
    
    async def evaluate(
        self,
        policy: PolicyRule,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate composite policy by checking all dimensions."""
        # Composite policies can match any target dimension
        target = policy.target
        matches = []
        
        # Check each dimension
        if target.subjects:
            identity_eval = IdentityPolicyEvaluator()
            subject_match = await identity_eval.evaluate(policy, context)
            matches.append(subject_match[0])
        
        if target.resources:
            app_eval = ApplicationPolicyEvaluator()
            resource_match = await app_eval.evaluate(policy, context)
            matches.append(resource_match[0])
        
        if target.networks:
            network_eval = NetworkPolicyEvaluator()
            network_match = await network_eval.evaluate(policy, context)
            matches.append(network_match[0])
        
        if target.devices:
            device_eval = DevicePolicyEvaluator()
            device_match = await device_eval.evaluate(policy, context)
            matches.append(device_match[0])
        
        if target.classifications:
            data_eval = DataPolicyEvaluator()
            class_match = await data_eval.evaluate(policy, context)
            matches.append(class_match[0])
        
        # If no specific targets, evaluate conditions only
        if not matches:
            evaluator = NetworkPolicyEvaluator()
            for condition in policy.conditions:
                if not evaluator._evaluate_condition(condition, context):
                    return False, f"Condition failed: {condition.field}"
            return True, None
        
        # All specified dimensions must match
        if all(matches):
            return True, None
        else:
            return False, "Not all target dimensions matched"