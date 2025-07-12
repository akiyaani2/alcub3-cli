#!/usr/bin/env python3
"""
ALCUB3 Identity-Based Access Control (ABAC) Engine
Dynamic attribute-based access control with classification awareness

This module implements patent-pending ABAC that:
- Provides attribute-based access control decisions
- Enables dynamic policy evaluation
- Maps roles to permissions with classification awareness
- Tracks temporary privilege elevation
- Integrates with JIT privilege system

Performance Targets:
- <1ms per access decision
- Support for 100,000+ policies
- Zero false negatives for security decisions
"""

import asyncio
import hashlib
import logging
import time
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from collections import defaultdict
import json
from pathlib import Path

# Import MAESTRO components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError, AuthorizationError
from shared.clearance_access_control import ClearanceLevel

logger = logging.getLogger(__name__)


class AccessDecision(Enum):
    """Access control decisions."""
    PERMIT = "permit"
    DENY = "deny"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"


class PolicyEffect(Enum):
    """Policy effects."""
    PERMIT = "permit"
    DENY = "deny"


class AttributeType(Enum):
    """Types of attributes for ABAC."""
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    LIST = "list"
    CLASSIFICATION = "classification"
    CLEARANCE = "clearance"


@dataclass
class Attribute:
    """Represents an ABAC attribute."""
    name: str
    value: Any
    type: AttributeType
    issuer: str = "system"
    issued_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Subject:
    """Subject (user/service) with attributes."""
    id: str
    type: str  # "user", "service", "device"
    attributes: Dict[str, Attribute] = field(default_factory=dict)
    roles: Set[str] = field(default_factory=set)
    clearance_level: Optional[ClearanceLevel] = None
    active_elevations: Dict[str, datetime] = field(default_factory=dict)  # Permission -> Expiry


@dataclass
class Resource:
    """Resource with attributes."""
    id: str
    type: str  # "file", "api", "database", "service"
    classification: ClassificationLevel
    attributes: Dict[str, Attribute] = field(default_factory=dict)
    owner: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Action:
    """Action to be performed."""
    id: str
    type: str  # "read", "write", "delete", "execute", "admin"
    attributes: Dict[str, Attribute] = field(default_factory=dict)
    risk_level: int = 0  # 0-10 risk score


@dataclass
class Environment:
    """Environmental context for access decision."""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    location: Optional[str] = None
    device_trust_score: float = 0.0
    network_zone: Optional[str] = None
    session_id: Optional[str] = None
    attributes: Dict[str, Attribute] = field(default_factory=dict)


@dataclass
class PolicyRule:
    """ABAC policy rule."""
    id: str
    name: str
    description: str
    effect: PolicyEffect
    priority: int = 100
    enabled: bool = True
    # Conditions as attribute expressions
    subject_conditions: List[Dict[str, Any]] = field(default_factory=list)
    resource_conditions: List[Dict[str, Any]] = field(default_factory=list)
    action_conditions: List[Dict[str, Any]] = field(default_factory=list)
    environment_conditions: List[Dict[str, Any]] = field(default_factory=list)
    obligations: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessRequest:
    """Access control request."""
    request_id: str
    subject: Subject
    resource: Resource
    action: Action
    environment: Environment
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AccessResponse:
    """Access control response."""
    request_id: str
    decision: AccessDecision
    applicable_policies: List[str] = field(default_factory=list)
    obligations: List[Dict[str, Any]] = field(default_factory=list)
    advice: List[str] = field(default_factory=list)
    evaluation_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


class IdentityAccessControl:
    """
    Patent-pending identity-based access control engine with ABAC.
    
    This engine provides fine-grained access control based on attributes
    with full support for security classifications and dynamic policies.
    """
    
    def __init__(
        self,
        audit_logger: AuditLogger,
        enable_policy_cache: bool = True,
        cache_ttl_seconds: int = 300
    ):
        """
        Initialize the identity access control engine.
        
        Args:
            audit_logger: Audit logger for access decisions
            enable_policy_cache: Enable policy evaluation caching
            cache_ttl_seconds: Cache TTL in seconds
        """
        self.audit_logger = audit_logger
        self.enable_policy_cache = enable_policy_cache
        self.cache_ttl = cache_ttl_seconds
        
        # Core data structures
        self.policies: Dict[str, PolicyRule] = {}
        self.subjects: Dict[str, Subject] = {}
        self.roles: Dict[str, Dict[str, Any]] = {}  # Role definitions
        self.role_hierarchies: Dict[str, Set[str]] = {}  # Role inheritance
        
        # Policy evaluation cache
        self.policy_cache: Dict[str, Tuple[AccessDecision, datetime]] = {}
        self.last_cache_cleanup = time.time()
        
        # Statistics
        self.stats = {
            'requests_evaluated': 0,
            'permits_granted': 0,
            'denies_issued': 0,
            'cache_hits': 0,
            'avg_evaluation_time_ms': 0.0,
            'policy_conflicts_resolved': 0
        }
        
        # Initialize default policies
        self._initialize_default_policies()
        
        logger.info("Identity access control engine initialized")
    
    def _initialize_default_policies(self):
        """Create default security policies."""
        # Classification-based access policy
        self.policies['classification_policy'] = PolicyRule(
            id='classification_policy',
            name='Classification-Based Access Control',
            description='Enforce access based on clearance and classification levels',
            effect=PolicyEffect.DENY,
            priority=10,  # High priority
            subject_conditions=[
                {
                    'attribute': 'clearance_level',
                    'operator': 'less_than',
                    'value': 'resource.classification'
                }
            ]
        )
        
        # Need-to-know policy
        self.policies['need_to_know'] = PolicyRule(
            id='need_to_know',
            name='Need-to-Know Enforcement',
            description='Enforce need-to-know for classified resources',
            effect=PolicyEffect.DENY,
            priority=20,
            resource_conditions=[
                {
                    'attribute': 'classification',
                    'operator': 'greater_than_or_equal',
                    'value': 'SECRET'
                }
            ],
            subject_conditions=[
                {
                    'attribute': 'need_to_know_groups',
                    'operator': 'not_contains',
                    'value': 'resource.compartment'
                }
            ]
        )
        
        # Time-based access policy
        self.policies['time_window_policy'] = PolicyRule(
            id='time_window_policy',
            name='Time Window Access Control',
            description='Restrict access outside business hours for sensitive resources',
            effect=PolicyEffect.DENY,
            priority=50,
            resource_conditions=[
                {
                    'attribute': 'classification',
                    'operator': 'greater_than_or_equal',
                    'value': 'CONFIDENTIAL'
                }
            ],
            environment_conditions=[
                {
                    'attribute': 'time_of_day',
                    'operator': 'not_between',
                    'value': ['08:00', '18:00']
                }
            ]
        )
        
        # Device trust policy
        self.policies['device_trust_policy'] = PolicyRule(
            id='device_trust_policy',
            name='Device Trust Requirement',
            description='Require minimum device trust score for sensitive actions',
            effect=PolicyEffect.DENY,
            priority=30,
            action_conditions=[
                {
                    'attribute': 'risk_level',
                    'operator': 'greater_than',
                    'value': 5
                }
            ],
            environment_conditions=[
                {
                    'attribute': 'device_trust_score',
                    'operator': 'less_than',
                    'value': 0.7
                }
            ]
        )
    
    async def evaluate_access(
        self,
        subject: Subject,
        resource: Resource,
        action: Action,
        environment: Environment
    ) -> AccessResponse:
        """
        Evaluate an access control request.
        
        Args:
            subject: Subject requesting access
            resource: Resource being accessed
            action: Action to be performed
            environment: Environmental context
            
        Returns:
            AccessResponse with decision and obligations
        """
        start_time = time.time()
        
        # Create access request
        request = AccessRequest(
            request_id=hashlib.sha256(
                f"{subject.id}:{resource.id}:{action.id}:{time.time()}".encode()
            ).hexdigest()[:16],
            subject=subject,
            resource=resource,
            action=action,
            environment=environment
        )
        
        # Check cache if enabled
        if self.enable_policy_cache:
            cache_key = self._generate_cache_key(request)
            if cache_key in self.policy_cache:
                cached_decision, cache_time = self.policy_cache[cache_key]
                if (datetime.utcnow() - cache_time).total_seconds() < self.cache_ttl:
                    self.stats['cache_hits'] += 1
                    evaluation_time = (time.time() - start_time) * 1000
                    
                    return AccessResponse(
                        request_id=request.request_id,
                        decision=cached_decision,
                        evaluation_time_ms=evaluation_time
                    )
        
        # Expand subject roles
        await self._expand_subject_roles(subject)
        
        # Evaluate policies
        applicable_policies = []
        permit_policies = []
        deny_policies = []
        obligations = []
        advice = []
        
        for policy in sorted(self.policies.values(), key=lambda p: p.priority):
            if not policy.enabled:
                continue
            
            # Check if policy applies
            if await self._evaluate_policy_conditions(policy, request):
                applicable_policies.append(policy.id)
                
                if policy.effect == PolicyEffect.PERMIT:
                    permit_policies.append(policy)
                else:
                    deny_policies.append(policy)
                
                # Collect obligations
                obligations.extend(policy.obligations)
        
        # Determine final decision
        decision = self._combine_decisions(permit_policies, deny_policies)
        
        # Check classification compatibility
        if decision == AccessDecision.PERMIT:
            if not self._check_classification_access(subject, resource):
                decision = AccessDecision.DENY
                advice.append("Classification level insufficient")
        
        # Create response
        response = AccessResponse(
            request_id=request.request_id,
            decision=decision,
            applicable_policies=applicable_policies,
            obligations=obligations,
            advice=advice,
            evaluation_time_ms=(time.time() - start_time) * 1000
        )
        
        # Update statistics
        self.stats['requests_evaluated'] += 1
        if decision == AccessDecision.PERMIT:
            self.stats['permits_granted'] += 1
        elif decision == AccessDecision.DENY:
            self.stats['denies_issued'] += 1
        
        self._update_avg_evaluation_time(response.evaluation_time_ms)
        
        # Cache decision
        if self.enable_policy_cache and decision != AccessDecision.INDETERMINATE:
            cache_key = self._generate_cache_key(request)
            self.policy_cache[cache_key] = (decision, datetime.utcnow())
        
        # Audit log
        await self._audit_access_decision(request, response)
        
        # Clean cache periodically
        if time.time() - self.last_cache_cleanup > 3600:  # Every hour
            await self._cleanup_cache()
        
        return response
    
    def _generate_cache_key(self, request: AccessRequest) -> str:
        """Generate cache key for access request."""
        # Include key attributes in cache key
        key_parts = [
            request.subject.id,
            request.resource.id,
            request.resource.classification.value,
            request.action.id,
            str(request.environment.device_trust_score),
            request.environment.network_zone or 'default'
        ]
        
        # Add subject roles
        key_parts.extend(sorted(request.subject.roles))
        
        return hashlib.sha256(":".join(key_parts).encode()).hexdigest()
    
    async def _expand_subject_roles(self, subject: Subject):
        """Expand subject roles including inherited roles."""
        expanded_roles = set(subject.roles)
        
        # Add inherited roles
        for role in list(subject.roles):
            if role in self.role_hierarchies:
                expanded_roles.update(self.role_hierarchies[role])
        
        subject.roles = expanded_roles
    
    async def _evaluate_policy_conditions(
        self,
        policy: PolicyRule,
        request: AccessRequest
    ) -> bool:
        """Evaluate if a policy applies to the request."""
        try:
            # Evaluate subject conditions
            if not self._evaluate_conditions(
                policy.subject_conditions,
                request.subject,
                request
            ):
                return False
            
            # Evaluate resource conditions
            if not self._evaluate_conditions(
                policy.resource_conditions,
                request.resource,
                request
            ):
                return False
            
            # Evaluate action conditions
            if not self._evaluate_conditions(
                policy.action_conditions,
                request.action,
                request
            ):
                return False
            
            # Evaluate environment conditions
            if not self._evaluate_conditions(
                policy.environment_conditions,
                request.environment,
                request
            ):
                return False
            
            return True
            
        except Exception as e:
            logger.error("Error evaluating policy %s: %s", policy.id, str(e))
            return False
    
    def _evaluate_conditions(
        self,
        conditions: List[Dict[str, Any]],
        target: Any,
        request: AccessRequest
    ) -> bool:
        """Evaluate a list of conditions against a target."""
        if not conditions:
            return True
        
        for condition in conditions:
            if not self._evaluate_single_condition(condition, target, request):
                return False
        
        return True
    
    def _evaluate_single_condition(
        self,
        condition: Dict[str, Any],
        target: Any,
        request: AccessRequest
    ) -> bool:
        """Evaluate a single condition."""
        attribute_path = condition.get('attribute')
        operator = condition.get('operator')
        expected_value = condition.get('value')
        
        # Get actual value
        actual_value = self._get_attribute_value(attribute_path, target, request)
        
        # Evaluate based on operator
        if operator == 'equals':
            return actual_value == expected_value
        elif operator == 'not_equals':
            return actual_value != expected_value
        elif operator == 'greater_than':
            return self._compare_values(actual_value, expected_value) > 0
        elif operator == 'less_than':
            return self._compare_values(actual_value, expected_value) < 0
        elif operator == 'greater_than_or_equal':
            return self._compare_values(actual_value, expected_value) >= 0
        elif operator == 'less_than_or_equal':
            return self._compare_values(actual_value, expected_value) <= 0
        elif operator == 'contains':
            return expected_value in actual_value if hasattr(actual_value, '__contains__') else False
        elif operator == 'not_contains':
            return expected_value not in actual_value if hasattr(actual_value, '__contains__') else True
        elif operator == 'matches':
            return bool(re.match(expected_value, str(actual_value)))
        elif operator == 'between':
            if isinstance(expected_value, list) and len(expected_value) == 2:
                return expected_value[0] <= actual_value <= expected_value[1]
            return False
        elif operator == 'not_between':
            if isinstance(expected_value, list) and len(expected_value) == 2:
                return not (expected_value[0] <= actual_value <= expected_value[1])
            return True
        else:
            logger.warning("Unknown operator: %s", operator)
            return False
    
    def _get_attribute_value(
        self,
        attribute_path: str,
        target: Any,
        request: AccessRequest
    ) -> Any:
        """Get attribute value from target or request context."""
        # Handle special attribute paths
        if attribute_path.startswith('resource.'):
            return self._get_nested_attribute(request.resource, attribute_path[9:])
        elif attribute_path.startswith('subject.'):
            return self._get_nested_attribute(request.subject, attribute_path[8:])
        elif attribute_path.startswith('action.'):
            return self._get_nested_attribute(request.action, attribute_path[7:])
        elif attribute_path.startswith('environment.'):
            return self._get_nested_attribute(request.environment, attribute_path[12:])
        else:
            # Direct attribute on target
            return self._get_nested_attribute(target, attribute_path)
    
    def _get_nested_attribute(self, obj: Any, path: str) -> Any:
        """Get nested attribute value."""
        parts = path.split('.')
        current = obj
        
        for part in parts:
            if hasattr(current, part):
                current = getattr(current, part)
            elif isinstance(current, dict) and part in current:
                current = current[part]
            elif hasattr(current, 'attributes') and part in current.attributes:
                attr = current.attributes[part]
                return attr.value if isinstance(attr, Attribute) else attr
            else:
                return None
        
        return current
    
    def _compare_values(self, value1: Any, value2: Any) -> int:
        """Compare two values, handling special types."""
        # Handle classification levels
        if isinstance(value1, ClassificationLevel) and isinstance(value2, ClassificationLevel):
            return value1.value - value2.value
        elif isinstance(value1, ClassificationLevel):
            value2_enum = ClassificationLevel[value2.upper()] if isinstance(value2, str) else value2
            return value1.value - value2_enum.value
        elif isinstance(value2, ClassificationLevel):
            value1_enum = ClassificationLevel[value1.upper()] if isinstance(value1, str) else value1
            return value1_enum.value - value2.value
        
        # Handle clearance levels
        if hasattr(value1, 'value') and hasattr(value2, 'value'):
            return value1.value - value2.value
        
        # Standard comparison
        try:
            if value1 < value2:
                return -1
            elif value1 > value2:
                return 1
            else:
                return 0
        except TypeError:
            # Convert to strings for comparison
            return -1 if str(value1) < str(value2) else (1 if str(value1) > str(value2) else 0)
    
    def _combine_decisions(
        self,
        permit_policies: List[PolicyRule],
        deny_policies: List[PolicyRule]
    ) -> AccessDecision:
        """Combine policy decisions using deny-overrides algorithm."""
        if deny_policies:
            # Any deny policy results in deny
            return AccessDecision.DENY
        elif permit_policies:
            # At least one permit and no deny
            return AccessDecision.PERMIT
        else:
            # No applicable policies
            return AccessDecision.NOT_APPLICABLE
    
    def _check_classification_access(
        self,
        subject: Subject,
        resource: Resource
    ) -> bool:
        """Check if subject has sufficient classification access."""
        # Get subject's clearance level
        if not subject.clearance_level:
            # No clearance means only UNCLASSIFIED access
            return resource.classification == ClassificationLevel.UNCLASSIFIED
        
        # Map clearance to max classification
        clearance_to_classification = {
            ClearanceLevel.NONE: ClassificationLevel.UNCLASSIFIED,
            ClearanceLevel.PUBLIC_TRUST: ClassificationLevel.UNCLASSIFIED,
            ClearanceLevel.CONFIDENTIAL: ClassificationLevel.CONFIDENTIAL,
            ClearanceLevel.SECRET: ClassificationLevel.SECRET,
            ClearanceLevel.TOP_SECRET: ClassificationLevel.TOP_SECRET,
            ClearanceLevel.TOP_SECRET_SCI: ClassificationLevel.TOP_SECRET
        }
        
        max_classification = clearance_to_classification.get(
            subject.clearance_level,
            ClassificationLevel.UNCLASSIFIED
        )
        
        return resource.classification.value <= max_classification.value
    
    async def _audit_access_decision(
        self,
        request: AccessRequest,
        response: AccessResponse
    ):
        """Audit log the access decision."""
        await self.audit_logger.log_event(
            "IDENTITY_ACCESS_DECISION",
            classification=request.resource.classification,
            details={
                'request_id': request.request_id,
                'subject_id': request.subject.id,
                'resource_id': request.resource.id,
                'action': request.action.id,
                'decision': response.decision.value,
                'applicable_policies': response.applicable_policies,
                'evaluation_time_ms': response.evaluation_time_ms
            }
        )
    
    def _update_avg_evaluation_time(self, evaluation_time_ms: float):
        """Update average evaluation time metric."""
        current_avg = self.stats['avg_evaluation_time_ms']
        total_requests = self.stats['requests_evaluated']
        
        # Calculate running average
        self.stats['avg_evaluation_time_ms'] = (
            (current_avg * (total_requests - 1) + evaluation_time_ms) / total_requests
        )
    
    async def _cleanup_cache(self):
        """Clean up expired cache entries."""
        current_time = datetime.utcnow()
        expired_keys = []
        
        for key, (_, cache_time) in self.policy_cache.items():
            if (current_time - cache_time).total_seconds() > self.cache_ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.policy_cache[key]
        
        self.last_cache_cleanup = time.time()
        
        if expired_keys:
            logger.debug("Cleaned up %d expired cache entries", len(expired_keys))
    
    async def add_policy(self, policy: PolicyRule) -> bool:
        """Add or update a policy rule."""
        self.policies[policy.id] = policy
        
        # Clear cache when policies change
        self.policy_cache.clear()
        
        await self.audit_logger.log_event(
            "IDENTITY_POLICY_ADDED",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'policy_id': policy.id,
                'policy_name': policy.name,
                'effect': policy.effect.value,
                'priority': policy.priority
            }
        )
        
        logger.info("Added policy: %s", policy.name)
        return True
    
    async def create_role(
        self,
        role_id: str,
        name: str,
        permissions: Set[str],
        parent_roles: Optional[Set[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Create a role with permissions."""
        self.roles[role_id] = {
            'name': name,
            'permissions': permissions,
            'parent_roles': parent_roles or set(),
            'metadata': metadata or {},
            'created_at': datetime.utcnow()
        }
        
        # Update role hierarchy
        if parent_roles:
            self.role_hierarchies[role_id] = parent_roles
        
        await self.audit_logger.log_event(
            "IDENTITY_ROLE_CREATED",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'role_id': role_id,
                'name': name,
                'permissions': list(permissions),
                'parent_roles': list(parent_roles) if parent_roles else []
            }
        )
        
        logger.info("Created role: %s", name)
        return True
    
    async def grant_temporary_elevation(
        self,
        subject_id: str,
        permission: str,
        duration_minutes: int,
        reason: str,
        approver: Optional[str] = None
    ) -> bool:
        """Grant temporary privilege elevation."""
        subject = self.subjects.get(subject_id)
        if not subject:
            logger.warning("Subject %s not found for elevation", subject_id)
            return False
        
        expiry_time = datetime.utcnow() + timedelta(minutes=duration_minutes)
        subject.active_elevations[permission] = expiry_time
        
        await self.audit_logger.log_event(
            "IDENTITY_PRIVILEGE_ELEVATED",
            classification=ClassificationLevel.UNCLASSIFIED,
            details={
                'subject_id': subject_id,
                'permission': permission,
                'duration_minutes': duration_minutes,
                'reason': reason,
                'approver': approver,
                'expiry_time': expiry_time.isoformat()
            }
        )
        
        logger.info("Granted temporary elevation for %s: %s", subject_id, permission)
        return True
    
    def check_elevation(self, subject: Subject, permission: str) -> bool:
        """Check if subject has active elevation for permission."""
        if permission in subject.active_elevations:
            if subject.active_elevations[permission] > datetime.utcnow():
                return True
            else:
                # Expired elevation
                del subject.active_elevations[permission]
        
        return False
    
    def register_subject(self, subject: Subject):
        """Register a subject in the system."""
        self.subjects[subject.id] = subject
        logger.debug("Registered subject: %s", subject.id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current engine statistics."""
        return {
            **self.stats,
            'total_policies': len(self.policies),
            'total_roles': len(self.roles),
            'registered_subjects': len(self.subjects),
            'cache_size': len(self.policy_cache),
            'cache_enabled': self.enable_policy_cache
        }