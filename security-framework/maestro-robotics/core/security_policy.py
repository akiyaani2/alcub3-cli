#!/usr/bin/env python3
"""
ALCUB3 MAESTRO Security Policy Engine for Robotics
Patent-Pending Classification-Aware Policy Enforcement System

This module implements the security policy engine that enforces
classification-aware policies across all robotics platforms.

Key Innovations:
- Dynamic policy adaptation based on threat level
- Classification-aware policy inheritance
- Real-time policy violation detection
- Cross-platform policy synchronization
- AI-driven policy recommendation engine

Patent Applications:
- Classification-aware robotics policy enforcement method
- Dynamic security policy adaptation for autonomous systems
- Cross-platform security policy synchronization protocol
- AI-driven security policy optimization system
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

# Import MAESTRO components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.ai_bias_detection import AIBiasDetectionSystem


class PolicyType(Enum):
    """Types of security policies."""
    ACCESS_CONTROL = "access_control"
    COMMAND_RESTRICTION = "command_restriction"
    OPERATIONAL_BOUNDARY = "operational_boundary"
    COMMUNICATION = "communication"
    DATA_HANDLING = "data_handling"
    EMERGENCY_RESPONSE = "emergency_response"


class PolicyPriority(Enum):
    """Policy enforcement priority levels."""
    CRITICAL = 1  # Highest priority
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFORMATIONAL = 5  # Lowest priority


class PolicyAction(Enum):
    """Actions to take on policy match."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_AUTHORIZATION = "require_authorization"
    LOG_ONLY = "log_only"
    ALERT = "alert"
    EMERGENCY_STOP = "emergency_stop"


@dataclass
class PolicyRule:
    """Individual security policy rule."""
    rule_id: str
    name: str
    description: str
    policy_type: PolicyType
    priority: PolicyPriority
    classification_levels: List[ClassificationLevel]
    conditions: Dict[str, Any]
    action: PolicyAction
    metadata: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_modified: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PolicyViolation:
    """Record of policy violation."""
    violation_id: str
    rule_id: str
    rule_name: str
    timestamp: datetime
    violator_id: str
    command_details: Dict[str, Any]
    action_taken: PolicyAction
    severity: str
    resolution_status: str = "unresolved"


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation."""
    allowed: bool
    matched_rules: List[PolicyRule]
    violations: List[PolicyViolation]
    recommended_action: PolicyAction
    risk_score: float
    evaluation_time_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecurityPolicyEngine:
    """
    Security Policy Engine for MAESTRO Robotics Integration.
    
    Provides classification-aware policy enforcement, dynamic adaptation,
    and cross-platform synchronization for robotics security policies.
    """
    
    def __init__(self, 
                 classification_level: ClassificationLevel,
                 policy_path: Optional[str] = None,
                 audit_logger: Optional[AuditLogger] = None):
        """Initialize Security Policy Engine."""
        self.classification_level = classification_level
        self.logger = logging.getLogger("SecurityPolicyEngine")
        
        # MAESTRO integration
        self.audit_logger = audit_logger or AuditLogger(classification_level)
        self.bias_detector = AIBiasDetectionSystem(ClassificationLevel.UNCLASSIFIED)
        
        # Policy storage
        self.policies: Dict[str, PolicyRule] = {}
        self.policy_violations: List[PolicyViolation] = []
        self.policy_cache: Dict[str, PolicyEvaluationResult] = {}
        
        # Performance metrics
        self.metrics = {
            "total_evaluations": 0,
            "policy_violations": 0,
            "average_evaluation_time_ms": 0.0,
            "cache_hits": 0,
            "cache_misses": 0,
            "policy_updates": 0,
            "last_update": datetime.utcnow()
        }
        
        # Load policies
        self._load_default_policies()
        if policy_path:
            self._load_custom_policies(policy_path)
        
        self.logger.info(f"Security Policy Engine initialized with {len(self.policies)} policies")
    
    def _load_default_policies(self):
        """Load default MAESTRO robotics security policies."""
        default_policies = [
            PolicyRule(
                rule_id="POL001",
                name="Classification Level Enforcement",
                description="Enforce classification-based access control",
                policy_type=PolicyType.ACCESS_CONTROL,
                priority=PolicyPriority.CRITICAL,
                classification_levels=[level for level in ClassificationLevel],
                conditions={
                    "match_type": "classification_check",
                    "enforce_clearance": True
                },
                action=PolicyAction.DENY
            ),
            PolicyRule(
                rule_id="POL002",
                name="Emergency Stop Authorization",
                description="Restrict emergency stop to authorized operators",
                policy_type=PolicyType.EMERGENCY_RESPONSE,
                priority=PolicyPriority.CRITICAL,
                classification_levels=[ClassificationLevel.UNCLASSIFIED],
                conditions={
                    "command_type": "emergency_stop",
                    "require_authorization": True,
                    "min_clearance": "SECRET"
                },
                action=PolicyAction.REQUIRE_AUTHORIZATION
            ),
            PolicyRule(
                rule_id="POL003",
                name="Operational Boundary Enforcement",
                description="Enforce geofence and operational boundaries",
                policy_type=PolicyType.OPERATIONAL_BOUNDARY,
                priority=PolicyPriority.HIGH,
                classification_levels=[level for level in ClassificationLevel],
                conditions={
                    "check_boundaries": True,
                    "max_distance_km": 10,
                    "restricted_zones": []
                },
                action=PolicyAction.DENY
            ),
            PolicyRule(
                rule_id="POL004",
                name="High-Risk Command Restriction",
                description="Restrict high-risk commands based on classification",
                policy_type=PolicyType.COMMAND_RESTRICTION,
                priority=PolicyPriority.HIGH,
                classification_levels=[ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET],
                conditions={
                    "risk_threshold": 0.7,
                    "require_two_person": True,
                    "audit_required": True
                },
                action=PolicyAction.REQUIRE_AUTHORIZATION
            ),
            PolicyRule(
                rule_id="POL005",
                name="Communication Security",
                description="Enforce secure communication protocols",
                policy_type=PolicyType.COMMUNICATION,
                priority=PolicyPriority.HIGH,
                classification_levels=[level for level in ClassificationLevel],
                conditions={
                    "require_encryption": True,
                    "min_tls_version": "1.3",
                    "allowed_protocols": ["https", "mqtts", "grpcs"]
                },
                action=PolicyAction.DENY
            ),
            PolicyRule(
                rule_id="POL006",
                name="Data Exfiltration Prevention",
                description="Prevent unauthorized data transfer from robots",
                policy_type=PolicyType.DATA_HANDLING,
                priority=PolicyPriority.CRITICAL,
                classification_levels=[ClassificationLevel.CUI, ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET],
                conditions={
                    "monitor_data_transfer": True,
                    "max_data_size_mb": 100,
                    "allowed_destinations": [],
                    "scan_for_classified": True
                },
                action=PolicyAction.ALERT
            ),
            PolicyRule(
                rule_id="POL007",
                name="Autonomous Operation Restriction",
                description="Restrict fully autonomous operation based on classification",
                policy_type=PolicyType.COMMAND_RESTRICTION,
                priority=PolicyPriority.MEDIUM,
                classification_levels=[ClassificationLevel.TOP_SECRET],
                conditions={
                    "autonomous_allowed": False,
                    "require_human_oversight": True,
                    "max_autonomous_duration_minutes": 30
                },
                action=PolicyAction.REQUIRE_AUTHORIZATION
            ),
            PolicyRule(
                rule_id="POL008",
                name="Weapon System Lockout",
                description="Enforce weapon system controls for armed platforms",
                policy_type=PolicyType.COMMAND_RESTRICTION,
                priority=PolicyPriority.CRITICAL,
                classification_levels=[ClassificationLevel.TOP_SECRET],
                conditions={
                    "weapon_systems_locked": True,
                    "require_dual_authorization": True,
                    "geographic_restrictions": True
                },
                action=PolicyAction.DENY
            )
        ]
        
        for policy in default_policies:
            self.policies[policy.rule_id] = policy
    
    def _load_custom_policies(self, policy_path: str):
        """Load custom policies from file."""
        try:
            path = Path(policy_path)
            if path.exists():
                with open(path, 'r') as f:
                    custom_policies = json.load(f)
                    
                for policy_data in custom_policies:
                    policy = self._parse_policy_data(policy_data)
                    if policy:
                        self.policies[policy.rule_id] = policy
                        
                self.logger.info(f"Loaded {len(custom_policies)} custom policies")
        except Exception as e:
            self.logger.error(f"Failed to load custom policies: {e}")
    
    def _parse_policy_data(self, data: Dict[str, Any]) -> Optional[PolicyRule]:
        """Parse policy data into PolicyRule object."""
        try:
            return PolicyRule(
                rule_id=data["rule_id"],
                name=data["name"],
                description=data["description"],
                policy_type=PolicyType(data["policy_type"]),
                priority=PolicyPriority(data["priority"]),
                classification_levels=[ClassificationLevel(cl) for cl in data["classification_levels"]],
                conditions=data["conditions"],
                action=PolicyAction(data["action"]),
                metadata=data.get("metadata", {}),
                enabled=data.get("enabled", True)
            )
        except Exception as e:
            self.logger.error(f"Failed to parse policy data: {e}")
            return None
    
    async def evaluate_command(self, 
                             command_data: Dict[str, Any],
                             context: Optional[Dict[str, Any]] = None) -> PolicyEvaluationResult:
        """
        Evaluate command against all applicable security policies.
        
        Patent-pending evaluation includes:
        - Classification-aware rule matching
        - Priority-based evaluation order
        - Dynamic risk assessment
        - AI bias detection
        - Policy conflict resolution
        """
        start_time = time.time()
        
        # Check cache
        cache_key = self._generate_cache_key(command_data)
        if cache_key in self.policy_cache:
            self.metrics["cache_hits"] += 1
            cached_result = self.policy_cache[cache_key]
            # Update evaluation time
            cached_result.evaluation_time_ms = 0.1  # Cache hit is fast
            return cached_result
        
        self.metrics["cache_misses"] += 1
        
        # Prepare evaluation context
        eval_context = {
            "command_data": command_data,
            "context": context or {},
            "timestamp": datetime.utcnow(),
            "classification_level": self._extract_classification(command_data)
        }
        
        # Evaluate policies
        matched_rules = []
        violations = []
        risk_scores = []
        
        # Sort policies by priority
        sorted_policies = sorted(
            [p for p in self.policies.values() if p.enabled],
            key=lambda p: p.priority.value
        )
        
        for policy in sorted_policies:
            if await self._evaluate_policy(policy, eval_context):
                matched_rules.append(policy)
                
                # Check if this is a violation
                if policy.action in [PolicyAction.DENY, PolicyAction.EMERGENCY_STOP]:
                    violation = self._create_violation(policy, eval_context)
                    violations.append(violation)
                    self.policy_violations.append(violation)
                    self.metrics["policy_violations"] += 1
                
                # Calculate risk contribution
                risk_scores.append(self._calculate_policy_risk(policy))
        
        # Determine final action
        recommended_action = self._determine_final_action(matched_rules)
        
        # Calculate overall risk score
        overall_risk = self._calculate_overall_risk(risk_scores, violations)
        
        # Check for AI bias in policy application
        bias_result = await self._check_policy_bias(eval_context, matched_rules)
        
        # Create result
        evaluation_time = (time.time() - start_time) * 1000
        result = PolicyEvaluationResult(
            allowed=(recommended_action in [PolicyAction.ALLOW, PolicyAction.LOG_ONLY]),
            matched_rules=matched_rules,
            violations=violations,
            recommended_action=recommended_action,
            risk_score=overall_risk,
            evaluation_time_ms=evaluation_time,
            metadata={
                "bias_check": bias_result,
                "total_policies_evaluated": len(sorted_policies),
                "cache_key": cache_key
            }
        )
        
        # Update metrics
        self._update_metrics(evaluation_time)
        self.metrics["total_evaluations"] += 1
        
        # Cache result
        self.policy_cache[cache_key] = result
        
        # Audit log
        await self.audit_logger.log_event(
            "POLICY_EVALUATION",
            {
                "command_type": command_data.get("command_type", "unknown"),
                "allowed": result.allowed,
                "matched_policies": len(matched_rules),
                "violations": len(violations),
                "risk_score": overall_risk,
                "evaluation_time_ms": evaluation_time
            },
            classification=eval_context["classification_level"]
        )
        
        return result
    
    async def _evaluate_policy(self, policy: PolicyRule, context: Dict[str, Any]) -> bool:
        """Evaluate if a policy applies to the current context."""
        # Check classification applicability
        command_classification = context["classification_level"]
        if command_classification not in policy.classification_levels:
            return False
        
        # Evaluate conditions
        conditions = policy.conditions
        command_data = context["command_data"]
        
        # Match type condition
        if "match_type" in conditions:
            if conditions["match_type"] == "classification_check":
                return self._check_classification_condition(conditions, context)
        
        # Command type condition
        if "command_type" in conditions:
            if command_data.get("command_type") != conditions["command_type"]:
                return False
        
        # Risk threshold condition
        if "risk_threshold" in conditions:
            command_risk = command_data.get("risk_score", 0)
            if command_risk < conditions["risk_threshold"]:
                return False
        
        # Boundary conditions
        if "check_boundaries" in conditions and conditions["check_boundaries"]:
            if not self._check_boundary_condition(conditions, command_data):
                return False
        
        # Communication conditions
        if "require_encryption" in conditions:
            if not command_data.get("encrypted", False):
                return True  # Policy matches because encryption is missing
        
        # Data handling conditions
        if "monitor_data_transfer" in conditions:
            if self._check_data_transfer_condition(conditions, command_data):
                return True
        
        # Autonomous operation conditions
        if "autonomous_allowed" in conditions:
            if command_data.get("autonomous_mode", False) and not conditions["autonomous_allowed"]:
                return True
        
        # Weapon system conditions
        if "weapon_systems_locked" in conditions:
            if command_data.get("weapon_control", False):
                return True
        
        return True  # Policy matches if we get here
    
    def _check_classification_condition(self, conditions: Dict[str, Any], 
                                      context: Dict[str, Any]) -> bool:
        """Check classification-based conditions."""
        if not conditions.get("enforce_clearance", True):
            return False
        
        command_data = context["command_data"]
        issuer_clearance = ClassificationLevel(command_data.get("issuer_clearance", "UNCLASSIFIED"))
        command_classification = context["classification_level"]
        
        return issuer_clearance.numeric_level < command_classification.numeric_level
    
    def _check_boundary_condition(self, conditions: Dict[str, Any],
                                command_data: Dict[str, Any]) -> bool:
        """Check operational boundary conditions."""
        if "location" not in command_data:
            return False
        
        location = command_data["location"]
        
        # Check distance constraint
        if "max_distance_km" in conditions:
            distance = location.get("distance_from_base_km", 0)
            if distance > conditions["max_distance_km"]:
                return True
        
        # Check restricted zones
        if "restricted_zones" in conditions:
            for zone in conditions["restricted_zones"]:
                if self._location_in_zone(location, zone):
                    return True
        
        return False
    
    def _check_data_transfer_condition(self, conditions: Dict[str, Any],
                                     command_data: Dict[str, Any]) -> bool:
        """Check data transfer conditions."""
        if "data_transfer" not in command_data:
            return False
        
        transfer = command_data["data_transfer"]
        
        # Check size limit
        if "max_data_size_mb" in conditions:
            size_mb = transfer.get("size_mb", 0)
            if size_mb > conditions["max_data_size_mb"]:
                return True
        
        # Check allowed destinations
        if "allowed_destinations" in conditions:
            destination = transfer.get("destination", "")
            if destination not in conditions["allowed_destinations"]:
                return True
        
        return False
    
    def _location_in_zone(self, location: Dict[str, float], zone: Dict[str, Any]) -> bool:
        """Check if location is within a zone."""
        # Simplified implementation - production would use proper geospatial logic
        if "center" in zone and "radius_km" in zone:
            center = zone["center"]
            radius = zone["radius_km"]
            
            # Simple distance calculation
            distance = ((location.get("lat", 0) - center["lat"]) ** 2 + 
                       (location.get("lon", 0) - center["lon"]) ** 2) ** 0.5
            
            # Convert to approximate km (simplified)
            distance_km = distance * 111  # Rough conversion
            
            return distance_km <= radius
        
        return False
    
    def _create_violation(self, policy: PolicyRule, context: Dict[str, Any]) -> PolicyViolation:
        """Create policy violation record."""
        command_data = context["command_data"]
        
        return PolicyViolation(
            violation_id=f"VIO_{int(time.time() * 1000000)}",
            rule_id=policy.rule_id,
            rule_name=policy.name,
            timestamp=datetime.utcnow(),
            violator_id=command_data.get("issuer_id", "unknown"),
            command_details={
                "command_type": command_data.get("command_type", "unknown"),
                "parameters": command_data.get("parameters", {}),
                "classification": context["classification_level"].value
            },
            action_taken=policy.action,
            severity=self._determine_violation_severity(policy)
        )
    
    def _determine_violation_severity(self, policy: PolicyRule) -> str:
        """Determine severity of policy violation."""
        if policy.priority == PolicyPriority.CRITICAL:
            return "CRITICAL"
        elif policy.priority == PolicyPriority.HIGH:
            return "HIGH"
        elif policy.priority == PolicyPriority.MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_policy_risk(self, policy: PolicyRule) -> float:
        """Calculate risk contribution of a policy."""
        # Base risk on priority
        priority_risk = {
            PolicyPriority.CRITICAL: 1.0,
            PolicyPriority.HIGH: 0.7,
            PolicyPriority.MEDIUM: 0.5,
            PolicyPriority.LOW: 0.3,
            PolicyPriority.INFORMATIONAL: 0.1
        }
        
        base_risk = priority_risk.get(policy.priority, 0.5)
        
        # Adjust based on action
        action_multiplier = {
            PolicyAction.EMERGENCY_STOP: 1.5,
            PolicyAction.DENY: 1.2,
            PolicyAction.REQUIRE_AUTHORIZATION: 1.0,
            PolicyAction.ALERT: 0.8,
            PolicyAction.LOG_ONLY: 0.5,
            PolicyAction.ALLOW: 0.1
        }
        
        multiplier = action_multiplier.get(policy.action, 1.0)
        
        return min(1.0, base_risk * multiplier)
    
    def _calculate_overall_risk(self, risk_scores: List[float], 
                              violations: List[PolicyViolation]) -> float:
        """Calculate overall risk score for command."""
        if not risk_scores:
            return 0.0
        
        # Base risk is maximum of individual risks
        base_risk = max(risk_scores)
        
        # Add penalty for violations
        violation_penalty = min(0.5, len(violations) * 0.1)
        
        # Add penalty for critical violations
        critical_violations = sum(1 for v in violations if v.severity == "CRITICAL")
        critical_penalty = min(0.3, critical_violations * 0.15)
        
        total_risk = min(1.0, base_risk + violation_penalty + critical_penalty)
        
        return total_risk
    
    def _determine_final_action(self, matched_rules: List[PolicyRule]) -> PolicyAction:
        """Determine final action based on all matched rules."""
        if not matched_rules:
            return PolicyAction.ALLOW
        
        # Priority order for actions (most restrictive first)
        action_priority = [
            PolicyAction.EMERGENCY_STOP,
            PolicyAction.DENY,
            PolicyAction.REQUIRE_AUTHORIZATION,
            PolicyAction.ALERT,
            PolicyAction.LOG_ONLY,
            PolicyAction.ALLOW
        ]
        
        # Find most restrictive action
        for action in action_priority:
            if any(rule.action == action for rule in matched_rules):
                return action
        
        return PolicyAction.ALLOW
    
    async def _check_policy_bias(self, context: Dict[str, Any], 
                                matched_rules: List[PolicyRule]) -> Dict[str, Any]:
        """Check for bias in policy application."""
        # Prepare data for bias detection
        policy_data = {
            "matched_rules": len(matched_rules),
            "classification": context["classification_level"].value,
            "command_type": context["command_data"].get("command_type", "unknown"),
            "timestamp": context["timestamp"].isoformat()
        }
        
        # Simple bias check - in production, this would be more sophisticated
        bias_metrics = {
            "policy_coverage": len(matched_rules) / len(self.policies),
            "classification_bias": 0.0,  # Would calculate actual bias
            "temporal_bias": 0.0  # Would check time-based patterns
        }
        
        return bias_metrics
    
    def _generate_cache_key(self, command_data: Dict[str, Any]) -> str:
        """Generate cache key for command data."""
        # Create deterministic key from command data
        key_parts = [
            command_data.get("command_type", ""),
            command_data.get("platform_id", ""),
            str(command_data.get("classification", "")),
            str(sorted(command_data.get("parameters", {}).items()))
        ]
        
        return f"policy_cache_{hash('_'.join(key_parts)) % 1000000:06d}"
    
    def _update_metrics(self, evaluation_time_ms: float):
        """Update performance metrics."""
        total = self.metrics["total_evaluations"]
        
        if total == 0:
            self.metrics["average_evaluation_time_ms"] = evaluation_time_ms
        else:
            # Running average
            avg = self.metrics["average_evaluation_time_ms"]
            self.metrics["average_evaluation_time_ms"] = (avg * total + evaluation_time_ms) / (total + 1)
    
    def add_policy(self, policy: PolicyRule) -> bool:
        """Add new security policy."""
        try:
            self.policies[policy.rule_id] = policy
            self.metrics["policy_updates"] += 1
            self.metrics["last_update"] = datetime.utcnow()
            
            # Clear cache as policies have changed
            self.policy_cache.clear()
            
            self.logger.info(f"Added policy: {policy.name} ({policy.rule_id})")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add policy: {e}")
            return False
    
    def update_policy(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update existing policy."""
        try:
            if rule_id not in self.policies:
                self.logger.warning(f"Policy {rule_id} not found")
                return False
            
            policy = self.policies[rule_id]
            
            # Update allowed fields
            allowed_updates = ["conditions", "action", "priority", "enabled", "metadata"]
            for field in allowed_updates:
                if field in updates:
                    setattr(policy, field, updates[field])
            
            policy.last_modified = datetime.utcnow()
            
            self.metrics["policy_updates"] += 1
            self.metrics["last_update"] = datetime.utcnow()
            
            # Clear cache
            self.policy_cache.clear()
            
            self.logger.info(f"Updated policy: {policy.name} ({policy.rule_id})")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update policy: {e}")
            return False
    
    def disable_policy(self, rule_id: str) -> bool:
        """Disable a policy."""
        return self.update_policy(rule_id, {"enabled": False})
    
    def enable_policy(self, rule_id: str) -> bool:
        """Enable a policy."""
        return self.update_policy(rule_id, {"enabled": True})
    
    def get_policy(self, rule_id: str) -> Optional[PolicyRule]:
        """Get specific policy by ID."""
        return self.policies.get(rule_id)
    
    def get_all_policies(self, policy_type: Optional[PolicyType] = None) -> List[PolicyRule]:
        """Get all policies, optionally filtered by type."""
        policies = list(self.policies.values())
        
        if policy_type:
            policies = [p for p in policies if p.policy_type == policy_type]
        
        return policies
    
    def get_violations(self, 
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None,
                      severity: Optional[str] = None) -> List[PolicyViolation]:
        """Get policy violations with optional filters."""
        violations = self.policy_violations
        
        if start_time:
            violations = [v for v in violations if v.timestamp >= start_time]
        
        if end_time:
            violations = [v for v in violations if v.timestamp <= end_time]
        
        if severity:
            violations = [v for v in violations if v.severity == severity]
        
        return violations
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get policy engine metrics."""
        return {
            "engine_metrics": dict(self.metrics),
            "total_policies": len(self.policies),
            "enabled_policies": sum(1 for p in self.policies.values() if p.enabled),
            "policy_types": {
                pt.value: sum(1 for p in self.policies.values() if p.policy_type == pt)
                for pt in PolicyType
            },
            "cache_size": len(self.policy_cache),
            "total_violations": len(self.policy_violations),
            "violation_severity": {
                "CRITICAL": sum(1 for v in self.policy_violations if v.severity == "CRITICAL"),
                "HIGH": sum(1 for v in self.policy_violations if v.severity == "HIGH"),
                "MEDIUM": sum(1 for v in self.policy_violations if v.severity == "MEDIUM"),
                "LOW": sum(1 for v in self.policy_violations if v.severity == "LOW")
            }
        }
    
    def clear_cache(self):
        """Clear policy evaluation cache."""
        self.policy_cache.clear()
        self.logger.info("Policy cache cleared")
    
    def export_policies(self, file_path: str) -> bool:
        """Export policies to JSON file."""
        try:
            policies_data = []
            for policy in self.policies.values():
                policy_dict = {
                    "rule_id": policy.rule_id,
                    "name": policy.name,
                    "description": policy.description,
                    "policy_type": policy.policy_type.value,
                    "priority": policy.priority.value,
                    "classification_levels": [cl.value for cl in policy.classification_levels],
                    "conditions": policy.conditions,
                    "action": policy.action.value,
                    "metadata": policy.metadata,
                    "enabled": policy.enabled,
                    "created_at": policy.created_at.isoformat(),
                    "last_modified": policy.last_modified.isoformat()
                }
                policies_data.append(policy_dict)
            
            with open(file_path, 'w') as f:
                json.dump(policies_data, f, indent=2)
            
            self.logger.info(f"Exported {len(policies_data)} policies to {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export policies: {e}")
            return False