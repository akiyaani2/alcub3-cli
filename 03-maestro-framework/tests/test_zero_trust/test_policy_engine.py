#!/usr/bin/env python3
"""
Tests for ALCUB3 Zero-Trust Policy Engine
Validates policy management, conflict resolution, and simulation functionality
"""

import pytest
import asyncio
import json
import yaml
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, mock_open

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.zero_trust.zero_trust_policy import (
    ZeroTrustPolicyEngine,
    PolicyType,
    PolicyScope,
    ConflictResolution,
    PolicyAction,
    PolicyCondition,
    PolicyRule,
    PolicySimulationResult,
    PolicyConflict,
    PolicyEvaluator
)
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import PolicyError
from shared.real_time_monitor import RealTimeMonitor


@pytest.fixture
async def mock_audit_logger():
    """Create mock audit logger."""
    logger = Mock(spec=AuditLogger)
    logger.log_event = AsyncMock()
    return logger


@pytest.fixture
async def mock_monitor():
    """Create mock real-time monitor."""
    monitor = Mock(spec=RealTimeMonitor)
    monitor.record_event = AsyncMock()
    monitor.record_metric = AsyncMock()
    return monitor


@pytest.fixture
async def policy_engine(mock_audit_logger, mock_monitor):
    """Create policy engine instance."""
    engine = ZeroTrustPolicyEngine(
        audit_logger=mock_audit_logger,
        monitor=mock_monitor,
        enable_caching=True
    )
    return engine


class TestZeroTrustPolicyEngine:
    """Test cases for zero-trust policy engine."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, policy_engine):
        """Test engine initialization."""
        engine = policy_engine
        
        assert engine.enable_caching is True
        assert len(engine.policies) == 0
        assert engine.conflict_resolution_strategy == ConflictResolution.DENY_OVERRIDES
        assert engine.cache_ttl == 300
    
    @pytest.mark.asyncio
    async def test_create_policy(self, policy_engine):
        """Test creating policies."""
        engine = policy_engine
        
        policy = await engine.create_policy(
            name="Network Access Policy",
            description="Control network access",
            policy_type=PolicyType.NETWORK,
            scope=PolicyScope.GLOBAL,
            conditions=[
                PolicyCondition(
                    field="source_ip",
                    operator="in_subnet",
                    value="10.0.0.0/8"
                ),
                PolicyCondition(
                    field="destination_port",
                    operator="equals",
                    value=443
                )
            ],
            actions=[PolicyAction.ALLOW],
            priority=10
        )
        
        assert policy.name == "Network Access Policy"
        assert policy.policy_type == PolicyType.NETWORK
        assert policy.scope == PolicyScope.GLOBAL
        assert len(policy.conditions) == 2
        assert PolicyAction.ALLOW in policy.actions
        assert policy.policy_id in engine.policies
    
    @pytest.mark.asyncio
    async def test_composite_policy(self, policy_engine):
        """Test creating composite policies."""
        engine = policy_engine
        
        # Create sub-policies
        network_policy = await engine.create_policy(
            name="Network Component",
            policy_type=PolicyType.NETWORK,
            conditions=[
                PolicyCondition(field="protocol", operator="equals", value="https")
            ],
            actions=[PolicyAction.ALLOW]
        )
        
        identity_policy = await engine.create_policy(
            name="Identity Component",
            policy_type=PolicyType.IDENTITY,
            conditions=[
                PolicyCondition(field="role", operator="contains", value="admin")
            ],
            actions=[PolicyAction.REQUIRE_MFA]
        )
        
        # Create composite policy
        composite = await engine.create_policy(
            name="Admin Access Policy",
            policy_type=PolicyType.COMPOSITE,
            sub_policies=[network_policy.policy_id, identity_policy.policy_id],
            combine_logic="all",  # All sub-policies must pass
            actions=[PolicyAction.ALLOW]
        )
        
        assert composite.policy_type == PolicyType.COMPOSITE
        assert len(composite.sub_policies) == 2
        assert composite.combine_logic == "all"
    
    @pytest.mark.asyncio
    async def test_evaluate_policies_simple(self, policy_engine):
        """Test simple policy evaluation."""
        engine = policy_engine
        
        # Create allow policy
        await engine.create_policy(
            name="Allow Internal",
            policy_type=PolicyType.NETWORK,
            conditions=[
                PolicyCondition(
                    field="source_ip",
                    operator="in_subnet",
                    value="192.168.0.0/16"
                )
            ],
            actions=[PolicyAction.ALLOW]
        )
        
        # Create deny policy
        await engine.create_policy(
            name="Deny Blacklisted",
            policy_type=PolicyType.NETWORK,
            conditions=[
                PolicyCondition(
                    field="source_ip",
                    operator="equals",
                    value="192.168.1.100"
                )
            ],
            actions=[PolicyAction.DENY],
            priority=1  # Higher priority
        )
        
        # Test evaluation - should be denied
        context = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "https"
        }
        
        results = await engine.evaluate_policies(context)
        
        assert len(results) > 0
        # Highest priority deny should win
        assert results[0][1] == PolicyAction.DENY
    
    @pytest.mark.asyncio
    async def test_conflict_resolution_strategies(self, policy_engine):
        """Test different conflict resolution strategies."""
        engine = policy_engine
        
        # Create conflicting policies
        await engine.create_policy(
            name="Allow Policy",
            conditions=[
                PolicyCondition(field="user", operator="equals", value="john")
            ],
            actions=[PolicyAction.ALLOW],
            priority=10
        )
        
        await engine.create_policy(
            name="Deny Policy",
            conditions=[
                PolicyCondition(field="user", operator="equals", value="john")
            ],
            actions=[PolicyAction.DENY],
            priority=10  # Same priority
        )
        
        context = {"user": "john"}
        
        # Test DENY_OVERRIDES (default)
        engine.conflict_resolution_strategy = ConflictResolution.DENY_OVERRIDES
        results = await engine.evaluate_policies(context)
        assert results[0][1] == PolicyAction.DENY
        
        # Test PERMIT_OVERRIDES
        engine.conflict_resolution_strategy = ConflictResolution.PERMIT_OVERRIDES
        results = await engine.evaluate_policies(context)
        assert results[0][1] == PolicyAction.ALLOW
        
        # Test MOST_RESTRICTIVE
        engine.conflict_resolution_strategy = ConflictResolution.MOST_RESTRICTIVE
        results = await engine.evaluate_policies(context)
        assert results[0][1] == PolicyAction.DENY
    
    @pytest.mark.asyncio
    async def test_policy_simulation(self, policy_engine):
        """Test policy simulation before deployment."""
        engine = policy_engine
        
        # Create existing policies
        existing_policy = await engine.create_policy(
            name="Existing Allow",
            conditions=[
                PolicyCondition(field="department", operator="equals", value="IT")
            ],
            actions=[PolicyAction.ALLOW]
        )
        
        # Create new policy to simulate
        new_policy = PolicyRule(
            policy_id="sim_policy_1",
            name="New Deny Policy",
            policy_type=PolicyType.IDENTITY,
            conditions=[
                PolicyCondition(field="department", operator="equals", value="IT"),
                PolicyCondition(field="role", operator="equals", value="intern")
            ],
            actions=[PolicyAction.DENY],
            priority=1
        )
        
        # Define test scenarios
        scenarios = [
            {"department": "IT", "role": "admin"},  # Should still be allowed
            {"department": "IT", "role": "intern"},  # Would be denied by new policy
            {"department": "HR", "role": "manager"}  # Not affected
        ]
        
        # Run simulation
        result = await engine.simulate_policy_change(
            new_policies=[new_policy],
            removed_policies=[],
            test_scenarios=scenarios
        )
        
        assert result.total_scenarios == 3
        assert result.affected_scenarios == 1  # Only IT intern affected
        assert len(result.conflicts) >= 0
        assert result.impact_score > 0
    
    @pytest.mark.asyncio
    async def test_time_based_policies(self, policy_engine):
        """Test time-based policy conditions."""
        engine = policy_engine
        
        # Create business hours policy
        await engine.create_policy(
            name="Business Hours Only",
            conditions=[
                PolicyCondition(
                    field="time_of_day",
                    operator="between",
                    value=(9, 17)  # 9 AM - 5 PM
                ),
                PolicyCondition(
                    field="day_of_week",
                    operator="in",
                    value=["Mon", "Tue", "Wed", "Thu", "Fri"]
                )
            ],
            actions=[PolicyAction.ALLOW]
        )
        
        # Test during business hours
        context_business = {
            "time_of_day": 14,  # 2 PM
            "day_of_week": "Wed",
            "user": "john"
        }
        
        results = await engine.evaluate_policies(context_business)
        assert any(action == PolicyAction.ALLOW for _, action in results)
        
        # Test outside business hours
        context_weekend = {
            "time_of_day": 14,
            "day_of_week": "Sat",
            "user": "john"
        }
        
        results = await engine.evaluate_policies(context_weekend)
        # Should not match the business hours policy
        allow_actions = [action for _, action in results if action == PolicyAction.ALLOW]
        assert len(allow_actions) == 0
    
    @pytest.mark.asyncio
    async def test_classification_aware_policies(self, policy_engine):
        """Test classification-aware policies."""
        engine = policy_engine
        
        # Create classification-based policies
        await engine.create_policy(
            name="Secret Data Access",
            policy_type=PolicyType.DATA,
            conditions=[
                PolicyCondition(
                    field="classification",
                    operator="equals",
                    value="SECRET"
                ),
                PolicyCondition(
                    field="clearance_level",
                    operator="greater_than_or_equal",
                    value="SECRET"
                )
            ],
            actions=[PolicyAction.ALLOW, PolicyAction.REQUIRE_ENCRYPTION]
        )
        
        # Test with proper clearance
        context_cleared = {
            "classification": "SECRET",
            "clearance_level": "TOP_SECRET",
            "user": "agent007"
        }
        
        results = await engine.evaluate_policies(context_cleared)
        actions = [action for _, action in results]
        assert PolicyAction.ALLOW in actions
        assert PolicyAction.REQUIRE_ENCRYPTION in actions
        
        # Test with insufficient clearance
        context_uncleared = {
            "classification": "SECRET",
            "clearance_level": "CONFIDENTIAL",
            "user": "intern001"
        }
        
        results = await engine.evaluate_policies(context_uncleared)
        # Should not match due to clearance requirement
        allow_actions = [action for _, action in results if action == PolicyAction.ALLOW]
        assert len(allow_actions) == 0
    
    @pytest.mark.asyncio
    async def test_policy_versioning(self, policy_engine):
        """Test policy versioning and history."""
        engine = policy_engine
        
        # Create initial policy
        policy = await engine.create_policy(
            name="Versioned Policy",
            conditions=[
                PolicyCondition(field="action", operator="equals", value="read")
            ],
            actions=[PolicyAction.ALLOW]
        )
        
        initial_version = policy.version
        
        # Update policy
        updated_policy = await engine.update_policy(
            policy_id=policy.policy_id,
            conditions=[
                PolicyCondition(field="action", operator="equals", value="read"),
                PolicyCondition(field="verified", operator="equals", value=True)
            ]
        )
        
        assert updated_policy.version > initial_version
        assert updated_policy.modified_by is not None
        assert updated_policy.modified_at > policy.created_at
    
    @pytest.mark.asyncio
    async def test_policy_dependencies(self, policy_engine):
        """Test policy dependency management."""
        engine = policy_engine
        
        # Create base policy
        base_policy = await engine.create_policy(
            name="Base Network Policy",
            policy_type=PolicyType.NETWORK,
            conditions=[
                PolicyCondition(field="network_zone", operator="equals", value="internal")
            ],
            actions=[PolicyAction.ALLOW]
        )
        
        # Create dependent policy
        dependent_policy = await engine.create_policy(
            name="Extended Network Policy",
            dependencies=[base_policy.policy_id],
            conditions=[
                PolicyCondition(field="protocol", operator="equals", value="https")
            ],
            actions=[PolicyAction.ALLOW]
        )
        
        # Check dependency tracking
        deps = engine.get_policy_dependencies(dependent_policy.policy_id)
        assert base_policy.policy_id in deps
        
        # Try to remove base policy - should fail
        with pytest.raises(PolicyError):
            await engine.remove_policy(base_policy.policy_id)
    
    @pytest.mark.asyncio
    async def test_bulk_policy_operations(self, policy_engine):
        """Test bulk policy operations."""
        engine = policy_engine
        
        # Create multiple policies in bulk
        policies_data = []
        for i in range(10):
            policies_data.append({
                "name": f"Bulk Policy {i}",
                "conditions": [
                    PolicyCondition(field="group", operator="equals", value=f"group{i}")
                ],
                "actions": [PolicyAction.ALLOW]
            })
        
        created_policies = await engine.bulk_create_policies(policies_data)
        assert len(created_policies) == 10
        
        # Bulk evaluate
        contexts = [{"group": f"group{i}"} for i in range(10)]
        results = await engine.bulk_evaluate_policies(contexts)
        assert len(results) == 10
    
    @pytest.mark.asyncio
    async def test_policy_export_import(self, policy_engine):
        """Test policy export and import."""
        engine = policy_engine
        
        # Create policies
        for i in range(5):
            await engine.create_policy(
                name=f"Export Policy {i}",
                conditions=[
                    PolicyCondition(field="test", operator="equals", value=f"value{i}")
                ],
                actions=[PolicyAction.ALLOW]
            )
        
        # Export to JSON
        exported_json = await engine.export_policies(format="json")
        policies_data = json.loads(exported_json)
        assert len(policies_data["policies"]) == 5
        
        # Clear and re-import
        engine.policies.clear()
        imported_count = await engine.import_policies(exported_json, format="json")
        assert imported_count == 5
        assert len(engine.policies) == 5
    
    @pytest.mark.asyncio
    async def test_policy_performance(self, policy_engine):
        """Test policy evaluation performance."""
        engine = policy_engine
        
        # Create many policies
        for i in range(100):
            await engine.create_policy(
                name=f"Perf Policy {i}",
                conditions=[
                    PolicyCondition(field=f"field{i % 10}", operator="equals", value=f"value{i}")
                ],
                actions=[PolicyAction.ALLOW]
            )
        
        # Evaluate with complex context
        context = {f"field{i}": f"value{i}" for i in range(10)}
        
        # Time evaluation
        import time
        start = time.time()
        results = await engine.evaluate_policies(context)
        duration_ms = (time.time() - start) * 1000
        
        assert duration_ms < 1.0  # Should meet <1ms target
        
        stats = engine.get_statistics()
        assert stats["avg_evaluation_time_ms"] < 1.0
    
    @pytest.mark.asyncio
    async def test_concurrent_policy_operations(self, policy_engine):
        """Test concurrent policy operations."""
        engine = policy_engine
        
        # Create policies concurrently
        create_tasks = []
        for i in range(50):
            task = engine.create_policy(
                name=f"Concurrent Policy {i}",
                conditions=[
                    PolicyCondition(field="id", operator="equals", value=i)
                ],
                actions=[PolicyAction.ALLOW]
            )
            create_tasks.append(task)
        
        created = await asyncio.gather(*create_tasks)
        assert len(created) == 50
        
        # Evaluate concurrently
        eval_tasks = []
        for i in range(50):
            context = {"id": i}
            task = engine.evaluate_policies(context)
            eval_tasks.append(task)
        
        results = await asyncio.gather(*eval_tasks)
        assert len(results) == 50
    
    @pytest.mark.asyncio
    async def test_policy_audit_trail(self, policy_engine, mock_audit_logger):
        """Test policy audit trail."""
        engine = policy_engine
        
        # Create policy
        policy = await engine.create_policy(
            name="Audited Policy",
            conditions=[
                PolicyCondition(field="sensitive", operator="equals", value=True)
            ],
            actions=[PolicyAction.ALLOW, PolicyAction.LOG_ONLY]
        )
        
        # Verify audit log was called
        mock_audit_logger.log_event.assert_called()
        
        # Update policy
        await engine.update_policy(
            policy_id=policy.policy_id,
            actions=[PolicyAction.DENY]
        )
        
        # Remove policy
        await engine.remove_policy(policy.policy_id)
        
        # Check audit trail
        assert mock_audit_logger.log_event.call_count >= 3  # Create, update, remove


if __name__ == "__main__":
    pytest.main([__file__, "-v"])