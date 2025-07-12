#!/usr/bin/env python3
"""
Tests for ALCUB3 Identity Access Control (ABAC) Engine
Validates attribute-based access control functionality
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.zero_trust.identity_access_control import (
    IdentityAccessControl,
    Subject,
    Resource,
    Action,
    Environment,
    PolicyRule,
    PolicyDecision,
    AccessResponse,
    AttributeOperator
)
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError


@pytest.fixture
async def mock_audit_logger():
    """Create mock audit logger."""
    logger = Mock(spec=AuditLogger)
    logger.log_event = AsyncMock()
    return logger


@pytest.fixture
async def identity_access_control(mock_audit_logger):
    """Create identity access control instance."""
    iac = IdentityAccessControl(
        audit_logger=mock_audit_logger,
        enable_policy_cache=True
    )
    return iac


class TestIdentityAccessControl:
    """Test cases for identity access control engine."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, identity_access_control):
        """Test engine initialization."""
        iac = identity_access_control
        
        assert iac.enable_policy_cache is True
        assert len(iac.policies) == 0
        assert len(iac.policy_cache) == 0
        assert iac.cache_ttl == 300
    
    @pytest.mark.asyncio
    async def test_create_policy(self, identity_access_control):
        """Test creating ABAC policies."""
        iac = identity_access_control
        
        policy = await iac.create_policy(
            name="Admin Access Policy",
            description="Allow admins to access admin resources",
            subject_conditions=[
                ("role", AttributeOperator.EQUALS, "admin"),
                ("department", AttributeOperator.IN, ["IT", "Security"])
            ],
            resource_conditions=[
                ("type", AttributeOperator.EQUALS, "admin_panel"),
                ("classification", AttributeOperator.LESS_THAN_OR_EQUAL, "SECRET")
            ],
            action_conditions=[
                ("type", AttributeOperator.IN, ["read", "write", "admin"])
            ],
            effect="permit"
        )
        
        assert policy.name == "Admin Access Policy"
        assert policy.effect == PolicyDecision.PERMIT
        assert len(policy.subject_conditions) == 2
        assert len(policy.resource_conditions) == 2
        assert len(policy.action_conditions) == 1
        assert policy.policy_id in iac.policies
    
    @pytest.mark.asyncio
    async def test_evaluate_access_permit(self, identity_access_control):
        """Test access evaluation that should be permitted."""
        iac = identity_access_control
        
        # Create policy
        await iac.create_policy(
            name="User Read Policy",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user"),
                ("active", AttributeOperator.EQUALS, True)
            ],
            resource_conditions=[
                ("type", AttributeOperator.EQUALS, "document"),
                ("public", AttributeOperator.EQUALS, True)
            ],
            action_conditions=[
                ("type", AttributeOperator.EQUALS, "read")
            ],
            effect="permit"
        )
        
        # Create request context
        subject = Subject(
            id="user-123",
            type="user",
            attributes={"active": True}
        )
        
        resource = Resource(
            id="doc-456",
            type="document",
            attributes={"public": True},
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        action = Action(
            id="read",
            type="read"
        )
        
        environment = Environment()
        
        # Evaluate access
        response = await iac.evaluate_access(
            subject, resource, action, environment
        )
        
        assert response.decision == PolicyDecision.PERMIT
        assert response.applicable_policies
        assert response.evaluation_time_ms < 1.0  # Should meet <1ms target
    
    @pytest.mark.asyncio
    async def test_evaluate_access_deny(self, identity_access_control):
        """Test access evaluation that should be denied."""
        iac = identity_access_control
        
        # Create deny policy
        await iac.create_policy(
            name="Deny Inactive Users",
            subject_conditions=[
                ("active", AttributeOperator.EQUALS, False)
            ],
            effect="deny",
            priority=1  # Higher priority
        )
        
        # Create permit policy
        await iac.create_policy(
            name="Allow All Users",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user")
            ],
            effect="permit",
            priority=10
        )
        
        # Create inactive user
        subject = Subject(
            id="user-123",
            type="user",
            attributes={"active": False}
        )
        
        resource = Resource(
            id="doc-456",
            type="document"
        )
        
        action = Action(id="read", type="read")
        environment = Environment()
        
        # Evaluate access - deny should override
        response = await iac.evaluate_access(
            subject, resource, action, environment
        )
        
        assert response.decision == PolicyDecision.DENY
    
    @pytest.mark.asyncio
    async def test_clearance_based_access(self, identity_access_control):
        """Test clearance level based access control."""
        iac = identity_access_control
        
        # Create classification policy
        await iac.create_policy(
            name="Classification Access Control",
            subject_conditions=[
                ("clearance_level", AttributeOperator.GREATER_THAN_OR_EQUAL, "SECRET")
            ],
            resource_conditions=[
                ("classification", AttributeOperator.EQUALS, "SECRET")
            ],
            effect="permit"
        )
        
        # Test with sufficient clearance
        subject_cleared = Subject(
            id="user-123",
            type="user",
            clearance_level="TOP_SECRET",
            attributes={"clearance_level": "TOP_SECRET"}
        )
        
        resource_secret = Resource(
            id="doc-789",
            type="document",
            classification=ClassificationLevel.SECRET,
            attributes={"classification": "SECRET"}
        )
        
        action = Action(id="read", type="read")
        environment = Environment()
        
        response = await iac.evaluate_access(
            subject_cleared, resource_secret, action, environment
        )
        
        assert response.decision == PolicyDecision.PERMIT
        
        # Test with insufficient clearance
        subject_uncleared = Subject(
            id="user-456",
            type="user",
            clearance_level="UNCLASSIFIED",
            attributes={"clearance_level": "UNCLASSIFIED"}
        )
        
        response = await iac.evaluate_access(
            subject_uncleared, resource_secret, action, environment
        )
        
        # Should be denied by default (no applicable permit policy)
        assert response.decision == PolicyDecision.DENY
    
    @pytest.mark.asyncio
    async def test_environment_conditions(self, identity_access_control):
        """Test environment-based access control."""
        iac = identity_access_control
        
        # Create time-based policy
        await iac.create_policy(
            name="Business Hours Only",
            environment_conditions=[
                ("time_of_day", AttributeOperator.BETWEEN, (9, 17)),  # 9 AM - 5 PM
                ("day_of_week", AttributeOperator.IN, ["Mon", "Tue", "Wed", "Thu", "Fri"])
            ],
            effect="permit"
        )
        
        subject = Subject(id="user-123", type="user")
        resource = Resource(id="doc-456", type="document")
        action = Action(id="read", type="read")
        
        # Test during business hours
        environment_business = Environment(
            attributes={
                "time_of_day": 14,  # 2 PM
                "day_of_week": "Wed"
            }
        )
        
        response = await iac.evaluate_access(
            subject, resource, action, environment_business
        )
        
        assert response.decision == PolicyDecision.PERMIT
        
        # Test outside business hours
        environment_weekend = Environment(
            attributes={
                "time_of_day": 14,
                "day_of_week": "Sat"
            }
        )
        
        response = await iac.evaluate_access(
            subject, resource, action, environment_weekend
        )
        
        assert response.decision == PolicyDecision.DENY
    
    @pytest.mark.asyncio
    async def test_complex_attribute_matching(self, identity_access_control):
        """Test complex attribute matching with various operators."""
        iac = identity_access_control
        
        # Create policy with complex conditions
        await iac.create_policy(
            name="Complex Policy",
            subject_conditions=[
                ("age", AttributeOperator.GREATER_THAN, 18),
                ("country", AttributeOperator.NOT_EQUALS, "restricted"),
                ("roles", AttributeOperator.CONTAINS, "developer")
            ],
            resource_conditions=[
                ("size", AttributeOperator.LESS_THAN, 1000000),  # < 1MB
                ("tags", AttributeOperator.CONTAINS_ANY, ["public", "internal"])
            ],
            effect="permit"
        )
        
        # Test matching subject
        subject = Subject(
            id="user-123",
            type="user",
            attributes={
                "age": 25,
                "country": "US",
                "roles": ["developer", "tester"]
            }
        )
        
        resource = Resource(
            id="file-456",
            type="file",
            attributes={
                "size": 500000,
                "tags": ["internal", "project-x"]
            }
        )
        
        action = Action(id="read", type="read")
        environment = Environment()
        
        response = await iac.evaluate_access(
            subject, resource, action, environment
        )
        
        assert response.decision == PolicyDecision.PERMIT
    
    @pytest.mark.asyncio
    async def test_policy_priority(self, identity_access_control):
        """Test policy priority evaluation."""
        iac = identity_access_control
        
        # Create conflicting policies with different priorities
        await iac.create_policy(
            name="General Deny",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user")
            ],
            effect="deny",
            priority=100  # Lower priority
        )
        
        await iac.create_policy(
            name="Specific Permit",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user"),
                ("vip", AttributeOperator.EQUALS, True)
            ],
            effect="permit",
            priority=1  # Higher priority
        )
        
        # Test VIP user
        vip_subject = Subject(
            id="vip-123",
            type="user",
            attributes={"vip": True}
        )
        
        resource = Resource(id="doc-456", type="document")
        action = Action(id="read", type="read")
        environment = Environment()
        
        response = await iac.evaluate_access(
            vip_subject, resource, action, environment
        )
        
        # Higher priority permit should win
        assert response.decision == PolicyDecision.PERMIT
    
    @pytest.mark.asyncio
    async def test_obligation_handling(self, identity_access_control):
        """Test policy obligations."""
        iac = identity_access_control
        
        # Create policy with obligations
        await iac.create_policy(
            name="Audit Required",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user")
            ],
            resource_conditions=[
                ("sensitive", AttributeOperator.EQUALS, True)
            ],
            effect="permit",
            obligations={
                "audit": {"level": "detailed", "retention_days": 90},
                "encrypt": {"algorithm": "AES-256"},
                "notify": {"recipients": ["security@company.com"]}
            }
        )
        
        subject = Subject(id="user-123", type="user")
        resource = Resource(
            id="doc-456",
            type="document",
            attributes={"sensitive": True}
        )
        action = Action(id="read", type="read")
        environment = Environment()
        
        response = await iac.evaluate_access(
            subject, resource, action, environment
        )
        
        assert response.decision == PolicyDecision.PERMIT
        assert "audit" in response.obligations
        assert "encrypt" in response.obligations
        assert response.obligations["audit"]["level"] == "detailed"
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self, identity_access_control):
        """Test policy evaluation caching."""
        iac = identity_access_control
        
        # Create policy
        await iac.create_policy(
            name="Cacheable Policy",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user")
            ],
            effect="permit"
        )
        
        subject = Subject(id="user-123", type="user")
        resource = Resource(id="doc-456", type="document")
        action = Action(id="read", type="read")
        environment = Environment()
        
        # First evaluation - cache miss
        response1 = await iac.evaluate_access(
            subject, resource, action, environment
        )
        
        initial_cache_hits = iac.stats['cache_hits']
        
        # Second identical evaluation - cache hit
        response2 = await iac.evaluate_access(
            subject, resource, action, environment
        )
        
        assert iac.stats['cache_hits'] == initial_cache_hits + 1
        assert response1.decision == response2.decision
    
    @pytest.mark.asyncio
    async def test_dynamic_attributes(self, identity_access_control):
        """Test dynamic attribute evaluation."""
        iac = identity_access_control
        
        # Create policy with dynamic conditions
        await iac.create_policy(
            name="Dynamic Trust Policy",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user")
            ],
            environment_conditions=[
                ("device_trust_score", AttributeOperator.GREATER_THAN, 0.7),
                ("network_zone", AttributeOperator.IN, ["corporate", "vpn"])
            ],
            effect="permit"
        )
        
        subject = Subject(id="user-123", type="user")
        resource = Resource(id="doc-456", type="document")
        action = Action(id="read", type="read")
        
        # Test with high trust score
        env_trusted = Environment(
            device_trust_score=0.85,
            network_zone="corporate",
            attributes={
                "device_trust_score": 0.85,
                "network_zone": "corporate"
            }
        )
        
        response = await iac.evaluate_access(
            subject, resource, action, env_trusted
        )
        
        assert response.decision == PolicyDecision.PERMIT
        
        # Test with low trust score
        env_untrusted = Environment(
            device_trust_score=0.5,
            network_zone="public",
            attributes={
                "device_trust_score": 0.5,
                "network_zone": "public"
            }
        )
        
        response = await iac.evaluate_access(
            subject, resource, action, env_untrusted
        )
        
        assert response.decision == PolicyDecision.DENY
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, identity_access_control):
        """Test performance tracking."""
        iac = identity_access_control
        
        # Create multiple policies
        for i in range(10):
            await iac.create_policy(
                name=f"Policy {i}",
                subject_conditions=[
                    ("department", AttributeOperator.EQUALS, f"dept{i}")
                ],
                effect="permit"
            )
        
        # Perform multiple evaluations
        for i in range(100):
            subject = Subject(
                id=f"user-{i}",
                type="user",
                attributes={"department": f"dept{i % 10}"}
            )
            resource = Resource(id=f"doc-{i}", type="document")
            action = Action(id="read", type="read")
            environment = Environment()
            
            await iac.evaluate_access(subject, resource, action, environment)
        
        stats = iac.get_statistics()
        assert stats['policies_created'] == 10
        assert stats['evaluations_performed'] == 100
        assert stats['avg_evaluation_time_ms'] < 1.0  # Should meet <1ms target
    
    @pytest.mark.asyncio
    async def test_concurrent_evaluations(self, identity_access_control):
        """Test concurrent access evaluations."""
        iac = identity_access_control
        
        # Create policy
        await iac.create_policy(
            name="Concurrent Test Policy",
            subject_conditions=[
                ("type", AttributeOperator.EQUALS, "user")
            ],
            effect="permit"
        )
        
        # Create evaluation tasks
        tasks = []
        for i in range(100):
            subject = Subject(id=f"user-{i}", type="user")
            resource = Resource(id=f"doc-{i}", type="document")
            action = Action(id="read", type="read")
            environment = Environment()
            
            task = iac.evaluate_access(subject, resource, action, environment)
            tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        assert len(results) == 100
        assert all(r.decision == PolicyDecision.PERMIT for r in results)
    
    @pytest.mark.asyncio
    async def test_policy_export_import(self, identity_access_control):
        """Test policy export and import functionality."""
        iac = identity_access_control
        
        # Create policies
        await iac.create_policy(
            name="Export Test Policy",
            subject_conditions=[
                ("role", AttributeOperator.EQUALS, "admin")
            ],
            resource_conditions=[
                ("type", AttributeOperator.EQUALS, "config")
            ],
            effect="permit"
        )
        
        # Export policies
        exported = await iac.export_policies()
        assert len(exported['policies']) == 1
        assert exported['policies'][0]['name'] == "Export Test Policy"
        
        # Clear and re-import
        iac.policies.clear()
        await iac.import_policies(exported)
        
        assert len(iac.policies) == 1
        imported_policy = list(iac.policies.values())[0]
        assert imported_policy.name == "Export Test Policy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])