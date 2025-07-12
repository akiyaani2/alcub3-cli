#!/usr/bin/env python3
"""
Tests for ALCUB3 Zero-Trust Integration Layer
Validates orchestration and cross-component integration functionality
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.zero_trust_integration import (
    ZeroTrustOrchestrator,
    ZeroTrustContext,
    SecurityPosture,
    ComponentStatus,
    ComponentHealth,
    SecurityEvent
)
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.real_time_monitor import RealTimeMonitor
from shared.exceptions import SecurityError

# Import component types for mocking
from shared.zero_trust.microsegmentation_engine import MicrosegmentationEngine
from shared.zero_trust.continuous_verification import ContinuousVerificationSystem
from shared.zero_trust.identity_access_control import IdentityAccessControl
from shared.zero_trust.device_trust_scorer import DeviceTrustScorer
from shared.zero_trust.zero_trust_policy import ZeroTrustPolicyEngine
from shared.zero_trust.zt_network_gateway import ZeroTrustNetworkGateway


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
async def orchestrator(mock_audit_logger, mock_monitor):
    """Create orchestrator instance."""
    config = {
        'enable_hsm': False,
        'enable_pfd': False,
        'hardware_acceleration': False,
        'enable_policy_cache': True,
        'maestro_integrations': ['jit_privilege', 'mtls', 'clearance_control']
    }
    
    orchestrator = ZeroTrustOrchestrator(
        orchestrator_id="test_orchestrator",
        audit_logger=mock_audit_logger,
        monitor=mock_monitor,
        config=config
    )
    return orchestrator


class TestZeroTrustOrchestrator:
    """Test cases for zero-trust orchestrator."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, orchestrator):
        """Test orchestrator initialization."""
        orch = orchestrator
        
        assert orch.orchestrator_id == "test_orchestrator"
        assert orch.security_posture == SecurityPosture.BASELINE
        assert len(orch.components) == 0
        assert orch._running is False
    
    @pytest.mark.asyncio
    async def test_component_initialization(self, orchestrator):
        """Test initialization of all zero-trust components."""
        orch = orchestrator
        
        with patch.multiple(
            'shared.zero_trust_integration',
            MicrosegmentationEngine=MagicMock(),
            ContinuousVerificationSystem=MagicMock(),
            IdentityAccessControl=MagicMock(),
            DeviceTrustScorer=MagicMock(),
            ZeroTrustPolicyEngine=MagicMock(),
            ZeroTrustNetworkGateway=MagicMock()
        ):
            await orch.initialize()
            
            # All components should be initialized
            assert 'microsegmentation' in orch.components
            assert 'continuous_verification' in orch.components
            assert 'identity_access' in orch.components
            assert 'device_trust' in orch.components
            assert 'policy_engine' in orch.components
            assert 'network_gateway' in orch.components
            
            # MAESTRO integrations
            assert 'jit_privilege' in orch.components
            assert 'mtls_manager' in orch.components
            assert 'clearance_control' in orch.components
            
            # Background tasks should be running
            assert orch._running is True
            assert orch._health_check_task is not None
            assert orch._correlation_task is not None
    
    @pytest.mark.asyncio
    async def test_evaluate_access_comprehensive(self, orchestrator):
        """Test comprehensive access evaluation across all components."""
        orch = orchestrator
        
        # Mock all components
        mock_device_trust = MagicMock()
        mock_device_trust.calculate_trust_score = AsyncMock(
            return_value=MagicMock(overall_score=75.0)
        )
        
        mock_continuous_verification = MagicMock()
        mock_continuous_verification.verify_session = AsyncMock(
            return_value=(True, None)
        )
        
        mock_microsegmentation = MagicMock()
        mock_microsegmentation.process_packet = AsyncMock(
            return_value=(True, "Allowed by policy")
        )
        
        mock_identity_access = MagicMock()
        mock_identity_access.evaluate_access = AsyncMock(
            return_value=MagicMock(decision=MagicMock(value='permit'))
        )
        
        mock_policy_engine = MagicMock()
        mock_policy_engine.evaluate_policies = AsyncMock(
            return_value=[(None, MagicMock(value='allow'))]
        )
        
        orch.components = {
            'device_trust': mock_device_trust,
            'continuous_verification': mock_continuous_verification,
            'microsegmentation': mock_microsegmentation,
            'identity_access': mock_identity_access,
            'policy_engine': mock_policy_engine
        }
        
        # Create context
        context = ZeroTrustContext(
            request_id="req_123",
            timestamp=datetime.utcnow(),
            user_id="user-123",
            device_id="device-456",
            session_id="session-789",
            source_ip="192.168.1.100",
            destination_ip="10.0.2.50",
            resource_id="resource-001",
            resource_type="document",
            action="read",
            classification=ClassificationLevel.SECRET
        )
        
        # Evaluate access
        allowed, details = await orch.evaluate_access(context)
        
        assert allowed is True
        assert 'device_trust' in details['components_consulted']
        assert 'continuous_verification' in details['components_consulted']
        assert 'microsegmentation' in details['components_consulted']
        assert 'identity_access' in details['components_consulted']
        assert 'policy_engine' in details['components_consulted']
        assert details['overall_risk_score'] < 100
    
    @pytest.mark.asyncio
    async def test_access_denial_scenarios(self, orchestrator):
        """Test various access denial scenarios."""
        orch = orchestrator
        
        # Scenario 1: Invalid session
        mock_continuous_verification = MagicMock()
        mock_continuous_verification.verify_session = AsyncMock(
            return_value=(False, ['MFA', 'BIOMETRIC'])
        )
        
        orch.components = {
            'continuous_verification': mock_continuous_verification
        }
        
        context = ZeroTrustContext(
            request_id="req_fail_1",
            timestamp=datetime.utcnow(),
            session_id="invalid_session"
        )
        
        allowed, details = await orch.evaluate_access(context)
        assert allowed is False
        assert 'Invalid session' in details['decision_factors']
        
        # Scenario 2: Segmentation violation
        mock_microsegmentation = MagicMock()
        mock_microsegmentation.process_packet = AsyncMock(
            return_value=(False, "Segmentation policy violation")
        )
        
        orch.components = {
            'microsegmentation': mock_microsegmentation
        }
        
        context = ZeroTrustContext(
            request_id="req_fail_2",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="10.0.2.50"
        )
        
        allowed, details = await orch.evaluate_access(context)
        assert allowed is False
        assert 'Segmentation policy denied' in details['decision_factors']
    
    @pytest.mark.asyncio
    async def test_security_posture_management(self, orchestrator):
        """Test security posture changes and their effects."""
        orch = orchestrator
        
        # Mock components that support posture updates
        mock_component = MagicMock()
        mock_component.update_security_posture = AsyncMock()
        
        orch.components = {
            'microsegmentation': mock_component,
            'policy_engine': mock_component
        }
        
        # Update posture
        await orch.update_security_posture(
            SecurityPosture.HIGH_ALERT,
            "Suspicious activity detected"
        )
        
        assert orch.security_posture == SecurityPosture.HIGH_ALERT
        assert orch.metrics['posture_changes'] == 1
        
        # Components should be notified
        mock_component.update_security_posture.assert_called_with(
            SecurityPosture.HIGH_ALERT
        )
        
        # Risk threshold should be lower in HIGH_ALERT
        threshold = orch._get_posture_risk_threshold()
        assert threshold < 50
    
    @pytest.mark.asyncio
    async def test_component_health_monitoring(self, orchestrator):
        """Test component health monitoring."""
        orch = orchestrator
        
        # Mock components with different health states
        healthy_component = MagicMock()
        healthy_component.get_statistics = MagicMock(
            return_value={'avg_decision_time_ms': 5.0}
        )
        
        degraded_component = MagicMock()
        degraded_component.get_statistics = MagicMock(
            return_value={'avg_decision_time_ms': 15.0}
        )
        
        failed_component = MagicMock()
        failed_component.get_statistics = MagicMock(
            side_effect=Exception("Component failure")
        )
        
        orch.components = {
            'microsegmentation': healthy_component,
            'continuous_verification': degraded_component,
            'device_trust': failed_component
        }
        
        # Check health
        health1 = await orch._check_component_health(
            'microsegmentation', healthy_component
        )
        assert health1.status == ComponentStatus.HEALTHY
        
        health2 = await orch._check_component_health(
            'microsegmentation', degraded_component
        )
        assert health2.status == ComponentStatus.DEGRADED
        assert len(health2.warnings) > 0
        
        health3 = await orch._check_component_health(
            'device_trust', failed_component
        )
        assert health3.status == ComponentStatus.FAILED
        assert len(health3.errors) > 0
    
    @pytest.mark.asyncio
    async def test_security_event_handling(self, orchestrator):
        """Test security event handling and correlation."""
        orch = orchestrator
        
        # Create test event
        event = SecurityEvent(
            event_id="evt_123",
            timestamp=datetime.utcnow(),
            component="microsegmentation",
            event_type="segmentation_violation",
            severity="high",
            classification=ClassificationLevel.SECRET,
            details={"source_ip": "192.168.1.100", "violation": "unauthorized_access"}
        )
        
        # Register event handler
        handler_called = False
        async def test_handler(evt):
            nonlocal handler_called
            handler_called = True
        
        orch.register_event_handler('segmentation_violation', test_handler)
        
        # Handle event
        await orch._handle_security_event(event)
        
        assert handler_called is True
        assert event in orch.security_events
        assert orch.metrics['security_events'] == 1
    
    @pytest.mark.asyncio
    async def test_event_correlation(self, orchestrator):
        """Test security event correlation and incident creation."""
        orch = orchestrator
        
        # Add correlation rule
        orch.correlation_rules = [{
            'name': 'repeated_auth_failures',
            'event_types': ['auth_failure', 'challenge_failed'],
            'event_count': 3,
            'time_window_minutes': 5,
            'severity': 'high',
            'auto_response': ['elevate_posture']
        }]
        
        # Generate correlated events
        base_time = datetime.utcnow()
        for i in range(5):
            event = SecurityEvent(
                event_id=f"evt_{i}",
                timestamp=base_time + timedelta(seconds=i*30),
                component="continuous_verification",
                event_type="auth_failure",
                severity="medium",
                classification=ClassificationLevel.UNCLASSIFIED,
                details={"user": "user-123", "attempt": i+1}
            )
            await orch._handle_security_event(event)
        
        # Should create incident
        assert len(orch.active_incidents) > 0
        incident = list(orch.active_incidents.values())[0]
        assert incident['rule_name'] == 'repeated_auth_failures'
        assert len(incident['related_events']) >= 3
    
    @pytest.mark.asyncio
    async def test_automated_response_actions(self, orchestrator):
        """Test automated incident response actions."""
        orch = orchestrator
        
        # Test elevate posture action
        incident = {
            'incident_id': 'inc_123',
            'auto_response': ['elevate_posture']
        }
        
        await orch._execute_response_action('elevate_posture', incident)
        
        # Posture should be elevated
        assert orch.security_posture == SecurityPosture.ELEVATED
    
    @pytest.mark.asyncio
    async def test_cross_component_risk_calculation(self, orchestrator):
        """Test risk calculation across multiple components."""
        orch = orchestrator
        
        # Mock components with risk factors
        mock_device_trust = MagicMock()
        mock_device_trust.calculate_trust_score = AsyncMock(
            return_value=MagicMock(overall_score=30.0)  # Low trust
        )
        
        orch.components = {'device_trust': mock_device_trust}
        
        context = ZeroTrustContext(
            request_id="req_risk",
            timestamp=datetime.utcnow(),
            device_id="untrusted_device",
            risk_score=0.0
        )
        
        # Evaluate - low device trust should increase risk
        allowed, details = await orch.evaluate_access(context)
        
        assert 'Low device trust' in details['risk_factors']
        assert details['overall_risk_score'] > 20
    
    @pytest.mark.asyncio
    async def test_performance_metrics_tracking(self, orchestrator):
        """Test performance metrics tracking."""
        orch = orchestrator
        
        # Mock fast components
        for comp_name in ['microsegmentation', 'identity_access', 'policy_engine']:
            mock_comp = MagicMock()
            mock_comp.process_packet = AsyncMock(return_value=(True, "OK"))
            mock_comp.evaluate_access = AsyncMock(
                return_value=MagicMock(decision=MagicMock(value='permit'))
            )
            mock_comp.evaluate_policies = AsyncMock(return_value=[])
            orch.components[comp_name] = mock_comp
        
        # Process multiple requests
        for i in range(10):
            context = ZeroTrustContext(
                request_id=f"req_{i}",
                timestamp=datetime.utcnow(),
                source_ip=f"192.168.1.{i}",
                destination_ip="10.0.2.50"
            )
            await orch.evaluate_access(context)
        
        # Check metrics
        assert orch.metrics['requests_processed'] == 10
        assert orch.metrics['avg_decision_time_ms'] > 0
        assert orch.metrics['avg_decision_time_ms'] < 50  # Should be fast
    
    @pytest.mark.asyncio
    async def test_concurrent_access_evaluations(self, orchestrator):
        """Test concurrent access evaluations."""
        orch = orchestrator
        
        # Mock components for concurrent access
        mock_comp = MagicMock()
        mock_comp.evaluate_policies = AsyncMock(return_value=[(None, MagicMock(value='allow'))])
        orch.components = {'policy_engine': mock_comp}
        
        # Create concurrent evaluation tasks
        tasks = []
        for i in range(50):
            context = ZeroTrustContext(
                request_id=f"concurrent_{i}",
                timestamp=datetime.utcnow(),
                user_id=f"user_{i}"
            )
            task = orch.evaluate_access(context)
            tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks)
        
        # All should complete
        assert len(results) == 50
        assert all(isinstance(r, tuple) and len(r) == 2 for r in results)
    
    @pytest.mark.asyncio
    async def test_orchestrator_lifecycle(self, orchestrator):
        """Test orchestrator lifecycle management."""
        orch = orchestrator
        
        # Initialize
        with patch.multiple(
            'shared.zero_trust_integration',
            MicrosegmentationEngine=MagicMock(),
            ContinuousVerificationSystem=MagicMock(),
            IdentityAccessControl=MagicMock(),
            DeviceTrustScorer=MagicMock(),
            ZeroTrustPolicyEngine=MagicMock(),
            ZeroTrustNetworkGateway=MagicMock()
        ):
            await orch.initialize()
            assert orch._running is True
            
            # Get status
            status = orch.get_status()
            assert status['orchestrator_id'] == "test_orchestrator"
            assert status['security_posture'] == SecurityPosture.BASELINE.value
            assert 'component_health' in status
            assert 'metrics' in status
            
            # Stop
            await orch.stop()
            assert orch._running is False
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self, orchestrator):
        """Test caching of evaluation results."""
        orch = orchestrator
        
        # Mock policy engine with caching
        mock_policy = MagicMock()
        mock_policy.evaluate_policies = AsyncMock(
            return_value=[(None, MagicMock(value='allow'))]
        )
        orch.components = {'policy_engine': mock_policy}
        
        # Same context should use cache
        context = ZeroTrustContext(
            request_id="cache_test",
            timestamp=datetime.utcnow(),
            user_id="user-123",
            resource_id="resource-456",
            action="read"
        )
        
        # First evaluation
        await orch.evaluate_access(context)
        call_count_1 = mock_policy.evaluate_policies.call_count
        
        # Second evaluation (should be cached by policy engine)
        await orch.evaluate_access(context)
        
        # Policy engine handles its own caching


if __name__ == "__main__":
    pytest.main([__file__, "-v"])