#!/usr/bin/env python3
"""
Comprehensive Test Suite for JIT Privilege Escalation System
Tests all components including behavioral analysis, risk scoring, and integrations
"""

import unittest
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import sys
from pathlib import Path

# Add the security framework to Python path
sys.path.append(str(Path(__file__).parent.parent / 'src'))

from jit_privilege_engine import (
    JITPrivilegeEngine,
    PrivilegeRequest,
    BehavioralAnalyzer,
    RiskScoringEngine,
    SessionMonitor,
    AnomalyDetector,
    ApprovalOrchestrator,
    RequestStatus,
    RiskLevel,
    AnomalySeverity,
    BehaviorScore,
    RiskScore,
    PrivilegedSession,
    ApprovalRequirements,
    SessionAnomaly
)

from jit_cisa_integration import (
    JITCISAIntegration,
    JITMAESTROIntegration
)


class TestBehavioralAnalyzer(unittest.TestCase):
    """Test the behavioral analysis component"""
    
    def setUp(self):
        self.analyzer = BehavioralAnalyzer()
        self.test_user_id = "test_user_123"
    
    async def async_test_normal_behavior_analysis(self):
        """Test analysis of normal user behavior"""
        # Simulate normal behavior history
        for i in range(10):
            self.analyzer.record_session(self.test_user_id, {
                "session_id": f"session_{i}",
                "role": "operator",
                "duration": 30,
                "resources": ["/var/log", "/etc/config"],
                "hour": 14,  # 2 PM - business hours
                "violation": False
            })
        
        # Analyze behavior
        context = {
            "failed_auth_count": 0,
            "source_ip": "192.168.1.100"
        }
        
        behavior_score = await self.analyzer.analyze(self.test_user_id, context)
        
        # Assertions
        self.assertGreater(behavior_score.normal_behavior_probability, 0.7)
        self.assertLess(len(behavior_score.anomaly_indicators), 2)
        self.assertGreater(behavior_score.trust_level, 0.5)
        self.assertIn("avg_session_duration", behavior_score.historical_patterns)
    
    def test_normal_behavior_analysis(self):
        """Test wrapper for async normal behavior analysis"""
        asyncio.run(self.async_test_normal_behavior_analysis())
    
    async def async_test_anomalous_behavior_detection(self):
        """Test detection of anomalous behavior"""
        # Normal history
        for i in range(5):
            self.analyzer.record_session(self.test_user_id, {
                "hour": 10,  # Normal hours
                "violation": False
            })
        
        # Analyze with anomalous context
        context = {
            "failed_auth_count": 5,  # Multiple failed attempts
            "source_ip": "10.0.0.1"  # Different subnet
        }
        
        # Set current time to after hours
        with patch('jit_privilege_engine.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = datetime(2024, 1, 1, 23, 0)  # 11 PM
            
            behavior_score = await self.analyzer.analyze(self.test_user_id, context)
        
        # Assertions
        self.assertLess(behavior_score.normal_behavior_probability, 0.5)
        self.assertIn("after_hours_access", behavior_score.anomaly_indicators)
        self.assertIn("multiple_failed_auths", behavior_score.anomaly_indicators)
        self.assertGreater(behavior_score.risk_factors["auth_anomaly"], 0.5)
    
    def test_anomalous_behavior_detection(self):
        """Test wrapper for async anomalous behavior detection"""
        asyncio.run(self.async_test_anomalous_behavior_detection())
    
    def test_new_user_behavior(self):
        """Test behavior analysis for new users"""
        asyncio.run(self._test_new_user_behavior())
    
    async def _test_new_user_behavior(self):
        new_user_id = "new_user_456"
        behavior_score = await self.analyzer.analyze(new_user_id)
        
        # New users should have neutral trust
        self.assertEqual(behavior_score.trust_level, 0.5)
        self.assertEqual(len(behavior_score.historical_patterns), 0)
        self.assertEqual(behavior_score.normal_behavior_probability, 1.0)


class TestRiskScoringEngine(unittest.TestCase):
    """Test the risk scoring component"""
    
    def setUp(self):
        self.scorer = RiskScoringEngine()
        self.base_request = PrivilegeRequest(
            request_id=str(uuid.uuid4()),
            user_id="test_user",
            requested_role="operator",
            requested_permissions=["read", "write"],
            duration_minutes=30,
            justification="Routine maintenance",
            classification_level="UNCLASSIFIED",
            target_resources=["/var/log"],
            request_time=datetime.utcnow(),
            mfa_verified=True
        )
        
        self.normal_behavior = BehaviorScore(
            user_id="test_user",
            normal_behavior_probability=0.9,
            anomaly_indicators=[],
            risk_factors={},
            trust_level=0.8,
            historical_patterns={
                "common_resources": ["/var/log"],
                "typical_roles": ["operator"]
            },
            last_analysis=datetime.utcnow()
        )
    
    async def async_test_low_risk_scoring(self):
        """Test scoring for low-risk requests"""
        # Normal request during business hours
        with patch('jit_privilege_engine.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = datetime(2024, 1, 1, 14, 0)  # 2 PM
            self.base_request.request_time = mock_datetime.utcnow()
            
            risk_score = await self.scorer.calculate(
                self.base_request,
                self.normal_behavior,
                {"current_classification": "UNCLASSIFIED"}
            )
        
        # Assertions
        self.assertLess(risk_score.value, 30)
        self.assertEqual(risk_score.risk_level, RiskLevel.LOW)
        self.assertTrue(risk_score.auto_approve_eligible)
        self.assertEqual(len(risk_score.required_approvers), 0)
    
    def test_low_risk_scoring(self):
        """Test wrapper for async low risk scoring"""
        asyncio.run(self.async_test_low_risk_scoring())
    
    async def async_test_high_risk_scoring(self):
        """Test scoring for high-risk requests"""
        # High privilege request at unusual time
        high_risk_request = PrivilegeRequest(
            request_id=str(uuid.uuid4()),
            user_id="test_user",
            requested_role="admin",  # High privilege
            requested_permissions=["all"],
            duration_minutes=480,  # 8 hours - unusually long
            justification="Need full access",
            classification_level="TOP_SECRET",  # High classification
            target_resources=["/etc/passwd", "/etc/shadow"],  # Sensitive resources
            request_time=datetime(2024, 1, 1, 3, 0),  # 3 AM
            mfa_verified=False
        )
        
        # Anomalous behavior
        anomalous_behavior = BehaviorScore(
            user_id="test_user",
            normal_behavior_probability=0.3,
            anomaly_indicators=["unusual_location", "rapid_escalation"],
            risk_factors={"location_anomaly": 0.7},
            trust_level=0.3,
            historical_patterns={},
            last_analysis=datetime.utcnow()
        )
        
        context = {
            "current_classification": "UNCLASSIFIED",
            "failed_auth_count": 3
        }
        
        risk_score = await self.scorer.calculate(
            high_risk_request,
            anomalous_behavior,
            context
        )
        
        # Assertions
        self.assertGreater(risk_score.value, 60)
        self.assertIn(risk_score.risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertFalse(risk_score.auto_approve_eligible)
        self.assertIn("security_team", risk_score.required_approvers)
        self.assertIn("classification_authority", risk_score.required_approvers)
    
    def test_high_risk_scoring(self):
        """Test wrapper for async high risk scoring"""
        asyncio.run(self.async_test_high_risk_scoring())
    
    def test_emergency_request_handling(self):
        """Test emergency request risk adjustment"""
        asyncio.run(self._test_emergency_request())
    
    async def _test_emergency_request(self):
        emergency_request = self.base_request
        emergency_request.justification = "EMERGENCY: Production system down"
        
        risk_score = await self.scorer.calculate(
            emergency_request,
            self.normal_behavior,
            {}
        )
        
        # Emergency requests should have adjusted recommendations
        self.assertIn("emergency", risk_score.recommendation.lower())


class TestSessionMonitor(unittest.TestCase):
    """Test the session monitoring component"""
    
    def setUp(self):
        self.monitor = SessionMonitor()
        self.test_request = PrivilegeRequest(
            request_id=str(uuid.uuid4()),
            user_id="test_user",
            requested_role="admin",
            requested_permissions=["all"],
            duration_minutes=30,
            justification="Testing",
            classification_level="SECRET",
            target_resources=[],
            request_time=datetime.utcnow()
        )
        
        self.test_risk_score = RiskScore(
            value=25.0,
            factors={},
            recommendation="Approve",
            auto_approve_eligible=True,
            required_approvers=[],
            risk_level=RiskLevel.LOW
        )
    
    async def async_test_session_creation(self):
        """Test creating a privileged session"""
        session = await self.monitor.create_session(self.test_request, self.test_risk_score)
        
        # Assertions
        self.assertIsNotNone(session.session_id)
        self.assertEqual(session.user_id, self.test_request.user_id)
        self.assertEqual(session.granted_role, self.test_request.requested_role)
        self.assertTrue(session.is_active)
        self.assertIsNotNone(session.session_token)
        self.assertEqual(session.classification_level, "SECRET")
        
        # Check session is tracked
        active_sessions = self.monitor.get_active_sessions()
        self.assertEqual(len(active_sessions), 1)
        self.assertEqual(active_sessions[0].session_id, session.session_id)
    
    def test_session_creation(self):
        """Test wrapper for async session creation"""
        asyncio.run(self.async_test_session_creation())
    
    async def async_test_session_expiration(self):
        """Test automatic session expiration"""
        # Create session with very short duration
        short_request = self.test_request
        short_request.duration_minutes = 0.01  # ~0.6 seconds
        
        session = await self.monitor.create_session(short_request, self.test_risk_score)
        
        # Wait for expiration
        await asyncio.sleep(1)
        
        # Session should be revoked
        active_sessions = self.monitor.get_active_sessions()
        self.assertEqual(len(active_sessions), 0)
        
        # Check session history
        self.assertGreater(len(self.monitor.session_history), 0)
    
    def test_session_expiration(self):
        """Test wrapper for async session expiration"""
        asyncio.run(self.async_test_session_expiration())
    
    async def async_test_session_revocation(self):
        """Test manual session revocation"""
        session = await self.monitor.create_session(self.test_request, self.test_risk_score)
        
        # Revoke session
        await self.monitor.revoke_session(session.session_id, "Testing revocation")
        
        # Assertions
        active_sessions = self.monitor.get_active_sessions()
        self.assertEqual(len(active_sessions), 0)
        
        # Check revocation was recorded
        history = list(self.monitor.session_history)
        self.assertEqual(history[0]["revocation_reason"], "Testing revocation")
        self.assertFalse(history[0]["is_active"])
    
    def test_session_revocation(self):
        """Test wrapper for async session revocation"""
        asyncio.run(self.async_test_session_revocation())
    
    def test_session_token_validation(self):
        """Test session token validation"""
        asyncio.run(self._test_token_validation())
    
    async def _test_token_validation(self):
        session = await self.monitor.create_session(self.test_request, self.test_risk_score)
        
        # Valid token
        self.assertTrue(
            self.monitor.validate_session_token(session.session_id, session.session_token)
        )
        
        # Invalid token
        self.assertFalse(
            self.monitor.validate_session_token(session.session_id, "invalid_token")
        )
        
        # Non-existent session
        self.assertFalse(
            self.monitor.validate_session_token("fake_session_id", session.session_token)
        )


class TestAnomalyDetector(unittest.TestCase):
    """Test the anomaly detection component"""
    
    def setUp(self):
        self.detector = AnomalyDetector()
        self.test_session = PrivilegedSession(
            session_id="test_session",
            user_id="test_user",
            granted_role="admin",
            granted_permissions=["all"],
            start_time=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            classification_level="SECRET",
            risk_score=30.0,
            monitoring_data={}
        )
    
    async def async_test_rapid_command_detection(self):
        """Test detection of rapid command execution"""
        # Simulate rapid commands
        self.test_session.monitoring_data["command_rate"] = 100  # Commands per minute
        
        anomalies = await self.detector.detect_session_anomalies(self.test_session)
        
        # Assertions
        self.assertGreater(len(anomalies), 0)
        rapid_anomaly = next((a for a in anomalies if a.anomaly_type == "rapid_command_execution"), None)
        self.assertIsNotNone(rapid_anomaly)
        self.assertEqual(rapid_anomaly.severity, AnomalySeverity.HIGH)
    
    def test_rapid_command_detection(self):
        """Test wrapper for async rapid command detection"""
        asyncio.run(self.async_test_rapid_command_detection())
    
    async def async_test_classification_boundary_detection(self):
        """Test detection of classification boundary violations"""
        # Simulate classification access attempts
        self.test_session.monitoring_data["classification_access_attempts"] = [
            {
                "target": "TOP_SECRET_resource",
                "denied": True,
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
        
        anomalies = await self.detector.detect_session_anomalies(self.test_session)
        
        # Assertions
        boundary_anomaly = next(
            (a for a in anomalies if a.anomaly_type == "classification_boundary_probe"),
            None
        )
        self.assertIsNotNone(boundary_anomaly)
        self.assertEqual(boundary_anomaly.severity, AnomalySeverity.CRITICAL)
        self.assertIn("classification_violation", boundary_anomaly.indicators)
    
    def test_classification_boundary_detection(self):
        """Test wrapper for async classification boundary detection"""
        asyncio.run(self.async_test_classification_boundary_detection())


class TestApprovalOrchestrator(unittest.TestCase):
    """Test the approval workflow component"""
    
    def setUp(self):
        self.orchestrator = ApprovalOrchestrator()
        self.test_request = PrivilegeRequest(
            request_id=str(uuid.uuid4()),
            user_id="test_user",
            requested_role="admin",
            requested_permissions=["all"],
            duration_minutes=60,
            justification="Testing approval workflow",
            classification_level="SECRET",
            target_resources=[],
            request_time=datetime.utcnow()
        )
        
        self.test_requirements = ApprovalRequirements(
            auto_approve=False,
            required_approvers=["supervisor", "security_team"],
            approval_timeout_minutes=30,
            require_mfa=True,
            require_justification_review=True,
            minimum_approvals=2
        )
    
    async def async_test_approval_initiation(self):
        """Test initiating an approval workflow"""
        result = await self.orchestrator.initiate_approval(
            self.test_request,
            self.test_requirements
        )
        
        # Assertions
        self.assertIn("approval_id", result)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["approvers_notified"], self.test_requirements.required_approvers)
        self.assertIn("expires_at", result)
        
        # Check pending approvals
        self.assertEqual(len(self.orchestrator.pending_approvals), 1)
    
    def test_approval_initiation(self):
        """Test wrapper for async approval initiation"""
        asyncio.run(self.async_test_approval_initiation())
    
    async def async_test_approval_processing(self):
        """Test processing approval responses"""
        # Initiate approval
        init_result = await self.orchestrator.initiate_approval(
            self.test_request,
            self.test_requirements
        )
        
        approval_id = init_result["approval_id"]
        
        # First approval
        result1 = await self.orchestrator.process_approval_response(
            approval_id,
            "supervisor",
            True,
            "Looks good"
        )
        
        self.assertEqual(result1["status"], "pending")
        self.assertEqual(result1["approvals_received"], 1)
        
        # Second approval (meets minimum)
        result2 = await self.orchestrator.process_approval_response(
            approval_id,
            "security_team",
            True,
            "Security verified"
        )
        
        self.assertEqual(result2["status"], "approved")
        
        # Check approval moved to history
        self.assertEqual(len(self.orchestrator.pending_approvals), 0)
        self.assertGreater(len(self.orchestrator.approval_history), 0)
    
    def test_approval_processing(self):
        """Test wrapper for async approval processing"""
        asyncio.run(self.async_test_approval_processing())
    
    async def async_test_approval_denial(self):
        """Test denial in approval workflow"""
        # Initiate approval
        init_result = await self.orchestrator.initiate_approval(
            self.test_request,
            self.test_requirements
        )
        
        approval_id = init_result["approval_id"]
        
        # Denial
        result = await self.orchestrator.process_approval_response(
            approval_id,
            "security_team",
            False,
            "Security concerns"
        )
        
        self.assertEqual(result["status"], "denied")
    
    def test_approval_denial(self):
        """Test wrapper for async approval denial"""
        asyncio.run(self.async_test_approval_denial())


class TestJITPrivilegeEngine(unittest.TestCase):
    """Test the main JIT privilege engine"""
    
    def setUp(self):
        self.engine = JITPrivilegeEngine("SECRET")
        self.test_request = PrivilegeRequest(
            request_id=str(uuid.uuid4()),
            user_id="test_user",
            requested_role="operator",
            requested_permissions=["read"],
            duration_minutes=30,
            justification="Routine maintenance task",
            classification_level="SECRET",
            target_resources=["/var/log"],
            request_time=datetime.utcnow(),
            mfa_verified=True
        )
    
    @patch('jit_privilege_engine.MAESTROClient')
    async def async_test_successful_auto_approval(self, mock_maestro):
        """Test successful auto-approval flow"""
        # Mock MAESTRO validation
        mock_maestro_instance = mock_maestro.return_value
        mock_maestro_instance.validate_security = AsyncMock(
            return_value={"is_valid": True, "threat_level": "LOW"}
        )
        
        self.engine.maestro_client = mock_maestro_instance
        
        # Process request
        result = await self.engine.request_privilege(self.test_request, {
            "current_classification": "SECRET",
            "failed_auth_count": 0
        })
        
        # Assertions
        self.assertEqual(result["status"], RequestStatus.APPROVED.value)
        self.assertIn("session_id", result)
        self.assertIn("session_token", result)
        self.assertIn("expires_at", result)
        self.assertEqual(result["granted_role"], "operator")
        
        # Check statistics
        stats = self.engine.get_statistics()
        self.assertEqual(stats["total_requests"], 1)
        self.assertEqual(stats["auto_approved"], 1)
    
    def test_successful_auto_approval(self):
        """Test wrapper for async successful auto-approval"""
        asyncio.run(self.async_test_successful_auto_approval())
    
    @patch('jit_privilege_engine.MAESTROClient')
    async def async_test_manual_approval_required(self, mock_maestro):
        """Test flow requiring manual approval"""
        # Mock MAESTRO validation
        mock_maestro_instance = mock_maestro.return_value
        mock_maestro_instance.validate_security = AsyncMock(
            return_value={"is_valid": True, "threat_level": "HIGH"}
        )
        
        self.engine.maestro_client = mock_maestro_instance
        
        # High-risk request
        high_risk_request = self.test_request
        high_risk_request.requested_role = "admin"
        high_risk_request.classification_level = "TOP_SECRET"
        
        # Process request
        result = await self.engine.request_privilege(high_risk_request, {
            "current_classification": "SECRET",
            "failed_auth_count": 2
        })
        
        # Assertions
        self.assertEqual(result["status"], "pending")
        self.assertIn("approval_id", result)
        self.assertIn("approvers_notified", result)
        self.assertGreater(len(result["approvers_notified"]), 0)
    
    def test_manual_approval_required(self):
        """Test wrapper for async manual approval required"""
        asyncio.run(self.async_test_manual_approval_required())
    
    @patch('jit_privilege_engine.MAESTROClient')
    async def async_test_maestro_denial(self, mock_maestro):
        """Test MAESTRO security denial"""
        # Mock MAESTRO validation failure
        mock_maestro_instance = mock_maestro.return_value
        mock_maestro_instance.validate_security = AsyncMock(
            return_value={"is_valid": False, "threat_level": "CRITICAL"}
        )
        
        self.engine.maestro_client = mock_maestro_instance
        
        # Process request
        result = await self.engine.request_privilege(self.test_request)
        
        # Assertions
        self.assertEqual(result["status"], RequestStatus.DENIED.value)
        self.assertIn("MAESTRO", result["reason"])
        
        # Check statistics
        stats = self.engine.get_statistics()
        self.assertEqual(stats["denied"], 1)
    
    def test_maestro_denial(self):
        """Test wrapper for async MAESTRO denial"""
        asyncio.run(self.async_test_maestro_denial())
    
    def test_session_management(self):
        """Test session management functionality"""
        asyncio.run(self._test_session_management())
    
    @patch('jit_privilege_engine.MAESTROClient')
    async def _test_session_management(self, mock_maestro):
        # Mock MAESTRO
        mock_maestro_instance = mock_maestro.return_value
        mock_maestro_instance.validate_security = AsyncMock(
            return_value={"is_valid": True, "threat_level": "LOW"}
        )
        self.engine.maestro_client = mock_maestro_instance
        
        # Create session
        result = await self.engine.request_privilege(self.test_request)
        session_id = result["session_id"]
        
        # Get session status
        status = await self.engine.get_session_status(session_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["session_id"], session_id)
        self.assertTrue(status["is_active"])
        
        # Get active sessions
        sessions = self.engine.get_active_sessions()
        self.assertEqual(len(sessions), 1)
        
        # Revoke session
        revoke_result = await self.engine.revoke_privilege(session_id, "Testing")
        self.assertEqual(revoke_result["status"], "revoked")
        
        # Verify revoked
        sessions_after = self.engine.get_active_sessions()
        self.assertEqual(len(sessions_after), 0)


class TestJITCISAIntegration(unittest.TestCase):
    """Test JIT-CISA integration"""
    
    def setUp(self):
        self.integration = JITCISAIntegration("SECRET")
    
    def test_cisa_policy_creation(self):
        """Test creating JIT policies from CISA findings"""
        asyncio.run(self._test_policy_creation())
    
    async def _test_policy_creation(self):
        # Mock CISA scan result
        from cisa_remediation_engine import ScanResult, ThreatLevel
        
        mock_result = ScanResult(
            misconfiguration_id="CISA-02",
            title="Improper Privilege Separation",
            severity=ThreatLevel.HIGH,
            is_compliant=False,
            findings=["Too many admin users"],
            remediation_steps=[],
            evidence={"excessive_admins": True},
            scan_time_ms=10.0,
            classification_level="SECRET"
        )
        
        # Process finding
        policy = await self.integration._handle_privilege_separation_finding(mock_result)
        
        # Assertions
        self.assertIsNotNone(policy)
        self.assertEqual(policy["type"], "enforce_jit")
        self.assertTrue(policy["restrictions"]["no_standing_privileges"])
        self.assertIn("admin", policy["affected_roles"])
    
    def test_maestro_integration(self):
        """Test JIT-MAESTRO integration"""
        asyncio.run(self._test_maestro_integration())
    
    async def _test_maestro_integration(self):
        jit_engine = JITPrivilegeEngine()
        maestro_integration = JITMAESTROIntegration(jit_engine)
        
        test_request = PrivilegeRequest(
            request_id=str(uuid.uuid4()),
            user_id="test_user",
            requested_role="admin",
            requested_permissions=["all"],
            duration_minutes=60,
            justification="Testing",
            classification_level="SECRET",
            target_resources=[],
            request_time=datetime.utcnow()
        )
        
        # Validate with MAESTRO
        validation = await maestro_integration.validate_privilege_request_with_maestro(test_request)
        
        # Assertions
        self.assertIn("valid", validation)
        self.assertIn("aggregate_risk", validation)
        self.assertIn("layer_results", validation)
        self.assertEqual(len(validation["layer_results"]), 7)  # All 7 MAESTRO layers


class TestPerformanceAndReliability(unittest.TestCase):
    """Test performance targets and reliability"""
    
    def setUp(self):
        self.engine = JITPrivilegeEngine()
    
    def test_request_processing_performance(self):
        """Test request processing meets performance targets"""
        asyncio.run(self._test_performance())
    
    @patch('jit_privilege_engine.MAESTROClient')
    async def _test_performance(self, mock_maestro):
        import time
        
        # Mock fast MAESTRO response
        mock_maestro_instance = mock_maestro.return_value
        mock_maestro_instance.validate_security = AsyncMock(
            return_value={"is_valid": True, "threat_level": "LOW"}
        )
        self.engine.maestro_client = mock_maestro_instance
        
        request = PrivilegeRequest(
            request_id=str(uuid.uuid4()),
            user_id="perf_test_user",
            requested_role="operator",
            requested_permissions=["read"],
            duration_minutes=15,
            justification="Performance testing",
            classification_level="UNCLASSIFIED",
            target_resources=[],
            request_time=datetime.utcnow(),
            mfa_verified=True
        )
        
        # Measure processing time
        start_time = time.time()
        result = await self.engine.request_privilege(request)
        end_time = time.time()
        
        processing_time = (end_time - start_time) * 1000  # milliseconds
        
        # Should complete within 500ms
        self.assertLess(processing_time, 500)
        self.assertEqual(result["status"], RequestStatus.APPROVED.value)
    
    def test_concurrent_session_handling(self):
        """Test handling multiple concurrent sessions"""
        asyncio.run(self._test_concurrent_sessions())
    
    @patch('jit_privilege_engine.MAESTROClient')
    async def _test_concurrent_sessions(self, mock_maestro):
        # Mock MAESTRO
        mock_maestro_instance = mock_maestro.return_value
        mock_maestro_instance.validate_security = AsyncMock(
            return_value={"is_valid": True, "threat_level": "LOW"}
        )
        self.engine.maestro_client = mock_maestro_instance
        
        # Create multiple concurrent requests
        tasks = []
        for i in range(10):
            request = PrivilegeRequest(
                request_id=str(uuid.uuid4()),
                user_id=f"concurrent_user_{i}",
                requested_role="operator",
                requested_permissions=["read"],
                duration_minutes=30,
                justification=f"Concurrent test {i}",
                classification_level="UNCLASSIFIED",
                target_resources=[],
                request_time=datetime.utcnow(),
                mfa_verified=True
            )
            
            task = self.engine.request_privilege(request)
            tasks.append(task)
        
        # Process all requests concurrently
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        for result in results:
            self.assertEqual(result["status"], RequestStatus.APPROVED.value)
        
        # Check active sessions
        sessions = self.engine.get_active_sessions()
        self.assertEqual(len(sessions), 10)


if __name__ == '__main__':
    unittest.main(verbosity=2)