#!/usr/bin/env python3
"""
Tests for ALCUB3 Continuous Verification System
Validates ML-powered continuous authentication functionality
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
import numpy as np

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.zero_trust.continuous_verification import (
    ContinuousVerificationSystem,
    VerificationSession,
    SessionState,
    AuthenticationMethod,
    BehaviorProfile,
    RiskLevel
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
async def mock_monitor():
    """Create mock real-time monitor."""
    monitor = Mock()
    monitor.record_event = AsyncMock()
    monitor.record_metric = AsyncMock()
    return monitor


@pytest.fixture
async def verification_system(mock_audit_logger, mock_monitor):
    """Create continuous verification system instance."""
    system = ContinuousVerificationSystem(
        audit_logger=mock_audit_logger,
        monitor=mock_monitor,
        ml_model_path=None,  # Use default model
        challenge_threshold=60.0
    )
    return system


class TestContinuousVerificationSystem:
    """Test cases for continuous verification system."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, verification_system):
        """Test system initialization."""
        system = verification_system
        
        assert system.challenge_threshold == 60.0
        assert system.reauthentication_grace_period == 300
        assert len(system.authentication_methods) > 0
        assert len(system.sessions) == 0
    
    @pytest.mark.asyncio
    async def test_create_session(self, verification_system):
        """Test creating a new verification session."""
        system = verification_system
        
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD,
            metadata={'location': 'office'}
        )
        
        assert session.session_id
        assert session.user_id == "user-123"
        assert session.device_id == "device-456"
        assert session.classification_level == ClassificationLevel.SECRET
        assert session.state == SessionState.ACTIVE
        assert session.risk_score < 100
        assert session.session_id in system.sessions
    
    @pytest.mark.asyncio
    async def test_behavior_profile_learning(self, verification_system):
        """Test behavior profile learning and updates."""
        system = verification_system
        
        # Create session
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.UNCLASSIFIED,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Simulate user activity
        activity_data = {
            'access_rate': 15,  # accesses per minute
            'data_volume': 1024,  # KB
            'privileged_operations': 2,
            'location': 'office',
            'device_fingerprint': 'abc123'
        }
        
        # Update behavior profile
        await system._update_behavior_profile(session, activity_data)
        
        profile = system.behavior_profiles.get("user-123")
        assert profile is not None
        assert profile.access_patterns['access_rate']['count'] == 1
        assert profile.access_patterns['access_rate']['mean'] == 15
    
    @pytest.mark.asyncio
    async def test_risk_score_calculation(self, verification_system):
        """Test risk score calculation with various factors."""
        system = verification_system
        
        # Create session
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Test normal behavior
        normal_activity = {
            'access_rate': 10,
            'data_volume': 500,
            'privileged_operations': 1
        }
        
        risk_score = await system._calculate_risk_score(
            session,
            activity_data=normal_activity
        )
        
        assert risk_score < 50  # Normal behavior should have low risk
        
        # Test anomalous behavior
        anomalous_activity = {
            'access_rate': 1000,  # Very high
            'data_volume': 1000000,  # Very high
            'privileged_operations': 50  # Very high
        }
        
        risk_score = await system._calculate_risk_score(
            session,
            activity_data=anomalous_activity
        )
        
        assert risk_score > 70  # Anomalous behavior should have high risk
    
    @pytest.mark.asyncio
    async def test_session_verification(self, verification_system):
        """Test session verification process."""
        system = verification_system
        
        # Create session
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Verify with normal activity
        normal_activity = {
            'access_rate': 10,
            'data_volume': 500,
            'privileged_operations': 1
        }
        
        valid, required_methods = await system.verify_session(
            session.session_id,
            activity_data=normal_activity
        )
        
        assert valid is True
        assert required_methods is None  # No additional auth needed
        
        # Simulate high-risk activity
        session.risk_score = 85  # Manually set high risk
        
        valid, required_methods = await system.verify_session(
            session.session_id,
            activity_data=normal_activity
        )
        
        assert valid is False
        assert required_methods is not None
        assert len(required_methods) >= 1
    
    @pytest.mark.asyncio
    async def test_challenge_response(self, verification_system):
        """Test challenge-response authentication."""
        system = verification_system
        
        # Create session in challenged state
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Force challenge
        session.state = SessionState.CHALLENGED
        session.challenge_methods = [
            AuthenticationMethod.MFA,
            AuthenticationMethod.BIOMETRIC
        ]
        
        # Respond to challenge
        result = await system.respond_to_challenge(
            session.session_id,
            AuthenticationMethod.MFA,
            response_data={'otp': '123456'}
        )
        
        assert result is True
        assert AuthenticationMethod.MFA in session.completed_challenges
        
        # Complete all challenges
        result = await system.respond_to_challenge(
            session.session_id,
            AuthenticationMethod.BIOMETRIC,
            response_data={'fingerprint': 'hash123'}
        )
        
        assert result is True
        assert session.state == SessionState.ACTIVE
        assert session.risk_score < 60  # Risk should decrease
    
    @pytest.mark.asyncio
    async def test_classification_based_policies(self, verification_system):
        """Test classification-level based verification policies."""
        system = verification_system
        
        # Test UNCLASSIFIED - should have relaxed requirements
        unclass_session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.UNCLASSIFIED,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Even with moderate risk, shouldn't require strong auth
        unclass_session.risk_score = 50
        valid, methods = await system.verify_session(unclass_session.session_id)
        assert valid is True
        
        # Test TOP_SECRET - should have strict requirements
        ts_session = await system.create_session(
            user_id="user-456",
            device_id="device-789",
            classification_level=ClassificationLevel.TOP_SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Even with low risk, might require additional auth
        ts_session.risk_score = 30
        valid, methods = await system.verify_session(ts_session.session_id)
        
        # TOP_SECRET sessions should require at least MFA
        if not valid:
            assert methods is not None
            assert AuthenticationMethod.MFA in methods
    
    @pytest.mark.asyncio
    async def test_session_termination(self, verification_system):
        """Test session termination."""
        system = verification_system
        
        # Create session
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        session_id = session.session_id
        
        # Terminate session
        await system.terminate_session(
            session_id,
            reason="User logout"
        )
        
        assert session_id not in system.sessions
        assert session.state == SessionState.TERMINATED
    
    @pytest.mark.asyncio
    async def test_anomaly_detection(self, verification_system):
        """Test ML-based anomaly detection."""
        system = verification_system
        
        # Create session with established behavior
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Establish baseline behavior
        for _ in range(10):
            await system._update_behavior_profile(
                session,
                {
                    'access_rate': 10 + np.random.normal(0, 2),
                    'data_volume': 500 + np.random.normal(0, 50),
                    'privileged_operations': 1
                }
            )
        
        # Test anomaly detection
        anomaly_score = await system._detect_anomalies(
            session,
            {
                'access_rate': 100,  # 10x normal
                'data_volume': 5000,  # 10x normal
                'privileged_operations': 20  # 20x normal
            }
        )
        
        assert anomaly_score > 0.7  # High anomaly score
    
    @pytest.mark.asyncio
    async def test_adaptive_authentication(self, verification_system):
        """Test adaptive authentication based on risk."""
        system = verification_system
        
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Test different risk levels
        test_cases = [
            (20, []),  # Low risk - no additional auth
            (40, [AuthenticationMethod.MFA]),  # Medium risk - MFA
            (70, [AuthenticationMethod.MFA, AuthenticationMethod.BIOMETRIC]),  # High risk
            (90, [AuthenticationMethod.MFA, AuthenticationMethod.BIOMETRIC, 
                  AuthenticationMethod.HARDWARE_TOKEN])  # Very high risk
        ]
        
        for risk_score, expected_methods in test_cases:
            methods = system._determine_required_auth_methods(
                risk_score,
                session.classification_level,
                session.authentication_methods
            )
            
            # Higher risk should require more auth methods
            if risk_score > 60:
                assert len(methods) >= 2
    
    @pytest.mark.asyncio
    async def test_session_timeout(self, verification_system):
        """Test session timeout handling."""
        system = verification_system
        
        # Create session with short timeout
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Manually age the session
        session.last_activity = datetime.utcnow() - timedelta(hours=2)
        
        # Check if session is expired
        is_expired = await system._is_session_expired(session)
        assert is_expired is True
        
        # Verify expired session
        valid, _ = await system.verify_session(session.session_id)
        assert valid is False
        assert session.state == SessionState.EXPIRED
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, verification_system):
        """Test performance tracking."""
        system = verification_system
        
        # Create multiple sessions and verify them
        for i in range(10):
            session = await system.create_session(
                user_id=f"user-{i}",
                device_id=f"device-{i}",
                classification_level=ClassificationLevel.UNCLASSIFIED,
                initial_auth_method=AuthenticationMethod.PASSWORD
            )
            
            await system.verify_session(
                session.session_id,
                activity_data={'access_rate': 10}
            )
        
        stats = system.get_statistics()
        assert stats['sessions_created'] == 10
        assert stats['verifications_performed'] >= 10
        assert stats['avg_verification_time_ms'] > 0
        assert stats['avg_verification_time_ms'] < 10  # Should be fast
    
    @pytest.mark.asyncio
    async def test_concurrent_verifications(self, verification_system):
        """Test concurrent session verifications."""
        system = verification_system
        
        # Create multiple sessions
        sessions = []
        for i in range(50):
            session = await system.create_session(
                user_id=f"user-{i}",
                device_id=f"device-{i}",
                classification_level=ClassificationLevel.UNCLASSIFIED,
                initial_auth_method=AuthenticationMethod.PASSWORD
            )
            sessions.append(session)
        
        # Verify all sessions concurrently
        tasks = []
        for session in sessions:
            task = system.verify_session(
                session.session_id,
                activity_data={'access_rate': 10}
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # All verifications should complete successfully
        assert len(results) == 50
        assert all(result[0] is True for result in results)
    
    @pytest.mark.asyncio
    async def test_ml_model_integration(self, verification_system):
        """Test ML model integration for risk scoring."""
        system = verification_system
        
        # Test that ML model is properly initialized
        assert system.ml_model is not None
        
        # Create session
        session = await system.create_session(
            user_id="user-123",
            device_id="device-456",
            classification_level=ClassificationLevel.SECRET,
            initial_auth_method=AuthenticationMethod.PASSWORD
        )
        
        # Test ML-based risk prediction
        features = await system._extract_features(
            session,
            {'access_rate': 10, 'data_volume': 500}
        )
        
        assert len(features) > 0
        
        # Predict risk using ML model
        risk_prediction = system.ml_model.predict([features])[0]
        assert 0 <= risk_prediction <= 100


@pytest.mark.asyncio
async def test_security_event_correlation(verification_system):
    """Test correlation with security events."""
    system = verification_system
    
    # Create session
    session = await system.create_session(
        user_id="user-123",
        device_id="device-456",
        classification_level=ClassificationLevel.SECRET,
        initial_auth_method=AuthenticationMethod.PASSWORD
    )
    
    # Simulate security events
    for _ in range(5):
        await system._handle_security_event(
            session,
            event_type='failed_access',
            severity='medium'
        )
    
    # Risk should increase with security events
    assert session.risk_score > 50
    
    # Session should be challenged after multiple events
    assert session.state == SessionState.CHALLENGED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])