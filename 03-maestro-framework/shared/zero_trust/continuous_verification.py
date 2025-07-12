#!/usr/bin/env python3
"""
ALCUB3 Continuous Verification System
AI-powered continuous authentication with behavioral risk scoring

This module implements patent-pending continuous verification that:
- Validates authentication state in real-time
- Uses ML models for session risk scoring
- Triggers re-authentication based on behavior
- Orchestrates multi-factor authentication
- Integrates with audit logging system

Performance Targets:
- <2% overhead on transaction throughput
- <100ms risk score calculation
- Support for 10,000+ concurrent sessions
"""

import asyncio
import hashlib
import logging
import time
import numpy as np
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import deque
import json
import pickle
from pathlib import Path

# ML libraries for risk scoring
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML libraries not available, using rule-based risk scoring")

# Import MAESTRO components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError, AuthenticationError
from shared.real_time_monitor import RealTimeMonitor

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for continuous verification."""
    MINIMAL = "minimal"      # 0-20
    LOW = "low"             # 21-40
    MEDIUM = "medium"       # 41-60
    HIGH = "high"           # 61-80
    CRITICAL = "critical"   # 81-100


class AuthenticationMethod(Enum):
    """Available authentication methods."""
    PASSWORD = "password"
    MFA_TOKEN = "mfa_token"
    BIOMETRIC = "biometric"
    PKI_CERTIFICATE = "pki_certificate"
    HARDWARE_TOKEN = "hardware_token"
    BEHAVIORAL = "behavioral"


class SessionState(Enum):
    """Session states in continuous verification."""
    ACTIVE = "active"
    CHALLENGED = "challenged"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"
    EXPIRED = "expired"


@dataclass
class AuthenticationEvent:
    """Represents an authentication event."""
    event_id: str
    session_id: str
    timestamp: datetime
    method: AuthenticationMethod
    success: bool
    risk_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorProfile:
    """User behavior profile for anomaly detection."""
    user_id: str
    typical_locations: Set[str] = field(default_factory=set)
    typical_times: List[Tuple[int, int]] = field(default_factory=list)  # Hour ranges
    typical_devices: Set[str] = field(default_factory=set)
    access_patterns: Dict[str, int] = field(default_factory=dict)
    keystroke_dynamics: Optional[Dict[str, float]] = None
    mouse_patterns: Optional[Dict[str, float]] = None
    resource_access_frequency: Dict[str, float] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VerificationSession:
    """Active verification session."""
    session_id: str
    user_id: str
    device_id: str
    start_time: datetime
    last_verification: datetime
    classification_level: ClassificationLevel
    state: SessionState = SessionState.ACTIVE
    risk_score: float = 0.0
    risk_history: deque = field(default_factory=lambda: deque(maxlen=100))
    auth_methods_used: Set[AuthenticationMethod] = field(default_factory=set)
    failed_challenges: int = 0
    location: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    behavior_anomalies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContinuousVerificationSystem:
    """
    Patent-pending continuous verification system with AI-powered risk scoring.
    
    This system provides real-time authentication state validation with
    behavioral analysis and adaptive re-authentication challenges.
    """
    
    def __init__(
        self,
        audit_logger: AuditLogger,
        monitor: Optional[RealTimeMonitor] = None,
        ml_model_path: Optional[str] = None,
        challenge_threshold: float = 60.0,
        termination_threshold: float = 85.0
    ):
        """
        Initialize the continuous verification system.
        
        Args:
            audit_logger: Audit logger for security events
            monitor: Real-time monitoring system
            ml_model_path: Path to pre-trained ML models
            challenge_threshold: Risk score threshold for re-authentication
            termination_threshold: Risk score threshold for session termination
        """
        self.audit_logger = audit_logger
        self.monitor = monitor
        self.challenge_threshold = challenge_threshold
        self.termination_threshold = termination_threshold
        
        # Core data structures
        self.active_sessions: Dict[str, VerificationSession] = {}
        self.user_profiles: Dict[str, BehaviorProfile] = {}
        self.auth_events: deque = deque(maxlen=10000)
        
        # ML components
        self.ml_available = ML_AVAILABLE
        self.risk_model = None
        self.anomaly_detector = None
        self.scaler = None
        
        if self.ml_available:
            self._initialize_ml_models(ml_model_path)
        
        # Performance tracking
        self.stats = {
            'sessions_created': 0,
            'challenges_issued': 0,
            'sessions_terminated': 0,
            'avg_risk_calculation_ms': 0.0,
            'auth_events_processed': 0,
            'ml_predictions_made': 0
        }
        
        # Challenge configuration
        self.challenge_methods = {
            RiskLevel.LOW: [AuthenticationMethod.MFA_TOKEN],
            RiskLevel.MEDIUM: [AuthenticationMethod.MFA_TOKEN, AuthenticationMethod.BIOMETRIC],
            RiskLevel.HIGH: [AuthenticationMethod.HARDWARE_TOKEN, AuthenticationMethod.BIOMETRIC],
            RiskLevel.CRITICAL: [AuthenticationMethod.PKI_CERTIFICATE, AuthenticationMethod.HARDWARE_TOKEN]
        }
        
        logger.info("Continuous verification system initialized with ML: %s", self.ml_available)
    
    def _initialize_ml_models(self, model_path: Optional[str]):
        """Initialize ML models for risk scoring."""
        try:
            if model_path and Path(model_path).exists():
                # Load pre-trained models
                model_dir = Path(model_path)
                self.risk_model = joblib.load(model_dir / "risk_model.pkl")
                self.anomaly_detector = joblib.load(model_dir / "anomaly_detector.pkl")
                self.scaler = joblib.load(model_dir / "scaler.pkl")
                logger.info("Loaded pre-trained ML models from %s", model_path)
            else:
                # Initialize new models
                self.risk_model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42
                )
                self.anomaly_detector = IsolationForest(
                    contamination=0.1,
                    random_state=42
                )
                self.scaler = StandardScaler()
                logger.info("Initialized new ML models for training")
        except Exception as e:
            logger.error("Failed to initialize ML models: %s", str(e))
            self.ml_available = False
    
    async def create_session(
        self,
        user_id: str,
        device_id: str,
        classification_level: ClassificationLevel,
        initial_auth_method: AuthenticationMethod,
        location: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> VerificationSession:
        """
        Create a new verification session.
        
        Args:
            user_id: User identifier
            device_id: Device identifier
            classification_level: Session classification level
            initial_auth_method: Initial authentication method used
            location: Geographic location
            ip_address: Client IP address
            user_agent: Client user agent string
            metadata: Additional session metadata
            
        Returns:
            Created VerificationSession
        """
        session_id = hashlib.sha256(
            f"{user_id}:{device_id}:{time.time()}".encode()
        ).hexdigest()[:32]
        
        session = VerificationSession(
            session_id=session_id,
            user_id=user_id,
            device_id=device_id,
            start_time=datetime.utcnow(),
            last_verification=datetime.utcnow(),
            classification_level=classification_level,
            location=location,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )
        
        session.auth_methods_used.add(initial_auth_method)
        
        # Calculate initial risk score
        initial_risk = await self._calculate_risk_score(session, is_initial=True)
        session.risk_score = initial_risk
        session.risk_history.append((datetime.utcnow(), initial_risk))
        
        # Store session
        self.active_sessions[session_id] = session
        self.stats['sessions_created'] += 1
        
        # Create or update user profile
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = BehaviorProfile(user_id=user_id)
        
        # Log session creation
        await self.audit_logger.log_event(
            "CONTINUOUS_VERIFICATION_SESSION_CREATED",
            classification=classification_level,
            details={
                'session_id': session_id,
                'user_id': user_id,
                'device_id': device_id,
                'initial_risk_score': initial_risk,
                'auth_method': initial_auth_method.value
            }
        )
        
        logger.info("Created verification session %s for user %s with risk score %.2f",
                   session_id, user_id, initial_risk)
        
        return session
    
    async def verify_session(
        self,
        session_id: str,
        activity_data: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[List[AuthenticationMethod]]]:
        """
        Verify an active session and determine if re-authentication is needed.
        
        Args:
            session_id: Session identifier
            activity_data: Current activity data for risk assessment
            
        Returns:
            Tuple of (session_valid, required_auth_methods)
        """
        start_time = time.time()
        
        session = self.active_sessions.get(session_id)
        if not session:
            return False, None
        
        # Check session state
        if session.state in [SessionState.TERMINATED, SessionState.EXPIRED]:
            return False, None
        
        # Calculate current risk score
        current_risk = await self._calculate_risk_score(session, activity_data)
        session.risk_score = current_risk
        session.risk_history.append((datetime.utcnow(), current_risk))
        
        # Update verification time
        session.last_verification = datetime.utcnow()
        
        # Determine risk level
        risk_level = self._get_risk_level(current_risk)
        
        # Check if re-authentication is needed
        if current_risk >= self.termination_threshold:
            # Terminate session
            await self._terminate_session(session, "Risk threshold exceeded")
            return False, None
        
        elif current_risk >= self.challenge_threshold:
            # Issue challenge
            required_methods = self._get_required_auth_methods(risk_level, session)
            session.state = SessionState.CHALLENGED
            self.stats['challenges_issued'] += 1
            
            await self.audit_logger.log_event(
                "CONTINUOUS_VERIFICATION_CHALLENGE_ISSUED",
                classification=session.classification_level,
                details={
                    'session_id': session_id,
                    'risk_score': current_risk,
                    'risk_level': risk_level.value,
                    'required_methods': [m.value for m in required_methods]
                }
            )
            
            # Monitor challenge issuance
            if self.monitor:
                await self.monitor.record_event(
                    'security.continuous_verification.challenge',
                    {
                        'session_id': session_id,
                        'risk_level': risk_level.value,
                        'user_id': session.user_id
                    }
                )
            
            # Update performance metrics
            verification_time = (time.time() - start_time) * 1000
            self._update_avg_calculation_time(verification_time)
            
            return True, required_methods
        
        # Session is valid, no challenge needed
        verification_time = (time.time() - start_time) * 1000
        self._update_avg_calculation_time(verification_time)
        
        return True, None
    
    async def _calculate_risk_score(
        self,
        session: VerificationSession,
        activity_data: Optional[Dict[str, Any]] = None,
        is_initial: bool = False
    ) -> float:
        """
        Calculate risk score using ML models or rule-based approach.
        
        Args:
            session: Verification session
            activity_data: Current activity data
            is_initial: Whether this is initial session creation
            
        Returns:
            Risk score (0-100)
        """
        features = []
        
        # Extract features for risk calculation
        profile = self.user_profiles.get(session.user_id)
        if not profile:
            profile = BehaviorProfile(user_id=session.user_id)
        
        # Time-based features
        current_hour = datetime.utcnow().hour
        is_typical_time = any(
            start <= current_hour <= end 
            for start, end in profile.typical_times
        ) if profile.typical_times else True
        features.append(0.0 if is_typical_time else 1.0)
        
        # Location-based features
        is_typical_location = session.location in profile.typical_locations if session.location else True
        features.append(0.0 if is_typical_location else 1.0)
        
        # Device-based features
        is_typical_device = session.device_id in profile.typical_devices
        features.append(0.0 if is_typical_device else 1.0)
        
        # Session duration feature
        session_duration_hours = (datetime.utcnow() - session.start_time).total_seconds() / 3600
        features.append(min(session_duration_hours / 24, 1.0))  # Normalize to 0-1
        
        # Failed challenges feature
        features.append(min(session.failed_challenges / 5, 1.0))  # Normalize to 0-1
        
        # Activity-based features
        if activity_data:
            # Resource access frequency
            access_rate = activity_data.get('access_rate', 0)
            typical_rate = profile.resource_access_frequency.get('average', 10)
            features.append(min(abs(access_rate - typical_rate) / typical_rate, 1.0))
            
            # Data volume
            data_volume = activity_data.get('data_volume', 0)
            features.append(min(data_volume / 1000000, 1.0))  # Normalize MB to 0-1
            
            # Privileged operations
            privileged_ops = activity_data.get('privileged_operations', 0)
            features.append(min(privileged_ops / 10, 1.0))
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # Classification level risk factor
        classification_factor = {
            ClassificationLevel.UNCLASSIFIED: 0.0,
            ClassificationLevel.CONFIDENTIAL: 0.2,
            ClassificationLevel.SECRET: 0.4,
            ClassificationLevel.TOP_SECRET: 0.6
        }.get(session.classification_level, 0.0)
        features.append(classification_factor)
        
        # Calculate risk score
        if self.ml_available and self.risk_model and not is_initial:
            try:
                # Use ML model for prediction
                features_array = np.array(features).reshape(1, -1)
                
                # Scale features
                if hasattr(self.risk_model, 'predict_proba'):
                    # Get probability of high risk
                    risk_probability = self.risk_model.predict_proba(features_array)[0][1]
                    base_risk = risk_probability * 100
                else:
                    # Use anomaly score
                    anomaly_score = self.anomaly_detector.decision_function(features_array)[0]
                    base_risk = max(0, min(100, 50 + anomaly_score * 10))
                
                self.stats['ml_predictions_made'] += 1
                
            except Exception as e:
                logger.warning("ML prediction failed, using rule-based: %s", str(e))
                base_risk = self._calculate_rule_based_risk(features)
        else:
            # Use rule-based calculation
            base_risk = self._calculate_rule_based_risk(features)
        
        # Apply behavioral anomaly adjustments
        if session.behavior_anomalies:
            anomaly_penalty = len(session.behavior_anomalies) * 5
            base_risk = min(100, base_risk + anomaly_penalty)
        
        # Apply time decay for long sessions
        if session_duration_hours > 8:
            time_penalty = (session_duration_hours - 8) * 2
            base_risk = min(100, base_risk + time_penalty)
        
        return round(base_risk, 2)
    
    def _calculate_rule_based_risk(self, features: List[float]) -> float:
        """Calculate risk score using rules when ML is not available."""
        # Weighted sum of features
        weights = [
            20.0,  # Atypical time
            15.0,  # Atypical location
            15.0,  # Unknown device
            10.0,  # Session duration
            25.0,  # Failed challenges
            5.0,   # Access rate anomaly
            5.0,   # High data volume
            10.0,  # Privileged operations
            20.0   # Classification level
        ]
        
        weighted_sum = sum(f * w for f, w in zip(features, weights))
        
        # Normalize to 0-100 scale
        return min(100, max(0, weighted_sum))
    
    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score."""
        if risk_score <= 20:
            return RiskLevel.MINIMAL
        elif risk_score <= 40:
            return RiskLevel.LOW
        elif risk_score <= 60:
            return RiskLevel.MEDIUM
        elif risk_score <= 80:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _get_required_auth_methods(
        self,
        risk_level: RiskLevel,
        session: VerificationSession
    ) -> List[AuthenticationMethod]:
        """Get required authentication methods based on risk level."""
        base_methods = self.challenge_methods.get(risk_level, [])
        
        # Filter out methods already used recently
        recent_methods = {
            method for method in session.auth_methods_used
            if method != AuthenticationMethod.PASSWORD
        }
        
        required_methods = [
            method for method in base_methods
            if method not in recent_methods
        ]
        
        # Always require at least one method
        if not required_methods and base_methods:
            required_methods = [base_methods[0]]
        
        return required_methods
    
    async def complete_challenge(
        self,
        session_id: str,
        auth_method: AuthenticationMethod,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Complete an authentication challenge.
        
        Args:
            session_id: Session identifier
            auth_method: Authentication method used
            success: Whether authentication succeeded
            metadata: Additional authentication metadata
            
        Returns:
            Whether session remains active
        """
        session = self.active_sessions.get(session_id)
        if not session or session.state != SessionState.CHALLENGED:
            return False
        
        # Create authentication event
        event = AuthenticationEvent(
            event_id=hashlib.sha256(f"{session_id}:{time.time()}".encode()).hexdigest()[:16],
            session_id=session_id,
            timestamp=datetime.utcnow(),
            method=auth_method,
            success=success,
            risk_score=session.risk_score,
            metadata=metadata or {}
        )
        self.auth_events.append(event)
        self.stats['auth_events_processed'] += 1
        
        if success:
            # Update session
            session.auth_methods_used.add(auth_method)
            session.state = SessionState.ACTIVE
            session.failed_challenges = 0
            
            # Reduce risk score after successful authentication
            session.risk_score = max(0, session.risk_score - 20)
            
            # Update user profile
            await self._update_user_profile(session)
            
            await self.audit_logger.log_event(
                "CONTINUOUS_VERIFICATION_CHALLENGE_COMPLETED",
                classification=session.classification_level,
                details={
                    'session_id': session_id,
                    'auth_method': auth_method.value,
                    'new_risk_score': session.risk_score
                }
            )
            
            return True
        else:
            # Failed authentication
            session.failed_challenges += 1
            
            # Check if too many failures
            if session.failed_challenges >= 3:
                await self._terminate_session(session, "Too many failed challenges")
                return False
            
            # Increase risk score
            session.risk_score = min(100, session.risk_score + 10)
            
            await self.audit_logger.log_event(
                "CONTINUOUS_VERIFICATION_CHALLENGE_FAILED",
                classification=session.classification_level,
                details={
                    'session_id': session_id,
                    'auth_method': auth_method.value,
                    'failed_attempts': session.failed_challenges
                }
            )
            
            return True
    
    async def _update_user_profile(self, session: VerificationSession):
        """Update user behavior profile based on session data."""
        profile = self.user_profiles.get(session.user_id)
        if not profile:
            return
        
        # Update typical locations
        if session.location:
            profile.typical_locations.add(session.location)
        
        # Update typical devices
        profile.typical_devices.add(session.device_id)
        
        # Update typical times (simplified - track hours)
        current_hour = datetime.utcnow().hour
        if not any(start <= current_hour <= end for start, end in profile.typical_times):
            # Add new time range
            profile.typical_times.append((current_hour, current_hour))
        
        profile.last_updated = datetime.utcnow()
    
    async def _terminate_session(self, session: VerificationSession, reason: str):
        """Terminate a session."""
        session.state = SessionState.TERMINATED
        self.stats['sessions_terminated'] += 1
        
        await self.audit_logger.log_event(
            "CONTINUOUS_VERIFICATION_SESSION_TERMINATED",
            classification=session.classification_level,
            details={
                'session_id': session.session_id,
                'user_id': session.user_id,
                'reason': reason,
                'final_risk_score': session.risk_score
            }
        )
        
        if self.monitor:
            await self.monitor.record_event(
                'security.continuous_verification.termination',
                {
                    'session_id': session.session_id,
                    'reason': reason,
                    'risk_score': session.risk_score
                }
            )
    
    def _update_avg_calculation_time(self, calculation_time_ms: float):
        """Update average risk calculation time metric."""
        current_avg = self.stats['avg_risk_calculation_ms']
        total_calculations = self.stats.get('total_risk_calculations', 0)
        
        # Calculate running average
        self.stats['avg_risk_calculation_ms'] = (
            (current_avg * total_calculations + calculation_time_ms) / (total_calculations + 1)
        )
        self.stats['total_risk_calculations'] = total_calculations + 1
    
    async def train_ml_models(self, training_data: List[Dict[str, Any]]):
        """
        Train ML models with historical session data.
        
        Args:
            training_data: List of session data with risk labels
        """
        if not self.ml_available:
            logger.warning("ML not available for training")
            return
        
        try:
            # Extract features and labels
            features = []
            labels = []
            
            for data in training_data:
                feature_vector = self._extract_features(data)
                features.append(feature_vector)
                labels.append(data.get('high_risk', False))
            
            features_array = np.array(features)
            labels_array = np.array(labels)
            
            # Scale features
            features_scaled = self.scaler.fit_transform(features_array)
            
            # Train risk model
            self.risk_model.fit(features_scaled, labels_array)
            
            # Train anomaly detector
            normal_data = features_scaled[~labels_array]
            if len(normal_data) > 0:
                self.anomaly_detector.fit(normal_data)
            
            logger.info("ML models trained with %d samples", len(training_data))
            
        except Exception as e:
            logger.error("Failed to train ML models: %s", str(e))
    
    def _extract_features(self, session_data: Dict[str, Any]) -> List[float]:
        """Extract features from session data for ML training."""
        # This should match the feature extraction in _calculate_risk_score
        features = []
        
        # Add features based on session data
        features.append(float(session_data.get('atypical_time', False)))
        features.append(float(session_data.get('atypical_location', False)))
        features.append(float(session_data.get('unknown_device', False)))
        features.append(session_data.get('session_duration_hours', 0) / 24)
        features.append(session_data.get('failed_challenges', 0) / 5)
        features.append(session_data.get('access_rate_anomaly', 0))
        features.append(session_data.get('data_volume_mb', 0) / 1000000)
        features.append(session_data.get('privileged_operations', 0) / 10)
        features.append(session_data.get('classification_factor', 0))
        
        return features
    
    async def save_ml_models(self, model_path: str):
        """Save trained ML models to disk."""
        if not self.ml_available or not self.risk_model:
            logger.warning("No ML models to save")
            return
        
        try:
            model_dir = Path(model_path)
            model_dir.mkdir(parents=True, exist_ok=True)
            
            # Save models
            joblib.dump(self.risk_model, model_dir / "risk_model.pkl")
            joblib.dump(self.anomaly_detector, model_dir / "anomaly_detector.pkl")
            joblib.dump(self.scaler, model_dir / "scaler.pkl")
            
            logger.info("ML models saved to %s", model_path)
            
        except Exception as e:
            logger.error("Failed to save ML models: %s", str(e))
    
    async def cleanup_expired_sessions(self, max_age_hours: int = 24):
        """Clean up expired sessions."""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if session.last_verification < cutoff_time:
                session.state = SessionState.EXPIRED
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
        
        if expired_sessions:
            logger.info("Cleaned up %d expired sessions", len(expired_sessions))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current system statistics."""
        active_count = sum(
            1 for s in self.active_sessions.values()
            if s.state == SessionState.ACTIVE
        )
        challenged_count = sum(
            1 for s in self.active_sessions.values()
            if s.state == SessionState.CHALLENGED
        )
        
        return {
            **self.stats,
            'active_sessions': active_count,
            'challenged_sessions': challenged_count,
            'total_sessions': len(self.active_sessions),
            'user_profiles': len(self.user_profiles),
            'ml_available': self.ml_available
        }