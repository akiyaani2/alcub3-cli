"""
Security Posture Forecasting System

A comprehensive ML-powered system for predicting security posture and risk levels
across the ALCUB3 platform with support for multi-layer correlation, Byzantine-aware
forecasting, and classification-weighted predictions.
"""

import asyncio
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import threading
import time
from collections import defaultdict, deque
import json

from .models.lstm_forecaster import LSTMForecaster
from .models.risk_classifier import RiskClassifier
from .models.anomaly_detector import AnomalyDetector
from .data.telemetry_collector import TelemetryCollector
from .data.feature_engineering import FeatureEngineer


class ClassificationLevel(Enum):
    """Security classification levels for adaptive threat handling."""
    UNCLASSIFIED = "U"
    SECRET = "S"
    TOP_SECRET = "TS"


class RiskLevel(Enum):
    """Risk assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Represents a security event with classification and metadata."""
    timestamp: datetime
    event_type: str
    severity: int
    classification: ClassificationLevel
    source: str
    description: str
    risk_score: float
    metadata: Dict[str, Any]


@dataclass
class ThreatForecast:
    """Represents a threat forecast with predictions and recommendations."""
    timestamp: datetime
    forecast_horizon: timedelta
    threat_probability: float
    risk_level: RiskLevel
    predicted_events: List[str]
    confidence_score: float
    recommendations: List[str]
    classification: ClassificationLevel


@dataclass
class SecurityPosture:
    """Represents the current security posture with risk metrics."""
    timestamp: datetime
    overall_risk_score: float
    risk_level: RiskLevel
    threat_indicators: Dict[str, float]
    security_metrics: Dict[str, float]
    classification_risks: Dict[ClassificationLevel, float]
    trends: Dict[str, float]


class SecurityForecaster:
    """
    Advanced security posture forecasting system with ML-powered threat prediction,
    classification-aware risk assessment, and Byzantine-aware analysis.
    
    Features:
    - Multi-layer security correlation across MAESTRO L1-L3
    - Real-time adaptive learning with <100ms prediction latency
    - Classification-weighted predictions and escalation paths
    - Byzantine fault-tolerant swarm integration
    - Predictive threat emergence detection
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Security Forecaster with ML models and data pipelines.
        
        Args:
            config: Configuration parameters for the forecaster
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize ML models
        self.lstm_forecaster = LSTMForecaster(
            sequence_length=self.config.get('sequence_length', 100),
            features=self.config.get('features', 50)
        )
        self.risk_classifier = RiskClassifier(
            model_type=self.config.get('risk_model', 'random_forest')
        )
        self.anomaly_detector = AnomalyDetector(
            method=self.config.get('anomaly_method', 'isolation_forest')
        )
        
        # Initialize data components
        self.telemetry_collector = TelemetryCollector(
            collection_interval=self.config.get('collection_interval', 30)
        )
        self.feature_engineer = FeatureEngineer(
            window_size=self.config.get('feature_window', 300)
        )
        
        # State management
        self.security_events: deque = deque(maxlen=10000)
        self.current_posture: Optional[SecurityPosture] = None
        self.model_last_trained: Dict[str, datetime] = {}
        self.performance_metrics: Dict[str, float] = {}
        
        # Threading and async support
        self.lock = threading.RLock()
        self.running = False
        self.background_tasks: List[asyncio.Task] = []
        
        # Classification-specific thresholds
        self.classification_thresholds = {
            ClassificationLevel.UNCLASSIFIED: 0.3,
            ClassificationLevel.SECRET: 0.2,
            ClassificationLevel.TOP_SECRET: 0.1
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'temporal_decay': 0.9,
            'classification_amplifier': {
                ClassificationLevel.UNCLASSIFIED: 1.0,
                ClassificationLevel.SECRET: 1.5,
                ClassificationLevel.TOP_SECRET: 2.0
            },
            'byzantine_factor': 1.2,
            'cross_layer_correlation': 0.8
        }
        
        self.logger.info("SecurityForecaster initialized with advanced ML models")

    async def start(self) -> None:
        """Start the security forecasting system with background tasks."""
        if self.running:
            self.logger.warning("SecurityForecaster already running")
            return
        
        self.running = True
        self.logger.info("Starting SecurityForecaster background tasks")
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._continuous_telemetry_collection()),
            asyncio.create_task(self._periodic_model_training()),
            asyncio.create_task(self._real_time_risk_assessment()),
            asyncio.create_task(self._threat_monitoring_loop())
        ]
        
        await asyncio.gather(*self.background_tasks, return_exceptions=True)

    async def stop(self) -> None:
        """Stop the security forecasting system."""
        self.running = False
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        self.background_tasks.clear()
        
        self.logger.info("SecurityForecaster stopped")

    async def collect_security_telemetry(self) -> Dict[str, Any]:
        """
        Aggregate security telemetry from all sources.
        
        Returns:
            Dictionary containing aggregated security telemetry
        """
        try:
            telemetry = await self.telemetry_collector.collect_all()
            
            # Add timestamp and metadata
            telemetry['collection_timestamp'] = datetime.now().isoformat()
            telemetry['forecaster_version'] = '1.0.0'
            
            return telemetry
            
        except Exception as e:
            self.logger.error(f"Error collecting security telemetry: {e}")
            return {}

    async def train_models(self, 
                          historical_data: Optional[pd.DataFrame] = None,
                          incremental: bool = True) -> Dict[str, float]:
        """
        Train or update ML models with security events and telemetry.
        
        Args:
            historical_data: Historical security data for training
            incremental: Whether to perform incremental learning
            
        Returns:
            Dictionary containing training metrics
        """
        try:
            start_time = time.time()
            
            # Prepare training data
            if historical_data is None:
                historical_data = await self._prepare_training_data()
            
            if historical_data.empty:
                self.logger.warning("No training data available")
                return {}
            
            # Feature engineering
            features = self.feature_engineer.extract_features(historical_data)
            
            # Train models
            training_metrics = {}
            
            # Train LSTM forecaster
            lstm_metrics = await self.lstm_forecaster.train(
                features, incremental=incremental
            )
            training_metrics['lstm'] = lstm_metrics
            
            # Train risk classifier
            risk_metrics = await self.risk_classifier.train(
                features, incremental=incremental
            )
            training_metrics['risk_classifier'] = risk_metrics
            
            # Train anomaly detector
            anomaly_metrics = await self.anomaly_detector.train(
                features, incremental=incremental
            )
            training_metrics['anomaly_detector'] = anomaly_metrics
            
            # Update training timestamps
            current_time = datetime.now()
            self.model_last_trained = {
                'lstm': current_time,
                'risk_classifier': current_time,
                'anomaly_detector': current_time
            }
            
            training_time = time.time() - start_time
            training_metrics['training_time'] = training_time
            
            self.logger.info(f"Model training completed in {training_time:.2f}s")
            return training_metrics
            
        except Exception as e:
            self.logger.error(f"Error training models: {e}")
            return {}

    async def forecast_security_posture(self,
                                      horizon: timedelta = timedelta(hours=24),
                                      classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
                                      ) -> ThreatForecast:
        """
        Generate comprehensive security posture forecast.
        
        Args:
            horizon: Time horizon for the forecast
            classification: Classification level for threat assessment
            
        Returns:
            ThreatForecast object with predictions and recommendations
        """
        try:
            start_time = time.time()
            
            # Collect current telemetry
            telemetry = await self.collect_security_telemetry()
            
            # Extract features for prediction
            features = self.feature_engineer.extract_features(
                pd.DataFrame([telemetry])
            )
            
            # Generate predictions from each model
            lstm_prediction = await self.lstm_forecaster.predict(
                features, horizon=horizon
            )
            risk_prediction = await self.risk_classifier.predict(features)
            anomaly_score = await self.anomaly_detector.predict(features)
            
            # Calculate threat probability with classification weighting
            base_threat_probability = self._calculate_threat_probability(
                lstm_prediction, risk_prediction, anomaly_score
            )
            
            # Apply classification-specific adjustments
            classification_weight = self.risk_weights['classification_amplifier'][classification]
            adjusted_threat_probability = min(
                base_threat_probability * classification_weight, 1.0
            )
            
            # Determine risk level
            risk_level = self._determine_risk_level(
                adjusted_threat_probability, classification
            )
            
            # Generate predicted events
            predicted_events = self._generate_predicted_events(
                lstm_prediction, risk_level
            )
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                lstm_prediction, risk_prediction, anomaly_score
            )
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(
                risk_level, predicted_events, classification
            )
            
            # Create forecast object
            forecast = ThreatForecast(
                timestamp=datetime.now(),
                forecast_horizon=horizon,
                threat_probability=adjusted_threat_probability,
                risk_level=risk_level,
                predicted_events=predicted_events,
                confidence_score=confidence_score,
                recommendations=recommendations,
                classification=classification
            )
            
            # Update performance metrics
            prediction_time = time.time() - start_time
            self.performance_metrics['prediction_latency'] = prediction_time
            
            if prediction_time > 0.1:  # 100ms threshold
                self.logger.warning(f"Prediction latency exceeded target: {prediction_time:.3f}s")
            
            self.logger.info(f"Security forecast generated in {prediction_time:.3f}s")
            return forecast
            
        except Exception as e:
            self.logger.error(f"Error generating security forecast: {e}")
            # Return safe default forecast
            return ThreatForecast(
                timestamp=datetime.now(),
                forecast_horizon=horizon,
                threat_probability=0.5,
                risk_level=RiskLevel.MEDIUM,
                predicted_events=["forecast_error"],
                confidence_score=0.0,
                recommendations=["investigate_forecasting_error"],
                classification=classification
            )

    def calculate_risk_scores(self, events: List[SecurityEvent]) -> Dict[str, float]:
        """
        Calculate multi-dimensional risk scores from security events.
        
        Args:
            events: List of security events
            
        Returns:
            Dictionary containing various risk score metrics
        """
        if not events:
            return {
                'overall_risk': 0.0,
                'temporal_risk': 0.0,
                'classification_risk': 0.0,
                'byzantine_risk': 0.0,
                'trend_risk': 0.0
            }
        
        # Sort events by timestamp
        events.sort(key=lambda x: x.timestamp)
        current_time = datetime.now()
        
        # Calculate temporal risk with decay
        temporal_risk = 0.0
        for event in events:
            time_delta = (current_time - event.timestamp).total_seconds()
            decay_factor = np.exp(-time_delta / 3600)  # 1-hour decay
            temporal_risk += event.risk_score * decay_factor
        
        # Calculate classification-weighted risk
        classification_risk = 0.0
        for event in events:
            weight = self.risk_weights['classification_amplifier'][event.classification]
            classification_risk += event.risk_score * weight
        
        # Calculate Byzantine risk (events from multiple sources)
        source_counts = defaultdict(int)
        for event in events:
            source_counts[event.source] += 1
        
        byzantine_risk = 0.0
        if len(source_counts) > 1:
            # Higher risk if events are distributed across many sources
            byzantine_risk = min(len(source_counts) * 0.1, 1.0)
        
        # Calculate trend risk (increasing event frequency)
        if len(events) > 1:
            recent_events = [e for e in events if 
                           (current_time - e.timestamp).total_seconds() < 3600]
            older_events = [e for e in events if 
                          (current_time - e.timestamp).total_seconds() >= 3600]
            
            recent_rate = len(recent_events) / 1.0  # per hour
            older_rate = len(older_events) / max(1.0, len(events) - len(recent_events))
            trend_risk = max(0.0, (recent_rate - older_rate) / 10.0)
        else:
            trend_risk = 0.0
        
        # Calculate overall risk
        overall_risk = min(
            (temporal_risk * 0.4 + 
             classification_risk * 0.3 + 
             byzantine_risk * 0.2 + 
             trend_risk * 0.1) / len(events),
            1.0
        )
        
        return {
            'overall_risk': overall_risk,
            'temporal_risk': temporal_risk / len(events),
            'classification_risk': classification_risk / len(events),
            'byzantine_risk': byzantine_risk,
            'trend_risk': trend_risk
        }

    async def generate_recommendations(self,
                                     risk_level: RiskLevel,
                                     predicted_events: List[str],
                                     classification: ClassificationLevel
                                     ) -> List[str]:
        """
        Generate mitigation recommendations based on risk assessment.
        
        Args:
            risk_level: Current risk level
            predicted_events: List of predicted security events
            classification: Classification level
            
        Returns:
            List of actionable recommendations
        """
        recommendations = []
        
        # Base recommendations by risk level
        if risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "Activate emergency response procedures",
                "Implement immediate containment measures",
                "Escalate to security operations center",
                "Prepare for potential system isolation"
            ])
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "Increase monitoring frequency",
                "Deploy additional security controls",
                "Notify security team for review",
                "Prepare contingency plans"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Schedule security review",
                "Update threat detection rules",
                "Verify backup systems",
                "Monitor for escalation"
            ])
        else:  # LOW
            recommendations.extend([
                "Continue normal monitoring",
                "Schedule routine maintenance",
                "Update security documentation"
            ])
        
        # Classification-specific recommendations
        if classification == ClassificationLevel.TOP_SECRET:
            recommendations.extend([
                "Implement automated immediate response",
                "Activate air-gapped backup systems",
                "Notify classified operations center"
            ])
        elif classification == ClassificationLevel.SECRET:
            recommendations.extend([
                "Escalate to security team immediately",
                "Implement enhanced monitoring",
                "Prepare for potential clearance review"
            ])
        else:  # UNCLASSIFIED
            recommendations.extend([
                "Schedule remediation during next maintenance window",
                "Update standard operating procedures"
            ])
        
        # Event-specific recommendations
        for event in predicted_events:
            if "byzantine" in event.lower():
                recommendations.append("Validate swarm consensus integrity")
            elif "anomaly" in event.lower():
                recommendations.append("Investigate anomalous behavior patterns")
            elif "resource" in event.lower():
                recommendations.append("Optimize resource allocation")
            elif "network" in event.lower():
                recommendations.append("Review network segmentation")
        
        return list(set(recommendations))  # Remove duplicates

    async def get_current_posture(self) -> Optional[SecurityPosture]:
        """
        Get the current security posture assessment.
        
        Returns:
            SecurityPosture object or None if not available
        """
        with self.lock:
            return self.current_posture

    async def update_security_event(self, event: SecurityEvent) -> None:
        """
        Update the system with a new security event.
        
        Args:
            event: New security event to process
        """
        with self.lock:
            self.security_events.append(event)
        
        # Trigger immediate risk assessment if critical
        if event.risk_score > 0.8:
            await self._update_current_posture()

    # Private methods for internal operations
    
    async def _continuous_telemetry_collection(self) -> None:
        """Background task for continuous telemetry collection."""
        while self.running:
            try:
                await self.collect_security_telemetry()
                await asyncio.sleep(30)  # Collect every 30 seconds
            except Exception as e:
                self.logger.error(f"Error in telemetry collection: {e}")
                await asyncio.sleep(60)  # Back off on error

    async def _periodic_model_training(self) -> None:
        """Background task for periodic model retraining."""
        while self.running:
            try:
                await asyncio.sleep(21600)  # Every 6 hours
                await self.train_models(incremental=True)
            except Exception as e:
                self.logger.error(f"Error in model training: {e}")
                await asyncio.sleep(3600)  # Retry in 1 hour

    async def _real_time_risk_assessment(self) -> None:
        """Background task for real-time risk assessment."""
        while self.running:
            try:
                await self._update_current_posture()
                await asyncio.sleep(30)  # Update every 30 seconds
            except Exception as e:
                self.logger.error(f"Error in risk assessment: {e}")
                await asyncio.sleep(60)

    async def _threat_monitoring_loop(self) -> None:
        """Background task for threat monitoring and alerting."""
        while self.running:
            try:
                # Monitor for critical threats
                if self.current_posture:
                    if self.current_posture.risk_level == RiskLevel.CRITICAL:
                        await self._trigger_emergency_response()
                
                await asyncio.sleep(10)  # Check every 10 seconds
            except Exception as e:
                self.logger.error(f"Error in threat monitoring: {e}")
                await asyncio.sleep(30)

    async def _prepare_training_data(self) -> pd.DataFrame:
        """Prepare historical data for model training."""
        # Convert security events to DataFrame
        events_data = []
        for event in list(self.security_events):
            events_data.append({
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'severity': event.severity,
                'classification': event.classification.value,
                'source': event.source,
                'risk_score': event.risk_score,
                'metadata': json.dumps(event.metadata)
            })
        
        return pd.DataFrame(events_data)

    def _calculate_threat_probability(self,
                                    lstm_pred: float,
                                    risk_pred: float,
                                    anomaly_score: float) -> float:
        """Calculate combined threat probability from model predictions."""
        # Weighted ensemble of model predictions
        weights = [0.4, 0.4, 0.2]  # LSTM, Risk, Anomaly
        predictions = [lstm_pred, risk_pred, anomaly_score]
        
        return np.average(predictions, weights=weights)

    def _determine_risk_level(self,
                            threat_probability: float,
                            classification: ClassificationLevel) -> RiskLevel:
        """Determine risk level based on threat probability and classification."""
        threshold = self.classification_thresholds[classification]
        
        if threat_probability >= 0.8:
            return RiskLevel.CRITICAL
        elif threat_probability >= 0.6:
            return RiskLevel.HIGH
        elif threat_probability >= threshold:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _generate_predicted_events(self,
                                 lstm_prediction: float,
                                 risk_level: RiskLevel) -> List[str]:
        """Generate list of predicted security events."""
        events = []
        
        if lstm_prediction > 0.7:
            events.append("high_threat_probability")
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            events.append("security_escalation")
        if len(self.security_events) > 0:
            recent_events = [e for e in self.security_events 
                           if (datetime.now() - e.timestamp).total_seconds() < 3600]
            if len(recent_events) > 5:
                events.append("anomalous_event_frequency")
        
        return events or ["normal_operations"]

    def _calculate_confidence_score(self,
                                  lstm_pred: float,
                                  risk_pred: float,
                                  anomaly_score: float) -> float:
        """Calculate confidence score for the prediction."""
        # Higher confidence when models agree
        predictions = [lstm_pred, risk_pred, anomaly_score]
        variance = np.var(predictions)
        
        # Inverse relationship: lower variance = higher confidence
        confidence = max(0.0, 1.0 - (variance * 2.0))
        return min(confidence, 1.0)

    async def _update_current_posture(self) -> None:
        """Update the current security posture assessment."""
        try:
            # Get recent events
            recent_events = [e for e in self.security_events 
                           if (datetime.now() - e.timestamp).total_seconds() < 3600]
            
            if not recent_events:
                return
            
            # Calculate risk scores
            risk_scores = self.calculate_risk_scores(recent_events)
            
            # Determine overall risk level
            overall_risk = risk_scores['overall_risk']
            if overall_risk >= 0.8:
                risk_level = RiskLevel.CRITICAL
            elif overall_risk >= 0.6:
                risk_level = RiskLevel.HIGH
            elif overall_risk >= 0.3:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW
            
            # Calculate classification-specific risks
            classification_risks = {}
            for level in ClassificationLevel:
                level_events = [e for e in recent_events if e.classification == level]
                if level_events:
                    level_risk_scores = self.calculate_risk_scores(level_events)
                    classification_risks[level] = level_risk_scores['overall_risk']
                else:
                    classification_risks[level] = 0.0
            
            # Update current posture
            with self.lock:
                self.current_posture = SecurityPosture(
                    timestamp=datetime.now(),
                    overall_risk_score=overall_risk,
                    risk_level=risk_level,
                    threat_indicators=risk_scores,
                    security_metrics=self.performance_metrics.copy(),
                    classification_risks=classification_risks,
                    trends=self._calculate_trends()
                )
        
        except Exception as e:
            self.logger.error(f"Error updating security posture: {e}")

    def _calculate_trends(self) -> Dict[str, float]:
        """Calculate security trend metrics."""
        trends = {}
        
        # Calculate event frequency trend
        current_time = datetime.now()
        recent_events = [e for e in self.security_events 
                        if (current_time - e.timestamp).total_seconds() < 3600]
        older_events = [e for e in self.security_events 
                       if 3600 <= (current_time - e.timestamp).total_seconds() < 7200]
        
        recent_rate = len(recent_events)
        older_rate = len(older_events)
        
        if older_rate > 0:
            trends['event_frequency_trend'] = (recent_rate - older_rate) / older_rate
        else:
            trends['event_frequency_trend'] = 0.0
        
        # Calculate risk trend
        if len(recent_events) > 0 and len(older_events) > 0:
            recent_avg_risk = sum(e.risk_score for e in recent_events) / len(recent_events)
            older_avg_risk = sum(e.risk_score for e in older_events) / len(older_events)
            trends['risk_trend'] = (recent_avg_risk - older_avg_risk) / older_avg_risk
        else:
            trends['risk_trend'] = 0.0
        
        return trends

    async def _trigger_emergency_response(self) -> None:
        """Trigger emergency response procedures for critical threats."""
        self.logger.critical("CRITICAL THREAT DETECTED - Triggering emergency response")
        
        # Implementation would integrate with actual emergency systems
        # This is a placeholder for the emergency response logic
        pass

    async def _generate_recommendations(self,
                                      risk_level: RiskLevel,
                                      predicted_events: List[str],
                                      classification: ClassificationLevel
                                      ) -> List[str]:
        """Generate mitigation recommendations (calls the public method)."""
        return await self.generate_recommendations(risk_level, predicted_events, classification)


# Performance monitoring and health check utilities

class SecurityForecasterHealthCheck:
    """Health check utilities for the Security Forecaster."""
    
    def __init__(self, forecaster: SecurityForecaster):
        self.forecaster = forecaster
    
    async def check_system_health(self) -> Dict[str, Any]:
        """Perform comprehensive system health check."""
        health_status = {
            'overall_status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        try:
            # Check if forecaster is running
            health_status['checks']['forecaster_running'] = {
                'status': 'pass' if self.forecaster.running else 'fail',
                'message': 'Forecaster is running' if self.forecaster.running else 'Forecaster is not running'
            }
            
            # Check model training status
            last_training = self.forecaster.model_last_trained
            if last_training:
                hours_since_training = (datetime.now() - min(last_training.values())).total_seconds() / 3600
                health_status['checks']['model_freshness'] = {
                    'status': 'pass' if hours_since_training < 24 else 'warn',
                    'message': f'Models last trained {hours_since_training:.1f} hours ago'
                }
            
            # Check prediction latency
            latency = self.forecaster.performance_metrics.get('prediction_latency', 0)
            health_status['checks']['prediction_latency'] = {
                'status': 'pass' if latency < 0.1 else 'warn',
                'message': f'Prediction latency: {latency:.3f}s'
            }
            
            # Check event queue size
            queue_size = len(self.forecaster.security_events)
            health_status['checks']['event_queue'] = {
                'status': 'pass' if queue_size < 9000 else 'warn',
                'message': f'Event queue size: {queue_size}'
            }
            
            # Determine overall status
            failed_checks = [check for check in health_status['checks'].values() 
                           if check['status'] == 'fail']
            if failed_checks:
                health_status['overall_status'] = 'unhealthy'
            elif any(check['status'] == 'warn' for check in health_status['checks'].values()):
                health_status['overall_status'] = 'degraded'
            
        except Exception as e:
            health_status['overall_status'] = 'unhealthy'
            health_status['error'] = str(e)
        
        return health_status


# Example usage and testing utilities

async def demo_security_forecaster():
    """Demonstration of the Security Forecaster capabilities."""
    
    # Initialize forecaster
    config = {
        'sequence_length': 50,
        'features': 30,
        'collection_interval': 10,
        'risk_model': 'random_forest'
    }
    
    forecaster = SecurityForecaster(config)
    
    try:
        # Start the forecaster
        print("Starting Security Forecaster...")
        await forecaster.start()
        
        # Create sample security events
        events = [
            SecurityEvent(
                timestamp=datetime.now() - timedelta(minutes=5),
                event_type="authentication_failure",
                severity=3,
                classification=ClassificationLevel.SECRET,
                source="auth_service",
                description="Multiple failed login attempts",
                risk_score=0.6,
                metadata={"user": "admin", "attempts": 5}
            ),
            SecurityEvent(
                timestamp=datetime.now() - timedelta(minutes=2),
                event_type="anomalous_behavior",
                severity=4,
                classification=ClassificationLevel.TOP_SECRET,
                source="behavior_monitor",
                description="Unusual data access pattern",
                risk_score=0.8,
                metadata={"data_volume": "high", "access_time": "off_hours"}
            )
        ]
        
        # Process events
        for event in events:
            await forecaster.update_security_event(event)
        
        # Generate forecast
        print("\nGenerating security forecast...")
        forecast = await forecaster.forecast_security_posture(
            horizon=timedelta(hours=24),
            classification=ClassificationLevel.SECRET
        )
        
        print(f"Threat Probability: {forecast.threat_probability:.2f}")
        print(f"Risk Level: {forecast.risk_level.value}")
        print(f"Confidence: {forecast.confidence_score:.2f}")
        print(f"Predicted Events: {forecast.predicted_events}")
        print(f"Recommendations: {forecast.recommendations}")
        
        # Check current posture
        posture = await forecaster.get_current_posture()
        if posture:
            print(f"\nCurrent Security Posture:")
            print(f"Overall Risk: {posture.overall_risk_score:.2f}")
            print(f"Risk Level: {posture.risk_level.value}")
            print(f"Classification Risks: {posture.classification_risks}")
        
        # Health check
        health_checker = SecurityForecasterHealthCheck(forecaster)
        health = await health_checker.check_system_health()
        print(f"\nSystem Health: {health['overall_status']}")
        
    finally:
        # Stop the forecaster
        await forecaster.stop()
        print("Security Forecaster stopped")


if __name__ == "__main__":
    # Run demonstration
    import asyncio
    asyncio.run(demo_security_forecaster()) 