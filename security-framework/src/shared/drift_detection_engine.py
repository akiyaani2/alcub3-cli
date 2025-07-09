"""
ALCUB3 Advanced Drift Detection Engine - Task 4.3.2
Patent-Pending AI-Powered Configuration Drift Detection

This module implements machine learning-based configuration drift detection with
predictive analytics, anomaly detection, and intelligent severity classification.

Key Features:
- Multi-algorithm drift detection with statistical analysis
- Machine learning models for anomaly detection and pattern recognition
- Predictive analytics for future drift forecasting
- AI-powered severity classification with MAESTRO integration
- Real-time drift scoring and risk assessment

Patent Innovations:
- Adaptive drift detection with self-learning baselines
- Multi-dimensional configuration correlation analysis
- Predictive drift modeling with confidence intervals
- Classification-aware drift impact assessment
"""

import os
import json
import time
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import asyncio
import threading
import statistics
import math

# Import MAESTRO framework components
try:
    from .classification import SecurityClassification, ClassificationLevel
    from .audit_logger import AuditLogger, AuditEvent, AuditSeverity, AuditEventType
    from .configuration_baseline_manager import BaselineSnapshot, ConfigurationItem, DriftAnalysis
    MAESTRO_AVAILABLE = True
except ImportError:
    MAESTRO_AVAILABLE = False
    logging.warning("MAESTRO components not available - running in standalone mode")

# Machine Learning imports (with fallbacks)
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.cluster import DBSCAN
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("Machine learning libraries not available - using statistical methods only")


class DriftDetectionMethod(Enum):
    """Methods for detecting configuration drift."""
    STATISTICAL_ANALYSIS = "statistical"
    MACHINE_LEARNING = "ml"
    PATTERN_RECOGNITION = "pattern"
    HYBRID_APPROACH = "hybrid"


class DriftSeverity(Enum):
    """Severity levels for configuration drift."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "info"


class AnomalyType(Enum):
    """Types of configuration anomalies."""
    SUDDEN_CHANGE = "sudden_change"
    GRADUAL_DRIFT = "gradual_drift"
    PATTERN_DEVIATION = "pattern_deviation"
    FREQUENCY_ANOMALY = "frequency_anomaly"
    VALUE_OUTLIER = "value_outlier"


@dataclass
class DriftEvent:
    """Individual configuration drift event."""
    event_id: str
    timestamp: float
    configuration_path: str
    change_type: str
    baseline_value: Any
    current_value: Any
    drift_score: float
    severity: DriftSeverity
    anomaly_type: AnomalyType
    confidence: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class DriftDetectionResult:
    """Result of drift detection analysis."""
    detection_id: str
    analysis_timestamp: float
    baseline_id: str
    drift_events: List[DriftEvent]
    overall_drift_score: float
    total_changes: int
    critical_changes: int
    anomaly_detected: bool
    risk_level: str
    recommendations: List[str]
    confidence_interval: Tuple[float, float]
    classification_level: ClassificationLevel


@dataclass
class DriftPrediction:
    """Predictive drift analysis result."""
    prediction_id: str
    prediction_timestamp: float
    baseline_id: str
    predicted_drift_probability: float
    prediction_horizon_hours: int
    risk_factors: List[str]
    mitigation_recommendations: List[str]
    confidence_score: float
    model_accuracy: float


class ConfigurationAnomalyDetector:
    """
    Advanced anomaly detection for configuration changes using multiple algorithms.
    """
    
    def __init__(self, classification_system: SecurityClassification):
        """Initialize anomaly detector."""
        self.classification = classification_system
        self.logger = logging.getLogger(__name__)
        
        # Statistical models
        self.statistical_models = {
            "z_score_threshold": 3.0,
            "iqr_multiplier": 1.5,
            "moving_average_window": 10,
            "std_deviation_threshold": 2.0
        }
        
        # Machine learning models
        self.ml_models = {}
        if ML_AVAILABLE:
            self._initialize_ml_models()
        
        # Historical data for pattern analysis
        self.change_history = defaultdict(deque)
        self.pattern_cache = {}
        
        self.logger.info("Configuration Anomaly Detector initialized")
    
    def _initialize_ml_models(self):
        """Initialize machine learning models for anomaly detection."""
        try:
            # Isolation Forest for outlier detection
            self.ml_models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Scaler for feature normalization
            self.ml_models['scaler'] = StandardScaler()
            
            # DBSCAN for clustering-based anomaly detection
            self.ml_models['dbscan'] = DBSCAN(eps=0.5, min_samples=5)
            
            self.logger.info("Machine learning models initialized successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to initialize ML models: {e}")
            self.ml_models = {}
    
    async def detect_anomalies(self, 
                             configuration_changes: List[Dict[str, Any]],
                             baseline_data: Dict[str, Any]) -> List[DriftEvent]:
        """
        Detect anomalies in configuration changes using multiple detection methods.
        
        Args:
            configuration_changes: List of configuration changes to analyze
            baseline_data: Baseline configuration data for comparison
            
        Returns:
            List[DriftEvent]: Detected drift events with anomaly information
        """
        drift_events = []
        
        for change in configuration_changes:
            # Statistical anomaly detection
            statistical_anomaly = await self._detect_statistical_anomaly(change, baseline_data)
            
            # Machine learning anomaly detection
            ml_anomaly = None
            if ML_AVAILABLE and self.ml_models:
                ml_anomaly = await self._detect_ml_anomaly(change, baseline_data)
            
            # Pattern-based anomaly detection
            pattern_anomaly = await self._detect_pattern_anomaly(change, baseline_data)
            
            # Combine detection results
            drift_event = await self._combine_anomaly_results(
                change, statistical_anomaly, ml_anomaly, pattern_anomaly
            )
            
            if drift_event:
                drift_events.append(drift_event)
        
        return drift_events
    
    async def _detect_statistical_anomaly(self, 
                                        change: Dict[str, Any],
                                        baseline_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect anomalies using statistical methods."""
        path = change.get('path', '')
        current_value = change.get('current_value')
        baseline_value = change.get('baseline_value')
        
        # Get historical data for this configuration path
        history = self.change_history[path]
        
        if len(history) < 3:  # Need minimum history for statistical analysis
            return None
        
        # Calculate statistical metrics
        values = [item['value'] for item in history if 'value' in item]
        if not values:
            return None
        
        try:
            mean_value = statistics.mean(values)
            std_dev = statistics.stdev(values) if len(values) > 1 else 0
            
            # Z-score analysis
            if std_dev > 0:
                z_score = abs((current_value - mean_value) / std_dev)
                if z_score > self.statistical_models['z_score_threshold']:
                    return {
                        'method': 'z_score',
                        'anomaly_score': z_score,
                        'threshold': self.statistical_models['z_score_threshold'],
                        'anomaly_type': AnomalyType.VALUE_OUTLIER
                    }
            
            # IQR analysis for outlier detection
            q1 = np.percentile(values, 25)
            q3 = np.percentile(values, 75)
            iqr = q3 - q1
            lower_bound = q1 - (self.statistical_models['iqr_multiplier'] * iqr)
            upper_bound = q3 + (self.statistical_models['iqr_multiplier'] * iqr)
            
            if current_value < lower_bound or current_value > upper_bound:
                return {
                    'method': 'iqr',
                    'anomaly_score': max(
                        abs(current_value - lower_bound) / iqr,
                        abs(current_value - upper_bound) / iqr
                    ),
                    'threshold': self.statistical_models['iqr_multiplier'],
                    'anomaly_type': AnomalyType.VALUE_OUTLIER
                }
            
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Statistical analysis failed for {path}: {e}")
        
        return None
    
    async def _detect_ml_anomaly(self, 
                               change: Dict[str, Any],
                               baseline_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect anomalies using machine learning models."""
        if not ML_AVAILABLE or not self.ml_models:
            return None
        
        try:
            path = change.get('path', '')
            current_value = change.get('current_value')
            
            # Get historical features for this configuration path
            history = self.change_history[path]
            if len(history) < 10:  # Need sufficient history for ML
                return None
            
            # Extract features for ML analysis
            features = self._extract_features(change, history)
            if not features:
                return None
            
            # Reshape for sklearn
            feature_array = np.array(features).reshape(1, -1)
            
            # Use Isolation Forest for anomaly detection
            if 'isolation_forest' in self.ml_models:
                isolation_model = self.ml_models['isolation_forest']
                
                # Fit model on historical data if not already fitted
                if not hasattr(isolation_model, 'is_fitted_'):
                    historical_features = [self._extract_features(item, history) for item in history]
                    historical_features = [f for f in historical_features if f]
                    
                    if len(historical_features) >= 5:
                        historical_array = np.array(historical_features)
                        isolation_model.fit(historical_array)
                        isolation_model.is_fitted_ = True
                
                if hasattr(isolation_model, 'is_fitted_'):
                    anomaly_score = isolation_model.decision_function(feature_array)[0]
                    is_anomaly = isolation_model.predict(feature_array)[0] == -1
                    
                    if is_anomaly:
                        return {
                            'method': 'isolation_forest',
                            'anomaly_score': abs(anomaly_score),
                            'threshold': 0.0,
                            'anomaly_type': AnomalyType.PATTERN_DEVIATION
                        }
            
        except Exception as e:
            self.logger.warning(f"ML anomaly detection failed: {e}")
        
        return None
    
    async def _detect_pattern_anomaly(self, 
                                    change: Dict[str, Any],
                                    baseline_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect anomalies based on pattern analysis."""
        path = change.get('path', '')
        timestamp = change.get('timestamp', time.time())
        
        # Get change frequency pattern
        history = self.change_history[path]
        if len(history) < 5:
            return None
        
        # Analyze change frequency
        timestamps = [item['timestamp'] for item in history if 'timestamp' in item]
        timestamps.append(timestamp)
        timestamps.sort()
        
        # Calculate intervals between changes
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if len(intervals) >= 3:
            avg_interval = statistics.mean(intervals)
            current_interval = intervals[-1]
            
            # Check for frequency anomalies
            if current_interval < avg_interval * 0.1:  # Too frequent
                return {
                    'method': 'frequency_pattern',
                    'anomaly_score': avg_interval / current_interval,
                    'threshold': 10.0,
                    'anomaly_type': AnomalyType.FREQUENCY_ANOMALY
                }
            elif current_interval > avg_interval * 5.0:  # Too infrequent
                return {
                    'method': 'frequency_pattern',
                    'anomaly_score': current_interval / avg_interval,
                    'threshold': 5.0,
                    'anomaly_type': AnomalyType.FREQUENCY_ANOMALY
                }
        
        return None
    
    def _extract_features(self, change: Dict[str, Any], history: deque) -> Optional[List[float]]:
        """Extract numerical features for ML analysis."""
        try:
            features = []
            
            # Temporal features
            timestamp = change.get('timestamp', time.time())
            hour_of_day = datetime.fromtimestamp(timestamp).hour
            day_of_week = datetime.fromtimestamp(timestamp).weekday()
            
            features.extend([hour_of_day, day_of_week])
            
            # Value-based features (if numerical)
            current_value = change.get('current_value')
            if isinstance(current_value, (int, float)):
                features.append(float(current_value))
                
                # Historical statistics
                values = [item.get('value', 0) for item in history if isinstance(item.get('value'), (int, float))]
                if values:
                    features.extend([
                        statistics.mean(values),
                        statistics.stdev(values) if len(values) > 1 else 0,
                        min(values),
                        max(values)
                    ])
            
            # Change frequency features
            recent_changes = [item for item in history if timestamp - item.get('timestamp', 0) < 3600]  # Last hour
            features.append(len(recent_changes))
            
            return features if len(features) >= 3 else None
            
        except Exception as e:
            self.logger.warning(f"Feature extraction failed: {e}")
            return None
    
    async def _combine_anomaly_results(self, 
                                     change: Dict[str, Any],
                                     statistical_result: Optional[Dict[str, Any]],
                                     ml_result: Optional[Dict[str, Any]],
                                     pattern_result: Optional[Dict[str, Any]]) -> Optional[DriftEvent]:
        """Combine results from different anomaly detection methods."""
        
        results = [r for r in [statistical_result, ml_result, pattern_result] if r is not None]
        if not results:
            return None
        
        # Calculate combined anomaly score
        total_score = sum(r.get('anomaly_score', 0) for r in results)
        max_score = max(r.get('anomaly_score', 0) for r in results)
        combined_score = (total_score + max_score) / 2
        
        # Determine severity based on combined score
        if combined_score >= 5.0:
            severity = DriftSeverity.CRITICAL
        elif combined_score >= 3.0:
            severity = DriftSeverity.HIGH
        elif combined_score >= 2.0:
            severity = DriftSeverity.MEDIUM
        else:
            severity = DriftSeverity.LOW
        
        # Determine primary anomaly type
        anomaly_types = [r.get('anomaly_type') for r in results]
        primary_anomaly_type = max(set(anomaly_types), key=anomaly_types.count)
        
        # Calculate confidence based on method agreement
        confidence = len(results) / 3.0  # Maximum confidence when all methods agree
        
        # Create drift event
        event_id = f"drift_{int(time.time())}_{change.get('path', 'unknown').replace('/', '_')}"
        
        return DriftEvent(
            event_id=event_id,
            timestamp=change.get('timestamp', time.time()),
            configuration_path=change.get('path', ''),
            change_type=change.get('change_type', 'unknown'),
            baseline_value=change.get('baseline_value'),
            current_value=change.get('current_value'),
            drift_score=combined_score,
            severity=severity,
            anomaly_type=primary_anomaly_type,
            confidence=confidence,
            metadata={
                'detection_methods': [r.get('method') for r in results],
                'individual_scores': [r.get('anomaly_score') for r in results],
                'thresholds': [r.get('threshold') for r in results]
            }
        )


class DriftPatternAnalyzer:
    """
    Pattern analysis for configuration drift with trend detection and prediction.
    """
    
    def __init__(self, classification_system: SecurityClassification):
        """Initialize drift pattern analyzer."""
        self.classification = classification_system
        self.logger = logging.getLogger(__name__)
        
        # Pattern recognition models
        self.pattern_models = {
            'trend_window_hours': 24,
            'seasonal_patterns': {},
            'drift_velocity_threshold': 0.1,
            'pattern_confidence_threshold': 0.7
        }
        
        # Historical pattern data
        self.pattern_history = defaultdict(list)
        self.trend_cache = {}
        
        self.logger.info("Drift Pattern Analyzer initialized")
    
    async def analyze_drift_patterns(self, 
                                   drift_events: List[DriftEvent],
                                   time_window_hours: int = 24) -> Dict[str, Any]:
        """Analyze patterns in configuration drift events."""
        
        if not drift_events:
            return {'patterns_detected': False}
        
        # Group events by configuration path
        events_by_path = defaultdict(list)
        for event in drift_events:
            events_by_path[event.configuration_path].append(event)
        
        patterns = {}
        
        for path, path_events in events_by_path.items():
            # Temporal pattern analysis
            temporal_patterns = await self._analyze_temporal_patterns(path_events)
            
            # Severity trend analysis
            severity_trends = await self._analyze_severity_trends(path_events)
            
            # Frequency pattern analysis
            frequency_patterns = await self._analyze_frequency_patterns(path_events)
            
            patterns[path] = {
                'temporal_patterns': temporal_patterns,
                'severity_trends': severity_trends,
                'frequency_patterns': frequency_patterns,
                'total_events': len(path_events),
                'risk_assessment': await self._assess_path_risk(path_events)
            }
        
        return {
            'patterns_detected': True,
            'analysis_timestamp': time.time(),
            'patterns_by_path': patterns,
            'overall_risk_level': await self._calculate_overall_risk(patterns)
        }
    
    async def _analyze_temporal_patterns(self, events: List[DriftEvent]) -> Dict[str, Any]:
        """Analyze temporal patterns in drift events."""
        if len(events) < 3:
            return {'insufficient_data': True}
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        # Analyze time intervals
        intervals = []
        for i in range(len(sorted_events) - 1):
            interval = sorted_events[i+1].timestamp - sorted_events[i].timestamp
            intervals.append(interval)
        
        # Calculate pattern metrics
        avg_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Detect patterns
        patterns = {
            'average_interval_hours': avg_interval / 3600,
            'interval_variability': std_interval / avg_interval if avg_interval > 0 else 0,
            'trend': 'stable'
        }
        
        # Trend detection
        if len(intervals) >= 5:
            # Simple linear regression for trend
            x = list(range(len(intervals)))
            y = intervals
            
            if len(x) == len(y):
                # Calculate correlation coefficient
                n = len(x)
                sum_x = sum(x)
                sum_y = sum(y)
                sum_xy = sum(x[i] * y[i] for i in range(n))
                sum_x2 = sum(xi ** 2 for xi in x)
                
                correlation = (n * sum_xy - sum_x * sum_y) / math.sqrt((n * sum_x2 - sum_x**2) * (n * sum(yi**2 for yi in y) - sum_y**2))
                
                if correlation > 0.5:
                    patterns['trend'] = 'increasing'
                elif correlation < -0.5:
                    patterns['trend'] = 'decreasing'
        
        return patterns
    
    async def _analyze_severity_trends(self, events: List[DriftEvent]) -> Dict[str, Any]:
        """Analyze trends in event severity over time."""
        if len(events) < 3:
            return {'insufficient_data': True}
        
        # Map severity to numeric values
        severity_values = {
            DriftSeverity.INFORMATIONAL: 1,
            DriftSeverity.LOW: 2,
            DriftSeverity.MEDIUM: 3,
            DriftSeverity.HIGH: 4,
            DriftSeverity.CRITICAL: 5
        }
        
        # Sort events and extract severity values
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        severities = [severity_values.get(event.severity, 1) for event in sorted_events]
        
        # Calculate trend metrics
        avg_severity = statistics.mean(severities)
        recent_avg = statistics.mean(severities[-3:]) if len(severities) >= 3 else avg_severity
        
        trend_direction = 'stable'
        if recent_avg > avg_severity * 1.2:
            trend_direction = 'escalating'
        elif recent_avg < avg_severity * 0.8:
            trend_direction = 'improving'
        
        return {
            'average_severity': avg_severity,
            'recent_average_severity': recent_avg,
            'trend_direction': trend_direction,
            'severity_distribution': {
                severity.value: severities.count(severity_values[severity])
                for severity in DriftSeverity
                if severity in [event.severity for event in events]
            }
        }
    
    async def _analyze_frequency_patterns(self, events: List[DriftEvent]) -> Dict[str, Any]:
        """Analyze frequency patterns in drift events."""
        if len(events) < 5:
            return {'insufficient_data': True}
        
        # Group events by hour of day and day of week
        hours = defaultdict(int)
        days = defaultdict(int)
        
        for event in events:
            dt = datetime.fromtimestamp(event.timestamp)
            hours[dt.hour] += 1
            days[dt.weekday()] += 1
        
        # Find peak hours and days
        peak_hour = max(hours.items(), key=lambda x: x[1])[0] if hours else None
        peak_day = max(days.items(), key=lambda x: x[1])[0] if days else None
        
        return {
            'total_events': len(events),
            'peak_hour': peak_hour,
            'peak_day': peak_day,
            'hourly_distribution': dict(hours),
            'daily_distribution': dict(days),
            'events_per_day': len(events) / max(1, len(set(datetime.fromtimestamp(e.timestamp).date() for e in events)))
        }
    
    async def _assess_path_risk(self, events: List[DriftEvent]) -> str:
        """Assess risk level for a configuration path based on its events."""
        if not events:
            return 'low'
        
        # Count critical and high severity events
        critical_count = sum(1 for e in events if e.severity == DriftSeverity.CRITICAL)
        high_count = sum(1 for e in events if e.severity == DriftSeverity.HIGH)
        
        # Risk assessment logic
        if critical_count > 0:
            return 'critical'
        elif high_count >= 3:
            return 'high'
        elif len(events) >= 10:
            return 'medium'
        else:
            return 'low'
    
    async def _calculate_overall_risk(self, patterns: Dict[str, Any]) -> str:
        """Calculate overall risk level from all pattern analyses."""
        if not patterns:
            return 'low'
        
        risk_levels = [pattern.get('risk_assessment', 'low') for pattern in patterns.values()]
        
        # Count risk levels
        critical_count = risk_levels.count('critical')
        high_count = risk_levels.count('high')
        medium_count = risk_levels.count('medium')
        
        # Overall risk assessment
        if critical_count > 0:
            return 'critical'
        elif high_count >= 2:
            return 'high'
        elif high_count >= 1 or medium_count >= 3:
            return 'medium'
        else:
            return 'low'


class AdvancedDriftDetectionEngine:
    """
    AI-Powered Configuration Drift Detection Engine
    
    Uses machine learning models to predict drift and classify
    configuration changes by severity and impact.
    """
    
    def __init__(self, classification_system: SecurityClassification):
        """Initialize advanced drift detection engine."""
        self.classification = classification_system
        self.logger = logging.getLogger(__name__)
        
        # Initialize sub-components
        self.anomaly_detector = ConfigurationAnomalyDetector(classification_system)
        self.pattern_analyzer = DriftPatternAnalyzer(classification_system)
        
        # Detection configuration
        self.detection_config = {
            'detection_methods': [DriftDetectionMethod.HYBRID_APPROACH],
            'sensitivity_level': 'medium',
            'prediction_horizon_hours': 24,
            'confidence_threshold': 0.7
        }
        
        # Performance tracking
        self.performance_metrics = {
            'total_detections': 0,
            'false_positives': 0,
            'detection_accuracy': 0.0,
            'average_detection_time_ms': 0.0
        }
        
        self.logger.info("Advanced Drift Detection Engine initialized")
    
    async def detect_drift(self, 
                          baseline: BaselineSnapshot,
                          current_config: Dict[str, Any]) -> DriftDetectionResult:
        """
        Multi-algorithm drift detection with ML scoring.
        
        Args:
            baseline: Baseline configuration snapshot
            current_config: Current configuration state
            
        Returns:
            DriftDetectionResult: Comprehensive drift analysis with ML insights
        """
        detection_start = time.time()
        detection_id = f"detection_{int(time.time())}"
        
        try:
            self.logger.info(f"Starting drift detection {detection_id}")
            
            # Convert baseline to comparable format
            baseline_config = {item.path: item.value for item in baseline.configuration_items}
            
            # Identify configuration changes
            changes = await self._identify_changes(baseline_config, current_config)
            
            # Detect anomalies in changes
            drift_events = await self.anomaly_detector.detect_anomalies(changes, baseline_config)
            
            # Analyze patterns in drift events
            pattern_analysis = await self.pattern_analyzer.analyze_drift_patterns(drift_events)
            
            # Calculate overall drift score
            overall_score = await self._calculate_drift_score(drift_events, pattern_analysis)
            
            # Assess risk level
            risk_level = await self._assess_risk_level(drift_events, overall_score)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(drift_events, pattern_analysis)
            
            # Calculate confidence interval
            confidence_interval = await self._calculate_confidence_interval(drift_events)
            
            # Count critical changes
            critical_changes = sum(1 for event in drift_events if event.severity == DriftSeverity.CRITICAL)
            
            # Create detection result
            result = DriftDetectionResult(
                detection_id=detection_id,
                analysis_timestamp=time.time(),
                baseline_id=baseline.baseline_id,
                drift_events=drift_events,
                overall_drift_score=overall_score,
                total_changes=len(changes),
                critical_changes=critical_changes,
                anomaly_detected=len(drift_events) > 0,
                risk_level=risk_level,
                recommendations=recommendations,
                confidence_interval=confidence_interval,
                classification_level=baseline.classification_level
            )
            
            # Update performance metrics
            detection_time = (time.time() - detection_start) * 1000
            self._update_performance_metrics(detection_time)
            
            self.logger.info(
                f"Drift detection {detection_id} completed in {detection_time:.2f}ms: "
                f"{len(drift_events)} events, score={overall_score:.3f}, risk={risk_level}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Drift detection failed: {e}")
            raise
    
    async def predict_future_drift(self, 
                                 config_history: List[Dict[str, Any]]) -> DriftPrediction:
        """
        Predictive analytics for potential configuration drift.
        
        Args:
            config_history: Historical configuration data
            
        Returns:
            DriftPrediction: Prediction of future drift probability
        """
        prediction_id = f"prediction_{int(time.time())}"
        
        try:
            if len(config_history) < 10:
                return DriftPrediction(
                    prediction_id=prediction_id,
                    prediction_timestamp=time.time(),
                    baseline_id="insufficient_history",
                    predicted_drift_probability=0.0,
                    prediction_horizon_hours=self.detection_config['prediction_horizon_hours'],
                    risk_factors=["Insufficient historical data for prediction"],
                    mitigation_recommendations=["Collect more historical data"],
                    confidence_score=0.0,
                    model_accuracy=0.0
                )
            
            # Analyze historical trends
            trend_analysis = await self._analyze_historical_trends(config_history)
            
            # Calculate drift probability
            drift_probability = await self._calculate_drift_probability(trend_analysis)
            
            # Identify risk factors
            risk_factors = await self._identify_risk_factors(trend_analysis)
            
            # Generate mitigation recommendations
            mitigation_recs = await self._generate_mitigation_recommendations(risk_factors)
            
            # Calculate confidence score
            confidence_score = await self._calculate_prediction_confidence(trend_analysis)
            
            return DriftPrediction(
                prediction_id=prediction_id,
                prediction_timestamp=time.time(),
                baseline_id="historical_analysis",
                predicted_drift_probability=drift_probability,
                prediction_horizon_hours=self.detection_config['prediction_horizon_hours'],
                risk_factors=risk_factors,
                mitigation_recommendations=mitigation_recs,
                confidence_score=confidence_score,
                model_accuracy=self.performance_metrics.get('detection_accuracy', 0.0)
            )
            
        except Exception as e:
            self.logger.error(f"Drift prediction failed: {e}")
            raise
    
    async def classify_drift_severity(self, 
                                    drift_events: List[DriftEvent]) -> Dict[str, Any]:
        """
        AI-powered severity classification with MAESTRO integration.
        
        Args:
            drift_events: List of drift events to classify
            
        Returns:
            Dict: Severity classification results
        """
        if not drift_events:
            return {'classification': 'no_drift', 'severity_score': 0.0}
        
        # Calculate severity distribution
        severity_counts = defaultdict(int)
        for event in drift_events:
            severity_counts[event.severity.value] += 1
        
        # Calculate weighted severity score
        severity_weights = {
            'informational': 1,
            'low': 2,
            'medium': 4,
            'high': 8,
            'critical': 16
        }
        
        total_weight = sum(severity_weights[severity] * count 
                          for severity, count in severity_counts.items())
        total_events = len(drift_events)
        
        normalized_score = total_weight / (total_events * 16)  # Normalize to 0-1 scale
        
        # Determine overall classification
        if normalized_score >= 0.8:
            classification = 'critical_drift'
        elif normalized_score >= 0.6:
            classification = 'significant_drift'
        elif normalized_score >= 0.4:
            classification = 'moderate_drift'
        elif normalized_score >= 0.2:
            classification = 'minor_drift'
        else:
            classification = 'negligible_drift'
        
        return {
            'classification': classification,
            'severity_score': normalized_score,
            'severity_distribution': dict(severity_counts),
            'total_events': total_events,
            'critical_events': severity_counts.get('critical', 0),
            'high_severity_events': severity_counts.get('high', 0) + severity_counts.get('critical', 0)
        }
    
    # Helper methods
    async def _identify_changes(self, 
                              baseline_config: Dict[str, Any],
                              current_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify configuration changes between baseline and current state."""
        changes = []
        
        # Check for modified items
        for path, current_value in current_config.items():
            if path in baseline_config:
                if baseline_config[path] != current_value:
                    changes.append({
                        'path': path,
                        'change_type': 'modified',
                        'baseline_value': baseline_config[path],
                        'current_value': current_value,
                        'timestamp': time.time()
                    })
        
        # Check for new items
        for path, current_value in current_config.items():
            if path not in baseline_config:
                changes.append({
                    'path': path,
                    'change_type': 'added',
                    'baseline_value': None,
                    'current_value': current_value,
                    'timestamp': time.time()
                })
        
        # Check for removed items
        for path, baseline_value in baseline_config.items():
            if path not in current_config:
                changes.append({
                    'path': path,
                    'change_type': 'removed',
                    'baseline_value': baseline_value,
                    'current_value': None,
                    'timestamp': time.time()
                })
        
        return changes
    
    async def _calculate_drift_score(self, 
                                   drift_events: List[DriftEvent],
                                   pattern_analysis: Dict[str, Any]) -> float:
        """Calculate overall drift score from events and patterns."""
        if not drift_events:
            return 0.0
        
        # Base score from individual events
        event_scores = [event.drift_score for event in drift_events]
        base_score = statistics.mean(event_scores)
        
        # Pattern-based adjustments
        pattern_multiplier = 1.0
        if pattern_analysis.get('patterns_detected'):
            overall_risk = pattern_analysis.get('overall_risk_level', 'low')
            risk_multipliers = {'low': 1.0, 'medium': 1.2, 'high': 1.5, 'critical': 2.0}
            pattern_multiplier = risk_multipliers.get(overall_risk, 1.0)
        
        # Critical event penalty
        critical_events = sum(1 for event in drift_events if event.severity == DriftSeverity.CRITICAL)
        critical_penalty = min(critical_events * 0.5, 2.0)
        
        return min(base_score * pattern_multiplier + critical_penalty, 10.0)
    
    async def _assess_risk_level(self, drift_events: List[DriftEvent], drift_score: float) -> str:
        """Assess overall risk level based on drift events and score."""
        critical_events = sum(1 for event in drift_events if event.severity == DriftSeverity.CRITICAL)
        
        if critical_events > 0 or drift_score >= 8.0:
            return 'critical'
        elif drift_score >= 6.0:
            return 'high'
        elif drift_score >= 4.0:
            return 'medium'
        elif drift_score >= 2.0:
            return 'low'
        else:
            return 'negligible'
    
    async def _generate_recommendations(self, 
                                      drift_events: List[DriftEvent],
                                      pattern_analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations for addressing drift."""
        recommendations = []
        
        if not drift_events:
            return ["No configuration drift detected. Continue monitoring."]
        
        critical_events = [e for e in drift_events if e.severity == DriftSeverity.CRITICAL]
        if critical_events:
            recommendations.append(
                f"URGENT: {len(critical_events)} critical configuration changes require immediate attention."
            )
        
        # Pattern-based recommendations
        if pattern_analysis.get('patterns_detected'):
            overall_risk = pattern_analysis.get('overall_risk_level', 'low')
            if overall_risk in ['high', 'critical']:
                recommendations.append(
                    "Systematic configuration drift detected. Consider automated remediation."
                )
        
        # Frequency-based recommendations
        high_frequency_paths = []
        for path, pattern in pattern_analysis.get('patterns_by_path', {}).items():
            freq_pattern = pattern.get('frequency_patterns', {})
            events_per_day = freq_pattern.get('events_per_day', 0)
            if events_per_day > 5:
                high_frequency_paths.append(path)
        
        if high_frequency_paths:
            recommendations.append(
                f"High-frequency changes detected in {len(high_frequency_paths)} configurations. "
                "Review change management processes."
            )
        
        if not recommendations:
            recommendations.append("Monitor drift trends and implement preventive measures.")
        
        return recommendations
    
    async def _calculate_confidence_interval(self, drift_events: List[DriftEvent]) -> Tuple[float, float]:
        """Calculate confidence interval for drift detection."""
        if not drift_events:
            return (0.0, 0.0)
        
        confidences = [event.confidence for event in drift_events]
        mean_confidence = statistics.mean(confidences)
        
        if len(confidences) > 1:
            std_confidence = statistics.stdev(confidences)
            margin = 1.96 * std_confidence / math.sqrt(len(confidences))  # 95% confidence interval
            return (max(0.0, mean_confidence - margin), min(1.0, mean_confidence + margin))
        else:
            return (mean_confidence, mean_confidence)
    
    def _update_performance_metrics(self, detection_time_ms: float):
        """Update performance tracking metrics."""
        self.performance_metrics['total_detections'] += 1
        
        # Update average detection time
        current_avg = self.performance_metrics['average_detection_time_ms']
        total_detections = self.performance_metrics['total_detections']
        
        new_avg = ((current_avg * (total_detections - 1)) + detection_time_ms) / total_detections
        self.performance_metrics['average_detection_time_ms'] = new_avg 