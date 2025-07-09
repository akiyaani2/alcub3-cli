"""
Anomaly Detection System

Advanced anomaly detection for security event monitoring using multiple
detection algorithms including Isolation Forest, One-Class SVM, and
statistical methods.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
import logging
import pickle
import os
from dataclasses import dataclass
from enum import Enum
import asyncio
from collections import deque
import warnings
warnings.filterwarnings('ignore')

# Scikit-learn imports
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.covariance import EllipticEnvelope
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN

# Statistical methods
from scipy import stats
from scipy.stats import zscore
import statistics


class AnomalyMethod(Enum):
    """Anomaly detection methods."""
    ISOLATION_FOREST = "isolation_forest"
    ONE_CLASS_SVM = "one_class_svm"
    ELLIPTIC_ENVELOPE = "elliptic_envelope"
    LOCAL_OUTLIER_FACTOR = "local_outlier_factor"
    STATISTICAL_ZSCORE = "statistical_zscore"
    ENSEMBLE = "ensemble"


class AnomalyType(Enum):
    """Types of anomalies detected."""
    POINT_ANOMALY = "point"
    CONTEXTUAL_ANOMALY = "contextual"
    COLLECTIVE_ANOMALY = "collective"
    TEMPORAL_ANOMALY = "temporal"


@dataclass
class AnomalyDetection:
    """Anomaly detection result."""
    timestamp: datetime
    is_anomaly: bool
    anomaly_score: float
    anomaly_type: AnomalyType
    confidence: float
    method_scores: Dict[AnomalyMethod, float]
    feature_contributions: Dict[str, float]
    reasoning: List[str]


@dataclass
class AnomalyPattern:
    """Detected anomaly pattern."""
    pattern_id: str
    first_detected: datetime
    last_detected: datetime
    frequency: int
    severity: float
    pattern_type: AnomalyType
    features_involved: List[str]
    description: str


class AnomalyDetector:
    """
    Advanced anomaly detection system for security monitoring.
    
    Features:
    - Multiple detection algorithms
    - Ensemble methods
    - Temporal anomaly detection
    - Pattern recognition
    - Adaptive thresholds
    - Real-time processing
    """
    
    def __init__(self,
                 method: str = 'isolation_forest',
                 contamination: float = 0.1,
                 window_size: int = 1000,
                 model_path: Optional[str] = None):
        """
        Initialize anomaly detector.
        
        Args:
            method: Detection method to use
            contamination: Expected proportion of outliers
            window_size: Window size for temporal analysis
            model_path: Path to saved model
        """
        self.method = AnomalyMethod(method)
        self.contamination = contamination
        self.window_size = window_size
        self.model_path = model_path or f"models/anomaly_detector_{method}.pkl"
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize models
        self.models = {}
        self.scalers = {}
        self.thresholds = {}
        
        # Data management
        self.data_window = deque(maxlen=window_size)
        self.anomaly_history = deque(maxlen=1000)
        self.pattern_history = {}
        
        # Performance tracking
        self.performance_metrics = {}
        self.last_training_time = None
        
        # Feature tracking
        self.feature_names = []
        self.feature_statistics = {}
        
        # Initialize models
        self._initialize_models()
        
        # Try to load existing model
        if os.path.exists(self.model_path):
            try:
                self.load_model(self.model_path)
                self.logger.info(f"Loaded existing model from {self.model_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load existing model: {e}")
        
        self.logger.info(f"Anomaly Detector initialized with {self.method.value} method")
    
    def _initialize_models(self) -> None:
        """Initialize all anomaly detection models."""
        
        # Isolation Forest
        self.models[AnomalyMethod.ISOLATION_FOREST] = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1
        )
        
        # One-Class SVM
        self.models[AnomalyMethod.ONE_CLASS_SVM] = OneClassSVM(
            nu=self.contamination,
            kernel='rbf',
            gamma='scale'
        )
        
        # Elliptic Envelope
        self.models[AnomalyMethod.ELLIPTIC_ENVELOPE] = EllipticEnvelope(
            contamination=self.contamination,
            random_state=42
        )
        
        # Local Outlier Factor
        self.models[AnomalyMethod.LOCAL_OUTLIER_FACTOR] = LocalOutlierFactor(
            n_neighbors=20,
            contamination=self.contamination,
            novelty=True
        )
        
        # Initialize scalers
        for method in AnomalyMethod:
            if method != AnomalyMethod.STATISTICAL_ZSCORE:
                self.scalers[method] = StandardScaler()
        
        # Statistical thresholds
        self.thresholds[AnomalyMethod.STATISTICAL_ZSCORE] = 3.0
    
    async def train(self,
                   training_data: pd.DataFrame,
                   incremental: bool = False) -> Dict[str, Any]:
        """
        Train anomaly detection models.
        
        Args:
            training_data: DataFrame with normal behavior data
            incremental: Whether to perform incremental learning
            
        Returns:
            Dictionary with training metrics
        """
        try:
            start_time = datetime.now()
            
            if training_data.empty:
                return {'error': 'No training data provided'}
            
            # Prepare features
            X = self._extract_features(training_data)
            
            if len(X) == 0:
                return {'error': 'No valid features extracted'}
            
            # Update data window
            for row in X:
                self.data_window.append(row)
            
            # Calculate feature statistics
            self._calculate_feature_statistics(X)
            
            # Train models
            training_results = {}
            
            if self.method == AnomalyMethod.ENSEMBLE:
                # Train all models
                for method in AnomalyMethod:
                    if method != AnomalyMethod.ENSEMBLE:
                        result = await self._train_single_model(method, X, incremental)
                        training_results[method.value] = result
            else:
                # Train single model
                result = await self._train_single_model(self.method, X, incremental)
                training_results[self.method.value] = result
            
            # Update training metadata
            self.last_training_time = datetime.now()
            training_time = (self.last_training_time - start_time).total_seconds()
            
            metrics = {
                'training_time': training_time,
                'training_samples': len(X),
                'features': len(self.feature_names),
                'method': self.method.value,
                'contamination': self.contamination,
                'models_trained': training_results
            }
            
            self.performance_metrics = metrics
            
            # Save model
            self.save_model(self.model_path)
            
            self.logger.info(f"Anomaly detector training completed in {training_time:.2f}s")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error training anomaly detector: {e}")
            return {'error': str(e)}
    
    async def _train_single_model(self,
                                 method: AnomalyMethod,
                                 X: np.ndarray,
                                 incremental: bool) -> Dict[str, Any]:
        """Train a single anomaly detection model."""
        try:
            if method == AnomalyMethod.STATISTICAL_ZSCORE:
                # Statistical method doesn't need training
                return {'status': 'ready', 'method': 'statistical'}
            
            # Scale features
            X_scaled = self.scalers[method].fit_transform(X)
            
            # Train model
            if method == AnomalyMethod.LOCAL_OUTLIER_FACTOR:
                # LOF is fit during prediction
                self.models[method].fit(X_scaled)
            else:
                self.models[method].fit(X_scaled)
            
            # Validation: predict on training data
            if method == AnomalyMethod.LOCAL_OUTLIER_FACTOR:
                predictions = self.models[method].predict(X_scaled)
            else:
                predictions = self.models[method].predict(X_scaled)
            
            # Calculate metrics
            n_outliers = np.sum(predictions == -1)
            outlier_rate = n_outliers / len(predictions)
            
            return {
                'status': 'trained',
                'outlier_rate': float(outlier_rate),
                'n_outliers': int(n_outliers),
                'training_samples': len(X)
            }
            
        except Exception as e:
            self.logger.error(f"Error training {method.value} model: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def predict(self, features: pd.DataFrame) -> float:
        """
        Predict anomaly score for given features.
        
        Args:
            features: DataFrame with feature values
            
        Returns:
            Anomaly score [0,1] where 1 indicates high anomaly
        """
        try:
            # Extract features
            X = self._extract_features(features)
            
            if len(X) == 0:
                return 0.0
            
            # Get predictions from all models
            if self.method == AnomalyMethod.ENSEMBLE:
                scores = []
                for method in AnomalyMethod:
                    if method != AnomalyMethod.ENSEMBLE:
                        score = await self._predict_single_model(method, X[0])
                        scores.append(score)
                
                # Ensemble score (average)
                return float(np.mean(scores))
            else:
                return await self._predict_single_model(self.method, X[0])
                
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return 0.0
    
    async def _predict_single_model(self,
                                   method: AnomalyMethod,
                                   features: np.ndarray) -> float:
        """Predict anomaly score using a single model."""
        try:
            if method == AnomalyMethod.STATISTICAL_ZSCORE:
                return self._statistical_anomaly_score(features)
            
            if method not in self.models:
                return 0.0
            
            # Scale features
            features_scaled = self.scalers[method].transform(features.reshape(1, -1))
            
            # Get prediction
            model = self.models[method]
            
            if method == AnomalyMethod.ISOLATION_FOREST:
                # Isolation Forest: decision_function returns anomaly score
                score = model.decision_function(features_scaled)[0]
                # Convert to [0,1] range (lower values = more anomalous)
                return float(max(0, min(1, (0.5 - score) / 0.5)))
            
            elif method == AnomalyMethod.ONE_CLASS_SVM:
                # One-Class SVM: decision_function returns signed distance
                score = model.decision_function(features_scaled)[0]
                # Convert to [0,1] range (negative values = anomalous)
                return float(max(0, min(1, -score if score < 0 else 0)))
            
            elif method == AnomalyMethod.ELLIPTIC_ENVELOPE:
                # Elliptic Envelope: decision_function returns Mahalanobis distance
                score = model.decision_function(features_scaled)[0]
                # Convert to [0,1] range
                return float(max(0, min(1, -score if score < 0 else 0)))
            
            elif method == AnomalyMethod.LOCAL_OUTLIER_FACTOR:
                # LOF: negative_outlier_factor_ returns LOF values
                score = model.negative_outlier_factor_[0] if hasattr(model, 'negative_outlier_factor_') else 0
                # Convert LOF to anomaly score
                return float(max(0, min(1, (score - 1) / 2 if score > 1 else 0)))
            
            else:
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Error predicting with {method.value}: {e}")
            return 0.0
    
    def _statistical_anomaly_score(self, features: np.ndarray) -> float:
        """Calculate anomaly score using statistical methods."""
        try:
            if not self.feature_statistics:
                return 0.0
            
            max_zscore = 0.0
            
            for i, feature_val in enumerate(features):
                if i < len(self.feature_names):
                    feature_name = self.feature_names[i]
                    
                    if feature_name in self.feature_statistics:
                        mean = self.feature_statistics[feature_name]['mean']
                        std = self.feature_statistics[feature_name]['std']
                        
                        if std > 0:
                            zscore = abs((feature_val - mean) / std)
                            max_zscore = max(max_zscore, zscore)
            
            # Convert z-score to anomaly score [0,1]
            threshold = self.thresholds[AnomalyMethod.STATISTICAL_ZSCORE]
            return float(min(1.0, max_zscore / threshold))
            
        except Exception as e:
            self.logger.error(f"Error calculating statistical anomaly score: {e}")
            return 0.0
    
    async def detect_anomaly(self, features: pd.DataFrame) -> AnomalyDetection:
        """
        Comprehensive anomaly detection with detailed analysis.
        
        Args:
            features: DataFrame with feature values
            
        Returns:
            AnomalyDetection with detailed results
        """
        try:
            # Extract features
            X = self._extract_features(features)
            
            if len(X) == 0:
                return self._default_detection()
            
            feature_vector = X[0]
            
            # Get scores from all methods
            method_scores = {}
            
            if self.method == AnomalyMethod.ENSEMBLE:
                for method in AnomalyMethod:
                    if method != AnomalyMethod.ENSEMBLE:
                        score = await self._predict_single_model(method, feature_vector)
                        method_scores[method] = score
            else:
                score = await self._predict_single_model(self.method, feature_vector)
                method_scores[self.method] = score
            
            # Calculate overall anomaly score
            overall_score = np.mean(list(method_scores.values()))
            
            # Determine if anomaly
            is_anomaly = overall_score > 0.5
            
            # Determine anomaly type
            anomaly_type = self._classify_anomaly_type(feature_vector, overall_score)
            
            # Calculate confidence
            confidence = self._calculate_confidence(method_scores)
            
            # Feature contributions
            feature_contributions = self._calculate_feature_contributions(feature_vector)
            
            # Generate reasoning
            reasoning = self._generate_reasoning(
                is_anomaly, overall_score, anomaly_type, feature_contributions
            )
            
            # Create detection result
            detection = AnomalyDetection(
                timestamp=datetime.now(),
                is_anomaly=is_anomaly,
                anomaly_score=overall_score,
                anomaly_type=anomaly_type,
                confidence=confidence,
                method_scores=method_scores,
                feature_contributions=feature_contributions,
                reasoning=reasoning
            )
            
            # Store in history
            self.anomaly_history.append(detection)
            
            # Update patterns
            if is_anomaly:
                await self._update_anomaly_patterns(detection)
            
            return detection
            
        except Exception as e:
            self.logger.error(f"Error detecting anomaly: {e}")
            return self._default_detection()
    
    def _classify_anomaly_type(self, features: np.ndarray, score: float) -> AnomalyType:
        """Classify the type of anomaly detected."""
        try:
            # Simple heuristic-based classification
            if score > 0.8:
                return AnomalyType.POINT_ANOMALY
            elif len(self.anomaly_history) > 0:
                # Check for temporal patterns
                recent_anomalies = [a for a in self.anomaly_history
                                  if (datetime.now() - a.timestamp).total_seconds() < 300]
                if len(recent_anomalies) > 3:
                    return AnomalyType.TEMPORAL_ANOMALY
            
            return AnomalyType.CONTEXTUAL_ANOMALY
            
        except Exception as e:
            self.logger.error(f"Error classifying anomaly type: {e}")
            return AnomalyType.POINT_ANOMALY
    
    def _calculate_confidence(self, method_scores: Dict[AnomalyMethod, float]) -> float:
        """Calculate confidence in the anomaly detection."""
        try:
            if not method_scores:
                return 0.0
            
            scores = list(method_scores.values())
            
            # Higher confidence when methods agree
            variance = np.var(scores)
            mean_score = np.mean(scores)
            
            # Confidence is higher when:
            # 1. Methods agree (low variance)
            # 2. Score is extreme (close to 0 or 1)
            agreement_factor = max(0, 1 - variance * 4)
            extremeness_factor = abs(mean_score - 0.5) * 2
            
            confidence = (agreement_factor + extremeness_factor) / 2
            return float(min(1.0, max(0.0, confidence)))
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence: {e}")
            return 0.5
    
    def _calculate_feature_contributions(self, features: np.ndarray) -> Dict[str, float]:
        """Calculate how much each feature contributes to the anomaly score."""
        try:
            contributions = {}
            
            if not self.feature_statistics or len(features) != len(self.feature_names):
                return contributions
            
            for i, (feature_name, feature_val) in enumerate(zip(self.feature_names, features)):
                if feature_name in self.feature_statistics:
                    mean = self.feature_statistics[feature_name]['mean']
                    std = self.feature_statistics[feature_name]['std']
                    
                    if std > 0:
                        # Normalized deviation from mean
                        deviation = abs(feature_val - mean) / std
                        contributions[feature_name] = float(min(1.0, deviation / 3.0))
                    else:
                        contributions[feature_name] = 0.0
                else:
                    contributions[feature_name] = 0.0
            
            return contributions
            
        except Exception as e:
            self.logger.error(f"Error calculating feature contributions: {e}")
            return {}
    
    def _generate_reasoning(self,
                           is_anomaly: bool,
                           score: float,
                           anomaly_type: AnomalyType,
                           feature_contributions: Dict[str, float]) -> List[str]:
        """Generate human-readable reasoning for the detection."""
        reasoning = []
        
        # Overall assessment
        if is_anomaly:
            reasoning.append(f"Anomaly detected with score {score:.3f}")
        else:
            reasoning.append(f"Normal behavior detected with score {score:.3f}")
        
        # Anomaly type
        reasoning.append(f"Anomaly type: {anomaly_type.value}")
        
        # Feature contributions
        if feature_contributions:
            high_contrib_features = [name for name, contrib in feature_contributions.items()
                                   if contrib > 0.5]
            if high_contrib_features:
                reasoning.append(f"High anomaly features: {', '.join(high_contrib_features)}")
        
        # Severity assessment
        if score > 0.8:
            reasoning.append("High severity anomaly - immediate attention required")
        elif score > 0.6:
            reasoning.append("Moderate severity anomaly - investigation recommended")
        elif score > 0.4:
            reasoning.append("Low severity anomaly - monitoring advised")
        else:
            reasoning.append("Normal behavior - no action required")
        
        return reasoning
    
    async def _update_anomaly_patterns(self, detection: AnomalyDetection) -> None:
        """Update anomaly pattern tracking."""
        try:
            # Simple pattern detection based on feature contributions
            pattern_signature = "_".join(sorted([
                name for name, contrib in detection.feature_contributions.items()
                if contrib > 0.5
            ]))
            
            if not pattern_signature:
                return
            
            current_time = datetime.now()
            
            if pattern_signature in self.pattern_history:
                # Update existing pattern
                pattern = self.pattern_history[pattern_signature]
                pattern.last_detected = current_time
                pattern.frequency += 1
                pattern.severity = max(pattern.severity, detection.anomaly_score)
            else:
                # Create new pattern
                pattern = AnomalyPattern(
                    pattern_id=pattern_signature,
                    first_detected=current_time,
                    last_detected=current_time,
                    frequency=1,
                    severity=detection.anomaly_score,
                    pattern_type=detection.anomaly_type,
                    features_involved=list(detection.feature_contributions.keys()),
                    description=f"Anomaly pattern involving {pattern_signature}"
                )
                self.pattern_history[pattern_signature] = pattern
            
        except Exception as e:
            self.logger.error(f"Error updating anomaly patterns: {e}")
    
    def _extract_features(self, data: pd.DataFrame) -> np.ndarray:
        """Extract features from input data."""
        if data.empty:
            return np.array([])
        
        # Define expected features
        expected_features = [
            'risk_score', 'event_count', 'severity_avg', 'classification_level',
            'source_entropy', 'temporal_pattern', 'system_load', 'anomaly_indicator',
            'byzantine_risk', 'cross_layer_correlation'
        ]
        
        features = []
        for _, row in data.iterrows():
            feature_vector = []
            
            for feature_name in expected_features:
                if feature_name in row:
                    feature_vector.append(float(row[feature_name]))
                else:
                    # Calculate or use default
                    value = self._calculate_feature(feature_name, row)
                    feature_vector.append(value)
            
            features.append(feature_vector)
        
        self.feature_names = expected_features
        return np.array(features)
    
    def _calculate_feature(self, feature_name: str, row: pd.Series) -> float:
        """Calculate feature value from available data."""
        if feature_name == 'risk_score':
            return float(row.get('risk_score', 0.0))
        elif feature_name == 'event_count':
            return float(row.get('event_count', 1))
        elif feature_name == 'severity_avg':
            return float(row.get('severity', 3)) / 5.0
        elif feature_name == 'classification_level':
            level_map = {'U': 0.0, 'S': 0.5, 'TS': 1.0}
            return level_map.get(row.get('classification', 'U'), 0.0)
        elif feature_name == 'source_entropy':
            return float(row.get('source_entropy', 0.5))
        elif feature_name == 'temporal_pattern':
            return float(row.get('temporal_pattern', 0.0))
        elif feature_name == 'system_load':
            return float(row.get('system_load', 0.5))
        elif feature_name == 'anomaly_indicator':
            return float(row.get('anomaly_score', 0.0))
        elif feature_name == 'byzantine_risk':
            return float(row.get('byzantine_risk', 0.0))
        elif feature_name == 'cross_layer_correlation':
            return float(row.get('cross_layer_correlation', 0.0))
        else:
            return 0.0
    
    def _calculate_feature_statistics(self, X: np.ndarray) -> None:
        """Calculate feature statistics for statistical anomaly detection."""
        try:
            if len(X) == 0 or not self.feature_names:
                return
            
            self.feature_statistics = {}
            
            for i, feature_name in enumerate(self.feature_names):
                if i < X.shape[1]:
                    feature_values = X[:, i]
                    
                    self.feature_statistics[feature_name] = {
                        'mean': float(np.mean(feature_values)),
                        'std': float(np.std(feature_values)),
                        'min': float(np.min(feature_values)),
                        'max': float(np.max(feature_values)),
                        'median': float(np.median(feature_values))
                    }
        
        except Exception as e:
            self.logger.error(f"Error calculating feature statistics: {e}")
    
    def _default_detection(self) -> AnomalyDetection:
        """Return default detection when model is unavailable."""
        return AnomalyDetection(
            timestamp=datetime.now(),
            is_anomaly=False,
            anomaly_score=0.0,
            anomaly_type=AnomalyType.POINT_ANOMALY,
            confidence=0.0,
            method_scores={},
            feature_contributions={},
            reasoning=["Model not available - default normal classification"]
        )
    
    def get_anomaly_patterns(self) -> Dict[str, AnomalyPattern]:
        """Get detected anomaly patterns."""
        return self.pattern_history.copy()
    
    def get_anomaly_history(self) -> List[AnomalyDetection]:
        """Get recent anomaly detection history."""
        return list(self.anomaly_history)
    
    def save_model(self, path: str) -> None:
        """Save the trained model."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            model_data = {
                'models': self.models,
                'scalers': self.scalers,
                'thresholds': self.thresholds,
                'method': self.method,
                'contamination': self.contamination,
                'feature_names': self.feature_names,
                'feature_statistics': self.feature_statistics,
                'performance_metrics': self.performance_metrics,
                'pattern_history': self.pattern_history,
                'last_training_time': self.last_training_time
            }
            
            with open(path, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Anomaly detector saved to {path}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def load_model(self, path: str) -> None:
        """Load a trained model."""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.models = model_data['models']
            self.scalers = model_data['scalers']
            self.thresholds = model_data['thresholds']
            self.method = model_data['method']
            self.contamination = model_data['contamination']
            self.feature_names = model_data.get('feature_names', [])
            self.feature_statistics = model_data.get('feature_statistics', {})
            self.performance_metrics = model_data.get('performance_metrics', {})
            self.pattern_history = model_data.get('pattern_history', {})
            self.last_training_time = model_data.get('last_training_time')
            
            self.logger.info(f"Anomaly detector loaded from {path}")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            'method': self.method.value,
            'contamination': self.contamination,
            'feature_names': self.feature_names,
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'performance_metrics': self.performance_metrics,
            'models_trained': list(self.models.keys()),
            'anomaly_patterns': len(self.pattern_history),
            'detection_history': len(self.anomaly_history)
        }


# Example usage
async def demo_anomaly_detector():
    """Demonstrate anomaly detector capabilities."""
    
    # Initialize detector
    detector = AnomalyDetector(
        method='ensemble',
        contamination=0.1,
        window_size=1000
    )
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 1000
    
    # Normal data
    normal_data = pd.DataFrame({
        'risk_score': np.random.normal(0.3, 0.1, n_samples),
        'event_count': np.random.poisson(3, n_samples),
        'severity': np.random.normal(2.5, 0.5, n_samples),
        'classification': np.random.choice(['U', 'S', 'TS'], n_samples),
        'source_entropy': np.random.normal(0.5, 0.2, n_samples),
        'temporal_pattern': np.sin(np.arange(n_samples) * 2 * np.pi / 24),
        'system_load': np.random.normal(0.4, 0.1, n_samples),
        'anomaly_score': np.random.normal(0.2, 0.1, n_samples),
        'byzantine_risk': np.random.normal(0.1, 0.05, n_samples),
        'cross_layer_correlation': np.random.normal(0.3, 0.1, n_samples)
    })
    
    # Anomalous data
    anomaly_data = pd.DataFrame({
        'risk_score': [0.9, 0.95, 0.85],
        'event_count': [50, 45, 40],
        'severity': [5.0, 4.8, 4.9],
        'classification': ['TS', 'TS', 'S'],
        'source_entropy': [0.1, 0.05, 0.08],
        'temporal_pattern': [0.0, 0.0, 0.0],
        'system_load': [0.95, 0.98, 0.92],
        'anomaly_score': [0.9, 0.95, 0.88],
        'byzantine_risk': [0.8, 0.85, 0.82],
        'cross_layer_correlation': [0.9, 0.88, 0.91]
    })
    
    try:
        # Train detector
        print("Training anomaly detector...")
        metrics = await detector.train(normal_data)
        print(f"Training metrics: {metrics}")
        
        # Test on normal data
        print("\nTesting on normal data...")
        for i in range(3):
            row = normal_data.iloc[[i]]
            
            # Basic prediction
            score = await detector.predict(row)
            print(f"Normal sample {i+1} - Anomaly score: {score:.3f}")
            
            # Detailed detection
            detection = await detector.detect_anomaly(row)
            print(f"  Is anomaly: {detection.is_anomaly}")
            print(f"  Confidence: {detection.confidence:.3f}")
            print(f"  Reasoning: {detection.reasoning}")
        
        # Test on anomalous data
        print("\nTesting on anomalous data...")
        for i in range(3):
            row = anomaly_data.iloc[[i]]
            
            # Basic prediction
            score = await detector.predict(row)
            print(f"Anomaly sample {i+1} - Anomaly score: {score:.3f}")
            
            # Detailed detection
            detection = await detector.detect_anomaly(row)
            print(f"  Is anomaly: {detection.is_anomaly}")
            print(f"  Confidence: {detection.confidence:.3f}")
            print(f"  Feature contributions: {detection.feature_contributions}")
            print(f"  Reasoning: {detection.reasoning}")
        
        # Show patterns
        patterns = detector.get_anomaly_patterns()
        print(f"\nDetected patterns: {len(patterns)}")
        for pattern_id, pattern in patterns.items():
            print(f"  Pattern {pattern_id}: {pattern.frequency} occurrences")
        
        # Model information
        info = detector.get_model_info()
        print(f"\nModel info: {info}")
        
    except Exception as e:
        print(f"Error in demo: {e}")


if __name__ == "__main__":
    asyncio.run(demo_anomaly_detector()) 