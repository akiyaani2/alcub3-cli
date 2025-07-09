"""
Risk Classification System

Multi-factor risk classification using Random Forest and Gradient Boosting
for comprehensive threat assessment in the ALCUB3 security platform.
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

# Scikit-learn imports
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)
from sklearn.utils.class_weight import compute_class_weight
import warnings
warnings.filterwarnings('ignore')

# XGBoost with fallback
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False


class RiskLevel(Enum):
    """Risk classification levels."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class RiskPrediction:
    """Risk prediction result with detailed metrics."""
    timestamp: datetime
    predicted_risk: RiskLevel
    confidence_scores: Dict[RiskLevel, float]
    feature_importance: Dict[str, float]
    model_version: str
    classification_reasoning: List[str]


@dataclass
class RiskFeatures:
    """Standardized risk features for classification."""
    temporal_risk: float
    classification_level: float
    event_frequency: float
    severity_average: float
    source_diversity: float
    anomaly_score: float
    byzantine_risk: float
    trend_acceleration: float
    cross_layer_correlation: float
    system_load: float


class RiskClassifier:
    """
    Advanced risk classification system using ensemble methods.
    
    Supports multiple ML algorithms:
    - Random Forest (default)
    - Gradient Boosting
    - XGBoost (if available)
    
    Features:
    - Multi-factor risk assessment
    - Classification-aware risk weighting
    - Byzantine fault consideration
    - Feature importance analysis
    - Confidence scoring
    """
    
    def __init__(self,
                 model_type: str = 'random_forest',
                 n_estimators: int = 100,
                 max_depth: Optional[int] = None,
                 model_path: Optional[str] = None):
        """
        Initialize risk classifier.
        
        Args:
            model_type: Type of model ('random_forest', 'gradient_boosting', 'xgboost')
            n_estimators: Number of estimators for ensemble methods
            max_depth: Maximum tree depth
            model_path: Path to saved model
        """
        self.model_type = model_type
        self.n_estimators = n_estimators
        self.max_depth = max_depth or 10
        self.model_path = model_path or f"models/risk_classifier_{model_type}.pkl"
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize model
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Training configuration
        self.test_size = 0.2
        self.random_state = 42
        self.cv_folds = 5
        
        # Model metrics
        self.model_metrics = {}
        self.feature_names = []
        self.last_training_time = None
        
        # Classification thresholds
        self.risk_thresholds = {
            RiskLevel.LOW: 0.25,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.75,
            RiskLevel.CRITICAL: 0.9
        }
        
        # Feature importance tracking
        self.feature_importance_history = []
        
        self._initialize_model()
        
        # Try to load existing model
        if os.path.exists(self.model_path):
            try:
                self.load_model(self.model_path)
                self.logger.info(f"Loaded existing model from {self.model_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load existing model: {e}")
        
        self.logger.info(f"Risk Classifier initialized with {self.model_type} model")
    
    def _initialize_model(self) -> None:
        """Initialize the classification model."""
        if self.model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                random_state=self.random_state,
                n_jobs=-1,
                class_weight='balanced',
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt'
            )
        elif self.model_type == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                random_state=self.random_state,
                learning_rate=0.1,
                subsample=0.8,
                min_samples_split=5,
                min_samples_leaf=2
            )
        elif self.model_type == 'xgboost' and XGBOOST_AVAILABLE:
            self.model = xgb.XGBClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                random_state=self.random_state,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                objective='multi:softprob',
                eval_metric='mlogloss'
            )
        else:
            # Fallback to Random Forest
            self.model_type = 'random_forest'
            self.model = RandomForestClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                random_state=self.random_state,
                n_jobs=-1,
                class_weight='balanced'
            )
    
    async def train(self,
                   training_data: pd.DataFrame,
                   incremental: bool = False) -> Dict[str, float]:
        """
        Train the risk classifier.
        
        Args:
            training_data: DataFrame with security features and risk labels
            incremental: Whether to perform incremental learning
            
        Returns:
            Dictionary with training metrics
        """
        try:
            start_time = datetime.now()
            
            if training_data.empty:
                return {'error': 'No training data provided'}
            
            # Prepare features and labels
            X, y = self._prepare_training_data(training_data)
            
            if len(X) == 0:
                return {'error': 'No valid features extracted'}
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.test_size, random_state=self.random_state,
                stratify=y if len(np.unique(y)) > 1 else None
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Handle incremental learning
            if incremental and hasattr(self.model, 'partial_fit'):
                # For models that support partial_fit
                self.model.partial_fit(X_train_scaled, y_train)
            else:
                # Full training
                self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            train_predictions = self.model.predict(X_train_scaled)
            test_predictions = self.model.predict(X_test_scaled)
            
            # Calculate metrics
            metrics = self._calculate_metrics(
                y_train, train_predictions, y_test, test_predictions,
                X_test_scaled
            )
            
            # Cross-validation
            cv_scores = cross_val_score(
                self.model, X_train_scaled, y_train, cv=self.cv_folds
            )
            metrics['cv_mean'] = float(np.mean(cv_scores))
            metrics['cv_std'] = float(np.std(cv_scores))
            
            # Feature importance
            if hasattr(self.model, 'feature_importances_'):
                importance = self.model.feature_importances_
                feature_importance = dict(zip(self.feature_names, importance))
                self.feature_importance_history.append(feature_importance)
                metrics['feature_importance'] = feature_importance
            
            # Update training metadata
            self.last_training_time = datetime.now()
            training_time = (self.last_training_time - start_time).total_seconds()
            
            metrics.update({
                'training_time': training_time,
                'training_samples': len(X_train),
                'test_samples': len(X_test),
                'features': len(self.feature_names),
                'model_type': self.model_type
            })
            
            self.model_metrics = metrics
            
            # Save model
            self.save_model(self.model_path)
            
            self.logger.info(f"Risk classifier training completed in {training_time:.2f}s")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error training risk classifier: {e}")
            return {'error': str(e)}
    
    async def predict(self, features: pd.DataFrame) -> float:
        """
        Predict risk level for given features.
        
        Args:
            features: DataFrame with security features
            
        Returns:
            Risk probability [0,1]
        """
        try:
            if self.model is None:
                self.logger.error("Model not trained")
                return 0.5  # Default uncertainty
            
            # Prepare features
            X = self._prepare_prediction_features(features)
            
            if len(X) == 0:
                return 0.5
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Get prediction probabilities
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(X_scaled)[0]
                # Convert to single risk probability
                risk_prob = np.average(range(len(probabilities)), weights=probabilities) / (len(probabilities) - 1)
            else:
                # For models without predict_proba
                prediction = self.model.predict(X_scaled)[0]
                risk_prob = prediction / (len(RiskLevel) - 1)
            
            return float(np.clip(risk_prob, 0.0, 1.0))
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return 0.5
    
    async def predict_detailed(self, features: pd.DataFrame) -> RiskPrediction:
        """
        Detailed risk prediction with confidence and reasoning.
        
        Args:
            features: DataFrame with security features
            
        Returns:
            RiskPrediction with detailed analysis
        """
        try:
            if self.model is None:
                return self._default_prediction()
            
            # Prepare features
            X = self._prepare_prediction_features(features)
            
            if len(X) == 0:
                return self._default_prediction()
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Get predictions
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(X_scaled)[0]
                prediction = np.argmax(probabilities)
            else:
                prediction = self.model.predict(X_scaled)[0]
                # Create dummy probabilities
                probabilities = np.zeros(len(RiskLevel))
                probabilities[prediction] = 1.0
            
            # Map to risk levels
            risk_levels = list(RiskLevel)
            predicted_risk = risk_levels[prediction]
            
            # Confidence scores
            confidence_scores = {}
            for i, level in enumerate(risk_levels):
                confidence_scores[level] = float(probabilities[i])
            
            # Feature importance
            feature_importance = {}
            if hasattr(self.model, 'feature_importances_') and self.feature_names:
                for name, importance in zip(self.feature_names, self.model.feature_importances_):
                    feature_importance[name] = float(importance)
            
            # Generate reasoning
            reasoning = self._generate_reasoning(X[0], predicted_risk, confidence_scores)
            
            return RiskPrediction(
                timestamp=datetime.now(),
                predicted_risk=predicted_risk,
                confidence_scores=confidence_scores,
                feature_importance=feature_importance,
                model_version=f"{self.model_type}_v1.0",
                classification_reasoning=reasoning
            )
            
        except Exception as e:
            self.logger.error(f"Error making detailed prediction: {e}")
            return self._default_prediction()
    
    def _prepare_training_data(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data with features and labels."""
        # Extract features
        features = self._extract_features(data)
        
        # Extract labels (risk levels)
        if 'risk_level' in data.columns:
            labels = data['risk_level'].values
        elif 'risk_score' in data.columns:
            # Convert risk scores to risk levels
            risk_scores = data['risk_score'].values
            labels = []
            for score in risk_scores:
                if score <= 0.25:
                    labels.append(RiskLevel.LOW.value)
                elif score <= 0.5:
                    labels.append(RiskLevel.MEDIUM.value)
                elif score <= 0.75:
                    labels.append(RiskLevel.HIGH.value)
                else:
                    labels.append(RiskLevel.CRITICAL.value)
            labels = np.array(labels)
        else:
            # Generate synthetic labels based on features
            labels = self._generate_synthetic_labels(features)
        
        return features, labels
    
    def _prepare_prediction_features(self, data: pd.DataFrame) -> np.ndarray:
        """Prepare features for prediction."""
        return self._extract_features(data)
    
    def _extract_features(self, data: pd.DataFrame) -> np.ndarray:
        """Extract standardized features from security data."""
        if data.empty:
            return np.array([])
        
        # Define expected features
        expected_features = [
            'temporal_risk', 'classification_level', 'event_frequency',
            'severity_average', 'source_diversity', 'anomaly_score',
            'byzantine_risk', 'trend_acceleration', 'cross_layer_correlation',
            'system_load'
        ]
        
        features = []
        for _, row in data.iterrows():
            feature_vector = []
            
            # Extract or calculate each feature
            for feature_name in expected_features:
                if feature_name in row:
                    feature_vector.append(float(row[feature_name]))
                else:
                    # Calculate feature based on available data
                    value = self._calculate_feature(feature_name, row)
                    feature_vector.append(value)
            
            features.append(feature_vector)
        
        self.feature_names = expected_features
        return np.array(features)
    
    def _calculate_feature(self, feature_name: str, row: pd.Series) -> float:
        """Calculate feature value from available data."""
        if feature_name == 'temporal_risk':
            # Based on timestamp proximity
            if 'timestamp' in row:
                time_diff = (datetime.now() - pd.to_datetime(row['timestamp'])).total_seconds()
                return np.exp(-time_diff / 3600)  # Exponential decay
            return 0.5
        
        elif feature_name == 'classification_level':
            # Map classification to numeric value
            if 'classification' in row:
                level_map = {'U': 0.0, 'S': 0.5, 'TS': 1.0}
                return level_map.get(row['classification'], 0.0)
            return 0.0
        
        elif feature_name == 'event_frequency':
            # Number of events in recent time window
            return float(row.get('event_count', 1))
        
        elif feature_name == 'severity_average':
            # Average severity of events
            return float(row.get('severity', 3)) / 5.0  # Normalize to [0,1]
        
        elif feature_name == 'source_diversity':
            # Entropy of event sources
            return float(row.get('source_entropy', 0.5))
        
        elif feature_name == 'anomaly_score':
            # Anomaly detection score
            return float(row.get('anomaly_score', 0.0))
        
        elif feature_name == 'byzantine_risk':
            # Risk of Byzantine behavior
            return float(row.get('byzantine_risk', 0.0))
        
        elif feature_name == 'trend_acceleration':
            # Rate of change in threat trends
            return float(row.get('trend_risk', 0.0))
        
        elif feature_name == 'cross_layer_correlation':
            # Correlation across security layers
            return float(row.get('cross_layer_correlation', 0.0))
        
        elif feature_name == 'system_load':
            # System resource utilization
            return float(row.get('system_load', 0.5))
        
        else:
            return 0.0
    
    def _generate_synthetic_labels(self, features: np.ndarray) -> np.ndarray:
        """Generate synthetic risk labels when not available."""
        labels = []
        for feature_vector in features:
            # Simple risk scoring based on feature values
            risk_score = np.mean(feature_vector)
            
            if risk_score <= 0.25:
                labels.append(RiskLevel.LOW.value)
            elif risk_score <= 0.5:
                labels.append(RiskLevel.MEDIUM.value)
            elif risk_score <= 0.75:
                labels.append(RiskLevel.HIGH.value)
            else:
                labels.append(RiskLevel.CRITICAL.value)
        
        return np.array(labels)
    
    def _calculate_metrics(self,
                          y_train: np.ndarray,
                          train_pred: np.ndarray,
                          y_test: np.ndarray,
                          test_pred: np.ndarray,
                          X_test: np.ndarray) -> Dict[str, float]:
        """Calculate comprehensive model metrics."""
        metrics = {}
        
        # Training metrics
        metrics['train_accuracy'] = float(accuracy_score(y_train, train_pred))
        metrics['train_precision'] = float(precision_score(y_train, train_pred, average='weighted'))
        metrics['train_recall'] = float(recall_score(y_train, train_pred, average='weighted'))
        metrics['train_f1'] = float(f1_score(y_train, train_pred, average='weighted'))
        
        # Test metrics
        metrics['test_accuracy'] = float(accuracy_score(y_test, test_pred))
        metrics['test_precision'] = float(precision_score(y_test, test_pred, average='weighted'))
        metrics['test_recall'] = float(recall_score(y_test, test_pred, average='weighted'))
        metrics['test_f1'] = float(f1_score(y_test, test_pred, average='weighted'))
        
        # ROC AUC (for multi-class)
        if hasattr(self.model, 'predict_proba'):
            try:
                test_proba = self.model.predict_proba(X_test)
                metrics['test_auc'] = float(roc_auc_score(y_test, test_proba, multi_class='ovr'))
            except:
                metrics['test_auc'] = 0.0
        
        return metrics
    
    def _generate_reasoning(self,
                           features: np.ndarray,
                           predicted_risk: RiskLevel,
                           confidence_scores: Dict[RiskLevel, float]) -> List[str]:
        """Generate human-readable reasoning for the prediction."""
        reasoning = []
        
        # Confidence assessment
        max_confidence = max(confidence_scores.values())
        if max_confidence > 0.8:
            reasoning.append(f"High confidence prediction ({max_confidence:.2f})")
        elif max_confidence > 0.6:
            reasoning.append(f"Moderate confidence prediction ({max_confidence:.2f})")
        else:
            reasoning.append(f"Low confidence prediction ({max_confidence:.2f})")
        
        # Feature-based reasoning
        if self.feature_names and len(features) == len(self.feature_names):
            # Identify top contributing features
            high_features = []
            for i, (feature_name, value) in enumerate(zip(self.feature_names, features)):
                if value > 0.7:
                    high_features.append(feature_name)
            
            if high_features:
                reasoning.append(f"High risk indicators: {', '.join(high_features)}")
        
        # Risk level specific reasoning
        if predicted_risk == RiskLevel.CRITICAL:
            reasoning.append("Immediate attention required - critical threat detected")
        elif predicted_risk == RiskLevel.HIGH:
            reasoning.append("High risk situation - enhanced monitoring recommended")
        elif predicted_risk == RiskLevel.MEDIUM:
            reasoning.append("Moderate risk - standard security protocols apply")
        else:
            reasoning.append("Low risk - normal operational security")
        
        return reasoning
    
    def _default_prediction(self) -> RiskPrediction:
        """Return default prediction when model is unavailable."""
        return RiskPrediction(
            timestamp=datetime.now(),
            predicted_risk=RiskLevel.MEDIUM,
            confidence_scores={level: 0.25 for level in RiskLevel},
            feature_importance={},
            model_version=f"{self.model_type}_v1.0",
            classification_reasoning=["Model not available - default risk assessment"]
        )
    
    def save_model(self, path: str) -> None:
        """Save the trained model."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'model_type': self.model_type,
                'feature_names': self.feature_names,
                'model_metrics': self.model_metrics,
                'feature_importance_history': self.feature_importance_history,
                'last_training_time': self.last_training_time,
                'risk_thresholds': self.risk_thresholds
            }
            
            with open(path, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Risk classifier saved to {path}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def load_model(self, path: str) -> None:
        """Load a trained model."""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoder = model_data['label_encoder']
            self.model_type = model_data['model_type']
            self.feature_names = model_data.get('feature_names', [])
            self.model_metrics = model_data.get('model_metrics', {})
            self.feature_importance_history = model_data.get('feature_importance_history', [])
            self.last_training_time = model_data.get('last_training_time')
            self.risk_thresholds = model_data.get('risk_thresholds', self.risk_thresholds)
            
            self.logger.info(f"Risk classifier loaded from {path}")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            'model_type': self.model_type,
            'feature_names': self.feature_names,
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'model_metrics': self.model_metrics,
            'is_trained': self.model is not None,
            'xgboost_available': XGBOOST_AVAILABLE,
            'feature_importance_available': hasattr(self.model, 'feature_importances_') if self.model else False
        }
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get current feature importance scores."""
        if hasattr(self.model, 'feature_importances_') and self.feature_names:
            return dict(zip(self.feature_names, self.model.feature_importances_))
        return {}


# Testing and validation utilities

class RiskClassifierValidator:
    """Validation utilities for risk classifier."""
    
    def __init__(self, classifier: RiskClassifier):
        self.classifier = classifier
    
    async def validate_classification(self,
                                   test_data: pd.DataFrame,
                                   ground_truth: List[RiskLevel]) -> Dict[str, Any]:
        """Validate classification accuracy."""
        if test_data.empty or not ground_truth:
            return {'error': 'No test data or ground truth provided'}
        
        predictions = []
        detailed_predictions = []
        
        for i in range(len(test_data)):
            row_data = test_data.iloc[[i]]
            
            # Basic prediction
            pred = await self.classifier.predict(row_data)
            predictions.append(pred)
            
            # Detailed prediction
            detailed_pred = await self.classifier.predict_detailed(row_data)
            detailed_predictions.append(detailed_pred)
        
        # Convert ground truth to numeric
        gt_numeric = [level.value for level in ground_truth]
        
        # Convert predictions to risk levels
        pred_levels = []
        for pred in predictions:
            if pred <= 0.25:
                pred_levels.append(RiskLevel.LOW.value)
            elif pred <= 0.5:
                pred_levels.append(RiskLevel.MEDIUM.value)
            elif pred <= 0.75:
                pred_levels.append(RiskLevel.HIGH.value)
            else:
                pred_levels.append(RiskLevel.CRITICAL.value)
        
        # Calculate metrics
        accuracy = accuracy_score(gt_numeric, pred_levels)
        precision = precision_score(gt_numeric, pred_levels, average='weighted')
        recall = recall_score(gt_numeric, pred_levels, average='weighted')
        f1 = f1_score(gt_numeric, pred_levels, average='weighted')
        
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'predictions': predictions,
            'detailed_predictions': detailed_predictions,
            'ground_truth': ground_truth,
            'confusion_matrix': confusion_matrix(gt_numeric, pred_levels).tolist()
        }
    
    async def benchmark_performance(self,
                                  test_data: pd.DataFrame,
                                  n_runs: int = 100) -> Dict[str, float]:
        """Benchmark prediction performance."""
        prediction_times = []
        detailed_prediction_times = []
        
        for _ in range(n_runs):
            # Basic prediction timing
            start_time = datetime.now()
            await self.classifier.predict(test_data)
            end_time = datetime.now()
            prediction_times.append((end_time - start_time).total_seconds())
            
            # Detailed prediction timing
            start_time = datetime.now()
            await self.classifier.predict_detailed(test_data)
            end_time = datetime.now()
            detailed_prediction_times.append((end_time - start_time).total_seconds())
        
        return {
            'avg_prediction_time': np.mean(prediction_times),
            'avg_detailed_prediction_time': np.mean(detailed_prediction_times),
            'p95_prediction_time': np.percentile(prediction_times, 95),
            'p99_prediction_time': np.percentile(prediction_times, 99)
        }


# Example usage
async def demo_risk_classifier():
    """Demonstrate risk classifier capabilities."""
    
    # Initialize classifier
    classifier = RiskClassifier(
        model_type='random_forest',
        n_estimators=100,
        max_depth=10
    )
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 1000
    
    data = pd.DataFrame({
        'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='H'),
        'risk_score': np.random.random(n_samples),
        'event_count': np.random.poisson(5, n_samples),
        'severity': np.random.randint(1, 6, n_samples),
        'classification': np.random.choice(['U', 'S', 'TS'], n_samples),
        'source_entropy': np.random.random(n_samples),
        'anomaly_score': np.random.random(n_samples),
        'byzantine_risk': np.random.random(n_samples),
        'trend_risk': np.random.random(n_samples),
        'cross_layer_correlation': np.random.random(n_samples),
        'system_load': np.random.random(n_samples)
    })
    
    try:
        # Train classifier
        print("Training risk classifier...")
        metrics = await classifier.train(data)
        print(f"Training metrics: {metrics}")
        
        # Make predictions
        print("\nGenerating predictions...")
        test_data = data.tail(10)
        
        for i in range(3):
            row = test_data.iloc[[i]]
            
            # Basic prediction
            risk_prob = await classifier.predict(row)
            print(f"Sample {i+1} - Risk probability: {risk_prob:.3f}")
            
            # Detailed prediction
            detailed = await classifier.predict_detailed(row)
            print(f"  Predicted level: {detailed.predicted_risk.name}")
            print(f"  Confidence: {detailed.confidence_scores}")
            print(f"  Reasoning: {detailed.classification_reasoning}")
        
        # Feature importance
        importance = classifier.get_feature_importance()
        print(f"\nFeature importance: {importance}")
        
        # Model information
        info = classifier.get_model_info()
        print(f"Model info: {info}")
        
    except Exception as e:
        print(f"Error in demo: {e}")


if __name__ == "__main__":
    asyncio.run(demo_risk_classifier()) 