"""
LSTM-based Time-Series Security Forecaster

Advanced LSTM neural network implementation for predicting security events
and threat patterns using sequential data analysis.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import logging
import asyncio
from dataclasses import dataclass
import pickle
import os

# TensorFlow/Keras imports with error handling
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
    from tensorflow.keras.regularizers import l2
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None

# Scikit-learn fallback
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error, mean_absolute_error


@dataclass
class LSTMPrediction:
    """LSTM prediction result with metadata."""
    timestamp: datetime
    predicted_value: float
    confidence_interval: Tuple[float, float]
    sequence_length: int
    model_version: str
    features_used: List[str]


class LSTMForecaster:
    """
    LSTM-based security forecaster for time-series threat prediction.
    
    Supports both TensorFlow/Keras LSTM models and scikit-learn fallback
    for environments without deep learning capabilities.
    """
    
    def __init__(self,
                 sequence_length: int = 100,
                 features: int = 50,
                 model_type: str = 'lstm',
                 model_path: Optional[str] = None):
        """
        Initialize LSTM forecaster.
        
        Args:
            sequence_length: Length of input sequences
            features: Number of input features
            model_type: Type of model ('lstm', 'random_forest', 'linear')
            model_path: Path to saved model
        """
        self.sequence_length = sequence_length
        self.features = features
        self.model_type = model_type if TENSORFLOW_AVAILABLE else 'random_forest'
        self.model_path = model_path or f"models/lstm_forecaster_{model_type}.pkl"
        
        self.logger = logging.getLogger(__name__)
        self.model = None
        self.scaler = StandardScaler()
        self.feature_scaler = MinMaxScaler()
        
        # Model configuration
        self.lstm_units = [64, 32, 16]
        self.dropout_rate = 0.3
        self.learning_rate = 0.001
        self.batch_size = 32
        self.epochs = 100
        self.patience = 15
        
        # Training history
        self.training_history = []
        self.last_training_time = None
        self.model_metrics = {}
        
        # Initialize model
        self._initialize_model()
        
        self.logger.info(f"LSTM Forecaster initialized with {self.model_type} model")
    
    def _initialize_model(self) -> None:
        """Initialize the prediction model."""
        if self.model_type == 'lstm' and TENSORFLOW_AVAILABLE:
            self._create_lstm_model()
        elif self.model_type == 'random_forest':
            self.model = RandomForestRegressor(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
        else:
            self.model = LinearRegression()
        
        # Try to load existing model
        if os.path.exists(self.model_path):
            try:
                self.load_model(self.model_path)
                self.logger.info(f"Loaded existing model from {self.model_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load existing model: {e}")
    
    def _create_lstm_model(self) -> None:
        """Create LSTM neural network model."""
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow not available for LSTM model")
        
        self.model = Sequential([
            LSTM(self.lstm_units[0], 
                 return_sequences=True, 
                 input_shape=(self.sequence_length, self.features),
                 kernel_regularizer=l2(0.01)),
            Dropout(self.dropout_rate),
            BatchNormalization(),
            
            LSTM(self.lstm_units[1], 
                 return_sequences=True,
                 kernel_regularizer=l2(0.01)),
            Dropout(self.dropout_rate),
            BatchNormalization(),
            
            LSTM(self.lstm_units[2], 
                 return_sequences=False,
                 kernel_regularizer=l2(0.01)),
            Dropout(self.dropout_rate),
            BatchNormalization(),
            
            Dense(32, activation='relu', kernel_regularizer=l2(0.01)),
            Dropout(self.dropout_rate),
            Dense(16, activation='relu', kernel_regularizer=l2(0.01)),
            Dense(1, activation='sigmoid')  # Output: threat probability [0,1]
        ])
        
        # Compile model
        self.model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='mse',
            metrics=['mae', 'mse']
        )
        
        self.logger.info(f"LSTM model created with {self.model.count_params()} parameters")
    
    async def train(self, 
                   training_data: pd.DataFrame,
                   incremental: bool = True) -> Dict[str, float]:
        """
        Train the LSTM forecaster on security data.
        
        Args:
            training_data: DataFrame with security events and features
            incremental: Whether to perform incremental learning
            
        Returns:
            Dictionary with training metrics
        """
        try:
            start_time = datetime.now()
            
            if training_data.empty:
                return {'error': 'No training data provided'}
            
            # Prepare training sequences
            X, y = self._prepare_sequences(training_data)
            
            if len(X) == 0:
                return {'error': 'Insufficient data for sequence creation'}
            
            # Scale features
            X_scaled = self._scale_features(X)
            
            # Train model
            if self.model_type == 'lstm' and TENSORFLOW_AVAILABLE:
                metrics = await self._train_lstm(X_scaled, y, incremental)
            else:
                metrics = await self._train_sklearn(X_scaled, y, incremental)
            
            # Update training metadata
            self.last_training_time = datetime.now()
            training_time = (self.last_training_time - start_time).total_seconds()
            
            metrics.update({
                'training_time': training_time,
                'training_samples': len(X),
                'sequence_length': self.sequence_length,
                'features': self.features
            })
            
            self.model_metrics = metrics
            
            # Save model
            self.save_model(self.model_path)
            
            self.logger.info(f"Model training completed in {training_time:.2f}s")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error training LSTM model: {e}")
            return {'error': str(e)}
    
    async def _train_lstm(self, 
                         X: np.ndarray, 
                         y: np.ndarray,
                         incremental: bool) -> Dict[str, float]:
        """Train LSTM neural network."""
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=self.patience,
                restore_best_weights=True
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-6
            )
        ]
        
        # Split data
        split_idx = int(len(X) * 0.8)
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]
        
        # Train model
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            batch_size=self.batch_size,
            epochs=self.epochs,
            callbacks=callbacks,
            verbose=0
        )
        
        # Calculate metrics
        train_loss = history.history['loss'][-1]
        val_loss = history.history['val_loss'][-1]
        train_mae = history.history['mae'][-1]
        val_mae = history.history['val_mae'][-1]
        
        # Make predictions for accuracy
        y_pred = self.model.predict(X_val, verbose=0)
        mse = mean_squared_error(y_val, y_pred)
        mae = mean_absolute_error(y_val, y_pred)
        
        self.training_history.append(history.history)
        
        return {
            'train_loss': float(train_loss),
            'val_loss': float(val_loss),
            'train_mae': float(train_mae),
            'val_mae': float(val_mae),
            'test_mse': float(mse),
            'test_mae': float(mae),
            'epochs_trained': len(history.history['loss'])
        }
    
    async def _train_sklearn(self,
                            X: np.ndarray,
                            y: np.ndarray,
                            incremental: bool) -> Dict[str, float]:
        """Train scikit-learn model."""
        # Reshape for sklearn (flatten sequences)
        X_flat = X.reshape(X.shape[0], -1)
        
        # Split data
        split_idx = int(len(X_flat) * 0.8)
        X_train, X_test = X_flat[:split_idx], X_flat[split_idx:]
        y_train, y_test = y[:split_idx], y[split_idx:]
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Calculate metrics
        train_pred = self.model.predict(X_train)
        test_pred = self.model.predict(X_test)
        
        train_mse = mean_squared_error(y_train, train_pred)
        test_mse = mean_squared_error(y_test, test_pred)
        train_mae = mean_absolute_error(y_train, train_pred)
        test_mae = mean_absolute_error(y_test, test_pred)
        
        return {
            'train_mse': float(train_mse),
            'test_mse': float(test_mse),
            'train_mae': float(train_mae),
            'test_mae': float(test_mae),
            'model_type': self.model_type
        }
    
    async def predict(self, 
                     input_data: pd.DataFrame,
                     horizon: timedelta = timedelta(hours=1)) -> float:
        """
        Generate threat prediction for the specified horizon.
        
        Args:
            input_data: Recent security data for prediction
            horizon: Prediction time horizon
            
        Returns:
            Predicted threat probability [0,1]
        """
        try:
            if self.model is None:
                self.logger.error("Model not trained")
                return 0.5  # Default uncertainty
            
            # Prepare input sequence
            X = self._prepare_prediction_input(input_data)
            
            if len(X) == 0:
                return 0.5
            
            # Scale input
            X_scaled = self._scale_features(X)
            
            # Make prediction
            if self.model_type == 'lstm' and TENSORFLOW_AVAILABLE:
                prediction = self.model.predict(X_scaled, verbose=0)[0][0]
            else:
                X_flat = X_scaled.reshape(X_scaled.shape[0], -1)
                prediction = self.model.predict(X_flat)[0]
            
            # Ensure prediction is in [0,1] range
            prediction = max(0.0, min(1.0, float(prediction)))
            
            return prediction
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return 0.5
    
    async def predict_with_confidence(self,
                                    input_data: pd.DataFrame,
                                    horizon: timedelta = timedelta(hours=1),
                                    n_samples: int = 100) -> LSTMPrediction:
        """
        Generate prediction with confidence intervals.
        
        Args:
            input_data: Recent security data
            horizon: Prediction horizon
            n_samples: Number of samples for confidence estimation
            
        Returns:
            LSTMPrediction with confidence intervals
        """
        try:
            # Get base prediction
            base_prediction = await self.predict(input_data, horizon)
            
            # Estimate confidence through bootstrap sampling
            predictions = []
            for _ in range(n_samples):
                # Add small random noise for uncertainty estimation
                noisy_data = input_data.copy()
                if not noisy_data.empty:
                    numeric_cols = noisy_data.select_dtypes(include=[np.number]).columns
                    noise = np.random.normal(0, 0.01, size=noisy_data[numeric_cols].shape)
                    noisy_data[numeric_cols] += noise
                    
                    pred = await self.predict(noisy_data, horizon)
                    predictions.append(pred)
            
            # Calculate confidence intervals
            if predictions:
                predictions = np.array(predictions)
                ci_lower = np.percentile(predictions, 5)
                ci_upper = np.percentile(predictions, 95)
            else:
                ci_lower, ci_upper = base_prediction * 0.8, base_prediction * 1.2
            
            return LSTMPrediction(
                timestamp=datetime.now(),
                predicted_value=base_prediction,
                confidence_interval=(ci_lower, ci_upper),
                sequence_length=self.sequence_length,
                model_version=f"{self.model_type}_v1.0",
                features_used=list(input_data.columns) if not input_data.empty else []
            )
            
        except Exception as e:
            self.logger.error(f"Error making prediction with confidence: {e}")
            return LSTMPrediction(
                timestamp=datetime.now(),
                predicted_value=0.5,
                confidence_interval=(0.0, 1.0),
                sequence_length=self.sequence_length,
                model_version=f"{self.model_type}_v1.0",
                features_used=[]
            )
    
    def _prepare_sequences(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training sequences from time-series data."""
        if data.empty:
            return np.array([]), np.array([])
        
        # Sort by timestamp
        if 'timestamp' in data.columns:
            data = data.sort_values('timestamp')
        
        # Select numeric features
        numeric_cols = data.select_dtypes(include=[np.number]).columns
        feature_data = data[numeric_cols].values
        
        # Create sequences
        X, y = [], []
        for i in range(len(feature_data) - self.sequence_length):
            sequence = feature_data[i:i + self.sequence_length]
            target = feature_data[i + self.sequence_length]
            
            # Pad or truncate to match expected feature count
            if sequence.shape[1] < self.features:
                padding = np.zeros((self.sequence_length, self.features - sequence.shape[1]))
                sequence = np.concatenate([sequence, padding], axis=1)
            elif sequence.shape[1] > self.features:
                sequence = sequence[:, :self.features]
            
            X.append(sequence)
            
            # Target is the first feature (assumed to be risk score)
            y.append(target[0] if len(target) > 0 else 0.0)
        
        return np.array(X), np.array(y)
    
    def _prepare_prediction_input(self, data: pd.DataFrame) -> np.ndarray:
        """Prepare input data for prediction."""
        if data.empty:
            return np.array([])
        
        # Sort by timestamp
        if 'timestamp' in data.columns:
            data = data.sort_values('timestamp')
        
        # Select numeric features
        numeric_cols = data.select_dtypes(include=[np.number]).columns
        feature_data = data[numeric_cols].values
        
        # Take last sequence_length samples
        if len(feature_data) >= self.sequence_length:
            sequence = feature_data[-self.sequence_length:]
        else:
            # Pad with zeros if insufficient data
            padding_length = self.sequence_length - len(feature_data)
            padding = np.zeros((padding_length, feature_data.shape[1]))
            sequence = np.concatenate([padding, feature_data], axis=0)
        
        # Adjust feature count
        if sequence.shape[1] < self.features:
            padding = np.zeros((self.sequence_length, self.features - sequence.shape[1]))
            sequence = np.concatenate([sequence, padding], axis=1)
        elif sequence.shape[1] > self.features:
            sequence = sequence[:, :self.features]
        
        return sequence.reshape(1, self.sequence_length, self.features)
    
    def _scale_features(self, X: np.ndarray) -> np.ndarray:
        """Scale features for model input."""
        if len(X.shape) == 3:  # LSTM input (samples, timesteps, features)
            # Reshape for scaling
            original_shape = X.shape
            X_reshaped = X.reshape(-1, X.shape[-1])
            
            # Scale
            X_scaled = self.feature_scaler.fit_transform(X_reshaped)
            
            # Reshape back
            return X_scaled.reshape(original_shape)
        else:  # 2D input for sklearn
            return self.feature_scaler.fit_transform(X)
    
    def save_model(self, path: str) -> None:
        """Save the trained model."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            model_data = {
                'model_type': self.model_type,
                'sequence_length': self.sequence_length,
                'features': self.features,
                'scaler': self.scaler,
                'feature_scaler': self.feature_scaler,
                'training_history': self.training_history,
                'model_metrics': self.model_metrics,
                'last_training_time': self.last_training_time
            }
            
            if self.model_type == 'lstm' and TENSORFLOW_AVAILABLE:
                # Save Keras model separately
                keras_path = path.replace('.pkl', '_keras.h5')
                self.model.save(keras_path)
                model_data['keras_model_path'] = keras_path
            else:
                # Save sklearn model
                model_data['model'] = self.model
            
            with open(path, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Model saved to {path}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def load_model(self, path: str) -> None:
        """Load a trained model."""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model_type = model_data['model_type']
            self.sequence_length = model_data['sequence_length']
            self.features = model_data['features']
            self.scaler = model_data['scaler']
            self.feature_scaler = model_data['feature_scaler']
            self.training_history = model_data.get('training_history', [])
            self.model_metrics = model_data.get('model_metrics', {})
            self.last_training_time = model_data.get('last_training_time')
            
            if self.model_type == 'lstm' and TENSORFLOW_AVAILABLE:
                # Load Keras model
                keras_path = model_data.get('keras_model_path')
                if keras_path and os.path.exists(keras_path):
                    self.model = load_model(keras_path)
                else:
                    self._create_lstm_model()
            else:
                # Load sklearn model
                self.model = model_data['model']
            
            self.logger.info(f"Model loaded from {path}")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            'model_type': self.model_type,
            'sequence_length': self.sequence_length,
            'features': self.features,
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'model_metrics': self.model_metrics,
            'is_trained': self.model is not None,
            'tensorflow_available': TENSORFLOW_AVAILABLE
        }


# Testing and validation utilities

class LSTMForecasterValidator:
    """Validation utilities for LSTM forecaster."""
    
    def __init__(self, forecaster: LSTMForecaster):
        self.forecaster = forecaster
    
    async def validate_predictions(self, 
                                 test_data: pd.DataFrame,
                                 ground_truth: List[float]) -> Dict[str, float]:
        """Validate prediction accuracy against ground truth."""
        if test_data.empty or not ground_truth:
            return {'error': 'No test data or ground truth provided'}
        
        predictions = []
        for i in range(len(test_data)):
            row_data = test_data.iloc[[i]]
            pred = await self.forecaster.predict(row_data)
            predictions.append(pred)
        
        # Calculate metrics
        mse = mean_squared_error(ground_truth, predictions)
        mae = mean_absolute_error(ground_truth, predictions)
        
        # Calculate accuracy within tolerance
        tolerance = 0.1
        accurate_predictions = sum(1 for gt, pred in zip(ground_truth, predictions) 
                                 if abs(gt - pred) <= tolerance)
        accuracy = accurate_predictions / len(ground_truth)
        
        return {
            'mse': float(mse),
            'mae': float(mae),
            'accuracy': float(accuracy),
            'predictions': predictions,
            'ground_truth': ground_truth
        }
    
    async def benchmark_performance(self, 
                                  test_data: pd.DataFrame,
                                  n_runs: int = 100) -> Dict[str, float]:
        """Benchmark prediction performance."""
        prediction_times = []
        
        for _ in range(n_runs):
            start_time = datetime.now()
            await self.forecaster.predict(test_data)
            end_time = datetime.now()
            
            prediction_times.append(
                (end_time - start_time).total_seconds()
            )
        
        return {
            'avg_prediction_time': np.mean(prediction_times),
            'min_prediction_time': np.min(prediction_times),
            'max_prediction_time': np.max(prediction_times),
            'p95_prediction_time': np.percentile(prediction_times, 95),
            'p99_prediction_time': np.percentile(prediction_times, 99)
        }


# Example usage
async def demo_lstm_forecaster():
    """Demonstrate LSTM forecaster capabilities."""
    
    # Initialize forecaster
    forecaster = LSTMForecaster(
        sequence_length=50,
        features=10,
        model_type='lstm' if TENSORFLOW_AVAILABLE else 'random_forest'
    )
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 1000
    
    data = pd.DataFrame({
        'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='H'),
        'risk_score': np.random.random(n_samples),
        'event_count': np.random.poisson(5, n_samples),
        'severity_avg': np.random.uniform(1, 5, n_samples),
        'classification_level': np.random.choice([0, 1, 2], n_samples),
        'source_entropy': np.random.uniform(0, 1, n_samples),
        'temporal_pattern': np.sin(np.arange(n_samples) * 2 * np.pi / 24),
        'threat_indicator': np.random.random(n_samples),
        'anomaly_score': np.random.random(n_samples),
        'system_load': np.random.uniform(0, 1, n_samples)
    })
    
    try:
        # Train model
        print("Training LSTM forecaster...")
        metrics = await forecaster.train(data)
        print(f"Training metrics: {metrics}")
        
        # Make predictions
        print("\nGenerating predictions...")
        recent_data = data.tail(50)
        
        prediction = await forecaster.predict(recent_data)
        print(f"Threat prediction: {prediction:.3f}")
        
        # Prediction with confidence
        detailed_prediction = await forecaster.predict_with_confidence(recent_data)
        print(f"Detailed prediction: {detailed_prediction.predicted_value:.3f}")
        print(f"Confidence interval: {detailed_prediction.confidence_interval}")
        
        # Model information
        info = forecaster.get_model_info()
        print(f"\nModel info: {info}")
        
        # Validation
        validator = LSTMForecasterValidator(forecaster)
        
        # Performance benchmark
        perf_metrics = await validator.benchmark_performance(recent_data, n_runs=10)
        print(f"\nPerformance metrics: {perf_metrics}")
        
    except Exception as e:
        print(f"Error in demo: {e}")


if __name__ == "__main__":
    asyncio.run(demo_lstm_forecaster()) 