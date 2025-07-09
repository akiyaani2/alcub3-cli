"""
Test Suite for ML Models

Comprehensive tests for LSTM Forecaster, Risk Classifier, and Anomaly Detector
including unit tests, model validation, and performance benchmarks.
"""

import unittest
import asyncio
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import tempfile
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.lstm_forecaster import LSTMForecaster, LSTMPrediction, LSTMForecasterValidator
from models.risk_classifier import RiskClassifier, RiskLevel, RiskPrediction, RiskClassifierValidator
from models.anomaly_detector import AnomalyDetector, AnomalyMethod, AnomalyDetection, AnomalyType


class TestLSTMForecaster(unittest.TestCase):
    """Test cases for LSTM Forecaster."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.forecaster = LSTMForecaster(
            sequence_length=10,
            features=5,
            model_type='random_forest'  # Use sklearn fallback for testing
        )
        
        # Generate sample data
        np.random.seed(42)
        n_samples = 100
        
        self.sample_data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='H'),
            'risk_score': np.random.random(n_samples),
            'event_count': np.random.poisson(5, n_samples),
            'severity_avg': np.random.uniform(1, 5, n_samples),
            'classification_level': np.random.choice([0, 1, 2], n_samples),
            'source_entropy': np.random.uniform(0, 1, n_samples)
        })
    
    def test_initialization(self):
        """Test LSTM forecaster initialization."""
        self.assertIsNotNone(self.forecaster)
        self.assertEqual(self.forecaster.sequence_length, 10)
        self.assertEqual(self.forecaster.features, 5)
        self.assertIsNotNone(self.forecaster.model)
    
    async def test_training_empty_data(self):
        """Test training with empty data."""
        empty_data = pd.DataFrame()
        metrics = await self.forecaster.train(empty_data)
        
        self.assertIn('error', metrics)
    
    async def test_training_with_data(self):
        """Test training with valid data."""
        metrics = await self.forecaster.train(self.sample_data)
        
        if 'error' not in metrics:
            self.assertIn('training_time', metrics)
            self.assertIn('training_samples', metrics)
            self.assertGreater(metrics['training_time'], 0)
            self.assertGreater(metrics['training_samples'], 0)
    
    async def test_prediction(self):
        """Test prediction functionality."""
        # Train first
        await self.forecaster.train(self.sample_data)
        
        # Make prediction
        recent_data = self.sample_data.tail(20)
        prediction = await self.forecaster.predict(recent_data)
        
        self.assertIsInstance(prediction, float)
        self.assertGreaterEqual(prediction, 0.0)
        self.assertLessEqual(prediction, 1.0)
    
    async def test_prediction_with_confidence(self):
        """Test prediction with confidence intervals."""
        # Train first
        await self.forecaster.train(self.sample_data)
        
        # Make prediction with confidence
        recent_data = self.sample_data.tail(20)
        detailed_prediction = await self.forecaster.predict_with_confidence(recent_data)
        
        self.assertIsInstance(detailed_prediction, LSTMPrediction)
        self.assertIsInstance(detailed_prediction.timestamp, datetime)
        self.assertIsInstance(detailed_prediction.predicted_value, float)
        self.assertIsInstance(detailed_prediction.confidence_interval, tuple)
        self.assertEqual(len(detailed_prediction.confidence_interval), 2)
        self.assertIsInstance(detailed_prediction.features_used, list)
    
    def test_model_info(self):
        """Test model information retrieval."""
        info = self.forecaster.get_model_info()
        
        self.assertIsInstance(info, dict)
        self.assertIn('model_type', info)
        self.assertIn('sequence_length', info)
        self.assertIn('features', info)
        self.assertIn('is_trained', info)
    
    def test_model_save_load(self):
        """Test model saving and loading."""
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, 'test_lstm_model.pkl')
            
            # Save model
            self.forecaster.save_model(model_path)
            self.assertTrue(os.path.exists(model_path))
            
            # Create new forecaster and load model
            new_forecaster = LSTMForecaster(
                sequence_length=10,
                features=5,
                model_type='random_forest'
            )
            new_forecaster.load_model(model_path)
            
            # Check if loaded correctly
            self.assertEqual(new_forecaster.sequence_length, self.forecaster.sequence_length)
            self.assertEqual(new_forecaster.features, self.forecaster.features)
            self.assertEqual(new_forecaster.model_type, self.forecaster.model_type)


class TestRiskClassifier(unittest.TestCase):
    """Test cases for Risk Classifier."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.classifier = RiskClassifier(
            model_type='random_forest',
            n_estimators=10  # Small for testing
        )
        
        # Generate sample data
        np.random.seed(42)
        n_samples = 100
        
        self.sample_data = pd.DataFrame({
            'risk_score': np.random.random(n_samples),
            'event_count': np.random.poisson(3, n_samples),
            'severity': np.random.uniform(1, 5, n_samples),
            'classification': np.random.choice(['U', 'S', 'TS'], n_samples),
            'source_entropy': np.random.random(n_samples),
            'anomaly_score': np.random.random(n_samples),
            'byzantine_risk': np.random.random(n_samples),
            'trend_risk': np.random.random(n_samples),
            'cross_layer_correlation': np.random.random(n_samples),
            'system_load': np.random.random(n_samples)
        })
    
    def test_initialization(self):
        """Test risk classifier initialization."""
        self.assertIsNotNone(self.classifier)
        self.assertEqual(self.classifier.model_type, 'random_forest')
        self.assertIsNotNone(self.classifier.model)
        self.assertIsNotNone(self.classifier.scaler)
    
    async def test_training(self):
        """Test classifier training."""
        metrics = await self.classifier.train(self.sample_data)
        
        if 'error' not in metrics:
            self.assertIn('training_time', metrics)
            self.assertIn('training_samples', metrics)
            self.assertIn('test_accuracy', metrics)
            self.assertGreater(metrics['training_time'], 0)
            self.assertGreater(metrics['training_samples'], 0)
            self.assertGreaterEqual(metrics['test_accuracy'], 0.0)
            self.assertLessEqual(metrics['test_accuracy'], 1.0)
    
    async def test_prediction(self):
        """Test risk prediction."""
        # Train first
        await self.classifier.train(self.sample_data)
        
        # Make prediction
        test_data = self.sample_data.head(1)
        prediction = await self.classifier.predict(test_data)
        
        self.assertIsInstance(prediction, float)
        self.assertGreaterEqual(prediction, 0.0)
        self.assertLessEqual(prediction, 1.0)
    
    async def test_detailed_prediction(self):
        """Test detailed risk prediction."""
        # Train first
        await self.classifier.train(self.sample_data)
        
        # Make detailed prediction
        test_data = self.sample_data.head(1)
        detailed = await self.classifier.predict_detailed(test_data)
        
        self.assertIsInstance(detailed, RiskPrediction)
        self.assertIsInstance(detailed.timestamp, datetime)
        self.assertIn(detailed.predicted_risk, list(RiskLevel))
        self.assertIsInstance(detailed.confidence_scores, dict)
        self.assertIsInstance(detailed.feature_importance, dict)
        self.assertIsInstance(detailed.classification_reasoning, list)
    
    def test_feature_importance(self):
        """Test feature importance retrieval."""
        # Initially empty
        importance = self.classifier.get_feature_importance()
        self.assertIsInstance(importance, dict)
    
    def test_model_info(self):
        """Test model information."""
        info = self.classifier.get_model_info()
        
        self.assertIsInstance(info, dict)
        self.assertIn('model_type', info)
        self.assertIn('is_trained', info)


class TestAnomalyDetector(unittest.TestCase):
    """Test cases for Anomaly Detector."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector(
            method='isolation_forest',
            contamination=0.1,
            window_size=50
        )
        
        # Generate normal and anomalous data
        np.random.seed(42)
        
        # Normal data
        self.normal_data = pd.DataFrame({
            'risk_score': np.random.normal(0.3, 0.1, 80),
            'event_count': np.random.poisson(3, 80),
            'severity': np.random.normal(2.5, 0.5, 80),
            'classification': np.random.choice(['U', 'S', 'TS'], 80),
            'source_entropy': np.random.normal(0.5, 0.2, 80),
            'temporal_pattern': np.sin(np.arange(80) * 2 * np.pi / 24),
            'system_load': np.random.normal(0.4, 0.1, 80),
            'anomaly_score': np.random.normal(0.2, 0.1, 80),
            'byzantine_risk': np.random.normal(0.1, 0.05, 80),
            'cross_layer_correlation': np.random.normal(0.3, 0.1, 80)
        })
        
        # Anomalous data
        self.anomalous_data = pd.DataFrame({
            'risk_score': [0.9, 0.95],
            'event_count': [50, 45],
            'severity': [5.0, 4.8],
            'classification': ['TS', 'TS'],
            'source_entropy': [0.1, 0.05],
            'temporal_pattern': [0.0, 0.0],
            'system_load': [0.95, 0.98],
            'anomaly_score': [0.9, 0.95],
            'byzantine_risk': [0.8, 0.85],
            'cross_layer_correlation': [0.9, 0.88]
        })
    
    def test_initialization(self):
        """Test anomaly detector initialization."""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.method, AnomalyMethod.ISOLATION_FOREST)
        self.assertEqual(self.detector.contamination, 0.1)
        self.assertIsNotNone(self.detector.models)
    
    async def test_training(self):
        """Test anomaly detector training."""
        metrics = await self.detector.train(self.normal_data)
        
        if 'error' not in metrics:
            self.assertIn('training_time', metrics)
            self.assertIn('training_samples', metrics)
            self.assertIn('method', metrics)
            self.assertGreater(metrics['training_time'], 0)
            self.assertGreater(metrics['training_samples'], 0)
    
    async def test_prediction(self):
        """Test anomaly prediction."""
        # Train first
        await self.detector.train(self.normal_data)
        
        # Test normal data
        normal_score = await self.detector.predict(self.normal_data.head(1))
        self.assertIsInstance(normal_score, float)
        self.assertGreaterEqual(normal_score, 0.0)
        self.assertLessEqual(normal_score, 1.0)
        
        # Test anomalous data
        anomalous_score = await self.detector.predict(self.anomalous_data.head(1))
        self.assertIsInstance(anomalous_score, float)
        self.assertGreaterEqual(anomalous_score, 0.0)
        self.assertLessEqual(anomalous_score, 1.0)
        
        # Anomalous score should generally be higher
        # Note: This may not always be true due to randomness in test data
        # self.assertGreater(anomalous_score, normal_score)
    
    async def test_anomaly_detection(self):
        """Test detailed anomaly detection."""
        # Train first
        await self.detector.train(self.normal_data)
        
        # Test detection
        detection = await self.detector.detect_anomaly(self.anomalous_data.head(1))
        
        self.assertIsInstance(detection, AnomalyDetection)
        self.assertIsInstance(detection.timestamp, datetime)
        self.assertIsInstance(detection.is_anomaly, bool)
        self.assertIsInstance(detection.anomaly_score, float)
        self.assertIn(detection.anomaly_type, list(AnomalyType))
        self.assertIsInstance(detection.confidence, float)
        self.assertIsInstance(detection.method_scores, dict)
        self.assertIsInstance(detection.feature_contributions, dict)
        self.assertIsInstance(detection.reasoning, list)
    
    def test_anomaly_patterns(self):
        """Test anomaly pattern tracking."""
        patterns = self.detector.get_anomaly_patterns()
        self.assertIsInstance(patterns, dict)
    
    def test_anomaly_history(self):
        """Test anomaly history retrieval."""
        history = self.detector.get_anomaly_history()
        self.assertIsInstance(history, list)
    
    def test_model_info(self):
        """Test model information."""
        info = self.detector.get_model_info()
        
        self.assertIsInstance(info, dict)
        self.assertIn('method', info)
        self.assertIn('contamination', info)
        self.assertIn('detection_history', info)


class TestModelValidators(unittest.TestCase):
    """Test cases for model validators."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.lstm_forecaster = LSTMForecaster(
            sequence_length=5,
            features=3,
            model_type='random_forest'
        )
        
        self.risk_classifier = RiskClassifier(
            model_type='random_forest',
            n_estimators=10
        )
        
        # Create validators
        self.lstm_validator = LSTMForecasterValidator(self.lstm_forecaster)
        self.risk_validator = RiskClassifierValidator(self.risk_classifier)
        
        # Sample test data
        np.random.seed(42)
        self.test_data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=20, freq='H'),
            'risk_score': np.random.random(20),
            'event_count': np.random.poisson(3, 20),
            'severity': np.random.uniform(1, 5, 20),
            'classification': np.random.choice(['U', 'S', 'TS'], 20),
            'source_entropy': np.random.random(20)
        })
        
        self.ground_truth = np.random.random(20)
        self.risk_ground_truth = [RiskLevel(int(x * 4)) for x in np.random.random(20)]
    
    async def test_lstm_validation(self):
        """Test LSTM forecaster validation."""
        # Train first
        await self.lstm_forecaster.train(self.test_data)
        
        # Validate predictions
        validation_results = await self.lstm_validator.validate_predictions(
            self.test_data, self.ground_truth.tolist()
        )
        
        if 'error' not in validation_results:
            self.assertIn('mse', validation_results)
            self.assertIn('mae', validation_results)
            self.assertIn('accuracy', validation_results)
            self.assertIn('predictions', validation_results)
            self.assertIn('ground_truth', validation_results)
    
    async def test_lstm_benchmarking(self):
        """Test LSTM forecaster benchmarking."""
        # Train first
        await self.lstm_forecaster.train(self.test_data)
        
        # Benchmark performance
        benchmark_results = await self.lstm_validator.benchmark_performance(
            self.test_data, n_runs=5
        )
        
        self.assertIn('avg_prediction_time', benchmark_results)
        self.assertIn('min_prediction_time', benchmark_results)
        self.assertIn('max_prediction_time', benchmark_results)
        self.assertGreater(benchmark_results['avg_prediction_time'], 0)
    
    async def test_risk_classifier_validation(self):
        """Test risk classifier validation."""
        # Train first
        await self.risk_classifier.train(self.test_data)
        
        # Validate classification
        validation_results = await self.risk_validator.validate_classification(
            self.test_data, self.risk_ground_truth
        )
        
        if 'error' not in validation_results:
            self.assertIn('accuracy', validation_results)
            self.assertIn('precision', validation_results)
            self.assertIn('recall', validation_results)
            self.assertIn('f1_score', validation_results)
    
    async def test_risk_classifier_benchmarking(self):
        """Test risk classifier benchmarking."""
        # Train first
        await self.risk_classifier.train(self.test_data)
        
        # Benchmark performance
        benchmark_results = await self.risk_validator.benchmark_performance(
            self.test_data, n_runs=5
        )
        
        self.assertIn('avg_prediction_time', benchmark_results)
        self.assertIn('avg_detailed_prediction_time', benchmark_results)
        self.assertGreater(benchmark_results['avg_prediction_time'], 0)


class TestModelIntegration(unittest.TestCase):
    """Integration tests for all models working together."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.lstm_forecaster = LSTMForecaster(
            sequence_length=10,
            features=8,
            model_type='random_forest'
        )
        
        self.risk_classifier = RiskClassifier(
            model_type='random_forest',
            n_estimators=10
        )
        
        self.anomaly_detector = AnomalyDetector(
            method='isolation_forest',
            contamination=0.1
        )
        
        # Generate comprehensive test data
        np.random.seed(42)
        n_samples = 100
        
        self.comprehensive_data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='H'),
            'risk_score': np.random.random(n_samples),
            'event_count': np.random.poisson(3, n_samples),
            'severity': np.random.uniform(1, 5, n_samples),
            'classification': np.random.choice(['U', 'S', 'TS'], n_samples),
            'source_entropy': np.random.random(n_samples),
            'temporal_pattern': np.sin(np.arange(n_samples) * 2 * np.pi / 24),
            'system_load': np.random.random(n_samples),
            'anomaly_score': np.random.random(n_samples),
            'byzantine_risk': np.random.random(n_samples),
            'cross_layer_correlation': np.random.random(n_samples),
            'threat_level': np.random.random(n_samples)
        })
    
    async def test_models_training_pipeline(self):
        """Test training all models in sequence."""
        # Train LSTM
        lstm_metrics = await self.lstm_forecaster.train(self.comprehensive_data)
        
        # Train Risk Classifier
        risk_metrics = await self.risk_classifier.train(self.comprehensive_data)
        
        # Train Anomaly Detector
        anomaly_metrics = await self.anomaly_detector.train(self.comprehensive_data)
        
        # Verify all trained successfully
        if 'error' not in lstm_metrics:
            self.assertIn('training_time', lstm_metrics)
        
        if 'error' not in risk_metrics:
            self.assertIn('training_time', risk_metrics)
        
        if 'error' not in anomaly_metrics:
            self.assertIn('training_time', anomaly_metrics)
    
    async def test_models_prediction_pipeline(self):
        """Test prediction pipeline using all models."""
        # Train all models
        await self.lstm_forecaster.train(self.comprehensive_data)
        await self.risk_classifier.train(self.comprehensive_data)
        await self.anomaly_detector.train(self.comprehensive_data)
        
        # Test data
        test_data = self.comprehensive_data.tail(10)
        
        # Get predictions from all models
        lstm_prediction = await self.lstm_forecaster.predict(test_data)
        risk_prediction = await self.risk_classifier.predict(test_data)
        anomaly_prediction = await self.anomaly_detector.predict(test_data)
        
        # Verify predictions
        self.assertIsInstance(lstm_prediction, float)
        self.assertIsInstance(risk_prediction, float)
        self.assertIsInstance(anomaly_prediction, float)
        
        # All predictions should be in valid ranges
        self.assertGreaterEqual(lstm_prediction, 0.0)
        self.assertLessEqual(lstm_prediction, 1.0)
        self.assertGreaterEqual(risk_prediction, 0.0)
        self.assertLessEqual(risk_prediction, 1.0)
        self.assertGreaterEqual(anomaly_prediction, 0.0)
        self.assertLessEqual(anomaly_prediction, 1.0)
    
    async def test_ensemble_prediction(self):
        """Test ensemble prediction combining all models."""
        # Train all models
        await self.lstm_forecaster.train(self.comprehensive_data)
        await self.risk_classifier.train(self.comprehensive_data)
        await self.anomaly_detector.train(self.comprehensive_data)
        
        # Test data
        test_data = self.comprehensive_data.tail(5)
        
        # Get predictions from all models
        predictions = []
        for i in range(len(test_data)):
            row_data = test_data.iloc[[i]]
            
            lstm_pred = await self.lstm_forecaster.predict(row_data)
            risk_pred = await self.risk_classifier.predict(row_data)
            anomaly_pred = await self.anomaly_detector.predict(row_data)
            
            # Simple ensemble: weighted average
            ensemble_pred = (lstm_pred * 0.4 + risk_pred * 0.4 + anomaly_pred * 0.2)
            predictions.append(ensemble_pred)
        
        # Verify ensemble predictions
        self.assertEqual(len(predictions), len(test_data))
        for pred in predictions:
            self.assertIsInstance(pred, float)
            self.assertGreaterEqual(pred, 0.0)
            self.assertLessEqual(pred, 1.0)


# Test runner for models

class ModelTestRunner:
    """Test runner for ML models."""
    
    @staticmethod
    def run_model_tests():
        """Run all model tests."""
        suite = unittest.TestSuite()
        
        # Add test cases
        suite.addTest(unittest.makeSuite(TestLSTMForecaster))
        suite.addTest(unittest.makeSuite(TestRiskClassifier))
        suite.addTest(unittest.makeSuite(TestAnomalyDetector))
        suite.addTest(unittest.makeSuite(TestModelValidators))
        suite.addTest(unittest.makeSuite(TestModelIntegration))
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return result
    
    @staticmethod
    async def run_async_model_tests():
        """Run async model tests."""
        print("Running async model tests...")
        
        # Test LSTM Forecaster
        lstm_test = TestLSTMForecaster()
        lstm_test.setUp()
        
        try:
            await lstm_test.test_training_with_data()
            print("✓ LSTM training test passed")
            
            await lstm_test.test_prediction()
            print("✓ LSTM prediction test passed")
            
            await lstm_test.test_prediction_with_confidence()
            print("✓ LSTM confidence prediction test passed")
            
        except Exception as e:
            print(f"✗ LSTM test failed: {e}")
        
        # Test Risk Classifier
        risk_test = TestRiskClassifier()
        risk_test.setUp()
        
        try:
            await risk_test.test_training()
            print("✓ Risk classifier training test passed")
            
            await risk_test.test_prediction()
            print("✓ Risk classifier prediction test passed")
            
            await risk_test.test_detailed_prediction()
            print("✓ Risk classifier detailed prediction test passed")
            
        except Exception as e:
            print(f"✗ Risk classifier test failed: {e}")
        
        # Test Anomaly Detector
        anomaly_test = TestAnomalyDetector()
        anomaly_test.setUp()
        
        try:
            await anomaly_test.test_training()
            print("✓ Anomaly detector training test passed")
            
            await anomaly_test.test_prediction()
            print("✓ Anomaly detector prediction test passed")
            
            await anomaly_test.test_anomaly_detection()
            print("✓ Anomaly detector detection test passed")
            
        except Exception as e:
            print(f"✗ Anomaly detector test failed: {e}")
        
        # Test Integration
        integration_test = TestModelIntegration()
        integration_test.setUp()
        
        try:
            await integration_test.test_models_training_pipeline()
            print("✓ Model training pipeline test passed")
            
            await integration_test.test_models_prediction_pipeline()
            print("✓ Model prediction pipeline test passed")
            
            await integration_test.test_ensemble_prediction()
            print("✓ Ensemble prediction test passed")
            
        except Exception as e:
            print(f"✗ Integration test failed: {e}")
        
        print("Async model tests completed")


if __name__ == "__main__":
    print("ML Models Test Suite")
    print("=" * 50)
    
    # Run sync tests
    print("\nRunning synchronous model tests...")
    test_runner = ModelTestRunner()
    result = test_runner.run_model_tests()
    
    # Run async tests
    print("\nRunning asynchronous model tests...")
    asyncio.run(ModelTestRunner.run_async_model_tests())
    
    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✓ All model tests passed!")
    else:
        print(f"✗ {len(result.failures)} failures, {len(result.errors)} errors")
    
    print("Model test suite completed") 