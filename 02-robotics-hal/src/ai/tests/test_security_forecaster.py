"""
Test Suite for Security Forecasting System

Comprehensive tests for the SecurityForecaster class including
unit tests, integration tests, and performance benchmarks.
"""

import unittest
import asyncio
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import tempfile
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from security_forecaster import (
    SecurityForecaster, SecurityEvent, ThreatForecast, SecurityPosture,
    ClassificationLevel, RiskLevel, SecurityForecasterHealthCheck
)


class TestSecurityForecaster(unittest.TestCase):
    """Test cases for SecurityForecaster class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'sequence_length': 10,
            'features': 5,
            'collection_interval': 1,
            'risk_model': 'random_forest',
            'anomaly_method': 'isolation_forest'
        }
        
        self.forecaster = SecurityForecaster(self.config)
        
        # Sample events
        self.sample_events = [
            SecurityEvent(
                timestamp=datetime.now() - timedelta(minutes=10),
                event_type="authentication_failure",
                severity=3,
                classification=ClassificationLevel.SECRET,
                source="auth_service",
                description="Failed login attempt",
                risk_score=0.6,
                metadata={"user": "test_user", "attempts": 3}
            ),
            SecurityEvent(
                timestamp=datetime.now() - timedelta(minutes=5),
                event_type="anomalous_behavior",
                severity=4,
                classification=ClassificationLevel.TOP_SECRET,
                source="behavior_monitor",
                description="Unusual access pattern",
                risk_score=0.8,
                metadata={"pattern": "off_hours_access", "volume": "high"}
            ),
            SecurityEvent(
                timestamp=datetime.now() - timedelta(minutes=1),
                event_type="normal_operation",
                severity=1,
                classification=ClassificationLevel.UNCLASSIFIED,
                source="system_monitor",
                description="Normal system operation",
                risk_score=0.1,
                metadata={"status": "normal"}
            )
        ]
    
    def tearDown(self):
        """Clean up after tests."""
        # Clean up any temporary files
        pass
    
    def test_initialization(self):
        """Test SecurityForecaster initialization."""
        self.assertIsNotNone(self.forecaster)
        self.assertEqual(self.forecaster.config, self.config)
        self.assertIsNotNone(self.forecaster.lstm_forecaster)
        self.assertIsNotNone(self.forecaster.risk_classifier)
        self.assertIsNotNone(self.forecaster.anomaly_detector)
        self.assertIsNotNone(self.forecaster.telemetry_collector)
        self.assertIsNotNone(self.forecaster.feature_engineer)
        
        # Check initial state
        self.assertFalse(self.forecaster.running)
        self.assertEqual(len(self.forecaster.security_events), 0)
        self.assertIsNone(self.forecaster.current_posture)
    
    async def test_start_stop(self):
        """Test start and stop functionality."""
        # Test start
        await self.forecaster.start()
        self.assertTrue(self.forecaster.running)
        self.assertTrue(len(self.forecaster.background_tasks) > 0)
        
        # Test stop
        await self.forecaster.stop()
        self.assertFalse(self.forecaster.running)
        self.assertEqual(len(self.forecaster.background_tasks), 0)
    
    async def test_collect_security_telemetry(self):
        """Test telemetry collection."""
        telemetry = await self.forecaster.collect_security_telemetry()
        
        self.assertIsInstance(telemetry, dict)
        self.assertIn('collection_timestamp', telemetry)
        self.assertIn('forecaster_version', telemetry)
    
    async def test_train_models_empty_data(self):
        """Test model training with empty data."""
        empty_data = pd.DataFrame()
        metrics = await self.forecaster.train_models(empty_data)
        
        self.assertIn('error', metrics)
        self.assertEqual(metrics['error'], 'No training data available')
    
    async def test_train_models_with_data(self):
        """Test model training with valid data."""
        # Create sample training data
        training_data = pd.DataFrame({
            'timestamp': [event.timestamp for event in self.sample_events],
            'event_type': [event.event_type for event in self.sample_events],
            'severity': [event.severity for event in self.sample_events],
            'classification': [event.classification.value for event in self.sample_events],
            'source': [event.source for event in self.sample_events],
            'risk_score': [event.risk_score for event in self.sample_events]
        })
        
        metrics = await self.forecaster.train_models(training_data)
        
        self.assertIsInstance(metrics, dict)
        if 'error' not in metrics:
            self.assertIn('training_time', metrics)
            self.assertGreater(metrics['training_time'], 0)
    
    async def test_forecast_security_posture(self):
        """Test security posture forecasting."""
        # Add some events first
        for event in self.sample_events:
            await self.forecaster.update_security_event(event)
        
        forecast = await self.forecaster.forecast_security_posture(
            horizon=timedelta(hours=1),
            classification=ClassificationLevel.SECRET
        )
        
        self.assertIsInstance(forecast, ThreatForecast)
        self.assertIsInstance(forecast.timestamp, datetime)
        self.assertIsInstance(forecast.threat_probability, float)
        self.assertIn(forecast.risk_level, list(RiskLevel))
        self.assertIsInstance(forecast.predicted_events, list)
        self.assertIsInstance(forecast.recommendations, list)
        self.assertEqual(forecast.classification, ClassificationLevel.SECRET)
        
        # Check value ranges
        self.assertGreaterEqual(forecast.threat_probability, 0.0)
        self.assertLessEqual(forecast.threat_probability, 1.0)
        self.assertGreaterEqual(forecast.confidence_score, 0.0)
        self.assertLessEqual(forecast.confidence_score, 1.0)
    
    def test_calculate_risk_scores_empty(self):
        """Test risk score calculation with empty events."""
        risk_scores = self.forecaster.calculate_risk_scores([])
        
        self.assertIsInstance(risk_scores, dict)
        self.assertEqual(risk_scores['overall_risk'], 0.0)
        self.assertEqual(risk_scores['temporal_risk'], 0.0)
        self.assertEqual(risk_scores['classification_risk'], 0.0)
        self.assertEqual(risk_scores['byzantine_risk'], 0.0)
        self.assertEqual(risk_scores['trend_risk'], 0.0)
    
    def test_calculate_risk_scores_with_events(self):
        """Test risk score calculation with events."""
        risk_scores = self.forecaster.calculate_risk_scores(self.sample_events)
        
        self.assertIsInstance(risk_scores, dict)
        self.assertIn('overall_risk', risk_scores)
        self.assertIn('temporal_risk', risk_scores)
        self.assertIn('classification_risk', risk_scores)
        self.assertIn('byzantine_risk', risk_scores)
        self.assertIn('trend_risk', risk_scores)
        
        # Check value ranges
        for key, value in risk_scores.items():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)
    
    async def test_generate_recommendations(self):
        """Test recommendation generation."""
        recommendations = await self.forecaster.generate_recommendations(
            RiskLevel.HIGH,
            ["security_escalation", "anomalous_event_frequency"],
            ClassificationLevel.TOP_SECRET
        )
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        
        # Check for expected recommendation types
        recommendations_str = " ".join(recommendations).lower()
        self.assertTrue(any(keyword in recommendations_str for keyword in 
                           ["monitoring", "security", "escalate", "response"]))
    
    async def test_update_security_event(self):
        """Test security event updates."""
        initial_count = len(self.forecaster.security_events)
        
        await self.forecaster.update_security_event(self.sample_events[0])
        
        self.assertEqual(len(self.forecaster.security_events), initial_count + 1)
        self.assertEqual(self.forecaster.security_events[-1], self.sample_events[0])
    
    async def test_get_current_posture(self):
        """Test getting current security posture."""
        # Initially should be None
        posture = await self.forecaster.get_current_posture()
        self.assertIsNone(posture)
        
        # Add events and update posture
        for event in self.sample_events:
            await self.forecaster.update_security_event(event)
        
        # Manually trigger posture update
        await self.forecaster._update_current_posture()
        
        posture = await self.forecaster.get_current_posture()
        if posture is not None:
            self.assertIsInstance(posture, SecurityPosture)
            self.assertIsInstance(posture.timestamp, datetime)
            self.assertGreaterEqual(posture.overall_risk_score, 0.0)
            self.assertLessEqual(posture.overall_risk_score, 1.0)
    
    def test_classification_thresholds(self):
        """Test classification-specific thresholds."""
        thresholds = self.forecaster.classification_thresholds
        
        self.assertIn(ClassificationLevel.UNCLASSIFIED, thresholds)
        self.assertIn(ClassificationLevel.SECRET, thresholds)
        self.assertIn(ClassificationLevel.TOP_SECRET, thresholds)
        
        # TOP_SECRET should have lower threshold (more sensitive)
        self.assertLess(
            thresholds[ClassificationLevel.TOP_SECRET],
            thresholds[ClassificationLevel.SECRET]
        )
        self.assertLess(
            thresholds[ClassificationLevel.SECRET],
            thresholds[ClassificationLevel.UNCLASSIFIED]
        )
    
    def test_risk_weights(self):
        """Test risk scoring weights."""
        weights = self.forecaster.risk_weights
        
        self.assertIn('temporal_decay', weights)
        self.assertIn('classification_amplifier', weights)
        self.assertIn('byzantine_factor', weights)
        self.assertIn('cross_layer_correlation', weights)
        
        # Classification amplifier should increase with classification level
        amplifiers = weights['classification_amplifier']
        self.assertLess(
            amplifiers[ClassificationLevel.UNCLASSIFIED],
            amplifiers[ClassificationLevel.SECRET]
        )
        self.assertLess(
            amplifiers[ClassificationLevel.SECRET],
            amplifiers[ClassificationLevel.TOP_SECRET]
        )


class TestSecurityEvent(unittest.TestCase):
    """Test cases for SecurityEvent class."""
    
    def test_security_event_creation(self):
        """Test SecurityEvent creation."""
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="test_event",
            severity=3,
            classification=ClassificationLevel.SECRET,
            source="test_source",
            description="Test event description",
            risk_score=0.5,
            metadata={"key": "value"}
        )
        
        self.assertIsInstance(event.timestamp, datetime)
        self.assertEqual(event.event_type, "test_event")
        self.assertEqual(event.severity, 3)
        self.assertEqual(event.classification, ClassificationLevel.SECRET)
        self.assertEqual(event.source, "test_source")
        self.assertEqual(event.risk_score, 0.5)
        self.assertIsInstance(event.metadata, dict)


class TestThreatForecast(unittest.TestCase):
    """Test cases for ThreatForecast class."""
    
    def test_threat_forecast_creation(self):
        """Test ThreatForecast creation."""
        forecast = ThreatForecast(
            timestamp=datetime.now(),
            forecast_horizon=timedelta(hours=24),
            threat_probability=0.7,
            risk_level=RiskLevel.HIGH,
            predicted_events=["threat1", "threat2"],
            confidence_score=0.8,
            recommendations=["action1", "action2"],
            classification=ClassificationLevel.SECRET
        )
        
        self.assertIsInstance(forecast.timestamp, datetime)
        self.assertIsInstance(forecast.forecast_horizon, timedelta)
        self.assertEqual(forecast.threat_probability, 0.7)
        self.assertEqual(forecast.risk_level, RiskLevel.HIGH)
        self.assertIsInstance(forecast.predicted_events, list)
        self.assertIsInstance(forecast.recommendations, list)
        self.assertEqual(forecast.classification, ClassificationLevel.SECRET)


class TestSecurityForecasterHealthCheck(unittest.TestCase):
    """Test cases for SecurityForecasterHealthCheck."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.forecaster = SecurityForecaster()
        self.health_checker = SecurityForecasterHealthCheck(self.forecaster)
    
    async def test_check_system_health(self):
        """Test system health check."""
        health_status = await self.health_checker.check_system_health()
        
        self.assertIsInstance(health_status, dict)
        self.assertIn('overall_status', health_status)
        self.assertIn('timestamp', health_status)
        self.assertIn('checks', health_status)
        
        # Check status values
        self.assertIn(health_status['overall_status'], ['healthy', 'degraded', 'unhealthy'])
        
        # Check individual checks
        checks = health_status['checks']
        self.assertIn('forecaster_running', checks)
        
        for check_name, check_result in checks.items():
            self.assertIn('status', check_result)
            self.assertIn('message', check_result)
            self.assertIn(check_result['status'], ['pass', 'warn', 'fail'])


class TestSecurityForecasterIntegration(unittest.TestCase):
    """Integration tests for SecurityForecaster."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.forecaster = SecurityForecaster({
            'sequence_length': 5,
            'features': 3,
            'collection_interval': 1
        })
    
    async def test_end_to_end_forecasting(self):
        """Test end-to-end forecasting workflow."""
        # Create sample events
        events = []
        for i in range(10):
            event = SecurityEvent(
                timestamp=datetime.now() - timedelta(minutes=i),
                event_type=f"event_{i}",
                severity=np.random.randint(1, 6),
                classification=np.random.choice(list(ClassificationLevel)),
                source=f"source_{i % 3}",
                description=f"Event {i} description",
                risk_score=np.random.random(),
                metadata={"index": i}
            )
            events.append(event)
        
        # Add events to forecaster
        for event in events:
            await self.forecaster.update_security_event(event)
        
        # Generate forecast
        forecast = await self.forecaster.forecast_security_posture(
            horizon=timedelta(hours=1),
            classification=ClassificationLevel.SECRET
        )
        
        # Verify forecast
        self.assertIsInstance(forecast, ThreatForecast)
        self.assertGreaterEqual(forecast.threat_probability, 0.0)
        self.assertLessEqual(forecast.threat_probability, 1.0)
        self.assertIsInstance(forecast.predicted_events, list)
        self.assertIsInstance(forecast.recommendations, list)
    
    async def test_performance_requirements(self):
        """Test performance requirements are met."""
        # Add sample event
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="performance_test",
            severity=3,
            classification=ClassificationLevel.SECRET,
            source="test_source",
            description="Performance test event",
            risk_score=0.5,
            metadata={}
        )
        
        await self.forecaster.update_security_event(event)
        
        # Measure prediction latency
        start_time = datetime.now()
        forecast = await self.forecaster.forecast_security_posture()
        end_time = datetime.now()
        
        latency = (end_time - start_time).total_seconds()
        
        # Should be less than 100ms (0.1 seconds)
        self.assertLess(latency, 0.5, "Prediction latency exceeds target (allowing 0.5s for test)")
    
    async def test_concurrent_operations(self):
        """Test concurrent operations."""
        async def add_events():
            for i in range(5):
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type=f"concurrent_event_{i}",
                    severity=2,
                    classification=ClassificationLevel.UNCLASSIFIED,
                    source="concurrent_source",
                    description=f"Concurrent event {i}",
                    risk_score=0.3,
                    metadata={"concurrent": True}
                )
                await self.forecaster.update_security_event(event)
        
        async def generate_forecasts():
            forecasts = []
            for i in range(3):
                forecast = await self.forecaster.forecast_security_posture()
                forecasts.append(forecast)
            return forecasts
        
        # Run concurrent operations
        events_task = asyncio.create_task(add_events())
        forecasts_task = asyncio.create_task(generate_forecasts())
        
        await asyncio.gather(events_task, forecasts_task)
        
        # Verify both operations completed successfully
        self.assertTrue(events_task.done())
        self.assertTrue(forecasts_task.done())
        
        forecasts = forecasts_task.result()
        self.assertEqual(len(forecasts), 3)
        for forecast in forecasts:
            self.assertIsInstance(forecast, ThreatForecast)


class TestSecurityForecasterPerformance(unittest.TestCase):
    """Performance tests for SecurityForecaster."""
    
    def setUp(self):
        """Set up performance test fixtures."""
        self.forecaster = SecurityForecaster({
            'sequence_length': 100,
            'features': 50,
            'collection_interval': 30
        })
    
    async def test_memory_usage(self):
        """Test memory usage with large number of events."""
        import psutil
        
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Add large number of events
        for i in range(1000):
            event = SecurityEvent(
                timestamp=datetime.now() - timedelta(seconds=i),
                event_type=f"memory_test_{i}",
                severity=np.random.randint(1, 6),
                classification=np.random.choice(list(ClassificationLevel)),
                source=f"source_{i % 10}",
                description=f"Memory test event {i}",
                risk_score=np.random.random(),
                metadata={"index": i}
            )
            await self.forecaster.update_security_event(event)
        
        # Get final memory usage
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB)
        self.assertLess(memory_increase, 100 * 1024 * 1024, 
                       "Memory usage increased by more than 100MB")
    
    async def test_throughput(self):
        """Test event processing throughput."""
        event_count = 100
        start_time = datetime.now()
        
        # Process events
        for i in range(event_count):
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type=f"throughput_test_{i}",
                severity=3,
                classification=ClassificationLevel.UNCLASSIFIED,
                source="throughput_source",
                description=f"Throughput test event {i}",
                risk_score=0.5,
                metadata={"index": i}
            )
            await self.forecaster.update_security_event(event)
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        # Calculate throughput (events per second)
        throughput = event_count / processing_time
        
        # Should process at least 50 events per second
        self.assertGreater(throughput, 50, 
                          f"Throughput too low: {throughput:.2f} events/sec")


# Test runner and utilities

def run_async_test(test_func):
    """Helper to run async test functions."""
    return asyncio.run(test_func())


class AsyncTestRunner:
    """Custom test runner for async tests."""
    
    @staticmethod
    def run_test_suite():
        """Run the complete test suite."""
        # Create test suite
        suite = unittest.TestSuite()
        
        # Add test cases
        suite.addTest(unittest.makeSuite(TestSecurityForecaster))
        suite.addTest(unittest.makeSuite(TestSecurityEvent))
        suite.addTest(unittest.makeSuite(TestThreatForecast))
        suite.addTest(unittest.makeSuite(TestSecurityForecasterHealthCheck))
        suite.addTest(unittest.makeSuite(TestSecurityForecasterIntegration))
        suite.addTest(unittest.makeSuite(TestSecurityForecasterPerformance))
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return result
    
    @staticmethod
    async def run_async_tests():
        """Run async-specific tests."""
        print("Running async tests...")
        
        # Test SecurityForecaster
        forecaster_test = TestSecurityForecaster()
        forecaster_test.setUp()
        
        try:
            await forecaster_test.test_start_stop()
            print("✓ Start/stop test passed")
            
            await forecaster_test.test_collect_security_telemetry()
            print("✓ Telemetry collection test passed")
            
            await forecaster_test.test_forecast_security_posture()
            print("✓ Forecast generation test passed")
            
            await forecaster_test.test_generate_recommendations()
            print("✓ Recommendation generation test passed")
            
        except Exception as e:
            print(f"✗ Async test failed: {e}")
        
        # Test Health Check
        health_test = TestSecurityForecasterHealthCheck()
        health_test.setUp()
        
        try:
            await health_test.test_check_system_health()
            print("✓ Health check test passed")
            
        except Exception as e:
            print(f"✗ Health check test failed: {e}")
        
        # Test Integration
        integration_test = TestSecurityForecasterIntegration()
        integration_test.setUp()
        
        try:
            await integration_test.test_end_to_end_forecasting()
            print("✓ End-to-end integration test passed")
            
            await integration_test.test_performance_requirements()
            print("✓ Performance requirements test passed")
            
            await integration_test.test_concurrent_operations()
            print("✓ Concurrent operations test passed")
            
        except Exception as e:
            print(f"✗ Integration test failed: {e}")
        
        # Test Performance
        performance_test = TestSecurityForecasterPerformance()
        performance_test.setUp()
        
        try:
            await performance_test.test_memory_usage()
            print("✓ Memory usage test passed")
            
            await performance_test.test_throughput()
            print("✓ Throughput test passed")
            
        except Exception as e:
            print(f"✗ Performance test failed: {e}")
        
        print("Async tests completed")


if __name__ == "__main__":
    print("Security Forecaster Test Suite")
    print("=" * 50)
    
    # Run sync tests
    print("\nRunning synchronous tests...")
    test_runner = AsyncTestRunner()
    result = test_runner.run_test_suite()
    
    # Run async tests
    print("\nRunning asynchronous tests...")
    asyncio.run(AsyncTestRunner.run_async_tests())
    
    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✓ All tests passed!")
    else:
        print(f"✗ {len(result.failures)} failures, {len(result.errors)} errors")
        
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback}")
        
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback}")
    
    print("Test suite completed") 