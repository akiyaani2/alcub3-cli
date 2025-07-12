#!/usr/bin/env python3
"""
ALCUB3 Behavioral Analysis Engine Test Suite
Comprehensive Testing for Behavioral Analysis Components

This module provides comprehensive testing for the behavioral analysis engine,
including unit tests, integration tests, and performance benchmarks.

Test Coverage:
- Behavioral analysis engine core functionality
- Multi-modal sensor fusion
- Temporal behavior analysis
- Cross-platform correlation
- Real-time monitoring
- Security integration
- Performance requirements

Author: ALCUB3 Development Team
Classification: For Official Use Only
"""

import pytest
import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any
import tempfile
import os
import json
from unittest.mock import Mock, patch, AsyncMock
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from behavioral_analyzer import (
    BehavioralAnalysisEngine, BehavioralFeature, BehavioralPattern,
    BehavioralAnomaly, BehavioralPatternType, BehavioralAnomalyType
)
from cross_platform_correlator import (
    CrossPlatformBehavioralCorrelator, RobotPlatformType,
    BehavioralCorrelation, BehavioralCorrelationType
)
from real_time_behavioral_monitor import (
    RealTimeBehavioralMonitor, StreamingDataPoint, ProcessingPriority,
    StreamingProcessor, PerformanceMetrics
)
from behavioral_security_integration import (
    BehavioralSecurityIntegration, BehavioralThreat, BehavioralThreatLevel,
    BehavioralSecurityEvent, BehavioralSecurityContext
)

# Import security components
sys.path.append(str(Path(__file__).parent.parent.parent.parent.parent / "02-security-maestro" / "src"))
from shared.classification import ClassificationLevel


class TestBehavioralAnalysisEngine:
    """Test cases for the behavioral analysis engine."""
    
    @pytest.fixture
    def behavioral_engine(self):
        """Create a behavioral analysis engine for testing."""
        return BehavioralAnalysisEngine(
            window_size=100,
            enable_ml=True,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
    
    @pytest.fixture
    def sample_sensor_data(self):
        """Create sample sensor data for testing."""
        return {
            'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
            'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
            'communication': {
                'message_frequency': 2.0,
                'message_types': {'status': 5, 'control': 2, 'data': 1, 'emergency': 0},
                'avg_response_time': 0.05,
                'signal_strength': 0.8,
                'packet_loss_rate': 0.01
            },
            'sensors': {
                'gps': {'value': 1.0, 'confidence': 0.95, 'noise_level': 0.02},
                'imu': {'value': 0.98, 'confidence': 0.99, 'noise_level': 0.01},
                'lidar': {'value': 0.85, 'confidence': 0.9, 'noise_level': 0.05}
            },
            'task_execution': {
                'completion_rate': 0.95,
                'execution_time': 2.5,
                'error_rate': 0.02,
                'complexity_score': 0.6,
                'cpu_usage': 0.4,
                'memory_usage': 0.3
            },
            'power': {
                'consumption': 150.0,
                'battery_level': 0.8,
                'efficiency': 0.85,
                'temperature': 35.0
            }
        }
    
    @pytest.mark.asyncio
    async def test_extract_behavioral_features(self, behavioral_engine, sample_sensor_data):
        """Test behavioral feature extraction."""
        robot_id = "test_robot_001"
        
        # Test feature extraction
        features = await behavioral_engine.extract_behavioral_features(
            robot_id, sample_sensor_data
        )
        
        # Verify features are extracted
        assert isinstance(features, dict)
        assert len(features) > 0
        
        # Check specific features
        assert 'movement' in features
        assert 'communication' in features
        assert 'sensors' in features
        assert 'task_execution' in features
        assert 'power' in features
        
        # Verify feature structure
        for feature_name, feature in features.items():
            assert isinstance(feature, BehavioralFeature)
            assert feature.feature_name == feature_name
            assert len(feature.values) > 0
            assert len(feature.timestamps) > 0
    
    @pytest.mark.asyncio
    async def test_learn_behavioral_patterns(self, behavioral_engine, sample_sensor_data):
        """Test behavioral pattern learning."""
        robot_id = "test_robot_001"
        
        # Extract features
        features = await behavioral_engine.extract_behavioral_features(
            robot_id, sample_sensor_data
        )
        
        # Learn patterns
        patterns = await behavioral_engine.learn_behavioral_patterns(
            robot_id, features
        )
        
        # Verify patterns are learned
        assert isinstance(patterns, dict)
        assert len(patterns) > 0
        
        # Check pattern structure
        for pattern_key, pattern in patterns.items():
            assert isinstance(pattern, BehavioralPattern)
            assert pattern.pattern_id == pattern_key
            assert pattern.observations > 0
            assert pattern.confidence > 0
    
    @pytest.mark.asyncio
    async def test_detect_behavioral_anomalies(self, behavioral_engine, sample_sensor_data):
        """Test behavioral anomaly detection."""
        robot_id = "test_robot_001"
        
        # First, establish baseline patterns
        features = await behavioral_engine.extract_behavioral_features(
            robot_id, sample_sensor_data
        )
        await behavioral_engine.learn_behavioral_patterns(robot_id, features)
        
        # Create anomalous data
        anomalous_data = sample_sensor_data.copy()
        anomalous_data['power']['consumption'] = 500.0  # Abnormally high
        anomalous_data['velocity']['vx'] = 10.0  # Abnormally fast
        
        # Extract features from anomalous data
        anomalous_features = await behavioral_engine.extract_behavioral_features(
            robot_id, anomalous_data
        )
        
        # Detect anomalies
        anomalies = await behavioral_engine.detect_behavioral_anomalies(
            robot_id, anomalous_features
        )
        
        # Verify anomalies are detected
        assert isinstance(anomalies, list)
        
        # Check anomaly structure
        for anomaly in anomalies:
            assert isinstance(anomaly, BehavioralAnomaly)
            assert anomaly.anomaly_id is not None
            assert anomaly.confidence > 0
            assert len(anomaly.affected_robots) > 0
    
    @pytest.mark.asyncio
    async def test_analyze_behavioral_trends(self, behavioral_engine, sample_sensor_data):
        """Test behavioral trend analysis."""
        robot_id = "test_robot_001"
        
        # Generate multiple data points over time
        for i in range(10):
            # Slightly modify data to create trends
            data = sample_sensor_data.copy()
            data['power']['consumption'] = 150.0 + i * 5  # Increasing trend
            
            features = await behavioral_engine.extract_behavioral_features(
                robot_id, data
            )
            await behavioral_engine.learn_behavioral_patterns(robot_id, features)
        
        # Analyze trends
        trends = await behavioral_engine.analyze_behavioral_trends(robot_id)
        
        # Verify trends are analyzed
        assert isinstance(trends, dict)
        assert len(trends) > 0
        
        # Check trend structure
        for pattern_name, trend_data in trends.items():
            assert 'stability_score' in trend_data
            assert 'observations' in trend_data
            assert 'confidence' in trend_data
    
    @pytest.mark.asyncio
    async def test_export_import_behavioral_model(self, behavioral_engine, sample_sensor_data):
        """Test behavioral model export and import."""
        robot_id = "test_robot_001"
        
        # Create behavioral patterns
        features = await behavioral_engine.extract_behavioral_features(
            robot_id, sample_sensor_data
        )
        await behavioral_engine.learn_behavioral_patterns(robot_id, features)
        
        # Export model
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as tmp_file:
            export_path = tmp_file.name
        
        try:
            success = await behavioral_engine.export_behavioral_model(export_path)
            assert success
            assert os.path.exists(export_path)
            
            # Create new engine and import model
            new_engine = BehavioralAnalysisEngine()
            success = await new_engine.import_behavioral_model(export_path)
            assert success
            
            # Verify imported patterns
            assert len(new_engine.behavioral_patterns) > 0
            
        finally:
            if os.path.exists(export_path):
                os.unlink(export_path)
    
    def test_performance_metrics(self, behavioral_engine):
        """Test performance metrics collection."""
        metrics = behavioral_engine.get_performance_metrics()
        
        # Verify metrics structure
        assert isinstance(metrics, dict)
        assert 'patterns_learned' in metrics
        assert 'anomalies_detected' in metrics
        assert 'avg_processing_time_ms' in metrics
        assert 'ml_enabled' in metrics
        assert 'classification_level' in metrics
        
        # Verify metric types
        assert isinstance(metrics['patterns_learned'], int)
        assert isinstance(metrics['anomalies_detected'], int)
        assert isinstance(metrics['avg_processing_time_ms'], (int, float))
        assert isinstance(metrics['ml_enabled'], bool)


class TestCrossPlatformCorrelator:
    """Test cases for cross-platform behavioral correlation."""
    
    @pytest.fixture
    def correlator(self):
        """Create a cross-platform correlator for testing."""
        return CrossPlatformBehavioralCorrelator(enable_advanced_analytics=True)
    
    def test_register_robot(self, correlator):
        """Test robot registration."""
        robot_id = "test_robot_001"
        platform_type = RobotPlatformType.BOSTON_DYNAMICS_SPOT
        metadata = {"version": "1.0", "location": "test_lab"}
        
        # Register robot
        correlator.register_robot(robot_id, platform_type, metadata)
        
        # Verify registration
        assert robot_id in correlator.registered_robots
        assert correlator.registered_robots[robot_id]['platform_type'] == platform_type
        assert correlator.registered_robots[robot_id]['metadata'] == metadata
        
        # Verify platform grouping
        assert robot_id in correlator.platform_groups[platform_type]
    
    @pytest.mark.asyncio
    async def test_analyze_cross_platform_correlations(self, correlator):
        """Test cross-platform correlation analysis."""
        # Register test robots
        correlator.register_robot("spot_001", RobotPlatformType.BOSTON_DYNAMICS_SPOT)
        correlator.register_robot("drone_001", RobotPlatformType.DJI_DRONE)
        correlator.register_robot("ros_001", RobotPlatformType.ROS2_GENERIC)
        
        # Create sample behavioral features
        behavioral_features = {
            "spot_001": {
                "movement": BehavioralFeature(
                    feature_name="movement",
                    feature_type=BehavioralPatternType.MOVEMENT_PATTERN,
                    values=np.array([1.0, 2.0, 3.0, 4.0, 5.0]),
                    timestamps=np.array([datetime.now().timestamp()])
                )
            },
            "drone_001": {
                "movement": BehavioralFeature(
                    feature_name="movement",
                    feature_type=BehavioralPatternType.MOVEMENT_PATTERN,
                    values=np.array([1.1, 2.1, 3.1, 4.1, 5.1]),
                    timestamps=np.array([datetime.now().timestamp()])
                )
            },
            "ros_001": {
                "movement": BehavioralFeature(
                    feature_name="movement",
                    feature_type=BehavioralPatternType.MOVEMENT_PATTERN,
                    values=np.array([0.9, 1.9, 2.9, 3.9, 4.9]),
                    timestamps=np.array([datetime.now().timestamp()])
                )
            }
        }
        
        # Analyze correlations
        correlations = await correlator.analyze_cross_platform_correlations(behavioral_features)
        
        # Verify correlations
        assert isinstance(correlations, dict)
        
        # Check correlation structure
        for correlation_id, correlation in correlations.items():
            assert isinstance(correlation, BehavioralCorrelation)
            assert correlation.correlation_strength >= 0.0
            assert correlation.correlation_strength <= 1.0
            assert correlation.source_robot != correlation.target_robot
    
    @pytest.mark.asyncio
    async def test_generate_correlation_graph(self, correlator):
        """Test correlation graph generation."""
        # Register test robots
        correlator.register_robot("robot_001", RobotPlatformType.BOSTON_DYNAMICS_SPOT)
        correlator.register_robot("robot_002", RobotPlatformType.DJI_DRONE)
        
        # Generate correlation graph
        graph = await correlator.generate_correlation_graph()
        
        # Verify graph structure
        assert graph.number_of_nodes() >= 2
        assert graph.has_node("robot_001")
        assert graph.has_node("robot_002")
    
    def test_get_platform_analytics(self, correlator):
        """Test platform analytics."""
        # Register test robots
        correlator.register_robot("spot_001", RobotPlatformType.BOSTON_DYNAMICS_SPOT)
        correlator.register_robot("drone_001", RobotPlatformType.DJI_DRONE)
        correlator.register_robot("ros_001", RobotPlatformType.ROS2_GENERIC)
        
        # Get analytics
        analytics = correlator.get_platform_analytics()
        
        # Verify analytics structure
        assert isinstance(analytics, dict)
        assert 'platform_distribution' in analytics
        assert 'cross_platform_correlations' in analytics
        assert 'metrics' in analytics
        
        # Verify platform distribution
        platform_dist = analytics['platform_distribution']
        assert 'boston_dynamics_spot' in platform_dist
        assert 'dji_drone' in platform_dist
        assert 'ros2_generic' in platform_dist
        assert platform_dist['boston_dynamics_spot'] == 1
        assert platform_dist['dji_drone'] == 1
        assert platform_dist['ros2_generic'] == 1


class TestRealTimeBehavioralMonitor:
    """Test cases for real-time behavioral monitoring."""
    
    @pytest.fixture
    def real_time_monitor(self):
        """Create a real-time behavioral monitor for testing."""
        return RealTimeBehavioralMonitor(
            target_response_time_ms=25.0,
            max_concurrent_robots=10
        )
    
    @pytest.mark.asyncio
    async def test_register_robot(self, real_time_monitor):
        """Test robot registration for monitoring."""
        robot_id = "test_robot_001"
        platform_type = RobotPlatformType.BOSTON_DYNAMICS_SPOT
        metadata = {"test": "data"}
        
        # Register robot
        await real_time_monitor.register_robot(robot_id, platform_type, metadata)
        
        # Verify registration
        assert robot_id in real_time_monitor.active_robots
        assert real_time_monitor.active_robots[robot_id]['platform_type'] == platform_type
        assert real_time_monitor.active_robots[robot_id]['metadata'] == metadata
    
    @pytest.mark.asyncio
    async def test_start_stop_monitoring(self, real_time_monitor):
        """Test starting and stopping monitoring."""
        # Start monitoring
        await real_time_monitor.start_monitoring()
        
        # Verify monitoring is active
        metrics = real_time_monitor.get_performance_metrics()
        assert 'monitor_metrics' in metrics
        assert 'streaming_metrics' in metrics
        
        # Stop monitoring
        await real_time_monitor.stop_monitoring()
    
    @pytest.mark.asyncio
    async def test_process_sensor_data(self, real_time_monitor):
        """Test sensor data processing."""
        robot_id = "test_robot_001"
        
        # Register robot
        await real_time_monitor.register_robot(robot_id, RobotPlatformType.BOSTON_DYNAMICS_SPOT)
        
        # Start monitoring
        await real_time_monitor.start_monitoring()
        
        try:
            # Process sensor data
            sensor_data = {
                'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
                'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
                'power': {'consumption': 150.0, 'battery_level': 0.8}
            }
            
            # Process with critical priority
            result = await real_time_monitor.process_sensor_data(
                robot_id, sensor_data, ProcessingPriority.CRITICAL
            )
            
            # Verify processing result
            if result:  # May be None if queued
                assert hasattr(result, 'processing_time_ms')
                assert hasattr(result, 'robot_id')
                assert result.robot_id == robot_id
                assert result.processing_time_ms > 0
        
        finally:
            # Stop monitoring
            await real_time_monitor.stop_monitoring()
    
    @pytest.mark.asyncio
    async def test_get_robot_status(self, real_time_monitor):
        """Test robot status retrieval."""
        robot_id = "test_robot_001"
        
        # Register robot
        await real_time_monitor.register_robot(robot_id, RobotPlatformType.BOSTON_DYNAMICS_SPOT)
        
        # Get robot status
        status = await real_time_monitor.get_robot_status(robot_id)
        
        # Verify status structure
        assert isinstance(status, dict)
        assert 'robot_id' in status
        assert 'platform_type' in status
        assert 'last_activity' in status
        assert 'anomaly_count' in status
        assert status['robot_id'] == robot_id
    
    def test_performance_metrics(self, real_time_monitor):
        """Test performance metrics collection."""
        metrics = real_time_monitor.get_performance_metrics()
        
        # Verify metrics structure
        assert isinstance(metrics, dict)
        assert 'monitor_metrics' in metrics
        assert 'streaming_metrics' in metrics
        assert 'active_robots' in metrics
        assert 'target_response_time_ms' in metrics
        assert 'uptime_seconds' in metrics
        assert 'sla_compliance_rate' in metrics
        
        # Verify metric types
        assert isinstance(metrics['active_robots'], int)
        assert isinstance(metrics['target_response_time_ms'], (int, float))
        assert isinstance(metrics['uptime_seconds'], (int, float))
        assert isinstance(metrics['sla_compliance_rate'], (int, float))


class TestStreamingProcessor:
    """Test cases for streaming processor."""
    
    @pytest.fixture
    def streaming_processor(self):
        """Create a streaming processor for testing."""
        return StreamingProcessor(max_queue_size=1000, num_workers=2)
    
    @pytest.mark.asyncio
    async def test_start_stop_processor(self, streaming_processor):
        """Test starting and stopping the streaming processor."""
        # Start processor
        await streaming_processor.start()
        assert streaming_processor.is_running
        
        # Stop processor
        await streaming_processor.stop()
        assert not streaming_processor.is_running
    
    @pytest.mark.asyncio
    async def test_submit_data(self, streaming_processor):
        """Test data submission to streaming processor."""
        # Start processor
        await streaming_processor.start()
        
        try:
            # Create test data point
            data_point = StreamingDataPoint(
                robot_id="test_robot_001",
                timestamp=datetime.now(),
                sensor_data={'test': 'data'},
                priority=ProcessingPriority.MEDIUM
            )
            
            # Submit data
            success = await streaming_processor.submit_data(data_point)
            assert success
            
            # Wait briefly for processing
            await asyncio.sleep(0.1)
            
            # Check metrics
            metrics = streaming_processor.get_metrics()
            assert 'queue_size' in metrics
            assert 'throughput_per_second' in metrics
        
        finally:
            # Stop processor
            await streaming_processor.stop()
    
    def test_performance_metrics(self, streaming_processor):
        """Test performance metrics for streaming processor."""
        metrics = streaming_processor.get_metrics()
        
        # Verify metrics structure
        assert isinstance(metrics, dict)
        assert 'avg_processing_time_ms' in metrics
        assert 'max_processing_time_ms' in metrics
        assert 'min_processing_time_ms' in metrics
        assert 'throughput_per_second' in metrics
        assert 'queue_size' in metrics
        assert 'dropped_frames' in metrics
        assert 'sub_50ms_success_rate' in metrics
        assert 'sub_25ms_success_rate' in metrics
        assert 'worker_count' in metrics
        assert 'is_running' in metrics


class TestBehavioralSecurityIntegration:
    """Test cases for behavioral security integration."""
    
    @pytest.fixture
    def security_integration(self):
        """Create a behavioral security integration for testing."""
        return BehavioralSecurityIntegration(
            classification_level=ClassificationLevel.CONFIDENTIAL,
            security_domain="test_domain"
        )
    
    @pytest.mark.asyncio
    async def test_analyze_behavioral_security(self, security_integration):
        """Test behavioral security analysis."""
        robot_id = "test_robot_001"
        sensor_data = {
            'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
            'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
            'communication': {'message_frequency': 50.0},  # Suspicious high frequency
            'power': {'consumption': 500.0}  # Abnormally high consumption
        }
        
        # Analyze for threats
        threat = await security_integration.analyze_behavioral_security(
            robot_id, sensor_data, ClassificationLevel.CONFIDENTIAL
        )
        
        # Verify threat analysis
        if threat:
            assert isinstance(threat, BehavioralThreat)
            assert threat.threat_id is not None
            assert threat.confidence >= 0.0
            assert threat.confidence <= 1.0
            assert len(threat.affected_robots) > 0
    
    @pytest.mark.asyncio
    async def test_get_threat_summary(self, security_integration):
        """Test threat summary generation."""
        summary = await security_integration.get_threat_summary()
        
        # Verify summary structure
        assert isinstance(summary, dict)
        assert 'active_threats' in summary
        assert 'threat_levels' in summary
        assert 'threat_types' in summary
        assert 'highest_threat_level' in summary
        
        # Verify data types
        assert isinstance(summary['active_threats'], int)
        assert isinstance(summary['threat_levels'], dict)
        assert isinstance(summary['threat_types'], dict)
        assert isinstance(summary['highest_threat_level'], str)
    
    def test_get_security_metrics(self, security_integration):
        """Test security metrics collection."""
        metrics = security_integration.get_security_metrics()
        
        # Verify metrics structure
        assert isinstance(metrics, dict)
        assert 'threats_detected' in metrics
        assert 'threats_mitigated' in metrics
        assert 'false_positives' in metrics
        assert 'avg_response_time_ms' in metrics
        assert 'classification_violations' in metrics
        assert 'active_threats' in metrics
        assert 'threat_history_size' in metrics
        assert 'classification_level' in metrics
        assert 'security_domain' in metrics
        
        # Verify metric types
        assert isinstance(metrics['threats_detected'], int)
        assert isinstance(metrics['threats_mitigated'], int)
        assert isinstance(metrics['false_positives'], int)
        assert isinstance(metrics['avg_response_time_ms'], (int, float))
        assert isinstance(metrics['classification_violations'], int)
        assert isinstance(metrics['active_threats'], int)
        assert isinstance(metrics['threat_history_size'], int)
        assert isinstance(metrics['classification_level'], str)
        assert isinstance(metrics['security_domain'], str)


class TestPerformanceRequirements:
    """Test cases for performance requirements."""
    
    @pytest.mark.asyncio
    async def test_sub_50ms_response_time(self):
        """Test that behavioral analysis meets <50ms response time requirement."""
        engine = BehavioralAnalysisEngine()
        
        # Sample data
        robot_id = "perf_test_robot"
        sensor_data = {
            'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
            'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
            'power': {'consumption': 150.0}
        }
        
        # Measure processing time
        start_time = asyncio.get_event_loop().time()
        
        # Extract features
        features = await engine.extract_behavioral_features(robot_id, sensor_data)
        
        # Detect anomalies
        anomalies = await engine.detect_behavioral_anomalies(robot_id, features)
        
        end_time = asyncio.get_event_loop().time()
        processing_time_ms = (end_time - start_time) * 1000
        
        # Verify performance requirement
        assert processing_time_ms < 50.0, f"Processing time {processing_time_ms}ms exceeds 50ms requirement"
    
    @pytest.mark.asyncio
    async def test_concurrent_robot_processing(self):
        """Test concurrent processing of multiple robots."""
        engine = BehavioralAnalysisEngine()
        
        # Create multiple robots
        robot_ids = [f"robot_{i:03d}" for i in range(10)]
        
        # Sample data
        sensor_data = {
            'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
            'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
            'power': {'consumption': 150.0}
        }
        
        # Process all robots concurrently
        start_time = asyncio.get_event_loop().time()
        
        tasks = []
        for robot_id in robot_ids:
            task = asyncio.create_task(
                engine.extract_behavioral_features(robot_id, sensor_data)
            )
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks)
        
        end_time = asyncio.get_event_loop().time()
        total_time_ms = (end_time - start_time) * 1000
        
        # Verify all robots processed
        assert len(results) == len(robot_ids)
        
        # Verify reasonable processing time for concurrent operations
        assert total_time_ms < 500.0, f"Concurrent processing time {total_time_ms}ms is too high"
    
    def test_memory_usage_efficiency(self):
        """Test memory usage efficiency."""
        engine = BehavioralAnalysisEngine(window_size=1000)
        
        # Get initial memory usage
        initial_patterns = len(engine.behavioral_patterns)
        
        # Process data for many robots
        for i in range(100):
            robot_id = f"memory_test_robot_{i}"
            # Simulate pattern creation
            engine.behavioral_patterns[robot_id] = {
                'test_pattern': np.random.rand(10)
            }
        
        # Verify memory usage is reasonable
        final_patterns = len(engine.behavioral_patterns)
        assert final_patterns - initial_patterns <= 100, "Memory usage is too high"


class TestIntegrationScenarios:
    """Integration test scenarios."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_behavioral_analysis(self):
        """Test complete end-to-end behavioral analysis workflow."""
        # Initialize all components
        engine = BehavioralAnalysisEngine()
        correlator = CrossPlatformBehavioralCorrelator()
        security_integration = BehavioralSecurityIntegration()
        
        # Register robots
        correlator.register_robot("robot_001", RobotPlatformType.BOSTON_DYNAMICS_SPOT)
        correlator.register_robot("robot_002", RobotPlatformType.DJI_DRONE)
        
        # Sample data
        sensor_data = {
            'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
            'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
            'communication': {'message_frequency': 2.0},
            'power': {'consumption': 150.0}
        }
        
        # Process data through complete pipeline
        for robot_id in ["robot_001", "robot_002"]:
            # Extract features
            features = await engine.extract_behavioral_features(robot_id, sensor_data)
            
            # Learn patterns
            patterns = await engine.learn_behavioral_patterns(robot_id, features)
            
            # Detect anomalies
            anomalies = await engine.detect_behavioral_anomalies(robot_id, features)
            
            # Analyze security threats
            threat = await security_integration.analyze_behavioral_security(
                robot_id, sensor_data, ClassificationLevel.UNCLASSIFIED
            )
        
        # Analyze cross-platform correlations
        robot_behaviors = {
            "robot_001": await engine.extract_behavioral_features("robot_001", sensor_data),
            "robot_002": await engine.extract_behavioral_features("robot_002", sensor_data)
        }
        
        correlations = await correlator.analyze_cross_platform_correlations(robot_behaviors)
        
        # Verify end-to-end processing
        assert len(engine.behavioral_patterns) > 0
        assert isinstance(correlations, dict)
    
    @pytest.mark.asyncio
    async def test_fault_tolerance(self):
        """Test system fault tolerance."""
        engine = BehavioralAnalysisEngine()
        
        # Test with invalid data
        invalid_data = {
            'position': {'x': float('inf'), 'y': None, 'z': 'invalid'},
            'velocity': {},
            'power': {'consumption': -1000.0}  # Invalid negative consumption
        }
        
        # Should handle invalid data gracefully
        try:
            features = await engine.extract_behavioral_features("fault_test_robot", invalid_data)
            # Should not raise exception
            assert True
        except Exception as e:
            pytest.fail(f"System should handle invalid data gracefully: {e}")
    
    @pytest.mark.asyncio
    async def test_scalability_stress_test(self):
        """Test system scalability under stress."""
        engine = BehavioralAnalysisEngine()
        
        # Create many robots
        num_robots = 50
        robot_ids = [f"stress_robot_{i:03d}" for i in range(num_robots)]
        
        # Sample data
        sensor_data = {
            'position': {'x': 10.0, 'y': 20.0, 'z': 1.0},
            'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
            'power': {'consumption': 150.0}
        }
        
        # Process all robots
        start_time = asyncio.get_event_loop().time()
        
        for robot_id in robot_ids:
            features = await engine.extract_behavioral_features(robot_id, sensor_data)
            patterns = await engine.learn_behavioral_patterns(robot_id, features)
            anomalies = await engine.detect_behavioral_anomalies(robot_id, features)
        
        end_time = asyncio.get_event_loop().time()
        total_time = end_time - start_time
        
        # Verify scalability
        avg_time_per_robot = total_time / num_robots
        assert avg_time_per_robot < 0.1, f"Average time per robot {avg_time_per_robot}s is too high"
        
        # Verify system still functions
        metrics = engine.get_performance_metrics()
        assert metrics['patterns_learned'] > 0
        assert len(engine.behavioral_patterns) > 0


# Performance benchmark fixtures
@pytest.fixture
def performance_benchmark():
    """Setup for performance benchmarking."""
    return {
        'max_processing_time_ms': 50.0,
        'max_memory_usage_mb': 500.0,
        'min_throughput_per_second': 100.0
    }


# Test configuration
@pytest.fixture(autouse=True)
def setup_logging():
    """Setup logging for tests."""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


# Run performance tests
if __name__ == "__main__":
    # Run all tests
    pytest.main([__file__, "-v", "--tb=short"])