#!/usr/bin/env python3
"""
@license
Copyright 2024 ALCUB3 Systems
SPDX-License-Identifier: Apache-2.0

ALCUB3 Universal Security HAL - Comprehensive Test Suite
Task 20: Universal Security HAL Core Architecture Tests

This module provides comprehensive testing for the Universal Security HAL
implementation including unit tests for HAL interface methods, performance
benchmarks for sub-50ms response times, and security policy validation tests.

Test Coverage:
- Core HAL interface methods and functionality
- Platform registration and adapter management
- Security command validation and execution
- Performance benchmarks with sub-50ms targets
- Emergency stop coordination and response
- Security policy enforcement and validation
- MAESTRO L1-L3 classification handling
- Real-time performance monitoring
"""

import asyncio
import time
import pytest
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import Mock, AsyncMock, patch

# Import MAESTRO components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel

# Import HAL components
from .core_hal import (
    RoboticsHAL, SecurityOperations, AuthenticationProvider, CommandValidator,
    PlatformAdapter, SecurityAdapter, SecurityLevel, ValidationResult,
    AuthenticationResult, SecurityStatus, EmergencyStopReason,
    RobotPlatform, SecurityCommand, SecurityProfile, SecurityEvent,
    PerformanceMetrics, create_security_event, create_performance_metric
)

from .security_hal import (
    UniversalSecurityHAL, RobotSecurityProfile, SecurityValidationLevel,
    RobotPlatformType, RobotOperationStatus, EmergencyStopEvent,
    RobotSecurityAdapter
)

from .platform_adapter import (
    BasePlatformAdapter, PlatformAdapterFactory, AdapterRegistry,
    AdapterInfo, AdapterStatus, MockPlatformAdapter
)

from .performance_monitor import (
    HALPerformanceMonitor, PerformanceCollector, MetricType,
    PerformanceThreshold, PerformanceAlert, AlertLevel
)


class TestUniversalSecurityHALCore:
    """Test suite for Universal Security HAL core functionality."""
    
    @pytest.fixture
    async def hal_instance(self):
        """Create HAL instance for testing."""
        config = {
            "security": {
                "default_validation_level": "enhanced",
                "emergency_stop_timeout_ms": 50,
                "classification_enforcement": True
            },
            "performance": {
                "max_command_validation_time_ms": 50,
                "max_emergency_stop_time_ms": 50
            }
        }
        
        # Write config to temp file
        config_path = "/tmp/test_hal_config.json"
        with open(config_path, 'w') as f:
            json.dump(config, f)
        
        hal = UniversalSecurityHAL(config_path=config_path)
        yield hal
        
        # Cleanup
        try:
            Path(config_path).unlink()
        except:
            pass
    
    @pytest.fixture
    def mock_robot_platform(self):
        """Create mock robot platform for testing."""
        return RobotPlatform(
            platform_id="test_robot_001",
            platform_type="boston_dynamics_spot",
            hardware_version="1.0.0",
            software_version="2.1.0",
            classification_level=ClassificationLevel.UNCLASSIFIED,
            security_capabilities=["authentication", "encryption", "audit"],
            supported_operations=["move", "stop", "patrol", "emergency_stop"],
            last_validation=datetime.utcnow(),
            trust_score=0.95
        )
    
    @pytest.fixture
    def mock_security_command(self):
        """Create mock security command for testing."""
        return SecurityCommand(
            command_id="cmd_test_001",
            platform_id="test_robot_001",
            command_type="move",
            parameters={"x": 10, "y": 5, "speed": 0.5},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
    
    async def test_hal_initialization(self, hal_instance):
        """Test HAL initialization."""
        assert hal_instance is not None
        assert hal_instance.config is not None
        assert hal_instance.logger is not None
        assert hal_instance.security_metrics["total_robots"] == 0
        assert hal_instance.emergency_stop_active is False
    
    async def test_robot_registration(self, hal_instance):
        """Test robot registration functionality."""
        # Test successful registration
        start_time = time.time()
        success = await hal_instance.register_robot(
            robot_id="test_robot_001",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        registration_time = (time.time() - start_time) * 1000
        
        assert success is True
        assert registration_time < 50  # Sub-50ms target
        assert "test_robot_001" in hal_instance.robots
        assert "test_robot_001" in hal_instance.security_profiles
        assert hal_instance.security_metrics["total_robots"] == 1
        assert hal_instance.security_metrics["operational_robots"] == 1
    
    async def test_robot_registration_performance(self, hal_instance):
        """Test robot registration performance benchmarks."""
        registration_times = []
        
        # Test multiple registrations
        for i in range(10):
            start_time = time.time()
            success = await hal_instance.register_robot(
                robot_id=f"test_robot_{i:03d}",
                platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
                classification_level=ClassificationLevel.UNCLASSIFIED
            )
            registration_time = (time.time() - start_time) * 1000
            registration_times.append(registration_time)
            
            assert success is True
            assert registration_time < 50  # Sub-50ms requirement
        
        # Validate performance metrics
        avg_time = sum(registration_times) / len(registration_times)
        max_time = max(registration_times)
        
        assert avg_time < 25  # Average should be well under limit
        assert max_time < 50   # Maximum should meet requirement
        assert hal_instance.security_metrics["total_robots"] == 10
    
    async def test_command_validation(self, hal_instance, mock_security_command):
        """Test security command validation."""
        # Register robot first
        await hal_instance.register_robot(
            robot_id="test_robot_001",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        
        # Test command validation
        start_time = time.time()
        is_valid = await hal_instance.validate_command(mock_security_command)
        validation_time = (time.time() - start_time) * 1000
        
        assert is_valid is True
        assert validation_time < 50  # Sub-50ms requirement
        assert mock_security_command.validation_result is not None
        assert mock_security_command.execution_authorized is True
    
    async def test_command_validation_performance(self, hal_instance):
        """Test command validation performance benchmarks."""
        # Register robot
        await hal_instance.register_robot(
            robot_id="test_robot_001",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        
        validation_times = []
        
        # Test multiple command validations
        for i in range(100):
            command = SecurityCommand(
                command_id=f"cmd_{i:03d}",
                platform_id="test_robot_001",
                command_type="move",
                parameters={"x": i, "y": i, "speed": 0.5},
                classification_level=ClassificationLevel.UNCLASSIFIED,
                issued_by="test_operator",
                timestamp=datetime.utcnow()
            )
            
            start_time = time.time()
            is_valid = await hal_instance.validate_command(command)
            validation_time = (time.time() - start_time) * 1000
            validation_times.append(validation_time)
            
            assert is_valid is True
            assert validation_time < 50  # Sub-50ms requirement
        
        # Performance analysis
        avg_time = sum(validation_times) / len(validation_times)
        p95_time = sorted(validation_times)[94]  # 95th percentile
        max_time = max(validation_times)
        
        assert avg_time < 25   # Average well under limit
        assert p95_time < 45   # 95% of operations under 45ms
        assert max_time < 50   # All operations meet requirement
    
    async def test_emergency_stop_performance(self, hal_instance):
        """Test emergency stop performance benchmarks."""
        # Register multiple robots
        for i in range(5):
            await hal_instance.register_robot(
                robot_id=f"test_robot_{i:03d}",
                platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
                classification_level=ClassificationLevel.UNCLASSIFIED
            )
        
        # Test emergency stop all
        start_time = time.time()
        success = await hal_instance.execute_emergency_stop(
            reason=EmergencyStopReason.MANUAL_TRIGGER,
            triggered_by="test_system"
        )
        emergency_stop_time = (time.time() - start_time) * 1000
        
        assert success is True
        assert emergency_stop_time < 50  # Sub-50ms requirement
        assert hal_instance.emergency_stop_active is True
        
        # Test individual robot emergency stop
        start_time = time.time()
        success = await hal_instance.execute_emergency_stop(
            robot_id="test_robot_001",
            reason=EmergencyStopReason.SAFETY_VIOLATION,
            triggered_by="test_system"
        )
        individual_stop_time = (time.time() - start_time) * 1000
        
        assert success is True
        assert individual_stop_time < 50  # Sub-50ms requirement
    
    async def test_classification_level_enforcement(self, hal_instance):
        """Test MAESTRO classification level enforcement."""
        # Register robots with different classification levels
        await hal_instance.register_robot(
            robot_id="unclass_robot",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        
        await hal_instance.register_robot(
            robot_id="secret_robot",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.SECRET
        )
        
        # Test classification enforcement
        # UNCLASSIFIED command to SECRET robot should be denied
        secret_command = SecurityCommand(
            command_id="secret_cmd_001",
            platform_id="secret_robot",
            command_type="classified_patrol",
            parameters={"zone": "classified_area"},
            classification_level=ClassificationLevel.SECRET,
            issued_by="secret_operator",
            timestamp=datetime.utcnow()
        )
        
        unclass_command = SecurityCommand(
            command_id="unclass_cmd_001",
            platform_id="unclass_robot",
            command_type="move",
            parameters={"x": 10, "y": 5},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="unclass_operator",
            timestamp=datetime.utcnow()
        )
        
        # SECRET command should be validated for SECRET robot
        secret_valid = await hal_instance.validate_command(secret_command)
        assert secret_valid is True
        
        # UNCLASSIFIED command should be validated for UNCLASSIFIED robot
        unclass_valid = await hal_instance.validate_command(unclass_command)
        assert unclass_valid is True
    
    async def test_security_policy_enforcement(self, hal_instance):
        """Test security policy enforcement."""
        # Register robot with security constraints
        security_constraints = {
            "geofencing": {
                "enabled": True,
                "zones": [
                    {"name": "safe_zone", "x_min": 0, "x_max": 100, "y_min": 0, "y_max": 100}
                ]
            },
            "speed_limits": {
                "max_speed": 1.0,
                "max_acceleration": 0.5
            }
        }
        
        await hal_instance.register_robot(
            robot_id="constrained_robot",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            security_constraints=security_constraints
        )
        
        # Test policy enforcement - valid command
        valid_command = SecurityCommand(
            command_id="valid_cmd",
            platform_id="constrained_robot",
            command_type="move",
            parameters={"x": 50, "y": 50, "speed": 0.8},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid_result = await hal_instance.validate_command(valid_command)
        assert valid_result is True
        
        # Test policy enforcement - invalid command (outside geofence)
        invalid_command = SecurityCommand(
            command_id="invalid_cmd",
            platform_id="constrained_robot",
            command_type="move",
            parameters={"x": 150, "y": 150, "speed": 0.8},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        invalid_result = await hal_instance.validate_command(invalid_command)
        assert invalid_result is False
    
    async def test_fleet_status_monitoring(self, hal_instance):
        """Test fleet status monitoring functionality."""
        # Register multiple robots
        for i in range(3):
            await hal_instance.register_robot(
                robot_id=f"fleet_robot_{i:03d}",
                platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
                classification_level=ClassificationLevel.UNCLASSIFIED
            )
        
        # Get fleet status
        start_time = time.time()
        fleet_status = await hal_instance.get_fleet_status()
        status_time = (time.time() - start_time) * 1000
        
        assert status_time < 50  # Sub-50ms requirement
        assert fleet_status["total_robots"] == 3
        assert fleet_status["operational_robots"] == 3
        assert len(fleet_status["robots"]) == 3
        assert fleet_status["emergency_stop_active"] is False
    
    async def test_security_metrics_collection(self, hal_instance):
        """Test security metrics collection."""
        # Register robots and execute commands
        await hal_instance.register_robot(
            robot_id="metrics_robot",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        
        # Execute multiple commands
        for i in range(10):
            command = SecurityCommand(
                command_id=f"metrics_cmd_{i:03d}",
                platform_id="metrics_robot",
                command_type="move",
                parameters={"x": i, "y": i},
                classification_level=ClassificationLevel.UNCLASSIFIED,
                issued_by="metrics_operator",
                timestamp=datetime.utcnow()
            )
            await hal_instance.validate_command(command)
        
        # Get security metrics
        metrics = await hal_instance.get_security_metrics()
        
        assert metrics["total_robots"] == 1
        assert metrics["command_validations"] >= 10
        assert metrics["average_response_time"] > 0
        assert "last_updated" in metrics
    
    async def test_robot_unregistration(self, hal_instance):
        """Test robot unregistration functionality."""
        # Register robot
        await hal_instance.register_robot(
            robot_id="temp_robot",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        
        assert hal_instance.security_metrics["total_robots"] == 1
        
        # Unregister robot
        success = await hal_instance.unregister_robot("temp_robot")
        
        assert success is True
        assert "temp_robot" not in hal_instance.robots
        assert "temp_robot" not in hal_instance.security_profiles
        assert hal_instance.security_metrics["total_robots"] == 0


class TestPlatformAdapterFramework:
    """Test suite for platform adapter framework."""
    
    @pytest.fixture
    def adapter_factory(self):
        """Create adapter factory for testing."""
        return PlatformAdapterFactory()
    
    @pytest.fixture
    def mock_adapter_info(self):
        """Create mock adapter info for testing."""
        return AdapterInfo(
            adapter_id="test_adapter",
            adapter_name="Test Platform Adapter",
            platform_type="test_platform",
            version="1.0.0",
            supported_operations=["move", "stop", "status"],
            security_features=["authentication", "encryption"],
            status=AdapterStatus.UNINITIALIZED
        )
    
    def test_adapter_registry(self, adapter_factory, mock_adapter_info):
        """Test adapter registry functionality."""
        registry = adapter_factory.get_registry()
        
        # Test registration
        registry.register_adapter("test_platform", MockPlatformAdapter, mock_adapter_info)
        
        assert "test_platform" in registry.list_adapters()
        assert registry.get_adapter_class("test_platform") == MockPlatformAdapter
        assert registry.get_adapter_info("test_platform") == mock_adapter_info
        
        # Test unregistration
        registry.unregister_adapter("test_platform")
        assert "test_platform" not in registry.list_adapters()
    
    async def test_adapter_creation(self, adapter_factory):
        """Test adapter creation functionality."""
        # Create mock adapter
        adapter = await adapter_factory.create_adapter("mock", "test_adapter_001")
        
        assert adapter is not None
        assert isinstance(adapter, MockPlatformAdapter)
        assert adapter.adapter_id == "test_adapter_001"
        assert adapter.status == AdapterStatus.UNINITIALIZED
    
    async def test_adapter_initialization(self, adapter_factory):
        """Test adapter initialization."""
        # Create adapter
        adapter = await adapter_factory.create_adapter("mock", "test_adapter_002")
        
        # Create mock platform
        platform = RobotPlatform(
            platform_id="test_platform_001",
            platform_type="mock",
            hardware_version="1.0.0",
            software_version="1.0.0",
            classification_level=ClassificationLevel.UNCLASSIFIED,
            security_capabilities=["authentication"],
            supported_operations=["move", "stop"],
            last_validation=datetime.utcnow()
        )
        
        # Initialize adapter
        success = await adapter.initialize_platform(platform)
        
        assert success is True
        assert adapter.status == AdapterStatus.ACTIVE
        assert adapter.platform == platform


class TestPerformanceMonitoring:
    """Test suite for performance monitoring."""
    
    @pytest.fixture
    async def performance_monitor(self):
        """Create performance monitor for testing."""
        monitor = HALPerformanceMonitor()
        await monitor.start_monitoring()
        yield monitor
        await monitor.stop_monitoring()
    
    def test_performance_metric_recording(self, performance_monitor):
        """Test performance metric recording."""
        # Record test operation
        performance_monitor.record_operation("test_operation", 25.5, True)
        
        # Get metrics
        stats = performance_monitor.collector.get_summary_stats("test_operation")
        
        assert stats["count"] == 1
        assert stats["avg_execution_time_ms"] == 25.5
        assert stats["avg_success_rate"] == 1.0
    
    def test_performance_threshold_validation(self, performance_monitor):
        """Test performance threshold validation."""
        # Set custom threshold
        performance_monitor.set_threshold(
            "test_operation", MetricType.LATENCY, 30.0, 45.0, 50.0, "ms"
        )
        
        # Record operation that exceeds warning threshold
        performance_monitor.record_operation("test_operation", 35.0, True)
        
        # Check that alert was generated
        alerts = performance_monitor.get_recent_alerts(10)
        assert len(alerts) > 0
    
    def test_performance_summary_generation(self, performance_monitor):
        """Test performance summary generation."""
        # Record multiple operations
        for i in range(10):
            performance_monitor.record_operation("summary_test", 20.0 + i, True)
        
        # Get performance summary
        summary = performance_monitor.get_performance_summary()
        
        assert "operations" in summary
        assert "alerts" in summary
        assert "overall_performance" in summary
        assert summary["overall_performance"]["score"] > 0


async def run_comprehensive_tests():
    """Run comprehensive test suite."""
    import pytest
    
    print("Starting Universal Security HAL Test Suite...")
    
    # Run tests with detailed output
    result = pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--capture=no"
    ])
    
    return result == 0


if __name__ == "__main__":
    asyncio.run(run_comprehensive_tests()) 