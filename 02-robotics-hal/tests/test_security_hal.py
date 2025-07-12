#!/usr/bin/env python3
"""
Test Suite for ALCUB3 Universal Security HAL - Task 3.1
Comprehensive validation of universal robotics security capabilities

This test suite validates:
- Universal security interface for heterogeneous robotics platforms
- Classification-aware robotics command validation
- <50ms emergency stop capability with fleet-wide coordination
- Real-time security state synchronization
- Performance targets for robotics security operations
- Patent-defensible universal security architecture
"""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import List, Dict, Any

# Import the Universal Security HAL
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from security_hal import (
    UniversalSecurityHAL,
    RobotPlatformType,
    SecurityValidationLevel,
    RobotOperationStatus,
    EmergencyStopReason,
    ClassificationLevel,
    RobotSecurityProfile,
    SecurityCommand,
    EmergencyStopEvent
)

class TestUniversalSecurityHAL:
    """Test suite for Universal Security HAL."""
    
    @pytest.fixture
    def security_hal(self):
        """Create security HAL instance for testing."""
        hal = UniversalSecurityHAL()
        return hal
    
    @pytest.fixture
    def sample_security_profile(self):
        """Create sample robot security profile."""
        return RobotSecurityProfile(
            robot_id="test_robot_01",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            validation_level=SecurityValidationLevel.ENHANCED,
            authorized_operations=["walk", "turn", "sit", "stand"],
            security_constraints={"max_speed": 2.0, "allowed_hours": list(range(6, 22))},
            last_security_check=datetime.utcnow(),
            security_status="operational"
        )
    
    @pytest.fixture
    def sample_security_command(self):
        """Create sample security command."""
        return SecurityCommand(
            command_id="cmd_test_001",
            robot_id="test_robot_01",
            command_type="walk",
            parameters={"speed": 1.0, "direction": "forward"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
    
    def test_hal_initialization(self, security_hal):
        """Test HAL proper initialization."""
        assert security_hal is not None
        assert security_hal.robots == {}
        assert security_hal.security_profiles == {}
        assert security_hal.active_commands == {}
        assert security_hal.config is not None
        assert security_hal.logger is not None
        assert security_hal.adapter_registry is not None
        assert len(security_hal.adapter_registry) > 0
    
    def test_adapter_registry(self, security_hal):
        """Test platform adapter registry."""
        # Verify all supported platforms are registered
        expected_platforms = [
            RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            RobotPlatformType.ROS2_GENERIC,
            RobotPlatformType.DJI_DRONE,
            RobotPlatformType.GHOST_ROBOTICS_VISION60,
            RobotPlatformType.ANDURIL_GHOST,
            RobotPlatformType.CUSTOM_PLATFORM
        ]
        
        for platform in expected_platforms:
            assert platform in security_hal.adapter_registry
            assert security_hal.adapter_registry[platform] is not None
    
    @pytest.mark.asyncio
    async def test_robot_registration(self, security_hal):
        """Test robot registration with security HAL."""
        robot_id = "test_spot_01"
        platform_type = RobotPlatformType.BOSTON_DYNAMICS_SPOT
        classification_level = ClassificationLevel.UNCLASSIFIED
        
        # Test successful registration
        success = await security_hal.register_robot(
            robot_id, platform_type, classification_level
        )
        
        assert success is True
        assert robot_id in security_hal.robots
        assert robot_id in security_hal.security_profiles
        assert security_hal.security_metrics["total_robots"] == 1
        assert security_hal.security_metrics["operational_robots"] == 1
        
        # Verify security profile
        profile = security_hal.security_profiles[robot_id]
        assert profile.robot_id == robot_id
        assert profile.platform_type == platform_type
        assert profile.classification_level == classification_level
        assert profile.security_status == "operational"
        assert len(profile.authorized_operations) > 0
    
    @pytest.mark.asyncio
    async def test_multiple_robot_registration(self, security_hal):
        """Test registration of multiple robots with different platforms."""
        robots = [
            ("spot_01", RobotPlatformType.BOSTON_DYNAMICS_SPOT, ClassificationLevel.UNCLASSIFIED),
            ("ghost_01", RobotPlatformType.GHOST_ROBOTICS_VISION60, ClassificationLevel.CUI),
            ("drone_01", RobotPlatformType.DJI_DRONE, ClassificationLevel.SECRET),
            ("ros_bot_01", RobotPlatformType.ROS2_GENERIC, ClassificationLevel.UNCLASSIFIED)
        ]
        
        # Register all robots
        for robot_id, platform, classification in robots:
            success = await security_hal.register_robot(robot_id, platform, classification)
            assert success is True
        
        # Verify all registered
        assert len(security_hal.robots) == 4
        assert len(security_hal.security_profiles) == 4
        assert security_hal.security_metrics["total_robots"] == 4
        
        # Verify classification distribution
        classification_counts = security_hal.security_metrics["classification_levels"]
        assert classification_counts[ClassificationLevel.UNCLASSIFIED.value] == 2
        assert classification_counts[ClassificationLevel.CUI.value] == 1
        assert classification_counts[ClassificationLevel.SECRET.value] == 1
    
    @pytest.mark.asyncio
    async def test_command_validation_performance(self, security_hal, sample_security_command):
        """Test command validation meets <50ms performance target."""
        # Register robot first
        await security_hal.register_robot(
            "test_robot_01", 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Test single command validation
        start_time = time.time()
        valid = await security_hal.validate_command(sample_security_command)
        validation_time = (time.time() - start_time) * 1000
        
        assert valid is True
        assert validation_time < 50  # Target: <50ms
        assert sample_security_command.validation_result == "approved"
        assert sample_security_command.execution_authorized is True
        assert sample_security_command.security_signature is not None
    
    @pytest.mark.asyncio
    async def test_command_validation_batch_performance(self, security_hal):
        """Test batch command validation performance."""
        # Register robot
        await security_hal.register_robot(
            "batch_test_robot", 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Create batch of commands
        commands = []
        for i in range(20):
            command = SecurityCommand(
                command_id=f"batch_cmd_{i}",
                robot_id="batch_test_robot",
                command_type="walk",
                parameters={"speed": 1.0},
                classification_level=ClassificationLevel.UNCLASSIFIED,
                issued_by="batch_tester",
                timestamp=datetime.utcnow()
            )
            commands.append(command)
        
        # Validate batch
        start_time = time.time()
        results = []
        for command in commands:
            result = await security_hal.validate_command(command)
            results.append(result)
        batch_time = (time.time() - start_time) * 1000
        
        # Verify all commands validated successfully
        assert all(results)
        assert batch_time < 1000  # 20 commands in under 1 second
        assert len(security_hal.active_commands) == 20
        
        # Check average validation time
        avg_time = batch_time / len(commands)
        assert avg_time < 50  # Each command <50ms on average
    
    @pytest.mark.asyncio
    async def test_classification_aware_validation(self, security_hal):
        """Test classification-aware command validation."""
        # Register robots with different classification levels
        await security_hal.register_robot(
            "unclass_robot", 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        await security_hal.register_robot(
            "secret_robot", 
            RobotPlatformType.GHOST_ROBOTICS_VISION60, 
            ClassificationLevel.SECRET
        )
        
        # Test 1: UNCLASSIFIED command to UNCLASSIFIED robot (should pass)
        unclass_command = SecurityCommand(
            command_id="unclass_cmd",
            robot_id="unclass_robot",
            command_type="walk",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(unclass_command)
        assert valid is True
        
        # Test 2: SECRET command to UNCLASSIFIED robot (should fail)
        secret_to_unclass_command = SecurityCommand(
            command_id="secret_cmd_fail",
            robot_id="unclass_robot",
            command_type="walk",
            parameters={},
            classification_level=ClassificationLevel.SECRET,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(secret_to_unclass_command)
        assert valid is False
        assert security_hal.security_metrics["security_violations"] > 0
        
        # Test 3: UNCLASSIFIED command to SECRET robot (should pass)
        unclass_to_secret_command = SecurityCommand(
            command_id="unclass_to_secret_cmd",
            robot_id="secret_robot",
            command_type="patrol",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(unclass_to_secret_command)
        assert valid is True
    
    @pytest.mark.asyncio
    async def test_emergency_stop_performance(self, security_hal):
        """Test emergency stop meets <50ms performance target."""
        # Register robot
        await security_hal.register_robot(
            "emergency_test_robot", 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Test single robot emergency stop
        start_time = time.time()
        success = await security_hal.execute_emergency_stop(
            robot_id="emergency_test_robot",
            reason=EmergencyStopReason.SAFETY_VIOLATION,
            triggered_by="test_system"
        )
        stop_time = (time.time() - start_time) * 1000
        
        assert success is True
        assert stop_time < 50  # Target: <50ms
        
        # Verify robot status updated
        profile = security_hal.security_profiles["emergency_test_robot"]
        assert profile.security_status == "emergency_stop"
        
        # Verify emergency event recorded
        events = await security_hal.get_emergency_events(limit=1)
        assert len(events) == 1
        assert events[0]["robot_id"] == "emergency_test_robot"
        assert events[0]["reason"] == EmergencyStopReason.SAFETY_VIOLATION.value
        assert events[0]["response_time_ms"] < 50
    
    @pytest.mark.asyncio
    async def test_fleet_wide_emergency_stop(self, security_hal):
        """Test fleet-wide emergency stop coordination."""
        # Register multiple robots
        robots = ["fleet_robot_01", "fleet_robot_02", "fleet_robot_03"]
        for robot_id in robots:
            await security_hal.register_robot(
                robot_id, 
                RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
                ClassificationLevel.UNCLASSIFIED
            )
        
        # Execute fleet-wide emergency stop
        start_time = time.time()
        success = await security_hal.execute_emergency_stop(
            robot_id=None,  # Fleet-wide
            reason=EmergencyStopReason.SECURITY_BREACH,
            triggered_by="security_system"
        )
        fleet_stop_time = (time.time() - start_time) * 1000
        
        assert success is True
        assert fleet_stop_time < 100  # Fleet coordination target: <100ms
        assert security_hal.emergency_stop_active is True
        
        # Verify all robots stopped
        for robot_id in robots:
            profile = security_hal.security_profiles[robot_id]
            assert profile.security_status == "emergency_stop"
        
        # Test clearing fleet emergency stop
        clear_success = await security_hal.clear_emergency_stop()
        assert clear_success is True
        assert security_hal.emergency_stop_active is False
        
        # Verify all robots operational again
        for robot_id in robots:
            profile = security_hal.security_profiles[robot_id]
            assert profile.security_status == "operational"
    
    @pytest.mark.asyncio
    async def test_fleet_status_query_performance(self, security_hal):
        """Test fleet status query meets performance targets."""
        # Register fleet of robots
        for i in range(10):
            await security_hal.register_robot(
                f"perf_robot_{i:02d}", 
                RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
                ClassificationLevel.UNCLASSIFIED
            )
        
        # Test fleet status query performance
        start_time = time.time()
        fleet_status = await security_hal.get_fleet_status()
        query_time = (time.time() - start_time) * 1000
        
        assert query_time < 100  # Target: <100ms for fleet status
        assert fleet_status["total_robots"] == 10
        assert fleet_status["operational_robots"] == 10
        assert len(fleet_status["robots"]) == 10
        
        # Verify performance metrics included
        assert "performance_metrics" in fleet_status
        assert "avg_command_validation_ms" in fleet_status["performance_metrics"]
    
    @pytest.mark.asyncio
    async def test_security_constraints_validation(self, security_hal):
        """Test security constraints enforcement."""
        # Register robot with specific constraints
        constraints = {
            "max_speed": 1.5,
            "allowed_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],  # 9 AM to 5 PM
            "restricted_zones": [
                {"center": {"x": 0, "y": 0}, "radius": 5.0}
            ]
        }
        
        await security_hal.register_robot(
            "constrained_robot", 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED,
            security_constraints=constraints
        )
        
        # Test 1: Speed constraint violation
        speed_violation_command = SecurityCommand(
            command_id="speed_violation",
            robot_id="constrained_robot",
            command_type="walk",
            parameters={"speed": 2.0},  # Exceeds max_speed of 1.5
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(speed_violation_command)
        assert valid is False
        
        # Test 2: Valid speed command
        valid_speed_command = SecurityCommand(
            command_id="valid_speed",
            robot_id="constrained_robot", 
            command_type="walk",
            parameters={"speed": 1.0},  # Within max_speed
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(valid_speed_command)
        assert valid is True
        
        # Test 3: Location constraint violation
        location_violation_command = SecurityCommand(
            command_id="location_violation",
            robot_id="constrained_robot",
            command_type="walk",
            parameters={"location": {"x": 2, "y": 2}},  # Within restricted zone
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(location_violation_command)
        assert valid is False
    
    @pytest.mark.asyncio
    async def test_unauthorized_operations(self, security_hal):
        """Test unauthorized operation detection."""
        await security_hal.register_robot(
            "limited_robot", 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Test unauthorized operation
        unauthorized_command = SecurityCommand(
            command_id="unauthorized",
            robot_id="limited_robot",
            command_type="unauthorized_operation",  # Not in authorized_operations
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(unauthorized_command)
        assert valid is False
        
        # Test authorized operation
        authorized_command = SecurityCommand(
            command_id="authorized",
            robot_id="limited_robot",
            command_type="walk",  # Should be in authorized_operations
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await security_hal.validate_command(authorized_command)
        assert valid is True
    
    @pytest.mark.asyncio
    async def test_security_metrics_tracking(self, security_hal):
        """Test security metrics collection and reporting."""
        # Register robot and execute operations
        await security_hal.register_robot(
            "metrics_robot", 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Execute valid command
        valid_command = SecurityCommand(
            command_id="metrics_cmd_valid",
            robot_id="metrics_robot",
            command_type="walk",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        await security_hal.validate_command(valid_command)
        
        # Execute invalid command
        invalid_command = SecurityCommand(
            command_id="metrics_cmd_invalid",
            robot_id="metrics_robot",
            command_type="walk",
            parameters={},
            classification_level=ClassificationLevel.SECRET,  # Classification violation
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        await security_hal.validate_command(invalid_command)
        
        # Execute emergency stop
        await security_hal.execute_emergency_stop(
            robot_id="metrics_robot",
            reason=EmergencyStopReason.MANUAL_TRIGGER
        )
        
        # Get metrics
        metrics = await security_hal.get_security_metrics()
        
        # Verify metrics
        assert metrics["total_robots"] == 1
        assert metrics["command_validations"] >= 2
        assert metrics["security_violations"] >= 1  # Classification violation should have occurred
        assert metrics["emergency_stops"] >= 1
        assert "performance" in metrics
        assert "query_time_ms" in metrics
    
    @pytest.mark.asyncio
    async def test_robot_unregistration(self, security_hal):
        """Test robot unregistration and cleanup."""
        robot_id = "temp_robot"
        
        # Register robot
        await security_hal.register_robot(
            robot_id, 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Add active command
        command = SecurityCommand(
            command_id="temp_cmd",
            robot_id=robot_id,
            command_type="walk",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="operator",
            timestamp=datetime.utcnow()
        )
        
        await security_hal.validate_command(command)
        assert len(security_hal.active_commands) == 1
        
        # Unregister robot
        success = await security_hal.unregister_robot(robot_id)
        
        assert success is True
        assert robot_id not in security_hal.robots
        assert robot_id not in security_hal.security_profiles
        assert len(security_hal.active_commands) == 0  # Commands cancelled
        assert security_hal.security_metrics["total_robots"] == 0
    
    @pytest.mark.asyncio
    async def test_security_profile_updates(self, security_hal):
        """Test security profile updates."""
        robot_id = "update_test_robot"
        
        # Register robot
        await security_hal.register_robot(
            robot_id, 
            RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Update security profile
        updates = {
            "validation_level": SecurityValidationLevel.MAXIMUM,
            "authorized_operations": ["walk", "turn", "emergency_stop"],
            "security_constraints": {"max_speed": 0.5}
        }
        
        success = await security_hal.update_robot_security_profile(robot_id, updates)
        assert success is True
        
        # Verify updates applied
        profile = security_hal.security_profiles[robot_id]
        assert profile.validation_level == SecurityValidationLevel.MAXIMUM
        assert "walk" in profile.authorized_operations
        assert "turn" in profile.authorized_operations
        assert profile.security_constraints["max_speed"] == 0.5

class TestSecurityHALIntegration:
    """Integration tests for Security HAL with realistic scenarios."""
    
    @pytest.mark.asyncio
    async def test_multi_platform_fleet_operations(self):
        """Test operations across multiple robot platforms."""
        hal = UniversalSecurityHAL()
        
        try:
            # Register diverse fleet
            fleet = [
                ("spot_patrol_01", RobotPlatformType.BOSTON_DYNAMICS_SPOT, ClassificationLevel.CUI),
                ("ghost_perimeter_01", RobotPlatformType.GHOST_ROBOTICS_VISION60, ClassificationLevel.SECRET),
                ("dji_survey_01", RobotPlatformType.DJI_DRONE, ClassificationLevel.UNCLASSIFIED),
                ("ros_support_01", RobotPlatformType.ROS2_GENERIC, ClassificationLevel.UNCLASSIFIED)
            ]
            
            # Register all robots
            for robot_id, platform, classification in fleet:
                success = await hal.register_robot(robot_id, platform, classification)
                assert success is True
            
            # Test mixed classification commands
            commands = [
                SecurityCommand(
                    command_id="multi_cmd_01",
                    robot_id="spot_patrol_01",
                    command_type="walk",
                    parameters={"speed": 1.0},
                    classification_level=ClassificationLevel.CUI,
                    issued_by="multi_operator",
                    timestamp=datetime.utcnow()
                ),
                SecurityCommand(
                    command_id="multi_cmd_02",
                    robot_id="ghost_perimeter_01", 
                    command_type="patrol",
                    parameters={"zone": "alpha"},
                    classification_level=ClassificationLevel.SECRET,
                    issued_by="multi_operator",
                    timestamp=datetime.utcnow()
                ),
                SecurityCommand(
                    command_id="multi_cmd_03",
                    robot_id="dji_survey_01",
                    command_type="takeoff",
                    parameters={"altitude": 50},
                    classification_level=ClassificationLevel.UNCLASSIFIED,
                    issued_by="multi_operator",
                    timestamp=datetime.utcnow()
                )
            ]
            
            # Validate all commands
            results = []
            for command in commands:
                result = await hal.validate_command(command)
                results.append(result)
            
            # All should be valid
            assert all(results)
            
            # Test fleet-wide emergency stop
            start_time = time.time()
            stop_success = await hal.execute_emergency_stop(
                reason=EmergencyStopReason.SECURITY_BREACH,
                triggered_by="security_system"
            )
            stop_time = (time.time() - start_time) * 1000
            
            assert stop_success is True
            assert stop_time < 100  # Fleet coordination under 100ms
            
            # Verify all robots stopped
            fleet_status = await hal.get_fleet_status()
            assert fleet_status["emergency_stop_robots"] == 4
            
        finally:
            # Cleanup
            for robot_id, _, _ in fleet:
                await hal.unregister_robot(robot_id)
    
    @pytest.mark.asyncio
    async def test_high_throughput_operations(self):
        """Test high-throughput command validation."""
        hal = UniversalSecurityHAL()
        
        try:
            # Register robots for load testing
            robots = []
            for i in range(5):
                robot_id = f"load_test_robot_{i:02d}"
                await hal.register_robot(
                    robot_id, 
                    RobotPlatformType.BOSTON_DYNAMICS_SPOT, 
                    ClassificationLevel.UNCLASSIFIED
                )
                robots.append(robot_id)
            
            # Generate high volume of commands
            commands = []
            for i in range(100):
                robot_id = robots[i % len(robots)]
                command = SecurityCommand(
                    command_id=f"load_cmd_{i:03d}",
                    robot_id=robot_id,
                    command_type="walk",
                    parameters={"speed": 1.0, "step": i},
                    classification_level=ClassificationLevel.UNCLASSIFIED,
                    issued_by="load_tester",
                    timestamp=datetime.utcnow()
                )
                commands.append(command)
            
            # Validate commands in batch
            start_time = time.time()
            results = []
            for command in commands:
                result = await hal.validate_command(command)
                results.append(result)
            batch_time = (time.time() - start_time) * 1000
            
            # Verify performance
            assert all(results)  # All commands should validate
            assert batch_time < 5000  # 100 commands in under 5 seconds
            assert len(hal.active_commands) == 100
            
            # Calculate throughput
            commands_per_second = len(commands) / (batch_time / 1000)
            assert commands_per_second > 20  # At least 20 commands/second
            
        finally:
            # Cleanup
            for robot_id in robots:
                await hal.unregister_robot(robot_id)

# Test runner
if __name__ == "__main__":
    # Run specific test categories
    import subprocess
    import sys
    
    print("🧪 Running ALCUB3 Universal Security HAL Tests...")
    
    # Run all tests with coverage
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        __file__, 
        "-v", 
        "--tb=short",
        "--durations=10"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    exit(result.returncode)