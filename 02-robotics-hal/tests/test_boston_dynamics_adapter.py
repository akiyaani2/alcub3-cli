#!/usr/bin/env python3
"""
Test Suite for ALCUB3 Boston Dynamics Spot Security Adapter - Task 3.2
Comprehensive validation of Spot-specific security capabilities

This test suite validates:
- Spot robot connection and initialization
- Classification-aware command validation for Spot operations
- Emergency stop capability with Spot-specific optimizations
- Secure telemetry collection and encryption
- Performance targets for Spot robotics operations
- Patent-defensible Spot security innovations

Test Categories:
- Spot connection and configuration validation
- Spot command validation and execution
- Emergency stop performance testing
- Security constraint enforcement
- Telemetry collection and encryption
- Performance benchmarking
"""

import pytest
import asyncio
import time
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import List, Dict, Any

# Import the Boston Dynamics Spot adapter
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "adapters"))
sys.path.append(str(Path(__file__).parent.parent / "src"))

from boston_dynamics_adapter import (
    BostonDynamicsSpotAdapter,
    SpotCommandType,
    SpotSecurityLevel,
    SpotSecurityProfile,
    SpotTelemetryData,
    MockSpotClient
)

from security_hal import (
    RobotSecurityProfile,
    SecurityCommand,
    EmergencyStopReason,
    ClassificationLevel,
    RobotPlatformType,
    SecurityValidationLevel
)

class TestBostonDynamicsSpotAdapter:
    """Test suite for Boston Dynamics Spot Security Adapter."""
    
    @pytest.fixture
    def spot_security_profile(self):
        """Create Spot robot security profile for testing."""
        return RobotSecurityProfile(
            robot_id="test_spot_01",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            validation_level=SecurityValidationLevel.ENHANCED,
            authorized_operations=["walk", "turn", "sit", "stand", "patrol", "inspect"],
            security_constraints={"max_speed": 1.5, "allowed_hours": list(range(8, 18))},
            last_security_check=datetime.utcnow(),
            security_status="operational"
        )
    
    @pytest.fixture
    def spot_config(self):
        """Create Spot configuration for testing."""
        return {
            "serial": "BD-TEST-12345",
            "ip_address": "192.168.1.100",
            "username": "test_operator",
            "firmware": "3.2.1",
            "security_level": "enhanced",
            "authorized_operators": ["test_operator", "operator_001"],
            "security_constraints": {"max_speed": 1.5, "allowed_hours": list(range(8, 18))}
        }
    
    @pytest.fixture
    def spot_adapter(self, spot_security_profile):
        """Create Spot adapter instance for testing."""
        adapter = BostonDynamicsSpotAdapter("test_spot_01", spot_security_profile)
        yield adapter
        # Cleanup
        adapter.stop_monitoring()
    
    @pytest.fixture
    def sample_spot_command(self):
        """Create sample Spot command for testing."""
        return SecurityCommand(
            command_id="spot_test_cmd_001",
            robot_id="test_spot_01",
            command_type="walk",
            parameters={"speed": 1.0, "direction": "forward", "distance": 3.0},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
    
    def test_spot_adapter_initialization(self, spot_adapter):
        """Test Spot adapter proper initialization."""
        assert spot_adapter is not None
        assert spot_adapter.robot_id == "test_spot_01"
        assert spot_adapter.is_connected is False
        assert spot_adapter.spot_profile is None
        assert spot_adapter.spot_client is None
        assert len(spot_adapter.performance_metrics) == 4
        assert len(spot_adapter.security_metrics) == 5
    
    @pytest.mark.asyncio
    async def test_spot_connection_initialization(self, spot_adapter, spot_config):
        """Test Spot robot connection initialization."""
        # Test successful initialization
        success = await spot_adapter.initialize_spot_connection(spot_config)
        
        assert success is True
        assert spot_adapter.is_connected is True
        assert spot_adapter.spot_profile is not None
        assert spot_adapter.spot_client is not None
        
        # Verify Spot profile
        profile = spot_adapter.spot_profile
        assert profile.spot_serial == "BD-TEST-12345"
        assert profile.firmware_version == "3.2.1"
        assert profile.security_level == SpotSecurityLevel.ENHANCED
        assert "test_operator" in profile.authorized_operators
    
    @pytest.mark.asyncio
    async def test_spot_config_validation(self, spot_adapter):
        """Test Spot configuration validation."""
        # Test valid config
        valid_config = {
            "serial": "BD-12345",
            "ip_address": "192.168.1.100",
            "username": "operator"
        }
        assert spot_adapter._validate_spot_config(valid_config) is True
        
        # Test invalid config - missing serial
        invalid_config = {
            "ip_address": "192.168.1.100",
            "username": "operator"
        }
        assert spot_adapter._validate_spot_config(invalid_config) is False
    
    @pytest.mark.asyncio
    async def test_spot_command_validation_performance(self, spot_adapter, spot_config, sample_spot_command):
        """Test Spot command validation meets <50ms performance target."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test command validation performance
        start_time = time.time()
        valid = await spot_adapter.validate_command(sample_spot_command)
        validation_time = (time.time() - start_time) * 1000
        
        assert valid is True
        assert validation_time < 50  # Target: <50ms
        assert spot_adapter.security_metrics["commands_validated"] == 1
        assert spot_adapter.security_metrics["commands_rejected"] == 0
    
    @pytest.mark.asyncio
    async def test_spot_command_classification_validation(self, spot_adapter, spot_config):
        """Test classification-aware Spot command validation."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test 1: UNCLASSIFIED command (should pass)
        unclass_command = SecurityCommand(
            command_id="unclass_cmd",
            robot_id="test_spot_01",
            command_type="walk",
            parameters={"speed": 1.0},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(unclass_command)
        assert valid is True
        
        # Test 2: SECRET command to UNCLASSIFIED Spot (should fail)
        secret_command = SecurityCommand(
            command_id="secret_cmd",
            robot_id="test_spot_01",
            command_type="patrol",
            parameters={"area": "classified_zone"},
            classification_level=ClassificationLevel.SECRET,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(secret_command)
        assert valid is False
        assert spot_adapter.security_metrics["security_violations"] > 0
    
    @pytest.mark.asyncio
    async def test_spot_command_type_validation(self, spot_adapter, spot_config):
        """Test Spot-specific command type validation."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test valid Spot commands
        valid_commands = ["walk", "turn", "sit", "stand", "patrol", "inspect"]
        
        for cmd_type in valid_commands:
            # Set appropriate parameters for each command type
            if cmd_type == "walk":
                params = {"speed": 1.0}
            elif cmd_type == "turn":
                params = {"angle": 45.0}
            elif cmd_type == "inspect":
                params = {"target": "test_target"}
            elif cmd_type == "patrol":
                params = {"waypoints": [
                    {"latitude": 42.3601, "longitude": -71.0589},
                    {"latitude": 42.3602, "longitude": -71.0590}
                ]}
            else:
                params = {}
            
            command = SecurityCommand(
                command_id=f"cmd_{cmd_type}",
                robot_id="test_spot_01",
                command_type=cmd_type,
                parameters=params,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                issued_by="test_operator",
                timestamp=datetime.utcnow()
            )
            
            valid = await spot_adapter.validate_command(command)
            assert valid is True, f"Command {cmd_type} should be valid"
        
        # Test invalid command
        invalid_command = SecurityCommand(
            command_id="invalid_cmd",
            robot_id="test_spot_01",
            command_type="invalid_operation",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(invalid_command)
        assert valid is False
    
    @pytest.mark.asyncio
    async def test_spot_walk_command_validation(self, spot_adapter, spot_config):
        """Test Spot walk command parameter validation."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test valid walk command
        valid_walk = SecurityCommand(
            command_id="valid_walk",
            robot_id="test_spot_01",
            command_type="walk",
            parameters={"speed": 1.0, "distance": 10.0},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(valid_walk)
        assert valid is True
        
        # Test walk command with excessive speed
        invalid_speed_walk = SecurityCommand(
            command_id="invalid_speed_walk",
            robot_id="test_spot_01",
            command_type="walk",
            parameters={"speed": 3.0, "distance": 5.0},  # Exceeds max speed
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(invalid_speed_walk)
        assert valid is False
        
        # Test walk command with excessive distance
        invalid_distance_walk = SecurityCommand(
            command_id="invalid_distance_walk",
            robot_id="test_spot_01",
            command_type="walk",
            parameters={"speed": 1.0, "distance": 100.0},  # Exceeds max distance
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(invalid_distance_walk)
        assert valid is False
    
    @pytest.mark.asyncio
    async def test_spot_emergency_stop_performance(self, spot_adapter, spot_config):
        """Test Spot emergency stop meets <50ms performance target."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test emergency stop performance
        start_time = time.time()
        success = await spot_adapter.execute_emergency_stop(EmergencyStopReason.SAFETY_VIOLATION)
        stop_time = (time.time() - start_time) * 1000
        
        assert success is True
        assert stop_time < 50  # Target: <50ms
        assert spot_adapter.security_metrics["emergency_stops"] == 1
        assert spot_adapter.security_profile.security_status == "emergency_stop"
    
    @pytest.mark.asyncio
    async def test_spot_emergency_stop_types(self, spot_adapter, spot_config):
        """Test different Spot emergency stop types."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test different emergency stop reasons
        reasons = [
            EmergencyStopReason.SAFETY_VIOLATION,
            EmergencyStopReason.SECURITY_BREACH,
            EmergencyStopReason.MANUAL_TRIGGER
        ]
        
        for reason in reasons:
            success = await spot_adapter.execute_emergency_stop(reason)
            assert success is True
            
            # Reset security status for next test
            spot_adapter.security_profile.security_status = "operational"
    
    @pytest.mark.asyncio
    async def test_spot_security_status(self, spot_adapter, spot_config):
        """Test Spot security status collection."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Get security status
        status = await spot_adapter.get_security_status()
        
        assert status is not None
        assert status["robot_id"] == "test_spot_01"
        assert status["platform"] == "boston_dynamics_spot"
        assert status["connected"] is True
        assert "telemetry" in status
        assert "performance_metrics" in status
        assert "security_metrics" in status
        assert "spot_specific" in status
        
        # Verify Spot-specific information
        spot_info = status["spot_specific"]
        assert spot_info["serial"] == "BD-TEST-12345"
        assert spot_info["firmware"] == "3.2.1"
        assert spot_info["security_level"] == "enhanced"
    
    @pytest.mark.asyncio
    async def test_spot_telemetry_collection(self, spot_adapter, spot_config):
        """Test Spot telemetry collection and encryption."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Collect telemetry
        telemetry = await spot_adapter._collect_spot_telemetry()
        
        assert telemetry is not None
        assert "robot_id" in telemetry
        assert "timestamp" in telemetry
        assert "position" in telemetry
        assert "velocity" in telemetry
        assert "orientation" in telemetry
        assert "battery_status" in telemetry
        assert "system_status" in telemetry
        assert "classification_level" in telemetry
        
        # Verify classification level
        assert telemetry["classification_level"] == ClassificationLevel.UNCLASSIFIED.value
    
    @pytest.mark.asyncio
    async def test_spot_security_constraints(self, spot_adapter, spot_config):
        """Test Spot security constraints enforcement."""
        # Modify config to include time constraints
        spot_config["security_constraints"]["allowed_hours"] = [9, 10, 11, 12, 13, 14, 15, 16, 17]
        
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test command with authorized operator
        authorized_command = SecurityCommand(
            command_id="authorized_cmd",
            robot_id="test_spot_01",
            command_type="walk",
            parameters={"operator": "test_operator", "speed": 1.0},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(authorized_command)
        assert valid is True
        
        # Test command with unauthorized operator
        unauthorized_command = SecurityCommand(
            command_id="unauthorized_cmd",
            robot_id="test_spot_01",
            command_type="walk",
            parameters={"operator": "unauthorized_user", "speed": 1.0},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="unauthorized_user",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(unauthorized_command)
        assert valid is False
    
    @pytest.mark.asyncio
    async def test_spot_navigation_command_validation(self, spot_adapter, spot_config):
        """Test Spot navigation command validation."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test valid navigation command
        valid_nav = SecurityCommand(
            command_id="valid_nav",
            robot_id="test_spot_01",
            command_type="navigate",
            parameters={"latitude": 42.3601, "longitude": -71.0589},  # Boston coordinates
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(valid_nav)
        assert valid is True
        
        # Test navigation with invalid coordinates
        invalid_nav = SecurityCommand(
            command_id="invalid_nav",
            robot_id="test_spot_01",
            command_type="navigate",
            parameters={"latitude": 200.0, "longitude": -300.0},  # Invalid coordinates
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(invalid_nav)
        assert valid is False
    
    @pytest.mark.asyncio
    async def test_spot_patrol_command_validation(self, spot_adapter, spot_config):
        """Test Spot patrol command validation."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test valid patrol command
        valid_patrol = SecurityCommand(
            command_id="valid_patrol",
            robot_id="test_spot_01",
            command_type="patrol",
            parameters={"waypoints": [
                {"latitude": 42.3601, "longitude": -71.0589},
                {"latitude": 42.3602, "longitude": -71.0590}
            ]},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(valid_patrol)
        assert valid is True
        
        # Test patrol with insufficient waypoints
        invalid_patrol = SecurityCommand(
            command_id="invalid_patrol",
            robot_id="test_spot_01",
            command_type="patrol",
            parameters={"waypoints": [{"latitude": 42.3601, "longitude": -71.0589}]},  # Only 1 waypoint
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(invalid_patrol)
        assert valid is False
    
    @pytest.mark.asyncio
    async def test_spot_inspect_command_validation(self, spot_adapter, spot_config):
        """Test Spot inspection command validation."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Test valid inspection command
        valid_inspect = SecurityCommand(
            command_id="valid_inspect",
            robot_id="test_spot_01",
            command_type="inspect",
            parameters={"target": "equipment_rack_01", "sensors": ["camera", "lidar"]},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(valid_inspect)
        assert valid is True
        
        # Test inspection without target
        invalid_inspect = SecurityCommand(
            command_id="invalid_inspect",
            robot_id="test_spot_01",
            command_type="inspect",
            parameters={"sensors": ["camera"]},  # Missing target
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await spot_adapter.validate_command(invalid_inspect)
        assert valid is False
    
    @pytest.mark.asyncio
    async def test_spot_performance_tracking(self, spot_adapter, spot_config, sample_spot_command):
        """Test Spot performance metrics tracking."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Execute multiple commands to track performance
        for i in range(5):
            command = SecurityCommand(
                command_id=f"perf_cmd_{i}",
                robot_id="test_spot_01",
                command_type="walk",
                parameters={"speed": 1.0, "step": i},
                classification_level=ClassificationLevel.UNCLASSIFIED,
                issued_by="test_operator",
                timestamp=datetime.utcnow()
            )
            
            await spot_adapter.validate_command(command)
        
        # Execute emergency stop
        await spot_adapter.execute_emergency_stop(EmergencyStopReason.MANUAL_TRIGGER)
        
        # Get status with performance metrics
        status = await spot_adapter.get_security_status()
        metrics = status["performance_metrics"]
        
        # Verify performance tracking
        assert metrics["avg_command_validation_ms"] > 0
        assert metrics["avg_emergency_stop_ms"] > 0
        assert metrics["avg_telemetry_collection_ms"] > 0
        
        # Verify all metrics are within targets
        assert metrics["avg_command_validation_ms"] < 50
        assert metrics["avg_emergency_stop_ms"] < 50
    
    @pytest.mark.asyncio
    async def test_spot_security_profile_update(self, spot_adapter, spot_config):
        """Test Spot security profile updates."""
        # Initialize Spot connection
        await spot_adapter.initialize_spot_connection(spot_config)
        
        # Update security profile
        updated_profile = RobotSecurityProfile(
            robot_id="test_spot_01",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.CUI,  # Upgraded classification
            validation_level=SecurityValidationLevel.MAXIMUM,
            authorized_operations=["walk", "turn", "sit", "stand", "patrol", "inspect", "emergency_stop"],
            security_constraints={"max_speed": 2.0, "allowed_hours": list(range(6, 22))},
            last_security_check=datetime.utcnow(),
            security_status="operational"
        )
        
        success = await spot_adapter.update_security_profile(updated_profile)
        assert success is True
        
        # Verify profile updated
        assert spot_adapter.security_profile.classification_level == ClassificationLevel.CUI
        assert spot_adapter.security_profile.validation_level == SecurityValidationLevel.MAXIMUM
        
        # Verify Spot profile audit timestamp updated
        if spot_adapter.spot_profile:
            assert spot_adapter.spot_profile.last_security_audit is not None

class TestMockSpotClient:
    """Test suite for Mock Spot Client."""
    
    @pytest.mark.asyncio
    async def test_mock_spot_client_connection(self):
        """Test mock Spot client connection."""
        config = {"ip_address": "192.168.1.100", "username": "test"}
        client = MockSpotClient(config)
        
        assert client.connected is False
        
        await client.connect()
        assert client.connected is True
    
    @pytest.mark.asyncio
    async def test_mock_spot_client_emergency_stops(self):
        """Test mock Spot client emergency stop functions."""
        config = {"ip_address": "192.168.1.100", "username": "test"}
        client = MockSpotClient(config)
        await client.connect()
        
        # Test different emergency stop types
        await client.immediate_stop()
        await client.secure_shutdown()
        await client.safe_stop()
        
        # All should complete without error
        assert client.connected is True
    
    @pytest.mark.asyncio
    async def test_mock_spot_client_telemetry(self):
        """Test mock Spot client telemetry collection."""
        config = {"ip_address": "192.168.1.100", "username": "test"}
        client = MockSpotClient(config)
        await client.connect()
        
        telemetry = await client.get_telemetry()
        
        assert telemetry is not None
        assert "position" in telemetry
        assert "velocity" in telemetry
        assert "orientation" in telemetry
        assert "battery" in telemetry
        assert "system" in telemetry
        
        # Verify data structure
        assert "x" in telemetry["position"]
        assert "y" in telemetry["position"]
        assert "z" in telemetry["position"]

class TestSpotIntegration:
    """Integration tests for Spot Security Adapter."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_spot_operation(self):
        """Test complete Spot security operation flow."""
        # Create security profile
        security_profile = RobotSecurityProfile(
            robot_id="integration_spot",
            platform_type=RobotPlatformType.BOSTON_DYNAMICS_SPOT,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            validation_level=SecurityValidationLevel.ENHANCED,
            authorized_operations=["walk", "turn", "sit", "stand", "patrol"],
            security_constraints={"max_speed": 1.5},
            last_security_check=datetime.utcnow(),
            security_status="operational"
        )
        
        # Create adapter
        adapter = BostonDynamicsSpotAdapter("integration_spot", security_profile)
        
        try:
            # Initialize connection
            spot_config = {
                "serial": "BD-INTEGRATION-01",
                "ip_address": "192.168.1.100",
                "username": "integration_test",
                "firmware": "3.2.1",
                "security_level": "enhanced",
                "authorized_operators": ["integration_test"],
                "security_constraints": {"max_speed": 1.5}
            }
            
            success = await adapter.initialize_spot_connection(spot_config)
            assert success is True
            
            # Execute multiple commands
            commands = [
                {"type": "stand", "params": {}},
                {"type": "walk", "params": {"speed": 1.0, "distance": 5.0}},
                {"type": "turn", "params": {"angle": 90}},
                {"type": "sit", "params": {}}
            ]
            
            for i, cmd in enumerate(commands):
                command = SecurityCommand(
                    command_id=f"integration_cmd_{i}",
                    robot_id="integration_spot",
                    command_type=cmd["type"],
                    parameters=cmd["params"],
                    classification_level=ClassificationLevel.UNCLASSIFIED,
                    issued_by="integration_test",
                    timestamp=datetime.utcnow()
                )
                
                valid = await adapter.validate_command(command)
                assert valid is True
            
            # Test emergency stop
            stop_success = await adapter.execute_emergency_stop(EmergencyStopReason.MANUAL_TRIGGER)
            assert stop_success is True
            
            # Verify final status
            status = await adapter.get_security_status()
            assert status["connected"] is True
            assert status["security_status"] == "emergency_stop"
            assert status["security_metrics"]["commands_validated"] == 4
            assert status["security_metrics"]["emergency_stops"] == 1
            
        finally:
            adapter.stop_monitoring()

# Test runner
if __name__ == "__main__":
    # Run specific test categories
    import subprocess
    import sys
    
    print("🧪 Running ALCUB3 Boston Dynamics Spot Security Adapter Tests...")
    
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