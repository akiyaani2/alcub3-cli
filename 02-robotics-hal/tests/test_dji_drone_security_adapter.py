#!/usr/bin/env python3
"""
Test Suite for DJI Drone Security Adapter - Task 3.4
Comprehensive validation of patent-defensible DJI drone security integration
"""

import pytest
import asyncio
import time
from datetime import datetime
from pathlib import Path
import sys

# Add src directory to path for imports
sys.path.append(str(Path(__file__).parent.parent / "src"))
sys.path.append(str(Path(__file__).parent.parent / "adapters"))

from dji_drone_security_adapter import (
    DJIDroneSecurityAdapter,
    DJICommandType,
    DJIFlightMode,
    DJISecurityLevel,
    DJISecurityConstraints,
    DJITelemetryData,
    DJIFlightEnvelope,
    DJIWaypoint
)

from security_hal import (
    SecurityCommand,
    EmergencyStopReason,
    ClassificationLevel,
    RobotSecurityProfile,
    RobotPlatformType,
    SecurityValidationLevel
)

class TestDJIDroneSecurityAdapter:
    """Test suite for DJI Drone Security Adapter."""

    @pytest.fixture
    def security_profile(self):
        """Create a test security profile for DJI drone."""
        return RobotSecurityProfile(
            robot_id="test_dji_01",
            platform_type=RobotPlatformType.DJI_DRONE,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            validation_level=SecurityValidationLevel.ENHANCED,
            authorized_operations=["takeoff", "land", "move_to", "hover", "return_to_home", "set_flight_mode", "arm_motors", "disarm_motors", "start_video_recording", "stop_video_recording", "capture_photo", "set_camera_mode", "set_gimbal_angle", "follow_path", "start_mission", "stop_mission", "emergency_stop"],
            security_constraints={
                "max_altitude_m": 100.0,
                "max_range_m": 300.0,
                "max_speed_ms": 10.0,
                "min_battery_percent": 25.0,
                "allowed_flight_modes": ["manual", "gps", "waypoint"],
                "geofence_enabled": True,
                "video_encryption_required": True
            },
            last_security_check=datetime.utcnow(),
            security_status="operational"
        )

    @pytest.fixture
    def dji_adapter(self, security_profile):
        """Create a DJI drone security adapter instance."""
        adapter = DJIDroneSecurityAdapter("test_dji_01", security_profile)
        yield adapter
        # Cleanup
        adapter.stop_monitoring()

    @pytest.fixture
    def dji_config(self):
        """Create test DJI configuration."""
        return {
            "home_latitude": 37.7749,
            "home_longitude": -122.4194,
            "min_altitude_m": 5.0,
            "max_altitude_m": 100.0,
            "geofence_zones": [
                {
                    "name": "test_no_fly_zone",
                    "type": "no_fly",
                    "geometry": {
                        "type": "circle",
                        "center_latitude": 37.7760,  # Closer to home
                        "center_longitude": -122.4200,
                        "radius_m": 30.0  # Smaller radius
                    }
                }
            ]
        }

    def test_dji_adapter_initialization(self, dji_adapter, security_profile):
        """Test DJI adapter initialization."""
        assert dji_adapter.robot_id == "test_dji_01"
        assert dji_adapter.security_profile == security_profile
        assert dji_adapter.current_flight_mode == DJIFlightMode.MANUAL
        assert dji_adapter.armed == False
        assert dji_adapter.flying == False
        assert len(dji_adapter._command_validators) == 17  # All DJI command types

    @pytest.mark.asyncio
    async def test_dji_connection_initialization(self, dji_adapter, dji_config):
        """Test DJI connection initialization."""
        success = await dji_adapter.initialize_dji_connection(dji_config)
        
        assert success == True
        assert dji_adapter.flight_envelope is not None
        assert dji_adapter.flight_envelope.center_lat == 37.7749
        assert dji_adapter.flight_envelope.center_lon == -122.4194
        assert dji_adapter.flight_envelope.max_radius_m == 300.0  # From security constraints
        assert len(dji_adapter.geofence_zones) == 1

    @pytest.mark.asyncio
    async def test_dji_config_validation(self, dji_adapter):
        """Test DJI configuration validation."""
        # Valid config
        valid_config = {
            "home_latitude": 37.7749,
            "home_longitude": -122.4194
        }
        assert dji_adapter._validate_dji_config(valid_config) == True
        
        # Missing required fields
        invalid_config = {"home_latitude": 37.7749}
        assert dji_adapter._validate_dji_config(invalid_config) == False
        
        # Invalid coordinates
        invalid_coords_config = {
            "home_latitude": 95.0,  # Out of range
            "home_longitude": -122.4194
        }
        assert dji_adapter._validate_dji_config(invalid_coords_config) == False

    @pytest.mark.asyncio
    async def test_dji_command_validation_performance(self, dji_adapter, dji_config):
        """Test DJI command validation performance."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Test command validation performance
        test_command = SecurityCommand(
            command_id="perf_test_001",
            robot_id="test_dji_01",
            command_type="hover",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        # Set drone to flying state for hover command
        dji_adapter.flying = True
        
        # Validate multiple times to test performance
        validation_times = []
        for i in range(10):
            start_time = time.time()
            valid = await dji_adapter.validate_command(test_command)
            validation_time = (time.time() - start_time) * 1000
            validation_times.append(validation_time)
            assert valid == True
        
        # Check performance target (<30ms for drone operations)
        avg_time = sum(validation_times) / len(validation_times)
        assert avg_time < 30, f"Average validation time {avg_time:.2f}ms exceeds 30ms target"
        
        # Verify performance metrics are tracked
        assert len(dji_adapter.performance_metrics["command_validation_times"]) >= 10

    @pytest.mark.asyncio
    async def test_dji_command_classification_validation(self, dji_adapter, dji_config):
        """Test classification-aware DJI command validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Test valid classification (UNCLASSIFIED command to UNCLASSIFIED drone)
        valid_command = SecurityCommand(
            command_id="class_test_001",
            robot_id="test_dji_01",
            command_type="takeoff",
            parameters={"altitude": 20.0},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        # Set armed state for takeoff
        dji_adapter.armed = True
        
        valid = await dji_adapter.validate_command(valid_command)
        assert valid == True
        
        # Test invalid classification (SECRET command to UNCLASSIFIED drone)
        invalid_command = SecurityCommand(
            command_id="class_test_002",
            robot_id="test_dji_01",
            command_type="start_mission",
            parameters={"mission_id": "classified_mission"},
            classification_level=ClassificationLevel.SECRET,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(invalid_command)
        assert valid == False
        assert dji_adapter.security_metrics["commands_rejected"] > 0

    @pytest.mark.asyncio
    async def test_dji_command_type_validation(self, dji_adapter, dji_config):
        """Test DJI-specific command type validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Test valid DJI command types
        valid_commands = [
            ("takeoff", {"altitude": 10.0}),
            ("land", {}),
            ("hover", {}),
            ("move_to", {"latitude": 37.7750, "longitude": -122.4195, "altitude": 25.0}),
            ("return_to_home", {}),
            ("set_flight_mode", {"flight_mode": "gps"}),
        ]
        
        # Set appropriate states for commands
        dji_adapter.armed = True
        dji_adapter.flying = True
        
        for cmd_type, params in valid_commands:
            command = SecurityCommand(
                command_id=f"type_test_{cmd_type}",
                robot_id="test_dji_01",
                command_type=cmd_type,
                parameters=params,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                issued_by="test_operator",
                timestamp=datetime.utcnow()
            )
            
            # Special handling for takeoff (needs not flying)
            if cmd_type == "takeoff":
                dji_adapter.flying = False
            elif cmd_type == "land":
                dji_adapter.flying = True
            
            valid = await dji_adapter.validate_command(command)
            assert valid == True, f"Command type {cmd_type} should be valid"
        
        # Test invalid command type
        invalid_command = SecurityCommand(
            command_id="invalid_type_test",
            robot_id="test_dji_01",
            command_type="invalid_dji_command",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(invalid_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_dji_flight_envelope_validation(self, dji_adapter, dji_config):
        """Test DJI flight envelope validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        dji_adapter.flying = True
        
        # Test movement within flight envelope
        within_envelope_command = SecurityCommand(
            command_id="envelope_valid_test",
            robot_id="test_dji_01",
            command_type="move_to",
            parameters={
                "latitude": 37.7750,  # Close to home
                "longitude": -122.4195,
                "altitude": 50.0
            },
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(within_envelope_command)
        assert valid == True
        
        # Test movement outside flight envelope (distance)
        outside_envelope_command = SecurityCommand(
            command_id="envelope_invalid_test",
            robot_id="test_dji_01",
            command_type="move_to",
            parameters={
                "latitude": 37.8000,  # Too far from home
                "longitude": -122.4000,
                "altitude": 50.0
            },
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(outside_envelope_command)
        assert valid == False
        
        # Test altitude violation
        high_altitude_command = SecurityCommand(
            command_id="altitude_invalid_test",
            robot_id="test_dji_01",
            command_type="move_to",
            parameters={
                "latitude": 37.7750,
                "longitude": -122.4195,
                "altitude": 150.0  # Above max altitude
            },
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(high_altitude_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_dji_geofence_validation(self, dji_adapter, dji_config):
        """Test DJI geofence validation."""
        # Initialize adapter with geofence zones
        await dji_adapter.initialize_dji_connection(dji_config)
        dji_adapter.flying = True
        
        # Test movement to allowed area
        allowed_command = SecurityCommand(
            command_id="geofence_allowed_test",
            robot_id="test_dji_01",
            command_type="move_to",
            parameters={
                "latitude": 37.7750,  # Away from no-fly zone
                "longitude": -122.4180,
                "altitude": 50.0
            },
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(allowed_command)
        assert valid == True
        
        # Test movement to no-fly zone (within flight envelope but in no-fly zone)
        restricted_command = SecurityCommand(
            command_id="geofence_restricted_test",
            robot_id="test_dji_01",
            command_type="move_to",
            parameters={
                "latitude": 37.7760,  # Center of no-fly zone
                "longitude": -122.4200,
                "altitude": 50.0
            },
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(restricted_command)
        assert valid == False
        assert dji_adapter.security_metrics["geofence_violations"] > 0

    @pytest.mark.asyncio
    async def test_dji_flight_mode_validation(self, dji_adapter, dji_config):
        """Test DJI flight mode validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Test allowed flight mode
        allowed_mode_command = SecurityCommand(
            command_id="mode_allowed_test",
            robot_id="test_dji_01",
            command_type="set_flight_mode",
            parameters={"flight_mode": "gps"},  # In allowed_flight_modes
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(allowed_mode_command)
        assert valid == True
        
        # Test disallowed flight mode
        disallowed_mode_command = SecurityCommand(
            command_id="mode_disallowed_test",
            robot_id="test_dji_01",
            command_type="set_flight_mode",
            parameters={"flight_mode": "sport"},  # Not in allowed_flight_modes
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(disallowed_mode_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_dji_safety_constraints_validation(self, dji_adapter, dji_config):
        """Test DJI safety constraints validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Test takeoff with sufficient battery
        dji_adapter.current_telemetry = DJITelemetryData(
            timestamp=datetime.utcnow(),
            classification_level=ClassificationLevel.UNCLASSIFIED,
            flight_mode="manual",
            armed=True,
            flying=False,
            battery_percent=80.0,  # Above minimum
            flight_time_seconds=0.0,
            latitude=37.7749,
            longitude=-122.4194,
            altitude_m=0.0,
            relative_altitude_m=0.0,
            velocity_ms=(0.0, 0.0, 0.0),
            heading_degrees=0.0,
            gps_satellite_count=12,
            gps_signal_strength=95,
            radio_signal_strength=90,
            video_signal_strength=88,
            temperature_celsius=25.0,
            geofence_violations=0,
            security_alerts=[],
            encryption_status={"video": True, "telemetry": True},
            camera_mode="photo",
            recording=False,
            gimbal_pitch=0.0,
            gimbal_yaw=0.0,
            gimbal_roll=0.0
        )
        
        dji_adapter.armed = True
        
        takeoff_command = SecurityCommand(
            command_id="safety_good_test",
            robot_id="test_dji_01",
            command_type="takeoff",
            parameters={"altitude": 10.0},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(takeoff_command)
        assert valid == True
        
        # Test takeoff with low battery
        dji_adapter.current_telemetry.battery_percent = 15.0  # Below minimum
        
        valid = await dji_adapter.validate_command(takeoff_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_dji_arm_disarm_validation(self, dji_adapter, dji_config):
        """Test DJI arm/disarm command validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Test arm when not flying
        dji_adapter.flying = False
        arm_command = SecurityCommand(
            command_id="arm_test",
            robot_id="test_dji_01",
            command_type="arm_motors",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(arm_command)
        assert valid == True
        
        # Test disarm when flying (should fail)
        dji_adapter.flying = True
        disarm_command = SecurityCommand(
            command_id="disarm_test",
            robot_id="test_dji_01",
            command_type="disarm_motors",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(disarm_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_dji_video_encryption_validation(self, dji_adapter, dji_config):
        """Test DJI video encryption requirement validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Test video recording with encryption enabled
        video_command = SecurityCommand(
            command_id="video_test",
            robot_id="test_dji_01",
            command_type="start_video_recording",
            parameters={"quality": "4K", "fps": 30},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(video_command)
        assert valid == True  # Should pass with encryption enabled

    @pytest.mark.asyncio
    async def test_dji_waypoint_validation(self, dji_adapter, dji_config):
        """Test DJI waypoint mission validation."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        dji_adapter.flying = True
        
        # Test valid waypoint mission
        valid_waypoints = [
            {"latitude": 37.7750, "longitude": -122.4195, "altitude": 30.0},
            {"latitude": 37.7751, "longitude": -122.4196, "altitude": 35.0},
            {"latitude": 37.7752, "longitude": -122.4197, "altitude": 40.0}
        ]
        
        waypoint_command = SecurityCommand(
            command_id="waypoint_valid_test",
            robot_id="test_dji_01",
            command_type="follow_path",
            parameters={"waypoints": valid_waypoints},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(waypoint_command)
        assert valid == True
        
        # Test empty waypoint mission
        empty_waypoint_command = SecurityCommand(
            command_id="waypoint_empty_test",
            robot_id="test_dji_01",
            command_type="follow_path",
            parameters={"waypoints": []},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await dji_adapter.validate_command(empty_waypoint_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_dji_emergency_stop_performance(self, dji_adapter, dji_config):
        """Test DJI emergency stop performance."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        dji_adapter.flying = True
        dji_adapter.armed = True
        
        # Test emergency stop performance
        emergency_times = []
        for reason in [EmergencyStopReason.SAFETY_VIOLATION, EmergencyStopReason.SECURITY_BREACH]:
            start_time = time.time()
            success = await dji_adapter.execute_emergency_stop(reason)
            emergency_time = (time.time() - start_time) * 1000
            emergency_times.append(emergency_time)
            
            assert success == True
            assert emergency_time < 30000, f"Emergency stop time {emergency_time:.2f}ms exceeds 30s target"
            
            # Reset state for next test
            dji_adapter.flying = True
            dji_adapter.armed = True
        
        # Check performance metrics
        assert len(dji_adapter.performance_metrics["emergency_responses"]) >= 2

    @pytest.mark.asyncio
    async def test_dji_security_status(self, dji_adapter, dji_config):
        """Test DJI security status reporting."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Get security status
        status = await dji_adapter.get_security_status()
        
        # Verify status structure
        assert "robot_id" in status
        assert "platform" in status
        assert "connected" in status
        assert "classification_level" in status
        assert "security_status" in status
        assert "flight_status" in status
        assert "security_metrics" in status
        assert "performance_metrics" in status
        assert "dji_specific" in status
        
        # Verify values
        assert status["robot_id"] == "test_dji_01"
        assert status["platform"] == "dji_drone"
        assert status["classification_level"] == "unclassified"
        
        # Verify flight status
        flight_status = status["flight_status"]
        assert "armed" in flight_status
        assert "flying" in flight_status
        assert "flight_mode" in flight_status
        
        # Verify DJI-specific information
        dji_info = status["dji_specific"]
        assert "flight_envelope_active" in dji_info
        assert "geofence_zones_count" in dji_info
        assert "video_encryption_active" in dji_info
        assert "constraints" in dji_info
        assert dji_info["flight_envelope_active"] == True
        assert dji_info["geofence_zones_count"] == 1

    @pytest.mark.asyncio
    async def test_dji_telemetry_monitoring(self, dji_adapter, dji_config):
        """Test DJI telemetry monitoring functionality."""
        # Initialize adapter
        await dji_adapter.initialize_dji_connection(dji_config)
        
        # Telemetry monitoring should be started automatically
        assert dji_adapter._monitoring_active == True
        assert dji_adapter._monitoring_thread is not None
        
        # Wait briefly for telemetry collection
        await asyncio.sleep(0.1)
        
        # Check that telemetry is being collected
        assert dji_adapter.current_telemetry is not None
        
        # Verify telemetry structure
        telemetry = dji_adapter.current_telemetry
        assert telemetry.timestamp is not None
        assert telemetry.classification_level == ClassificationLevel.UNCLASSIFIED
        assert isinstance(telemetry.battery_percent, float)
        assert isinstance(telemetry.latitude, float)
        assert isinstance(telemetry.longitude, float)

    def test_dji_distance_calculation(self, dji_adapter):
        """Test DJI distance calculation utility."""
        # Test distance between two known points
        # San Francisco to Oakland (approximately 13.6 km)
        sf_lat, sf_lon = 37.7749, -122.4194
        oak_lat, oak_lon = 37.8044, -122.2712
        
        distance = dji_adapter._calculate_distance(sf_lat, sf_lon, oak_lat, oak_lon)
        
        # Should be approximately 13600 meters
        assert 13000 < distance < 14000

    def test_dji_performance_metrics_tracking(self, dji_adapter):
        """Test DJI performance metrics tracking."""
        # Test average calculation
        test_values = [10.0, 20.0, 30.0]
        avg = dji_adapter._calculate_average(test_values)
        assert avg == 20.0
        
        # Test empty values
        empty_avg = dji_adapter._calculate_average([])
        assert empty_avg == 0.0
        
        # Verify all performance metric categories exist
        expected_metrics = [
            "command_validation_times",
            "flight_mode_changes",
            "emergency_responses", 
            "video_encryption_times",
            "telemetry_processing_times"
        ]
        
        for metric in expected_metrics:
            assert metric in dji_adapter.performance_metrics

    def test_dji_security_metrics_tracking(self, dji_adapter):
        """Test DJI security metrics tracking."""
        # Verify all security metric categories exist
        expected_metrics = [
            "commands_validated",
            "commands_rejected",
            "geofence_violations",
            "emergency_stops",
            "security_violations",
            "video_streams_encrypted",
            "unauthorized_commands"
        ]
        
        for metric in expected_metrics:
            assert metric in dji_adapter.security_metrics
            assert dji_adapter.security_metrics[metric] == 0  # Initial state

    def test_dji_command_type_enum_validation(self):
        """Test DJI command type enum validation."""
        # Test all valid command types
        valid_types = [
            "takeoff", "land", "move_to", "hover", "return_to_home", "follow_path",
            "start_mission", "stop_mission", "set_flight_mode", "arm_motors",
            "disarm_motors", "start_video_recording", "stop_video_recording",
            "capture_photo", "set_camera_mode", "set_gimbal_angle", "emergency_stop"
        ]
        
        for cmd_type in valid_types:
            try:
                dji_cmd = DJICommandType(cmd_type)
                assert dji_cmd.value == cmd_type
            except ValueError:
                pytest.fail(f"Valid DJI command type {cmd_type} should not raise ValueError")
        
        # Test invalid command type
        with pytest.raises(ValueError):
            DJICommandType("invalid_command_type")

    def test_dji_flight_mode_enum(self):
        """Test DJI flight mode enum validation."""
        valid_modes = ["manual", "attitude", "gps", "sport", "tripod", "cinematic", 
                      "waypoint", "follow_me", "orbit", "active_track"]
        
        for mode in valid_modes:
            try:
                dji_mode = DJIFlightMode(mode)
                assert dji_mode.value == mode
            except ValueError:
                pytest.fail(f"Valid DJI flight mode {mode} should not raise ValueError")

    def test_dji_security_constraints_creation(self):
        """Test DJI security constraints creation."""
        constraints = DJISecurityConstraints(
            max_altitude_m=120.0,
            max_range_m=500.0,
            max_speed_ms=15.0,
            min_battery_percent=20.0,
            allowed_flight_modes={"manual", "gps", "waypoint"},
            geofence_enabled=True,
            video_encryption_required=True
        )
        
        assert constraints.max_altitude_m == 120.0
        assert constraints.max_range_m == 500.0
        assert constraints.max_speed_ms == 15.0
        assert constraints.min_battery_percent == 20.0
        assert "manual" in constraints.allowed_flight_modes
        assert "gps" in constraints.allowed_flight_modes
        assert constraints.geofence_enabled == True
        assert constraints.video_encryption_required == True

    def test_dji_flight_envelope_creation(self):
        """Test DJI flight envelope creation."""
        envelope = DJIFlightEnvelope(
            center_lat=37.7749,
            center_lon=-122.4194,
            max_radius_m=500.0,
            min_altitude_m=5.0,
            max_altitude_m=120.0
        )
        
        assert envelope.center_lat == 37.7749
        assert envelope.center_lon == -122.4194
        assert envelope.max_radius_m == 500.0
        assert envelope.min_altitude_m == 5.0
        assert envelope.max_altitude_m == 120.0
        assert envelope.restricted_zones == []  # Default empty list

    def test_dji_waypoint_creation(self):
        """Test DJI waypoint creation."""
        waypoint = DJIWaypoint(
            latitude=37.7749,
            longitude=-122.4194,
            altitude_m=50.0,
            speed_ms=10.0,
            actions=["hover", "photo"],
            dwell_time_s=30.0,
            heading_degrees=90.0
        )
        
        assert waypoint.latitude == 37.7749
        assert waypoint.longitude == -122.4194
        assert waypoint.altitude_m == 50.0
        assert waypoint.speed_ms == 10.0
        assert "hover" in waypoint.actions
        assert "photo" in waypoint.actions
        assert waypoint.dwell_time_s == 30.0
        assert waypoint.heading_degrees == 90.0

if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])