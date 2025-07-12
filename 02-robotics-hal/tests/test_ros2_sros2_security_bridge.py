#!/usr/bin/env python3
"""
Test Suite for ROS2/SROS2 Security Bridge - Task 3.3
Comprehensive validation of patent-defensible ROS2 security integration
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

from ros2_sros2_security_bridge import (
    ROS2SROS2SecurityBridge,
    ROS2CommandType,
    SROS2SecurityLevel,
    ROS2NodeSecurityProfile,
    ROS2TelemetryData
)

from security_hal import (
    SecurityCommand,
    EmergencyStopReason,
    ClassificationLevel,
    RobotSecurityProfile,
    RobotPlatformType,
    SecurityValidationLevel
)

class TestROS2SROS2SecurityBridge:
    """Test suite for ROS2/SROS2 Security Bridge."""

    @pytest.fixture
    def security_profile(self):
        """Create a test security profile for ROS2 system."""
        return RobotSecurityProfile(
            robot_id="test_ros2_01",
            platform_type=RobotPlatformType.ROS2_GENERIC,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            validation_level=SecurityValidationLevel.ENHANCED,
            authorized_operations=["publish_message", "call_service", "navigate_to_goal"],
            security_constraints={"domain_id": 0, "sros2_required": True},
            last_security_check=datetime.utcnow(),
            security_status="operational"
        )

    @pytest.fixture
    def ros2_bridge(self, security_profile):
        """Create a ROS2/SROS2 Security Bridge instance."""
        bridge = ROS2SROS2SecurityBridge("test_ros2_01", security_profile)
        yield bridge
        # Cleanup
        bridge.stop_monitoring()

    @pytest.fixture
    def ros2_config(self):
        """Create test ROS2 configuration."""
        return {
            "domain_id": 0,
            "node_name": "test_alcub3_security",
            "namespace": "/test",
            "sros2_enabled": True,
            "security_level": "enhanced",
            "allowed_topics": ["/cmd_vel", "/scan", "/odom"],
            "allowed_services": ["/global_localization", "/clear_costmaps"],
            "allowed_parameters": ["use_sim_time", "robot_radius"],
            "encryption_required": True,
            "authentication_required": True
        }

    def test_ros2_bridge_initialization(self, ros2_bridge, security_profile):
        """Test ROS2 bridge initialization."""
        assert ros2_bridge.robot_id == "test_ros2_01"
        assert ros2_bridge.security_profile == security_profile
        assert ros2_bridge.ros2_profile is None  # Not connected yet
        assert ros2_bridge.sros2_enabled == False  # Not initialized yet
        assert len(ros2_bridge._command_validators) == 11  # All ROS2 command types

    @pytest.mark.asyncio
    async def test_ros2_connection_initialization(self, ros2_bridge, ros2_config):
        """Test ROS2 connection initialization."""
        # Note: This is a mock test since we don't have actual ROS2 environment
        # In real deployment, this would connect to actual ROS2 system
        
        # Override the ROS2 environment validation for testing
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        
        success = await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        assert success == True
        assert ros2_bridge.ros2_domain_id == 0
        assert ros2_bridge.sros2_enabled == True
        assert ros2_bridge.ros2_profile is not None
        assert ros2_bridge.ros2_profile.node_name == "test_alcub3_security"
        assert ros2_bridge.ros2_profile.namespace == "/test"
        assert ros2_bridge.ros2_profile.security_level == SROS2SecurityLevel.ENHANCED

    @pytest.mark.asyncio
    async def test_ros2_config_validation(self, ros2_bridge):
        """Test ROS2 configuration validation."""
        # Valid config
        valid_config = {
            "domain_id": 0,
            "node_name": "test_node"
        }
        assert ros2_bridge._validate_ros2_config(valid_config) == True
        
        # Missing required fields
        invalid_config = {"domain_id": 0}
        assert ros2_bridge._validate_ros2_config(invalid_config) == False
        
        # Invalid domain ID
        invalid_domain_config = {
            "domain_id": 300,  # Out of range
            "node_name": "test_node"
        }
        assert ros2_bridge._validate_ros2_config(invalid_domain_config) == False

    @pytest.mark.asyncio
    async def test_ros2_command_validation_performance(self, ros2_bridge, ros2_config):
        """Test ROS2 command validation performance."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test command validation performance
        test_command = SecurityCommand(
            command_id="perf_test_001",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/cmd_vel", "message_type": "geometry_msgs/Twist"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        # Validate multiple times to test performance
        validation_times = []
        for i in range(10):
            start_time = time.time()
            valid = await ros2_bridge.validate_command(test_command)
            validation_time = (time.time() - start_time) * 1000
            validation_times.append(validation_time)
            assert valid == True
        
        # Check performance target (<50ms)
        avg_time = sum(validation_times) / len(validation_times)
        assert avg_time < 50, f"Average validation time {avg_time:.2f}ms exceeds 50ms target"
        
        # Verify performance metrics are tracked
        assert len(ros2_bridge.performance_metrics["command_validation_times"]) >= 10

    @pytest.mark.asyncio
    async def test_ros2_command_classification_validation(self, ros2_bridge, ros2_config):
        """Test classification-aware ROS2 command validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test valid classification (UNCLASSIFIED command to UNCLASSIFIED robot)
        valid_command = SecurityCommand(
            command_id="class_test_001",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/cmd_vel"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(valid_command)
        assert valid == True
        
        # Test invalid classification (SECRET command to UNCLASSIFIED robot)
        invalid_command = SecurityCommand(
            command_id="class_test_002",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/classified_topic"},
            classification_level=ClassificationLevel.SECRET,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(invalid_command)
        assert valid == False
        assert ros2_bridge.security_metrics["security_violations"] > 0

    @pytest.mark.asyncio
    async def test_ros2_command_type_validation(self, ros2_bridge, ros2_config):
        """Test ROS2-specific command type validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test valid ROS2 command types
        valid_commands = [
            ("publish_message", {"topic": "/cmd_vel"}),
            ("call_service", {"service": "/global_localization"}),
            ("set_parameter", {"parameter": "use_sim_time", "value": True}),
            ("navigate_to_goal", {"goal": {"position": {"x": 1.0, "y": 2.0}}}),
        ]
        
        for cmd_type, params in valid_commands:
            command = SecurityCommand(
                command_id=f"type_test_{cmd_type}",
                robot_id="test_ros2_01",
                command_type=cmd_type,
                parameters=params,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                issued_by="test_operator",
                timestamp=datetime.utcnow()
            )
            
            valid = await ros2_bridge.validate_command(command)
            assert valid == True, f"Command type {cmd_type} should be valid"
        
        # Test invalid command type
        invalid_command = SecurityCommand(
            command_id="invalid_type_test",
            robot_id="test_ros2_01",
            command_type="invalid_ros2_command",
            parameters={},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(invalid_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_ros2_topic_permission_validation(self, ros2_bridge, ros2_config):
        """Test ROS2 topic permission validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test allowed topic
        allowed_command = SecurityCommand(
            command_id="topic_allowed_test",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/cmd_vel"},  # In allowed_topics
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(allowed_command)
        assert valid == True
        
        # Test disallowed topic
        disallowed_command = SecurityCommand(
            command_id="topic_disallowed_test",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/unauthorized_topic"},  # Not in allowed_topics
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(disallowed_command)
        assert valid == False
        
        # Test standard topics (should be allowed even if not explicitly listed)
        standard_command = SecurityCommand(
            command_id="topic_standard_test",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/tf"},  # Standard ROS2 topic
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(standard_command)
        assert valid == True

    @pytest.mark.asyncio
    async def test_ros2_service_permission_validation(self, ros2_bridge, ros2_config):
        """Test ROS2 service permission validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test allowed service
        allowed_command = SecurityCommand(
            command_id="service_allowed_test",
            robot_id="test_ros2_01",
            command_type="call_service",
            parameters={"service": "/global_localization"},  # In allowed_services
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(allowed_command)
        assert valid == True
        
        # Test disallowed service
        disallowed_command = SecurityCommand(
            command_id="service_disallowed_test",
            robot_id="test_ros2_01",
            command_type="call_service",
            parameters={"service": "/unauthorized_service"},  # Not in allowed_services
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(disallowed_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_ros2_parameter_validation(self, ros2_bridge, ros2_config):
        """Test ROS2 parameter validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test allowed parameter
        allowed_command = SecurityCommand(
            command_id="param_allowed_test",
            robot_id="test_ros2_01",
            command_type="set_parameter",
            parameters={"parameter": "use_sim_time", "value": True},  # In allowed_parameters
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(allowed_command)
        assert valid == True
        
        # Test standard parameter (should be allowed)
        standard_command = SecurityCommand(
            command_id="param_standard_test",
            robot_id="test_ros2_01",
            command_type="set_parameter",
            parameters={"parameter": "qos_overrides.test", "value": "best_effort"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(standard_command)
        assert valid == True

    @pytest.mark.asyncio
    async def test_ros2_node_launch_security(self, ros2_bridge, ros2_config):
        """Test ROS2 node launch security validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test normal node launch
        normal_command = SecurityCommand(
            command_id="launch_normal_test",
            robot_id="test_ros2_01",
            command_type="launch_node",
            parameters={"node_name": "navigation_node", "package": "nav2_core"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(normal_command)
        assert valid == True
        
        # Test security node launch with insufficient clearance
        security_command = SecurityCommand(
            command_id="launch_security_test",
            robot_id="test_ros2_01",
            command_type="launch_node",
            parameters={"node_name": "security_monitor", "package": "alcub3_security"},
            classification_level=ClassificationLevel.UNCLASSIFIED,  # Insufficient for security nodes
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(security_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_ros2_node_kill_protection(self, ros2_bridge, ros2_config):
        """Test protection against killing critical security nodes."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test normal node kill
        normal_command = SecurityCommand(
            command_id="kill_normal_test",
            robot_id="test_ros2_01",
            command_type="kill_node",
            parameters={"node_name": "test_node"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(normal_command)
        assert valid == True
        
        # Test security node kill (should be prevented)
        security_command = SecurityCommand(
            command_id="kill_security_test",
            robot_id="test_ros2_01",
            command_type="kill_node",
            parameters={"node_name": "alcub3_security_monitor"},
            classification_level=ClassificationLevel.SECRET,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(security_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_ros2_recording_classification_check(self, ros2_bridge, ros2_config):
        """Test ROS2 bag recording classification validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test normal recording
        normal_command = SecurityCommand(
            command_id="record_normal_test",
            robot_id="test_ros2_01",
            command_type="start_recording",
            parameters={"topics": ["/cmd_vel", "/scan"], "output": "/tmp/test.bag"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(normal_command)
        assert valid == True
        
        # Test classified topic recording with insufficient clearance
        classified_command = SecurityCommand(
            command_id="record_classified_test",
            robot_id="test_ros2_01",
            command_type="start_recording",
            parameters={"topics": ["/classified_sensor_data"], "output": "/tmp/classified.bag"},
            classification_level=ClassificationLevel.UNCLASSIFIED,  # Insufficient
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(classified_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_ros2_emergency_stop_performance(self, ros2_bridge, ros2_config):
        """Test ROS2 emergency stop performance."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test emergency stop performance
        emergency_times = []
        for reason in [EmergencyStopReason.SAFETY_VIOLATION, EmergencyStopReason.SECURITY_BREACH]:
            start_time = time.time()
            success = await ros2_bridge.execute_emergency_stop(reason)
            emergency_time = (time.time() - start_time) * 1000
            emergency_times.append(emergency_time)
            
            assert success == True
            assert emergency_time < 50, f"Emergency stop time {emergency_time:.2f}ms exceeds 50ms target"
        
        # Check performance metrics
        assert len(ros2_bridge.performance_metrics["emergency_stop_times"]) >= 2

    @pytest.mark.asyncio
    async def test_ros2_sros2_policy_validation(self, ros2_bridge, ros2_config):
        """Test SROS2 security policy validation."""
        # Initialize bridge with SROS2 enabled
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Verify SROS2 is enabled and policies are loaded
        assert ros2_bridge.sros2_enabled == True
        assert ros2_bridge.security_policies is not None
        
        # Test command that should pass SROS2 policies
        valid_command = SecurityCommand(
            command_id="sros2_valid_test",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/cmd_vel"},  # Should be in allowed topics
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        # Mock the SROS2 policy validation
        original_validate = ros2_bridge._validate_sros2_policies
        
        async def mock_sros2_validate(command):
            # Simulate SROS2 policy check
            return command.parameters.get("topic") in ["/cmd_vel", "/scan", "/odom"]
        
        ros2_bridge._validate_sros2_policies = mock_sros2_validate
        
        valid = await ros2_bridge.validate_command(valid_command)
        assert valid == True
        
        # Test command that should fail SROS2 policies
        invalid_command = SecurityCommand(
            command_id="sros2_invalid_test",
            robot_id="test_ros2_01",
            command_type="publish_message",
            parameters={"topic": "/unauthorized_topic"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(invalid_command)
        assert valid == False
        assert ros2_bridge.security_metrics["sros2_violations"] > 0
        
        # Restore original method
        ros2_bridge._validate_sros2_policies = original_validate

    @pytest.mark.asyncio
    async def test_ros2_security_status(self, ros2_bridge, ros2_config):
        """Test ROS2 security status reporting."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Get security status
        status = await ros2_bridge.get_security_status()
        
        # Verify status structure
        assert "robot_id" in status
        assert "platform" in status
        assert "connected" in status
        assert "sros2_enabled" in status
        assert "domain_id" in status
        assert "security_status" in status
        assert "classification_level" in status
        assert "performance_metrics" in status
        assert "security_metrics" in status
        assert "ros2_specific" in status
        
        # Verify values
        assert status["robot_id"] == "test_ros2_01"
        assert status["platform"] == "ros2_sros2"
        assert status["connected"] == True
        assert status["sros2_enabled"] == True
        assert status["domain_id"] == 0
        
        # Verify ROS2-specific information
        ros2_info = status["ros2_specific"]
        assert "node_name" in ros2_info
        assert "namespace" in ros2_info
        assert "security_level" in ros2_info
        assert ros2_info["node_name"] == "test_alcub3_security"
        assert ros2_info["namespace"] == "/test"

    @pytest.mark.asyncio
    async def test_ros2_telemetry_collection(self, ros2_bridge, ros2_config):
        """Test ROS2 telemetry collection."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Collect telemetry
        telemetry = await ros2_bridge._collect_ros2_telemetry()
        
        # Verify telemetry structure
        assert "active_nodes" in telemetry
        assert "node_status" in telemetry
        assert "topic_statistics" in telemetry
        assert "service_statistics" in telemetry
        assert "security_violations" in telemetry
        assert "classification_level" in telemetry
        
        # Verify classification level is properly serialized
        assert telemetry["classification_level"] == ClassificationLevel.UNCLASSIFIED.value
        
        # Verify performance tracking
        assert len(ros2_bridge.performance_metrics["telemetry_collection_times"]) > 0

    @pytest.mark.asyncio
    async def test_ros2_navigation_command_validation(self, ros2_bridge, ros2_config):
        """Test ROS2 navigation command validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test valid navigation command
        valid_nav_command = SecurityCommand(
            command_id="nav_valid_test",
            robot_id="test_ros2_01",
            command_type="navigate_to_goal",
            parameters={
                "goal": {
                    "position": {"x": 5.0, "y": 3.0, "z": 0.0},
                    "orientation": {"w": 1.0, "x": 0.0, "y": 0.0, "z": 0.0}
                }
            },
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(valid_nav_command)
        assert valid == True
        
        # Test invalid navigation command (missing goal)
        invalid_nav_command = SecurityCommand(
            command_id="nav_invalid_test",
            robot_id="test_ros2_01",
            command_type="navigate_to_goal",
            parameters={"invalid": "params"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(invalid_nav_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_ros2_trajectory_command_validation(self, ros2_bridge, ros2_config):
        """Test ROS2 trajectory command validation."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test valid trajectory command
        valid_traj_command = SecurityCommand(
            command_id="traj_valid_test",
            robot_id="test_ros2_01",
            command_type="execute_trajectory",
            parameters={
                "trajectory": [
                    {"position": {"x": 1.0, "y": 0.0, "z": 0.0}, "time": 1.0},
                    {"position": {"x": 2.0, "y": 1.0, "z": 0.0}, "time": 2.0},
                    {"position": {"x": 3.0, "y": 2.0, "z": 0.0}, "time": 3.0}
                ]
            },
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(valid_traj_command)
        assert valid == True
        
        # Test invalid trajectory command (empty trajectory)
        invalid_traj_command = SecurityCommand(
            command_id="traj_invalid_test",
            robot_id="test_ros2_01",
            command_type="execute_trajectory",
            parameters={"trajectory": []},  # Empty trajectory
            classification_level=ClassificationLevel.UNCLASSIFIED,
            issued_by="test_operator",
            timestamp=datetime.utcnow()
        )
        
        valid = await ros2_bridge.validate_command(invalid_traj_command)
        assert valid == False

    @pytest.mark.asyncio
    async def test_ros2_heartbeat_functionality(self, ros2_bridge, ros2_config):
        """Test ROS2 heartbeat functionality."""
        # Initialize bridge
        async def mock_validate_env():
            return True
        ros2_bridge._validate_ros2_environment = mock_validate_env
        await ros2_bridge.initialize_ros2_connection(ros2_config)
        
        # Test heartbeat
        success = await ros2_bridge.send_heartbeat()
        assert success == True
        
        # Verify heartbeat data structure would be sent to MAESTRO
        # (In real implementation, this would be sent to monitoring endpoint)

    def test_ros2_performance_metrics_tracking(self, ros2_bridge):
        """Test ROS2 performance metrics tracking."""
        # Test average calculation
        test_values = [10.0, 20.0, 30.0]
        avg = ros2_bridge._calculate_average(test_values)
        assert avg == 20.0
        
        # Test empty values
        empty_avg = ros2_bridge._calculate_average([])
        assert empty_avg == 0.0
        
        # Verify all performance metric categories exist
        expected_metrics = [
            "command_validation_times",
            "sros2_policy_times", 
            "node_launch_times",
            "emergency_stop_times",
            "telemetry_collection_times"
        ]
        
        for metric in expected_metrics:
            assert metric in ros2_bridge.performance_metrics

    def test_ros2_security_metrics_tracking(self, ros2_bridge):
        """Test ROS2 security metrics tracking."""
        # Verify all security metric categories exist
        expected_metrics = [
            "commands_validated",
            "commands_rejected",
            "sros2_violations",
            "node_security_checks",
            "emergency_stops",
            "security_violations",
            "classification_checks"
        ]
        
        for metric in expected_metrics:
            assert metric in ros2_bridge.security_metrics
            assert ros2_bridge.security_metrics[metric] == 0  # Initial state

    def test_ros2_command_type_enum_validation(self):
        """Test ROS2 command type enum validation."""
        # Test all valid command types
        valid_types = [
            "publish_message", "call_service", "set_parameter", "launch_node",
            "kill_node", "start_recording", "stop_recording", "emergency_stop",
            "set_transform", "navigate_to_goal", "execute_trajectory"
        ]
        
        for cmd_type in valid_types:
            try:
                ros2_cmd = ROS2CommandType(cmd_type)
                assert ros2_cmd.value == cmd_type
            except ValueError:
                pytest.fail(f"Valid ROS2 command type {cmd_type} should not raise ValueError")
        
        # Test invalid command type
        with pytest.raises(ValueError):
            ROS2CommandType("invalid_command_type")

    def test_sros2_security_level_enum(self):
        """Test SROS2 security level enum validation."""
        valid_levels = ["basic", "enhanced", "defense_grade", "classified"]
        
        for level in valid_levels:
            try:
                sros2_level = SROS2SecurityLevel(level)
                assert sros2_level.value == level
            except ValueError:
                pytest.fail(f"Valid SROS2 security level {level} should not raise ValueError")

    def test_ros2_node_security_profile_creation(self):
        """Test ROS2 node security profile creation."""
        profile = ROS2NodeSecurityProfile(
            node_name="test_node",
            namespace="/test",
            security_level=SROS2SecurityLevel.ENHANCED,
            allowed_topics={"/cmd_vel", "/scan"},
            allowed_services={"/global_localization"},
            allowed_parameters={"use_sim_time"}
        )
        
        assert profile.node_name == "test_node"
        assert profile.namespace == "/test"
        assert profile.security_level == SROS2SecurityLevel.ENHANCED
        assert "/cmd_vel" in profile.allowed_topics
        assert "/global_localization" in profile.allowed_services
        assert "use_sim_time" in profile.allowed_parameters
        assert profile.encryption_required == True  # Default value
        assert profile.authentication_required == True  # Default value

if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])