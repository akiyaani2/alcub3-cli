#!/usr/bin/env python3
"""
ALCUB3 Universal Security HAL Test Suite
Comprehensive testing for MAESTRO robotics integration
"""

import asyncio
import pytest
import time
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch

# Import test targets
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "maestro-robotics"))

from core.universal_hal import (
    UniversalSecurityHAL, FleetCoordinationMode, EmergencyResponseLevel
)
from core.platform_adapter import (
    PlatformType, CommandType, ClassificationLevel, SecurityState
)
from adapters.boston_dynamics import BostonDynamicsAdapter
from adapters.ros2 import ROS2Adapter
from adapters.dji import DJIAdapter


class TestUniversalSecurityHAL:
    """Test Universal Security HAL core functionality."""
    
    @pytest.fixture
    async def hal(self):
        """Create HAL instance for testing."""
        hal = UniversalSecurityHAL(
            classification_level=ClassificationLevel.TOP_SECRET
        )
        yield hal
        await hal.shutdown()
    
    @pytest.fixture
    async def registered_hal(self, hal):
        """HAL with registered test robots."""
        # Register test robots
        await hal.register_robot(
            "test_spot",
            PlatformType.BOSTON_DYNAMICS,
            ClassificationLevel.SECRET,
            {"robot_ip": "test"}
        )
        
        await hal.register_robot(
            "test_ros",
            PlatformType.ROS2,
            ClassificationLevel.CUI,
            {"dds_domain": 0}
        )
        
        await hal.register_robot(
            "test_drone",
            PlatformType.DJI,
            ClassificationLevel.UNCLASSIFIED,
            {"drone_ip": "test"}
        )
        
        return hal
    
    @pytest.mark.asyncio
    async def test_hal_initialization(self, hal):
        """Test HAL initializes correctly."""
        assert hal.classification_level == ClassificationLevel.TOP_SECRET
        assert len(hal.robots) == 0
        assert hal.security_metrics["total_robots"] == 0
        assert not hal.fleet_state["emergency_active"]
    
    @pytest.mark.asyncio
    async def test_robot_registration(self, hal):
        """Test robot registration process."""
        # Register Boston Dynamics Spot
        success = await hal.register_robot(
            "spot_001",
            PlatformType.BOSTON_DYNAMICS,
            ClassificationLevel.SECRET,
            {"robot_ip": "192.168.1.100", "username": "admin"}
        )
        
        assert success
        assert "spot_001" in hal.robots
        assert hal.security_metrics["total_robots"] == 1
        assert hal.security_metrics["platform_distribution"]["boston_dynamics"] == 1
        
        # Verify registration details
        registration = hal.robots["spot_001"]
        assert registration.platform_type == PlatformType.BOSTON_DYNAMICS
        assert registration.classification_level == ClassificationLevel.SECRET
        assert registration.security_state == SecurityState.SECURE
    
    @pytest.mark.asyncio
    async def test_duplicate_registration_fails(self, hal):
        """Test duplicate robot registration is rejected."""
        # First registration
        await hal.register_robot(
            "robot_001",
            PlatformType.ROS2,
            ClassificationLevel.UNCLASSIFIED,
            {"dds_domain": 0}
        )
        
        # Duplicate registration should fail
        success = await hal.register_robot(
            "robot_001",
            PlatformType.ROS2,
            ClassificationLevel.UNCLASSIFIED,
            {"dds_domain": 0}
        )
        
        assert not success
        assert hal.security_metrics["total_robots"] == 1
    
    @pytest.mark.asyncio
    async def test_command_execution(self, registered_hal):
        """Test secure command execution."""
        hal = registered_hal
        
        # Execute movement command
        success, result = await hal.execute_command(
            robot_id="test_spot",
            command_type="stand",
            parameters={},
            issuer_id="operator_001",
            issuer_clearance=ClassificationLevel.SECRET
        )
        
        assert success
        assert result is not None
        assert result.success
        assert result.execution_time_ms < 1000  # Should be fast
        
        # Verify metrics updated
        assert hal.security_metrics["total_commands"] > 0
        assert hal.security_metrics["successful_commands"] > 0
    
    @pytest.mark.asyncio
    async def test_classification_enforcement(self, registered_hal):
        """Test classification-based access control."""
        hal = registered_hal
        
        # Try to execute SECRET command with UNCLASSIFIED clearance
        success, result = await hal.execute_command(
            robot_id="test_spot",
            command_type="navigate",
            parameters={"waypoints": [{"x": 10, "y": 10}]},
            issuer_id="operator_002",
            issuer_clearance=ClassificationLevel.UNCLASSIFIED,
            classification=ClassificationLevel.SECRET
        )
        
        assert not success  # Should fail due to insufficient clearance
        assert hal.security_metrics["failed_commands"] > 0
    
    @pytest.mark.asyncio
    async def test_fleet_command_synchronized(self, registered_hal):
        """Test synchronized fleet command execution."""
        hal = registered_hal
        
        # Execute fleet-wide stand command
        fleet_command = await hal.execute_fleet_command(
            target_robots=["test_spot", "test_ros"],
            command_type="emergency_stop",
            parameters={},
            coordination_mode=FleetCoordinationMode.SYNCHRONIZED,
            issuer_id="operator_001",
            issuer_clearance=ClassificationLevel.SECRET
        )
        
        assert fleet_command.command_id.startswith("FLEET_")
        assert len(fleet_command.execution_results) == 2
        
        # Check results for each robot
        for robot_id, result in fleet_command.execution_results.items():
            assert result.success or result.error_message is not None
    
    @pytest.mark.asyncio
    async def test_emergency_stop_single_robot(self, registered_hal):
        """Test emergency stop on single robot."""
        hal = registered_hal
        start_time = time.time()
        
        # Execute emergency stop
        results = await hal.emergency_stop(
            target="test_spot",
            reason="test_emergency",
            response_level=EmergencyResponseLevel.LOCAL
        )
        
        stop_time = (time.time() - start_time) * 1000
        
        assert "test_spot" in results
        assert results["test_spot"]  # Should succeed
        assert stop_time < 100  # Should be under 100ms
        assert hal.security_metrics["emergency_stops"] == 1
        
        # Verify robot state
        registration = hal.robots["test_spot"]
        assert registration.security_state == SecurityState.EMERGENCY_STOP
    
    @pytest.mark.asyncio
    async def test_emergency_stop_fleet_wide(self, registered_hal):
        """Test fleet-wide emergency stop."""
        hal = registered_hal
        
        # Execute fleet-wide emergency stop
        results = await hal.emergency_stop(
            target=None,  # None means entire fleet
            reason="fleet_emergency",
            response_level=EmergencyResponseLevel.FLEET
        )
        
        assert len(results) == 3  # All three robots
        assert all(results.values())  # All should succeed
        
        # Verify all robots are in emergency stop state
        for robot_id, registration in hal.robots.items():
            assert registration.security_state == SecurityState.EMERGENCY_STOP
    
    @pytest.mark.asyncio
    async def test_fleet_status_reporting(self, registered_hal):
        """Test fleet status reporting."""
        hal = registered_hal
        
        status = await hal.get_fleet_status()
        
        assert status["fleet_size"] == 3
        assert status["active_robots"] == 3
        assert "robot_statuses" in status
        assert len(status["robot_statuses"]) == 3
        
        # Check individual robot status
        for robot_id, robot_status in status["robot_statuses"].items():
            assert "platform_type" in robot_status
            assert "classification" in robot_status
            assert "security_state" in robot_status
            assert robot_status["is_active"]
    
    @pytest.mark.asyncio
    async def test_performance_targets(self, registered_hal):
        """Test performance meets targets."""
        hal = registered_hal
        
        # Measure command validation time
        validation_times = []
        
        for i in range(10):
            start = time.time()
            success, result = await hal.execute_command(
                robot_id="test_spot",
                command_type="stand",
                parameters={},
                issuer_id="operator_001",
                issuer_clearance=ClassificationLevel.SECRET
            )
            validation_times.append((time.time() - start) * 1000)
        
        # Average should be under 100ms
        avg_time = sum(validation_times) / len(validation_times)
        assert avg_time < 100, f"Average validation time {avg_time}ms exceeds 100ms target"
    
    @pytest.mark.asyncio
    async def test_heartbeat_timeout(self, registered_hal):
        """Test robot heartbeat timeout detection."""
        hal = registered_hal
        
        # Manually set old heartbeat
        from datetime import timedelta
        old_time = datetime.utcnow() - timedelta(seconds=120)
        hal.robots["test_spot"].last_heartbeat = old_time
        
        # Get fleet status
        status = await hal.get_fleet_status()
        
        # Robot should be marked as inactive
        assert not status["robot_statuses"]["test_spot"]["is_active"]
        assert status["active_robots"] == 2  # Only 2 active now


class TestPlatformAdapters:
    """Test platform-specific adapters."""
    
    @pytest.mark.asyncio
    async def test_boston_dynamics_adapter(self):
        """Test Boston Dynamics adapter functionality."""
        adapter = BostonDynamicsAdapter(
            "bd_test",
            ClassificationLevel.SECRET
        )
        
        # Test connection
        connected = await adapter.connect_platform({
            "robot_ip": "test",
            "username": "test"
        })
        assert connected
        
        # Test capabilities
        assert "walk" in adapter.capabilities
        assert "emergency_stop" in adapter.capabilities
        
        # Test platform status
        status = await adapter.get_platform_status()
        assert status["connected"]
        assert "battery_percent" in status
    
    @pytest.mark.asyncio
    async def test_ros2_adapter(self):
        """Test ROS2 adapter functionality."""
        adapter = ROS2Adapter(
            "ros2_test",
            ClassificationLevel.CUI,
            namespace="/test"
        )
        
        # Test connection
        connected = await adapter.connect_platform({
            "dds_domain": 0,
            "sros2_enabled": True
        })
        assert connected
        
        # Test capabilities
        assert "publish_twist" in adapter.capabilities
        assert "call_move_service" in adapter.capabilities
        
        # Test topic security
        assert "/cmd_vel" in adapter.topic_security
    
    @pytest.mark.asyncio
    async def test_dji_adapter(self):
        """Test DJI drone adapter functionality."""
        adapter = DJIAdapter(
            "dji_test",
            ClassificationLevel.UNCLASSIFIED,
            drone_model="matrice_300"
        )
        
        # Test connection
        connected = await adapter.connect_platform({
            "connection_type": "wifi",
            "drone_ip": "test"
        })
        assert connected
        
        # Test capabilities
        assert "takeoff" in adapter.capabilities
        assert "capture_photo" in adapter.capabilities
        
        # Test flight restrictions
        restrictions = adapter.flight_restrictions[ClassificationLevel.UNCLASSIFIED]
        assert restrictions["max_altitude_m"] == 120  # FAA limit


class TestSecurityFeatures:
    """Test security-specific features."""
    
    @pytest.mark.asyncio
    async def test_policy_enforcement(self):
        """Test security policy enforcement."""
        hal = UniversalSecurityHAL()
        
        # Register robot
        await hal.register_robot(
            "policy_test",
            PlatformType.BOSTON_DYNAMICS,
            ClassificationLevel.SECRET,
            {"robot_ip": "test"}
        )
        
        # Test policy violations are caught
        with patch.object(hal.policy_engine, 'evaluate_command') as mock_eval:
            # Mock policy violation
            mock_result = Mock()
            mock_result.allowed = False
            mock_result.risk_score = 0.9
            mock_eval.return_value = mock_result
            
            success, result = await hal.execute_command(
                robot_id="policy_test",
                command_type="walk",
                parameters={"velocity_mps": 5},  # High speed
                issuer_id="operator_001",
                issuer_clearance=ClassificationLevel.SECRET
            )
            
            assert not success
            assert hal.security_metrics["policy_violations"] > 0
    
    @pytest.mark.asyncio 
    async def test_threat_detection(self):
        """Test threat detection in commands."""
        hal = UniversalSecurityHAL()
        
        # Register robot
        await hal.register_robot(
            "threat_test",
            PlatformType.DJI,
            ClassificationLevel.SECRET,
            {"drone_ip": "test"}
        )
        
        # Test threat detection
        with patch.object(hal.command_validator.threat_detector, 'analyze_robotics_command') as mock_threat:
            # Mock threat detection
            threat_result = Mock()
            threat_result.threat_detected = True
            threat_result.threat_type = "command_injection"
            threat_result.confidence = 0.95
            mock_threat.return_value = threat_result
            
            success, result = await hal.execute_command(
                robot_id="threat_test",
                command_type="goto",
                parameters={"location": {"lat": 0, "lon": 0}},
                issuer_id="suspicious_operator",
                issuer_clearance=ClassificationLevel.SECRET
            )
            
            assert not success


class TestPerformanceOptimization:
    """Test performance optimization features."""
    
    @pytest.mark.asyncio
    async def test_command_caching(self):
        """Test command validation caching."""
        hal = UniversalSecurityHAL()
        
        # Register robot
        await hal.register_robot(
            "cache_test",
            PlatformType.ROS2,
            ClassificationLevel.UNCLASSIFIED,
            {"dds_domain": 0}
        )
        
        # Execute same command multiple times
        command_params = {
            "robot_id": "cache_test",
            "command_type": "publish_twist",
            "parameters": {"linear_x": 1.0},
            "issuer_id": "operator_001",
            "issuer_clearance": ClassificationLevel.UNCLASSIFIED
        }
        
        # First execution (cache miss)
        start1 = time.time()
        await hal.execute_command(**command_params)
        time1 = (time.time() - start1) * 1000
        
        # Second execution (cache hit)
        start2 = time.time()
        await hal.execute_command(**command_params)
        time2 = (time.time() - start2) * 1000
        
        # Cache hit should be faster
        assert time2 < time1 * 0.5  # At least 50% faster
    
    @pytest.mark.asyncio
    async def test_parallel_fleet_execution(self):
        """Test parallel execution of fleet commands."""
        hal = UniversalSecurityHAL()
        
        # Register multiple robots
        for i in range(5):
            await hal.register_robot(
                f"parallel_test_{i}",
                PlatformType.BOSTON_DYNAMICS,
                ClassificationLevel.UNCLASSIFIED,
                {"robot_ip": f"test_{i}"}
            )
        
        # Execute fleet command
        start = time.time()
        fleet_command = await hal.execute_fleet_command(
            target_robots=[f"parallel_test_{i}" for i in range(5)],
            command_type="stand",
            parameters={},
            coordination_mode=FleetCoordinationMode.SYNCHRONIZED,
            issuer_id="operator_001",
            issuer_clearance=ClassificationLevel.UNCLASSIFIED
        )
        total_time = (time.time() - start) * 1000
        
        # Should complete quickly despite 5 robots
        assert total_time < 500  # Less than 500ms for 5 robots
        assert len(fleet_command.execution_results) == 5


@pytest.mark.asyncio
async def test_integration_scenario():
    """Test complete integration scenario."""
    hal = UniversalSecurityHAL(ClassificationLevel.TOP_SECRET)
    
    try:
        # 1. Register diverse robot fleet
        robots = [
            ("spot_alpha", PlatformType.BOSTON_DYNAMICS, ClassificationLevel.SECRET),
            ("ros_bot_1", PlatformType.ROS2, ClassificationLevel.CUI),
            ("drone_1", PlatformType.DJI, ClassificationLevel.UNCLASSIFIED)
        ]
        
        for robot_id, platform, classification in robots:
            success = await hal.register_robot(
                robot_id, platform, classification,
                {"test": True}
            )
            assert success
        
        # 2. Execute individual commands
        success, result = await hal.execute_command(
            "spot_alpha", "stand", {},
            "operator_001", ClassificationLevel.SECRET
        )
        assert success
        
        # 3. Execute fleet command
        fleet_cmd = await hal.execute_fleet_command(
            ["spot_alpha", "ros_bot_1"],
            "emergency_stop", {},
            FleetCoordinationMode.SYNCHRONIZED,
            "operator_001", ClassificationLevel.SECRET
        )
        assert len(fleet_cmd.execution_results) == 2
        
        # 4. Check fleet status
        status = await hal.get_fleet_status()
        assert status["fleet_size"] == 3
        
        # 5. Emergency stop
        results = await hal.emergency_stop(reason="test_complete")
        assert len(results) == 3
        
    finally:
        await hal.shutdown()


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])