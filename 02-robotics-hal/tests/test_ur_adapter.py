#!/usr/bin/env python3
"""
Test suite for Universal Robots adapter
Task 2.30 - Phase 1 validation
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add paths for imports
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "adapters"))
sys.path.append(str(Path(__file__).parent.parent / "core"))
sys.path.append(str(Path(__file__).parent.parent.parent / "02-security-maestro" / "src"))

from ur_adapter import (
    UniversalRobotsAdapter, URModel, URSafetyMode, 
    URProgramState, URStatus, URScriptBuilder
)
from platform_adapter import SecureCommand, CommandType, SecurityState
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger


class TestURScriptBuilder:
    """Test URScript command generation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.safety_limits = {
            "max_joint_velocity": 3.14,
            "max_joint_acceleration": 3.14,
            "max_tcp_velocity": 1.0,
            "max_tcp_acceleration": 1.0,
            "joint_0_min": -360,
            "joint_0_max": 360,
            "tcp_x_min": -2.0,
            "tcp_x_max": 2.0,
            "tcp_y_min": -2.0,
            "tcp_y_max": 2.0,
            "tcp_z_min": -2.0,
            "tcp_z_max": 2.0,
        }
        self.builder = URScriptBuilder(self.safety_limits)
    
    def test_move_joint_command(self):
        """Test joint movement command generation."""
        positions = [0, -1.57, 1.57, -1.57, -1.57, 0]
        script = self.builder.move_j(positions, acceleration=1.0, velocity=0.5)
        
        assert "movej([0, -1.57, 1.57, -1.57, -1.57, 0]" in script
        assert "a=1.0" in script
        assert "v=0.5" in script
    
    def test_move_joint_safety_limits(self):
        """Test joint movement safety validation."""
        # Test exceeding joint limits
        positions = [400, 0, 0, 0, 0, 0]  # Exceeds 360 degree limit
        
        with pytest.raises(ValueError) as exc_info:
            self.builder.move_j(positions)
        
        assert "exceeds limits" in str(exc_info.value)
    
    def test_move_linear_command(self):
        """Test linear movement command generation."""
        tcp_pose = [0.5, 0.0, 0.3, 0.0, 3.14, 0.0]
        script = self.builder.move_l(tcp_pose, acceleration=0.5, velocity=0.1)
        
        assert "movel(p[0.5, 0.0, 0.3, 0.0, 3.14, 0.0]" in script
        assert "a=0.5" in script
        assert "v=0.1" in script
    
    def test_velocity_limiting(self):
        """Test automatic velocity limiting."""
        positions = [0, 0, 0, 0, 0, 0]
        # Request velocity above limit
        script = self.builder.move_j(positions, velocity=5.0)  # Above 3.14 limit
        
        # Should be clamped to max
        assert "v=3.14" in script
    
    def test_digital_output_command(self):
        """Test digital output command."""
        script = self.builder.set_digital_output(3, True)
        assert "set_digital_out(3, True)" in script
        
        # Test invalid pin
        with pytest.raises(ValueError):
            self.builder.set_digital_output(10, True)
    
    def test_protective_stop_command(self):
        """Test protective stop command."""
        script = self.builder.protective_stop()
        assert "stopj(2.0)" in script


class TestUniversalRobotsAdapter:
    """Test Universal Robots adapter functionality."""
    
    @pytest.fixture
    def audit_logger(self):
        """Create mock audit logger."""
        return Mock(spec=AuditLogger)
    
    @pytest.fixture
    def adapter(self, audit_logger):
        """Create UR adapter instance."""
        return UniversalRobotsAdapter(
            robot_id="UR_TEST_001",
            model=URModel.UR5e,
            classification_level=ClassificationLevel.SECRET,
            audit_logger=audit_logger
        )
    
    @pytest.mark.asyncio
    async def test_adapter_initialization(self, adapter):
        """Test adapter initialization."""
        assert adapter.robot_id == "UR_TEST_001"
        assert adapter.model == URModel.UR5e
        assert adapter.classification_level == ClassificationLevel.SECRET
        assert adapter.platform_type.value == "industrial_robot"
        assert not adapter.is_connected
    
    @pytest.mark.asyncio
    async def test_connect_simulator(self, adapter, audit_logger):
        """Test connecting to UR simulator."""
        connection_params = {
            "ip_address": "192.168.1.100",
            "use_simulator": True
        }
        
        result = await adapter.connect_platform(connection_params)
        
        assert result is True
        assert adapter.is_connected
        assert adapter.security_state == SecurityState.SECURE
        assert adapter.robot_ip == "192.168.1.100"
        
        # Verify audit log
        audit_logger.log_event.assert_called()
    
    @pytest.mark.asyncio
    async def test_connect_real_robot(self, adapter, audit_logger):
        """Test connecting to real UR robot."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket.recv.return_value = b"Universal Robots Dashboard\n"
            mock_socket_class.return_value = mock_socket
            
            connection_params = {
                "ip_address": "192.168.1.100",
                "use_simulator": False
            }
            
            result = await adapter.connect_platform(connection_params)
            
            assert result is True
            assert adapter.is_connected
            assert mock_socket.connect.called
    
    @pytest.mark.asyncio
    async def test_move_joint_command_translation(self, adapter):
        """Test translating move joint command."""
        secure_command = SecureCommand(
            command_id="CMD_001",
            platform_command="move_joint",
            command_type=CommandType.MOVEMENT,
            parameters={
                "joint_positions": [0, -1.57, 1.57, -1.57, -1.57, 0],
                "velocity": 0.5,
                "acceleration": 1.0
            },
            classification=ClassificationLevel.UNCLASSIFIED,
            issuer_id="operator_1",
            issuer_clearance=ClassificationLevel.SECRET,
            timestamp=datetime.utcnow()
        )
        
        success, command = await adapter.translate_command(secure_command)
        
        assert success is True
        assert "urscript" in command
        assert "movej([0, -1.57, 1.57, -1.57, -1.57, 0]" in command["urscript"]
    
    @pytest.mark.asyncio
    async def test_emergency_stop_translation(self, adapter):
        """Test emergency stop command translation."""
        secure_command = SecureCommand(
            command_id="CMD_002",
            platform_command="emergency_stop",
            command_type=CommandType.EMERGENCY,
            parameters={},
            classification=ClassificationLevel.UNCLASSIFIED,
            issuer_id="operator_1",
            issuer_clearance=ClassificationLevel.SECRET,
            timestamp=datetime.utcnow()
        )
        
        success, command = await adapter.translate_command(secure_command)
        
        assert success is True
        assert "dashboard_command" in command
        assert command["dashboard_command"] == "stop"
    
    @pytest.mark.asyncio
    async def test_execute_urscript_simulated(self, adapter):
        """Test executing URScript in simulator mode."""
        platform_command = {
            "urscript": "movej([0, 0, 0, 0, 0, 0], a=1.0, v=0.5)"
        }
        
        result = await adapter.execute_platform_command(platform_command)
        
        assert result.success is True
        assert result.execution_time_ms > 0
        assert result.execution_time_ms < 1000  # Should be fast in sim mode
        assert "simulated" in result.platform_response
    
    @pytest.mark.asyncio
    async def test_get_platform_status(self, adapter):
        """Test getting robot status."""
        status = await adapter.get_platform_status()
        
        assert "model" in status
        assert status["model"] == "ur5e"
        assert "safety_mode" in status
        assert "tcp_position" in status
        assert "joint_positions" in status
        assert len(status["joint_positions"]) == 6
    
    @pytest.mark.asyncio
    async def test_emergency_stop(self, adapter, audit_logger):
        """Test emergency stop functionality."""
        # Set up adapter as connected
        adapter.is_connected = True
        adapter.dashboard_socket = MagicMock()
        adapter.dashboard_socket.recv.return_value = b"stopped\n"
        
        result = await adapter.emergency_stop()
        
        assert result is True
        assert adapter.security_state == SecurityState.EMERGENCY_STOP
        audit_logger.log_event.assert_called_with(
            "UR_EMERGENCY_STOP",
            {
                "robot_id": "UR_TEST_001",
                "timestamp": pytest.approx(datetime.utcnow().isoformat(), abs=2)
            }
        )
    
    @pytest.mark.asyncio
    async def test_capabilities_initialization(self, adapter):
        """Test capability definitions."""
        capabilities = adapter.capabilities
        
        # Check movement capabilities
        assert "move_joint" in capabilities
        assert capabilities["move_joint"].command_type == CommandType.MOVEMENT
        assert capabilities["move_joint"].risk_level == 3
        
        # Check safety capabilities
        assert "emergency_stop" in capabilities
        assert capabilities["emergency_stop"].command_type == CommandType.EMERGENCY
        assert capabilities["emergency_stop"].requires_authorization is False
        
        # Check I/O capabilities
        assert "set_digital_output" in capabilities
        assert capabilities["set_digital_output"].command_type == CommandType.ACTUATOR
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, adapter):
        """Test performance metric tracking."""
        # Execute some commands to generate metrics
        for _ in range(5):
            await adapter.execute_platform_command({
                "urscript": "movej([0, 0, 0, 0, 0, 0])"
            })
        
        metrics = adapter.get_performance_metrics()
        
        assert "average_latency_ms" in metrics
        assert "max_latency_ms" in metrics
        assert "commands_executed" in metrics
        assert metrics["commands_executed"] == 5
        assert metrics["average_latency_ms"] > 0
        assert metrics["max_latency_ms"] >= metrics["average_latency_ms"]
    
    @pytest.mark.asyncio
    async def test_disconnect(self, adapter, audit_logger):
        """Test disconnecting from robot."""
        # Set up as connected
        adapter.is_connected = True
        adapter.dashboard_socket = MagicMock()
        adapter.realtime_socket = MagicMock()
        
        result = await adapter.disconnect_platform()
        
        assert result is True
        assert not adapter.is_connected
        assert adapter.security_state == SecurityState.DISCONNECTED
        audit_logger.log_event.assert_called_with(
            "UR_ROBOT_DISCONNECTED",
            {"robot_id": "UR_TEST_001"}
        )
    
    @pytest.mark.asyncio
    async def test_invalid_command_translation(self, adapter):
        """Test handling invalid command types."""
        secure_command = SecureCommand(
            command_id="CMD_003",
            platform_command="invalid_command",
            command_type=CommandType.MOVEMENT,
            parameters={},
            classification=ClassificationLevel.UNCLASSIFIED,
            issuer_id="operator_1",
            issuer_clearance=ClassificationLevel.SECRET,
            timestamp=datetime.utcnow()
        )
        
        success, command = await adapter.translate_command(secure_command)
        
        assert success is False
        assert command is None
    
    @pytest.mark.asyncio
    async def test_model_specific_limits(self):
        """Test model-specific safety limits."""
        # Test different models have different limits
        ur3_adapter = UniversalRobotsAdapter(
            "UR3_TEST",
            URModel.UR3e,
            ClassificationLevel.UNCLASSIFIED,
            Mock()
        )
        
        ur30_adapter = UniversalRobotsAdapter(
            "UR30_TEST",
            URModel.UR30,
            ClassificationLevel.UNCLASSIFIED,
            Mock()
        )
        
        assert ur3_adapter.safety_limits["reach"] == 0.5
        assert ur3_adapter.safety_limits["payload"] == 3.0
        
        assert ur30_adapter.safety_limits["reach"] == 1.3
        assert ur30_adapter.safety_limits["payload"] == 30.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])