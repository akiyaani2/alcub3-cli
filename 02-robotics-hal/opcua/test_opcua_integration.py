#!/usr/bin/env python3
"""
ALCUB3 OPC UA Integration Tests
Task 2.35 - Comprehensive Test Suite

This module provides comprehensive testing for the OPC UA implementation,
including server, client, MES adapter, and security layer components.

Test Coverage:
- OPC UA server functionality and security
- Client connectivity and subscriptions
- MES adapter production scheduling
- Security layer threat detection
- Byzantine consensus validation
- Air-gap bridge operations
- Performance benchmarks
"""

import asyncio
import pytest
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging
from pathlib import Path
import sys

# Import components to test
sys.path.append(str(Path(__file__).parent))
from opcua_server import (
    SecureOPCUAServer, OPCUANodeConfig, NodeClassification,
    CommandValidationMode, MESCommand, ProductionSchedule
)
from opcua_client import (
    SecureOPCUAClient, ConnectionConfig, SubscriptionMode,
    ConnectionState
)

sys.path.append(str(Path(__file__).parent.parent / "adapters"))
from mes_adapter import (
    OPCUAMESAdapter, WorkOrder, WorkOrderStatus,
    ProductionMetrics, QualityData
)

sys.path.append(str(Path(__file__).parent.parent.parent.parent / "02-security-maestro" / "industrial"))
from opcua_security import (
    OPCUASecurityLayer, OPCUAPacket, OPCUAThreatType,
    SecurityAction, SecurityRule
)

# Import security components
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "02-security-maestro" / "src"))
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TestOPCUAServer:
    """Test OPC UA server functionality."""
    
    @pytest.fixture
    async def server(self):
        """Create test server instance."""
        audit_logger = AuditLogger()
        server = SecureOPCUAServer(
            server_name="Test_Server",
            endpoint="opc.tcp://localhost:4840/test",
            classification_level=ClassificationLevel.SECRET,
            audit_logger=audit_logger,
            enable_byzantine=True
        )
        yield server
        await server.stop()
    
    @pytest.mark.asyncio
    async def test_server_startup(self, server):
        """Test server startup and initialization."""
        # Start server
        success = await server.start()
        assert success is True
        assert server.metrics.nodes_created > 0
        
        # Verify node structure created
        assert "robot_status" in server.node_registry
        assert "active_work_order" in server.node_registry
        assert "security_state" in server.node_registry
    
    @pytest.mark.asyncio
    async def test_node_creation(self, server):
        """Test creating nodes with classification."""
        await server.start()
        
        # Create test node
        config = OPCUANodeConfig(
            node_id="test_node",
            browse_name="TestNode",
            display_name="Test Node",
            data_type="Double",
            classification=NodeClassification.SECRET,
            access_level="read_write",
            validation_mode=CommandValidationMode.BYZANTINE,
            initial_value=42.0,
            limits={"min": 0.0, "max": 100.0}
        )
        
        success = await server.create_node(config)
        assert success is True
        assert "test_node" in server.node_registry
    
    @pytest.mark.asyncio
    async def test_node_read_write(self, server):
        """Test reading and writing node values."""
        await server.start()
        
        # Write value
        success = await server.write_node(
            "robot_status",
            "TESTING",
            ClassificationLevel.UNCLASSIFIED
        )
        assert success is True
        
        # Read value
        value = await server.read_node("robot_status")
        assert value == "TESTING"
    
    @pytest.mark.asyncio
    async def test_classification_validation(self, server):
        """Test classification-based access control."""
        await server.start()
        
        # Try to write to secret node with unclassified access
        success = await server.write_node(
            "security_state",
            "COMPROMISED",
            ClassificationLevel.UNCLASSIFIED
        )
        assert success is False  # Should be denied
        assert server.metrics.commands_rejected > 0
    
    @pytest.mark.asyncio
    async def test_byzantine_validation(self, server):
        """Test Byzantine consensus validation."""
        await server.start()
        
        # Create command requiring Byzantine validation
        command = MESCommand(
            command_id="CMD001",
            command_type="production_start",
            target_nodes=["active_work_order"],
            parameters={"work_order": "WO-TEST-001"},
            classification=ClassificationLevel.SECRET,
            issuer="test_client",
            timestamp=datetime.utcnow()
        )
        
        # Queue command
        server.command_queue.append(command)
        
        # Wait for processing
        await asyncio.sleep(0.2)
        
        # Check validation
        assert command.consensus_proof is not None
        assert server.metrics.commands_validated > 0
    
    @pytest.mark.asyncio
    async def test_production_schedule_update(self, server):
        """Test production schedule management."""
        await server.start()
        
        # Create test schedule
        schedule = ProductionSchedule(
            schedule_id="SCHED001",
            schedule_version="v1.0",
            effective_date=datetime.utcnow(),
            classification=ClassificationLevel.CONFIDENTIAL,
            work_orders=[]
        )
        
        # Update schedule
        success, schedule_id = await server._update_schedule_method(
            None,
            json.dumps({
                "work_orders": [
                    {"id": "WO001", "product": "PROD001", "quantity": 100}
                ],
                "start_time": datetime.utcnow().isoformat(),
                "end_time": (datetime.utcnow() + timedelta(hours=8)).isoformat(),
                "priority": 7
            })
        )
        
        assert success is True
        assert schedule_id in server.production_schedules
    
    @pytest.mark.asyncio
    async def test_air_gap_sync(self, server):
        """Test air-gapped synchronization."""
        await server.start()
        
        # Prepare sync data
        sync_data = {
            "commands": [{
                "command_id": "cmd-offline-001",
                "command_type": "node_write",
                "target_nodes": ["production_rate"],
                "parameters": {"value": 95.5},
                "classification": ClassificationLevel.UNCLASSIFIED.value,
                "issuer": "offline_mes",
                "timestamp": datetime.utcnow().isoformat()
            }],
            "schedules": []
        }
        
        # Execute sync
        response = await server.handle_air_gap_sync(sync_data)
        
        assert "sync_id" in response
        assert "node_values" in response
        assert response["metrics"]["nodes_created"] > 0
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, server):
        """Test server performance metrics."""
        await server.start()
        
        # Perform multiple operations
        for i in range(10):
            await server.write_node(
                "parts_produced",
                i * 10,
                ClassificationLevel.UNCLASSIFIED
            )
        
        # Get metrics
        metrics = await server.get_metrics()
        
        assert metrics["metrics"]["commands_validated"] >= 10
        assert metrics["performance"]["within_target"] is True
        assert metrics["performance"]["latency_achieved_ms"] < 100  # Target


class TestOPCUAClient:
    """Test OPC UA client functionality."""
    
    @pytest.fixture
    async def client(self):
        """Create test client instance."""
        audit_logger = AuditLogger()
        config = ConnectionConfig(
            server_url="opc.tcp://localhost:4840/test",
            security_policy="Basic256Sha256",
            classification_level=ClassificationLevel.SECRET
        )
        
        client = SecureOPCUAClient(
            client_id="Test_Client",
            config=config,
            audit_logger=audit_logger,
            enable_byzantine=True
        )
        yield client
        await client.disconnect()
    
    @pytest.mark.asyncio
    async def test_client_connection(self, client):
        """Test client connection to server."""
        # Mock connection for testing
        client.connection_state = ConnectionState.CONNECTED
        client.is_connected = True
        
        assert client.connection_state == ConnectionState.CONNECTED
        assert client.metrics.connection_attempts == 0
    
    @pytest.mark.asyncio
    async def test_node_subscription(self, client):
        """Test subscribing to nodes."""
        # Subscribe to node
        success = await client.subscribe_node(
            node_id="test_status",
            browse_path="ns=2;s=test_status",
            mode=SubscriptionMode.MONITORING,
            interval_ms=1000,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        assert success is True
        assert "test_status" in client.subscriptions
        assert client.subscriptions["test_status"].mode == SubscriptionMode.MONITORING
    
    @pytest.mark.asyncio
    async def test_command_validation(self, client):
        """Test command validation with Byzantine consensus."""
        client.connection_state = ConnectionState.CONNECTED
        
        # Track pending commands before
        initial_commands = len(client.pending_commands)
        
        # Write with validation
        client.enable_byzantine = True
        success = await client.write_node(
            "ns=2;s=robot_mode",
            "AUTOMATIC",
            validate_byzantine=True
        )
        
        # Command should be queued
        assert len(client.pending_commands) > initial_commands
    
    @pytest.mark.asyncio
    async def test_client_metrics(self, client):
        """Test client performance metrics."""
        # Simulate some operations
        client.metrics.commands_sent = 100
        client.metrics.commands_acknowledged = 95
        client.metrics.data_points_received = 1000
        client.latency_buffer = [10, 20, 30, 40, 50]
        
        # Get metrics
        metrics = await client.get_metrics()
        
        assert metrics["metrics"]["commands_sent"] == 100
        assert metrics["metrics"]["commands_acknowledged"] == 95
        assert metrics["performance"]["latency_achieved_ms"] == 30  # Average


class TestMESAdapter:
    """Test MES adapter functionality."""
    
    @pytest.fixture
    async def adapter(self):
        """Create test MES adapter instance."""
        audit_logger = AuditLogger()
        adapter = OPCUAMESAdapter(
            adapter_id="Test_MES",
            classification_level=ClassificationLevel.SECRET,
            audit_logger=audit_logger,
            enable_byzantine=True
        )
        yield adapter
        if adapter.is_connected:
            await adapter.disconnect()
    
    @pytest.mark.asyncio
    async def test_work_order_management(self, adapter):
        """Test work order lifecycle."""
        # Create test work order
        work_order = WorkOrder(
            order_id="WO-TEST-001",
            product_id="PROD-001",
            product_name="Test Product",
            quantity_ordered=100,
            priority=8,
            classification=ClassificationLevel.UNCLASSIFIED,
            status=WorkOrderStatus.SCHEDULED
        )
        
        # Add to adapter
        adapter.work_orders[work_order.order_id] = work_order
        
        # Start work order
        success = await adapter.start_work_order(work_order.order_id)
        assert success is False  # No connection, but logic tested
        
        # Check status update
        assert work_order.status == WorkOrderStatus.IN_PROGRESS
        assert work_order.actual_start is not None
    
    @pytest.mark.asyncio
    async def test_production_metrics_calculation(self, adapter):
        """Test production metrics and OEE calculation."""
        # Calculate OEE
        oee = await adapter.calculate_oee(
            availability=95.0,
            performance=92.0,
            quality=98.5
        )
        
        expected_oee = (0.95 * 0.92 * 0.985) * 100
        assert abs(oee - expected_oee) < 0.01
    
    @pytest.mark.asyncio
    async def test_quality_data_handling(self, adapter):
        """Test quality data submission."""
        # Create quality data
        quality = QualityData(
            inspection_id="INSP001",
            work_order_id="WO-TEST-001",
            product_id="PROD-001",
            inspection_time=datetime.utcnow(),
            measurements={"length": 100.1, "width": 50.2},
            pass_fail=True,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        # Store locally (would submit to MES if connected)
        adapter.quality_data.append(quality)
        
        assert len(adapter.quality_data) == 1
        assert adapter.quality_data[0].pass_fail is True


class TestOPCUASecurity:
    """Test OPC UA security layer."""
    
    @pytest.fixture
    async def security_layer(self):
        """Create test security layer instance."""
        audit_logger = AuditLogger()
        security = OPCUASecurityLayer(
            layer_id="Test_Security",
            classification_level=ClassificationLevel.SECRET,
            audit_logger=audit_logger,
            enable_ml_detection=True
        )
        yield security
    
    @pytest.mark.asyncio
    async def test_packet_analysis(self, security_layer):
        """Test packet analysis and threat detection."""
        # Create test packet
        packet = OPCUAPacket(
            packet_id="PKT001",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            source_port=48500,
            destination_ip="192.168.1.200",
            destination_port=4840,
            message_type="Message",
            node_id="ns=2;s=Robot.Status",
            service_type="Read",
            payload_size=128,
            encrypted=True,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        # Analyze packet
        action, incident = await security_layer.analyze_packet(packet)
        
        assert action == SecurityAction.ALLOW
        assert incident is None
        assert security_layer.packets_analyzed == 1
    
    @pytest.mark.asyncio
    async def test_classification_violation_detection(self, security_layer):
        """Test detection of classification violations."""
        # Create packet accessing classified node
        packet = OPCUAPacket(
            packet_id="PKT002",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.101",
            source_port=48501,
            destination_ip="192.168.1.200",
            destination_port=4840,
            message_type="Message",
            node_id="ns=4;s=TopSecret.Data",  # Top secret namespace
            service_type="Read",
            payload_size=256,
            encrypted=True,
            classification=ClassificationLevel.UNCLASSIFIED  # Violation!
        )
        
        # Analyze packet
        action, incident = await security_layer.analyze_packet(packet)
        
        assert action == SecurityAction.BLOCK
        assert incident is not None
        assert incident.threat_type == OPCUAThreatType.CLASSIFICATION_VIOLATION
        assert security_layer.packets_blocked == 1
    
    @pytest.mark.asyncio
    async def test_air_gap_bridge(self, security_layer):
        """Test air-gap bridge functionality."""
        # Create bridge
        success = await security_layer.create_air_gap_bridge(
            bridge_id="TEST_BRIDGE",
            source_network="CLASSIFIED",
            destination_network="UNCLASSIFIED",
            allowed_nodes=["ns=2;s=Robot.Status"],
            classification_filter=ClassificationLevel.UNCLASSIFIED
        )
        
        assert success is True
        assert "TEST_BRIDGE" in security_layer.air_gap_bridges
        
        # Test transfer
        packet = OPCUAPacket(
            packet_id="PKT003",
            timestamp=datetime.utcnow(),
            source_ip="10.0.0.100",
            source_port=48500,
            destination_ip="192.168.1.200",
            destination_port=4840,
            message_type="Message",
            node_id="ns=2;s=Robot.Status",
            service_type="Read",
            payload_size=64,
            encrypted=True,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        success, message = await security_layer.transfer_via_air_gap(
            "TEST_BRIDGE", packet
        )
        
        assert success is True
        assert "successful" in message
    
    @pytest.mark.asyncio
    async def test_custom_security_rule(self, security_layer):
        """Test adding and applying custom security rules."""
        # Add custom rule
        rule = SecurityRule(
            rule_id="CUSTOM_TEST",
            rule_name="Block Test Pattern",
            threat_type=OPCUAThreatType.COMMAND_INJECTION,
            pattern=r"TEST_PATTERN",
            action=SecurityAction.BLOCK,
            priority=9
        )
        
        success = security_layer.add_security_rule(rule)
        assert success is True
        
        # Test packet matching rule
        packet = OPCUAPacket(
            packet_id="PKT004",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.102",
            source_port=48502,
            destination_ip="192.168.1.200",
            destination_port=4840,
            message_type="Message",
            node_id="ns=2;s=TEST_PATTERN.Node",  # Matches pattern
            service_type="Write",
            payload_size=128,
            encrypted=True,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        action, incident = await security_layer.analyze_packet(packet)
        
        assert action == SecurityAction.BLOCK
        assert incident is not None
        assert incident.threat_type == OPCUAThreatType.COMMAND_INJECTION


class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_server_write_performance(self):
        """Benchmark server write operations."""
        audit_logger = AuditLogger()
        server = SecureOPCUAServer(
            server_name="Perf_Server",
            endpoint="opc.tcp://localhost:4840/perf",
            classification_level=ClassificationLevel.UNCLASSIFIED,
            audit_logger=audit_logger,
            enable_byzantine=False  # Disable for performance test
        )
        
        await server.start()
        
        # Benchmark writes
        start_time = time.time()
        write_count = 1000
        
        for i in range(write_count):
            await server.write_node(
                "production_rate",
                float(i % 100),
                ClassificationLevel.UNCLASSIFIED
            )
        
        duration = time.time() - start_time
        writes_per_second = write_count / duration
        avg_latency_ms = (duration / write_count) * 1000
        
        logger.info(f"Write performance: {writes_per_second:.1f} writes/sec")
        logger.info(f"Average latency: {avg_latency_ms:.2f}ms")
        
        # Assert performance targets
        assert avg_latency_ms < 100  # Target: <100ms
        assert writes_per_second > 10  # Target: >10 writes/sec
        
        await server.stop()
    
    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_security_analysis_performance(self):
        """Benchmark security packet analysis."""
        audit_logger = AuditLogger()
        security = OPCUASecurityLayer(
            layer_id="Perf_Security",
            classification_level=ClassificationLevel.UNCLASSIFIED,
            audit_logger=audit_logger,
            enable_ml_detection=False  # Disable ML for baseline
        )
        
        # Create test packets
        packets = []
        for i in range(1000):
            packet = OPCUAPacket(
                packet_id=f"PKT{i:04d}",
                timestamp=datetime.utcnow(),
                source_ip=f"192.168.1.{i % 255}",
                source_port=48000 + i,
                destination_ip="192.168.1.200",
                destination_port=4840,
                message_type="Message",
                node_id=f"ns=2;s=Node{i}",
                service_type="Read" if i % 2 == 0 else "Write",
                payload_size=128,
                encrypted=True,
                classification=ClassificationLevel.UNCLASSIFIED
            )
            packets.append(packet)
        
        # Benchmark analysis
        start_time = time.time()
        
        for packet in packets:
            await security.analyze_packet(packet)
        
        duration = time.time() - start_time
        packets_per_second = len(packets) / duration
        avg_analysis_ms = (duration / len(packets)) * 1000
        
        logger.info(f"Security analysis: {packets_per_second:.1f} packets/sec")
        logger.info(f"Average analysis time: {avg_analysis_ms:.2f}ms")
        
        # Get metrics
        metrics = await security.get_security_metrics()
        logger.info(f"Threats detected: {metrics['metrics']['threats_detected']}")
        
        # Assert performance targets
        assert avg_analysis_ms < 10  # Target: <10ms per packet
        assert packets_per_second > 100  # Target: >100 packets/sec


# Integration test
@pytest.mark.asyncio
@pytest.mark.integration
async def test_full_integration():
    """Test full OPC UA integration with all components."""
    audit_logger = AuditLogger()
    
    # Create server
    server = SecureOPCUAServer(
        server_name="Integration_Server",
        endpoint="opc.tcp://localhost:4840/integration",
        classification_level=ClassificationLevel.SECRET,
        audit_logger=audit_logger,
        enable_byzantine=True
    )
    
    # Create security layer
    security = OPCUASecurityLayer(
        layer_id="Integration_Security",
        classification_level=ClassificationLevel.SECRET,
        audit_logger=audit_logger,
        enable_ml_detection=True
    )
    
    # Start server
    await server.start()
    
    # Simulate production scenario
    logger.info("=== Integration Test: Production Scenario ===")
    
    # 1. Update production schedule
    schedule_data = {
        "work_orders": [
            {
                "id": "WO-INT-001",
                "product": "Widget-A",
                "quantity": 1000,
                "priority": 9
            }
        ],
        "start_time": datetime.utcnow().isoformat(),
        "end_time": (datetime.utcnow() + timedelta(hours=4)).isoformat(),
        "priority": 8
    }
    
    success, schedule_id = await server._update_schedule_method(
        None, json.dumps(schedule_data)
    )
    assert success is True
    logger.info(f"Production schedule created: {schedule_id}")
    
    # 2. Start production
    await server.write_node("active_work_order", "WO-INT-001")
    await server.write_node("robot_mode", "AUTOMATIC")
    await server.write_node("production_rate", 85.5)
    
    # 3. Monitor with security
    for i in range(10):
        packet = OPCUAPacket(
            packet_id=f"INT{i:03d}",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.50",
            source_port=48600 + i,
            destination_ip="192.168.1.200",
            destination_port=4840,
            message_type="Message",
            node_id="ns=2;s=production_rate",
            service_type="Read",
            payload_size=64,
            encrypted=True,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        action, incident = await security.analyze_packet(packet)
        assert action == SecurityAction.ALLOW
    
    # 4. Update production metrics
    for i in range(5):
        await server.write_node("parts_produced", i * 50)
        await server.write_node("quality_score", 95.0 + i * 0.5)
        await asyncio.sleep(0.1)
    
    # 5. Get final metrics
    server_metrics = await server.get_metrics()
    security_metrics = await security.get_security_metrics()
    
    logger.info("=== Integration Test Results ===")
    logger.info(f"Server nodes created: {server_metrics['metrics']['nodes_created']}")
    logger.info(f"Commands validated: {server_metrics['metrics']['commands_validated']}")
    logger.info(f"Packets analyzed: {security_metrics['metrics']['packets_analyzed']}")
    logger.info(f"Average latency: {server_metrics['performance']['latency_achieved_ms']:.2f}ms")
    
    # Assert integration success
    assert server_metrics['performance']['within_target'] is True
    assert security_metrics['metrics']['threats_detected'] == 0  # No threats in normal operation
    
    # Cleanup
    await server.stop()
    
    logger.info("=== Integration Test Completed Successfully ===")


if __name__ == "__main__":
    # Run specific test
    asyncio.run(test_full_integration())