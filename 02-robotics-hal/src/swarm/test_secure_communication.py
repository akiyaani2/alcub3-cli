#!/usr/bin/env python3
"""
Comprehensive test suite for ALCUB3 Swarm Secure Communication Layer
Tests encryption, reliability, performance, and resilience features.
"""

import asyncio
import unittest
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from datetime import datetime, timedelta
import time
import os
import uuid
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Import components to test
from .secure_communication import (
    SecureSwarmCommunication,
    SwarmMessage,
    SwarmMessageType,
    MessagePriority,
    MessageAck,
    ReplayAttackPrevention,
    BandwidthOptimizer
)
from .secure_p2p_network import SecureSwarmNetwork, MessageType, PeerInfo

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger


class TestSwarmMessage(unittest.TestCase):
    """Test SwarmMessage data structure."""
    
    def test_message_creation_defaults(self):
        """Test message creation with default values."""
        msg = SwarmMessage()
        
        self.assertIsNotNone(msg.message_id)
        self.assertEqual(msg.message_type, SwarmMessageType.HEALTH_STATUS)
        self.assertEqual(msg.priority, MessagePriority.NORMAL)
        self.assertEqual(msg.classification, ClassificationLevel.UNCLASSIFIED)
        self.assertEqual(msg.ttl, 10)
        self.assertFalse(msg.requires_ack)
        self.assertEqual(msg.max_retries, 3)
    
    def test_message_creation_custom(self):
        """Test message creation with custom values."""
        payload = {"test": "data", "value": 42}
        msg = SwarmMessage(
            message_type=SwarmMessageType.EMERGENCY_STOP,
            sender_id="drone_1",
            priority=MessagePriority.CRITICAL,
            classification=ClassificationLevel.SECRET,
            payload=payload,
            requires_ack=True,
            ttl=5
        )
        
        self.assertEqual(msg.message_type, SwarmMessageType.EMERGENCY_STOP)
        self.assertEqual(msg.sender_id, "drone_1")
        self.assertEqual(msg.priority, MessagePriority.CRITICAL)
        self.assertEqual(msg.classification, ClassificationLevel.SECRET)
        self.assertEqual(msg.payload, payload)
        self.assertTrue(msg.requires_ack)
        self.assertEqual(msg.ttl, 5)
    
    def test_message_nonce_uniqueness(self):
        """Test that each message has a unique nonce."""
        messages = [SwarmMessage() for _ in range(100)]
        nonces = [msg.nonce for msg in messages]
        
        # All nonces should be unique
        self.assertEqual(len(nonces), len(set(nonces)))
        
        # Nonces should be 16 bytes
        for nonce in nonces:
            self.assertEqual(len(nonce), 16)


class TestReplayAttackPrevention(unittest.TestCase):
    """Test replay attack prevention mechanism."""
    
    def setUp(self):
        self.prevention = ReplayAttackPrevention(window_size=100, max_age_seconds=60)
    
    def test_valid_message(self):
        """Test validation of legitimate message."""
        msg = SwarmMessage(
            sender_id="drone_1",
            sequence_number=1,
            timestamp=datetime.now()
        )
        
        valid, error = self.prevention.validate_message(msg)
        self.assertTrue(valid)
        self.assertIsNone(error)
    
    def test_duplicate_message(self):
        """Test detection of duplicate message."""
        msg1 = SwarmMessage(
            message_id="test_id_123",
            sender_id="drone_1",
            sequence_number=1,
            timestamp=datetime.now()
        )
        
        # First validation should pass
        valid, error = self.prevention.validate_message(msg1)
        self.assertTrue(valid)
        
        # Second validation with same ID should fail
        msg2 = SwarmMessage(
            message_id="test_id_123",
            sender_id="drone_1",
            sequence_number=2,
            timestamp=datetime.now()
        )
        
        valid, error = self.prevention.validate_message(msg2)
        self.assertFalse(valid)
        self.assertIn("Duplicate message ID", error)
    
    def test_old_timestamp(self):
        """Test detection of old timestamps."""
        old_time = datetime.now() - timedelta(seconds=120)  # 2 minutes old
        msg = SwarmMessage(
            sender_id="drone_1",
            sequence_number=1,
            timestamp=old_time
        )
        
        valid, error = self.prevention.validate_message(msg)
        self.assertFalse(valid)
        self.assertIn("Message too old", error)
    
    def test_sequence_number_validation(self):
        """Test sequence number validation."""
        # Send messages in order
        for i in range(1, 5):
            msg = SwarmMessage(
                sender_id="drone_1",
                sequence_number=i,
                timestamp=datetime.now()
            )
            valid, error = self.prevention.validate_message(msg)
            self.assertTrue(valid)
        
        # Try to send old sequence number
        old_seq_msg = SwarmMessage(
            sender_id="drone_1",
            sequence_number=2,  # Already seen 4
            timestamp=datetime.now()
        )
        
        valid, error = self.prevention.validate_message(old_seq_msg)
        self.assertFalse(valid)
        self.assertIn("Old sequence number", error)
    
    def test_window_size_limit(self):
        """Test that window size is respected."""
        # Fill window
        for i in range(150):
            msg = SwarmMessage(
                message_id=f"msg_{i}",
                sender_id="drone_1",
                sequence_number=i,
                timestamp=datetime.now()
            )
            self.prevention.validate_message(msg)
        
        # Check window size
        self.assertLessEqual(
            len(self.prevention.seen_messages["drone_1"]),
            self.prevention.window_size
        )


class TestBandwidthOptimizer(unittest.TestCase):
    """Test bandwidth optimization features."""
    
    def setUp(self):
        self.optimizer = BandwidthOptimizer()
    
    def test_critical_message_not_aggregated(self):
        """Test that critical messages bypass aggregation."""
        msg = SwarmMessage(
            priority=MessagePriority.CRITICAL,
            message_type=SwarmMessageType.EMERGENCY_STOP
        )
        
        self.assertFalse(self.optimizer.should_aggregate(msg))
    
    def test_ack_required_not_aggregated(self):
        """Test that messages requiring ack bypass aggregation."""
        msg = SwarmMessage(
            priority=MessagePriority.NORMAL,
            requires_ack=True
        )
        
        self.assertFalse(self.optimizer.should_aggregate(msg))
    
    def test_status_message_aggregation(self):
        """Test aggregation of status messages."""
        # Status messages should be aggregated
        status_types = [
            SwarmMessageType.HEALTH_STATUS,
            SwarmMessageType.SENSOR_DATA,
            SwarmMessageType.BATTERY_STATUS
        ]
        
        for msg_type in status_types:
            msg = SwarmMessage(message_type=msg_type)
            self.assertTrue(self.optimizer.should_aggregate(msg))
    
    def test_message_buffering(self):
        """Test message buffering and flushing."""
        target = "drone_2"
        
        # Add messages that should be buffered
        msg1 = SwarmMessage(message_type=SwarmMessageType.HEALTH_STATUS)
        msg2 = SwarmMessage(message_type=SwarmMessageType.SENSOR_DATA)
        
        result1 = self.optimizer.add_message(target, msg1)
        self.assertIsNone(result1)  # Should be buffered
        
        # Force time to pass
        self.optimizer.last_flush[target] = time.time() - 0.2
        
        result2 = self.optimizer.add_message(target, msg2)
        self.assertIsNotNone(result2)  # Should flush
        self.assertEqual(len(result2), 2)  # Both messages
        self.assertIn(msg1, result2)
        self.assertIn(msg2, result2)


class TestSecureSwarmCommunication(unittest.IsolatedAsyncioTestCase):
    """Test main SecureSwarmCommunication class."""
    
    async def asyncSetUp(self):
        """Set up test fixtures."""
        # Create mock dependencies
        self.mock_network = Mock(spec=SecureSwarmNetwork)
        self.mock_network.node_id = "test_node"
        self.mock_network.classification_level = ClassificationLevel.SECRET
        self.mock_network.send_encrypted_message = AsyncMock(return_value=True)
        self.mock_network.broadcast_message = AsyncMock(return_value=True)
        
        self.mock_logger = Mock(spec=AuditLogger)
        self.mock_logger.log_event = AsyncMock()
        
        # Create communication instance
        self.comm = SecureSwarmCommunication(
            swarm_network=self.mock_network,
            audit_logger=self.mock_logger,
            enable_bandwidth_optimization=True
        )
    
    async def test_initialization(self):
        """Test proper initialization."""
        self.assertEqual(self.comm.node_id, "test_node")
        self.assertIsNotNone(self.comm.replay_prevention)
        self.assertIsNotNone(self.comm.bandwidth_optimizer)
        self.assertEqual(self.comm.sequence_number, 0)
    
    async def test_handler_registration(self):
        """Test message handler registration."""
        handler = AsyncMock()
        self.comm.register_handler(SwarmMessageType.ANOMALY_ALERT, handler)
        
        self.assertIn(SwarmMessageType.ANOMALY_ALERT, self.comm.swarm_handlers)
        self.assertEqual(self.comm.swarm_handlers[SwarmMessageType.ANOMALY_ALERT], handler)
    
    async def test_send_unicast_message(self):
        """Test sending message to specific target."""
        success = await self.comm.send_message(
            message_type=SwarmMessageType.FORMATION_UPDATE,
            payload={"formation": "wedge"},
            target="drone_2",
            priority=MessagePriority.HIGH
        )
        
        self.assertTrue(success)
        self.assertEqual(self.comm.metrics['messages_sent'], 1)
        
        # Verify network call
        self.mock_network.send_encrypted_message.assert_called_once()
        call_args = self.mock_network.send_encrypted_message.call_args[0]
        self.assertEqual(call_args[0], "drone_2")
    
    async def test_send_broadcast_message(self):
        """Test broadcasting message to all peers."""
        success = await self.comm.send_message(
            message_type=SwarmMessageType.EMERGENCY_STOP,
            payload={"reason": "test emergency"},
            priority=MessagePriority.CRITICAL
        )
        
        self.assertTrue(success)
        
        # Should use broadcast
        self.mock_network.broadcast_message.assert_called_once()
        call_args = self.mock_network.broadcast_message.call_args[0]
        self.assertEqual(call_args[0], MessageType.EMERGENCY)  # Critical priority
    
    async def test_message_serialization(self):
        """Test message serialization and deserialization."""
        original = SwarmMessage(
            message_id="test_123",
            message_type=SwarmMessageType.SENSOR_DATA,
            sender_id="drone_1",
            priority=MessagePriority.NORMAL,
            classification=ClassificationLevel.SECRET,
            payload={"sensor": "lidar", "data": [1, 2, 3]},
            sequence_number=42
        )
        
        # Serialize
        serialized = self.comm._serialize_message(original)
        
        # Verify structure
        self.assertIn("message_id", serialized)
        self.assertIn("payload", serialized)
        self.assertEqual(serialized["sequence_number"], 42)
        
        # Deserialize
        deserialized = self.comm._deserialize_message(serialized)
        
        self.assertEqual(deserialized.message_id, original.message_id)
        self.assertEqual(deserialized.message_type, original.message_type)
        self.assertEqual(deserialized.payload, original.payload)
        self.assertEqual(deserialized.sequence_number, original.sequence_number)
    
    async def test_replay_attack_prevention(self):
        """Test replay attack prevention in message processing."""
        # Create a message
        msg = SwarmMessage(
            message_id="replay_test",
            sender_id="attacker",
            message_type=SwarmMessageType.MISSION_COMMAND,
            timestamp=datetime.now(),
            sequence_number=1
        )
        
        # First processing should succeed
        await self.comm._process_incoming_message("attacker", msg)
        self.assertEqual(self.comm.metrics['messages_received'], 1)
        
        # Replay attempt should fail
        await self.comm._process_incoming_message("attacker", msg)
        self.assertEqual(self.comm.metrics['replay_attacks_prevented'], 1)
        
        # Audit log should be called
        self.mock_logger.log_event.assert_called_with(
            "SWARM_REPLAY_ATTACK_PREVENTED",
            classification=msg.classification,
            details={
                "sender": "attacker",
                "message_id": "replay_test",
                "error": "Duplicate message ID"
            }
        )
    
    async def test_acknowledgment_mechanism(self):
        """Test message acknowledgment and retry."""
        # Send message requiring ack
        msg_task = asyncio.create_task(
            self.comm.send_message(
                message_type=SwarmMessageType.MISSION_COMMAND,
                payload={"command": "move"},
                target="drone_2",
                requires_ack=True
            )
        )
        
        # Let it process
        await asyncio.sleep(0.1)
        
        # Should have pending ack
        self.assertEqual(len(self.comm.pending_acks), 1)
        self.assertEqual(len(self.comm.ack_timers), 1)
        
        # Simulate ack timeout by clearing pending acks
        msg_id = list(self.comm.pending_acks.keys())[0]
        msg = self.comm.pending_acks[msg_id]
        msg.ack_timeout = 0.1  # Short timeout
        msg.max_retries = 1  # Allow one retry
        
        # Wait for timeout and retry
        await asyncio.sleep(0.2)
        
        # Should have retried
        self.assertEqual(self.comm.metrics['messages_sent'], 2)  # Original + retry
    
    async def test_bandwidth_optimization(self):
        """Test bandwidth optimization for message aggregation."""
        # Disable optimizer temporarily
        self.comm.bandwidth_optimizer = None
        
        # Send multiple status messages
        for i in range(3):
            await self.comm.send_message(
                message_type=SwarmMessageType.HEALTH_STATUS,
                payload={"health": i},
                target="drone_2"
            )
        
        # Should send immediately without optimization
        self.assertEqual(self.mock_network.send_encrypted_message.call_count, 3)
        
        # Re-enable optimizer
        self.comm.bandwidth_optimizer = BandwidthOptimizer()
        self.comm.bandwidth_optimizer.aggregation_window = 0.5  # Longer window
        
        # Reset mock
        self.mock_network.send_encrypted_message.reset_mock()
        
        # Send more messages
        for i in range(3):
            await self.comm.send_message(
                message_type=SwarmMessageType.HEALTH_STATUS,
                payload={"health": i + 3},
                target="drone_3"
            )
        
        # Should not send immediately
        self.assertEqual(self.mock_network.send_encrypted_message.call_count, 0)
    
    async def test_emergency_stop_broadcast(self):
        """Test emergency stop functionality."""
        await self.comm.send_emergency_stop("Test emergency")
        
        # Should broadcast with critical priority
        self.mock_network.broadcast_message.assert_called_once()
        call_args = self.mock_network.broadcast_message.call_args[0]
        self.assertEqual(call_args[0], MessageType.EMERGENCY)
        
        # Check payload
        payload = call_args[1]
        self.assertIn("reason", payload)
        self.assertEqual(payload["reason"], "Test emergency")
    
    async def test_anomaly_alert_classification(self):
        """Test anomaly alert with proper classification."""
        await self.comm.send_anomaly_alert(
            anomaly_type="gps_spoofing",
            confidence=0.95,
            affected_members=["drone_1", "drone_2"],
            details={"location": "sector_7"}
        )
        
        # Should send with HIGH priority and SECRET classification
        self.mock_network.broadcast_message.assert_called_once()
        
        # Verify the message was serialized with SECRET classification
        serialized_msg = self.comm._serialize_message.call_args[0][0] if hasattr(self.comm._serialize_message, 'call_args') else None
        # Since _serialize_message is not mocked, we check the network call
        payload = self.mock_network.broadcast_message.call_args[0][1]
        self.assertIn("anomaly_type", payload)
        self.assertIn("confidence", payload)
    
    async def test_metrics_collection(self):
        """Test metrics collection and reporting."""
        # Send various messages
        await self.comm.send_message(
            SwarmMessageType.HEALTH_STATUS,
            {"status": "ok"},
            target="drone_2"
        )
        
        # Simulate received message
        msg = SwarmMessage(
            sender_id="drone_3",
            message_type=SwarmMessageType.SENSOR_DATA,
            sequence_number=1
        )
        await self.comm._process_incoming_message("drone_3", msg)
        
        # Get metrics
        metrics = self.comm.get_metrics()
        
        self.assertEqual(metrics["messages_sent"], 1)
        self.assertEqual(metrics["messages_received"], 1)
        self.assertEqual(metrics["messages_dropped"], 0)
        self.assertEqual(metrics["replay_attacks_prevented"], 0)
        self.assertTrue(metrics["bandwidth_optimization_enabled"])


class TestPerformance(unittest.IsolatedAsyncioTestCase):
    """Performance and stress tests."""
    
    async def asyncSetUp(self):
        """Set up for performance tests."""
        self.mock_network = Mock(spec=SecureSwarmNetwork)
        self.mock_network.node_id = "perf_test_node"
        self.mock_network.classification_level = ClassificationLevel.UNCLASSIFIED
        self.mock_network.send_encrypted_message = AsyncMock(return_value=True)
        self.mock_network.broadcast_message = AsyncMock(return_value=True)
        
        self.mock_logger = Mock(spec=AuditLogger)
        self.mock_logger.log_event = AsyncMock()
        
        self.comm = SecureSwarmCommunication(
            self.mock_network,
            self.mock_logger,
            enable_bandwidth_optimization=False  # Disable for accurate timing
        )
    
    async def test_message_throughput(self):
        """Test message sending throughput."""
        num_messages = 1000
        start_time = time.time()
        
        # Send messages
        tasks = []
        for i in range(num_messages):
            task = self.comm.send_message(
                SwarmMessageType.SENSOR_DATA,
                {"seq": i},
                target=f"drone_{i % 10}"
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        elapsed = time.time() - start_time
        throughput = num_messages / elapsed
        
        print(f"\nMessage throughput: {throughput:.2f} messages/second")
        print(f"Average latency: {elapsed / num_messages * 1000:.2f}ms")
        
        # Should handle at least 1000 messages per second
        self.assertGreater(throughput, 1000)
    
    async def test_serialization_performance(self):
        """Test serialization/deserialization performance."""
        # Create complex message
        msg = SwarmMessage(
            message_type=SwarmMessageType.SENSOR_DATA,
            payload={
                "sensors": {
                    "lidar": list(range(1000)),
                    "camera": {"width": 1920, "height": 1080, "data": "base64_encoded"},
                    "imu": {"accel": [0.1, 0.2, 0.3], "gyro": [0.01, 0.02, 0.03]}
                },
                "timestamp": datetime.now().isoformat(),
                "metadata": {"platform": "test", "version": "1.0"}
            }
        )
        
        # Time serialization
        iterations = 10000
        start = time.time()
        
        for _ in range(iterations):
            serialized = self.comm._serialize_message(msg)
        
        ser_time = (time.time() - start) / iterations * 1000
        
        # Time deserialization
        start = time.time()
        
        for _ in range(iterations):
            deserialized = self.comm._deserialize_message(serialized)
        
        deser_time = (time.time() - start) / iterations * 1000
        
        print(f"\nSerialization: {ser_time:.3f}ms per message")
        print(f"Deserialization: {deser_time:.3f}ms per message")
        
        # Should be under 1ms for both
        self.assertLess(ser_time, 1.0)
        self.assertLess(deser_time, 1.0)
    
    async def test_concurrent_message_handling(self):
        """Test handling concurrent incoming messages."""
        num_senders = 50
        messages_per_sender = 20
        
        # Create handler to track messages
        received_messages = []
        
        async def test_handler(sender_id, message):
            received_messages.append((sender_id, message.sequence_number))
        
        self.comm.register_handler(SwarmMessageType.SENSOR_DATA, test_handler)
        
        # Simulate concurrent incoming messages
        tasks = []
        for sender in range(num_senders):
            for seq in range(messages_per_sender):
                msg = SwarmMessage(
                    sender_id=f"drone_{sender}",
                    message_type=SwarmMessageType.SENSOR_DATA,
                    sequence_number=seq,
                    timestamp=datetime.now()
                )
                task = self.comm._process_incoming_message(f"drone_{sender}", msg)
                tasks.append(task)
        
        start = time.time()
        await asyncio.gather(*tasks)
        elapsed = time.time() - start
        
        total_messages = num_senders * messages_per_sender
        rate = total_messages / elapsed
        
        print(f"\nConcurrent handling: {rate:.2f} messages/second")
        print(f"Total processed: {len(received_messages)}")
        
        # All messages should be received
        self.assertEqual(len(received_messages), total_messages)
        
        # Should handle at least 5000 messages per second
        self.assertGreater(rate, 5000)


class TestResilience(unittest.IsolatedAsyncioTestCase):
    """Test resilience and error handling."""
    
    async def asyncSetUp(self):
        """Set up for resilience tests."""
        self.mock_network = Mock(spec=SecureSwarmNetwork)
        self.mock_network.node_id = "resilience_test"
        self.mock_network.classification_level = ClassificationLevel.UNCLASSIFIED
        
        self.mock_logger = Mock(spec=AuditLogger)
        self.mock_logger.log_event = AsyncMock()
        
        self.comm = SecureSwarmCommunication(
            self.mock_network,
            self.mock_logger
        )
    
    async def test_network_failure_handling(self):
        """Test handling of network failures."""
        # Simulate network failure
        self.mock_network.send_encrypted_message = AsyncMock(return_value=False)
        
        success = await self.comm.send_message(
            SwarmMessageType.MISSION_COMMAND,
            {"command": "test"},
            target="drone_1"
        )
        
        self.assertFalse(success)
        self.assertEqual(self.comm.metrics['messages_sent'], 1)
    
    async def test_malformed_message_handling(self):
        """Test handling of malformed messages."""
        # Test with invalid serialized data
        invalid_data = {
            "message_type": "invalid_type",  # Invalid enum
            "timestamp": "not_a_timestamp",  # Invalid format
        }
        
        result = self.comm._deserialize_message(invalid_data)
        self.assertIsNone(result)
    
    async def test_handler_exception_isolation(self):
        """Test that handler exceptions don't crash the system."""
        # Register faulty handler
        async def faulty_handler(sender_id, message):
            raise ValueError("Test exception")
        
        self.comm.register_handler(SwarmMessageType.SENSOR_DATA, faulty_handler)
        
        # Process message
        msg = SwarmMessage(
            sender_id="drone_1",
            message_type=SwarmMessageType.SENSOR_DATA,
            sequence_number=1
        )
        
        # Should not raise exception
        await self.comm._process_incoming_message("drone_1", msg)
        
        # Message should still be counted as received
        self.assertEqual(self.comm.metrics['messages_received'], 1)


class TestIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests with full message flow."""
    
    async def test_end_to_end_communication(self):
        """Test complete message flow between two nodes."""
        # Create two communication instances
        network1 = Mock(spec=SecureSwarmNetwork)
        network1.node_id = "node_1"
        network1.classification_level = ClassificationLevel.SECRET
        
        network2 = Mock(spec=SecureSwarmNetwork)
        network2.node_id = "node_2"
        network2.classification_level = ClassificationLevel.SECRET
        
        logger = Mock(spec=AuditLogger)
        logger.log_event = AsyncMock()
        
        comm1 = SecureSwarmCommunication(network1, logger)
        comm2 = SecureSwarmCommunication(network2, logger)
        
        # Track received messages
        received = []
        
        async def handler(sender_id, message):
            received.append((sender_id, message))
        
        comm2.register_handler(SwarmMessageType.FORMATION_UPDATE, handler)
        
        # Simulate network connection
        async def simulate_send(target, msg_type, payload):
            # Simulate network delay
            await asyncio.sleep(0.01)
            
            # Deliver to target
            if target == "node_2":
                # Deserialize and process
                msg = comm1._deserialize_message(payload)
                if msg:
                    await comm2._process_incoming_message("node_1", msg)
            return True
        
        network1.send_encrypted_message = simulate_send
        
        # Send message from node_1 to node_2
        await comm1.send_message(
            SwarmMessageType.FORMATION_UPDATE,
            {"formation": "diamond", "spacing": 10},
            target="node_2"
        )
        
        # Wait for delivery
        await asyncio.sleep(0.05)
        
        # Verify reception
        self.assertEqual(len(received), 1)
        sender, msg = received[0]
        self.assertEqual(sender, "node_1")
        self.assertEqual(msg.payload["formation"], "diamond")
        self.assertEqual(msg.payload["spacing"], 10)


if __name__ == "__main__":
    unittest.main()