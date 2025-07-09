#!/usr/bin/env python3
"""
ALCUB3 Swarm Secure Communication Layer (Task 2.28)
High-level secure communication interface for swarm coordination

This module provides swarm-specific secure communication protocols
built on top of the P2P network, with optimizations for large-scale
swarm operations and defense-grade security.
"""

import asyncio
import time
import uuid
import hashlib
import json
import logging
import struct
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import numpy as np

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

# Import swarm components
from .secure_p2p_network import SecureSwarmNetwork, MessageType, PeerInfo

logger = logging.getLogger(__name__)


class SwarmMessageType(Enum):
    """Swarm-specific message types."""
    # Coordination messages
    FORMATION_UPDATE = "formation_update"
    MISSION_COMMAND = "mission_command"
    EMERGENCY_STOP = "emergency_stop"
    
    # Status messages
    HEALTH_STATUS = "health_status"
    SENSOR_DATA = "sensor_data"
    BATTERY_STATUS = "battery_status"
    
    # Security messages
    ANOMALY_ALERT = "anomaly_alert"
    THREAT_DETECTED = "threat_detected"
    MEMBER_COMPROMISED = "member_compromised"
    
    # Consensus messages
    CONSENSUS_REQUEST = "consensus_request"
    CONSENSUS_VOTE = "consensus_vote"
    CONSENSUS_RESULT = "consensus_result"


class MessagePriority(Enum):
    """Message priority levels for QoS."""
    CRITICAL = 0  # Emergency/safety messages
    HIGH = 1      # Security alerts, commands
    NORMAL = 2    # Regular coordination
    LOW = 3       # Status updates, telemetry


@dataclass
class SwarmMessage:
    """Enhanced swarm message with security and QoS features."""
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    message_type: SwarmMessageType = SwarmMessageType.HEALTH_STATUS
    sender_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    priority: MessagePriority = MessagePriority.NORMAL
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    ttl: int = 10  # Time-to-live in hops
    
    # Message content
    payload: Dict[str, Any] = field(default_factory=dict)
    
    # Security features
    sequence_number: int = 0
    nonce: bytes = field(default_factory=lambda: os.urandom(16))
    signature: Optional[bytes] = None
    
    # Multicast/broadcast support
    target_group: Optional[str] = None  # None = broadcast
    target_members: Optional[List[str]] = None  # Specific targets
    
    # Reliability features
    requires_ack: bool = False
    ack_timeout: float = 5.0  # seconds
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class MessageAck:
    """Acknowledgment for reliable messaging."""
    message_id: str
    sender_id: str
    receiver_id: str
    timestamp: datetime
    success: bool
    error_message: Optional[str] = None


class ReplayAttackPrevention:
    """Prevent replay attacks using sliding window and timestamps."""
    
    def __init__(self, window_size: int = 1000, max_age_seconds: int = 300):
        self.window_size = window_size
        self.max_age = timedelta(seconds=max_age_seconds)
        self.seen_messages: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.sequence_counters: Dict[str, int] = defaultdict(int)
    
    def validate_message(self, message: SwarmMessage) -> Tuple[bool, Optional[str]]:
        """Validate message against replay attacks."""
        # Check timestamp freshness
        age = datetime.now() - message.timestamp
        if age > self.max_age:
            return False, f"Message too old: {age.total_seconds()}s"
        
        # Check if we've seen this message ID
        message_key = f"{message.sender_id}:{message.message_id}"
        if message_key in self.seen_messages[message.sender_id]:
            return False, "Duplicate message ID"
        
        # Check sequence number
        expected_seq = self.sequence_counters[message.sender_id]
        if message.sequence_number < expected_seq:
            return False, f"Old sequence number: {message.sequence_number} < {expected_seq}"
        
        # Update tracking
        self.seen_messages[message.sender_id].append(message_key)
        self.sequence_counters[message.sender_id] = message.sequence_number + 1
        
        return True, None


class BandwidthOptimizer:
    """Optimize bandwidth usage for large swarms."""
    
    def __init__(self):
        self.compression_enabled = True
        self.aggregation_window = 0.1  # seconds
        self.message_buffer: Dict[str, List[SwarmMessage]] = defaultdict(list)
        self.last_flush: Dict[str, float] = defaultdict(time.time)
    
    def should_aggregate(self, message: SwarmMessage) -> bool:
        """Determine if message should be aggregated."""
        # Don't aggregate critical messages
        if message.priority == MessagePriority.CRITICAL:
            return False
        
        # Don't aggregate messages requiring acknowledgment
        if message.requires_ack:
            return False
        
        # Aggregate similar message types
        return message.message_type in [
            SwarmMessageType.HEALTH_STATUS,
            SwarmMessageType.SENSOR_DATA,
            SwarmMessageType.BATTERY_STATUS
        ]
    
    def add_message(self, target: str, message: SwarmMessage) -> Optional[List[SwarmMessage]]:
        """Add message to buffer, return messages to send if buffer should flush."""
        if not self.should_aggregate(message):
            return [message]
        
        self.message_buffer[target].append(message)
        
        # Check if we should flush
        if time.time() - self.last_flush[target] > self.aggregation_window:
            messages = self.message_buffer[target]
            self.message_buffer[target] = []
            self.last_flush[target] = time.time()
            return messages
        
        return None


class SecureSwarmCommunication:
    """
    High-level secure communication interface for swarm operations.
    
    Features:
    - End-to-end encryption with forward secrecy
    - Message authentication and integrity
    - Replay attack prevention
    - Bandwidth optimization for large swarms
    - Priority-based QoS
    - Reliable messaging with acknowledgments
    - Classification-aware routing
    """
    
    def __init__(
        self,
        swarm_network: SecureSwarmNetwork,
        audit_logger: AuditLogger,
        enable_bandwidth_optimization: bool = True
    ):
        self.network = swarm_network
        self.audit_logger = audit_logger
        self.node_id = swarm_network.node_id
        
        # Security components
        self.replay_prevention = ReplayAttackPrevention()
        self.sequence_number = 0
        
        # Optimization components
        self.bandwidth_optimizer = BandwidthOptimizer() if enable_bandwidth_optimization else None
        
        # Reliability tracking
        self.pending_acks: Dict[str, SwarmMessage] = {}
        self.ack_timers: Dict[str, asyncio.Task] = {}
        
        # Message handlers
        self.swarm_handlers: Dict[SwarmMessageType, Callable] = {}
        
        # Metrics
        self.metrics = {
            'messages_sent': 0,
            'messages_received': 0,
            'messages_dropped': 0,
            'replay_attacks_prevented': 0,
            'bandwidth_saved_bytes': 0
        }
        
        # Register base handlers with network
        self._register_network_handlers()
        
        logger.info("Secure swarm communication initialized for node %s", self.node_id)
    
    def _register_network_handlers(self):
        """Register handlers with underlying P2P network."""
        # Map our message types to network message types
        self.network.register_handler(
            MessageType.EMERGENCY,
            self._handle_emergency_message
        )
        self.network.register_handler(
            MessageType.TASK_ALLOCATION,
            self._handle_coordination_message
        )
        self.network.register_handler(
            MessageType.STATE_SYNC,
            self._handle_status_message
        )
    
    async def _handle_emergency_message(self, sender_id: str, payload: Dict[str, Any]):
        """Handle emergency/security messages."""
        message = self._deserialize_message(payload)
        if message and message.message_type in [
            SwarmMessageType.EMERGENCY_STOP,
            SwarmMessageType.THREAT_DETECTED,
            SwarmMessageType.MEMBER_COMPROMISED,
            SwarmMessageType.ANOMALY_ALERT
        ]:
            await self._process_incoming_message(sender_id, message)
    
    async def _handle_coordination_message(self, sender_id: str, payload: Dict[str, Any]):
        """Handle coordination messages."""
        message = self._deserialize_message(payload)
        if message and message.message_type in [
            SwarmMessageType.FORMATION_UPDATE,
            SwarmMessageType.MISSION_COMMAND,
            SwarmMessageType.CONSENSUS_REQUEST,
            SwarmMessageType.CONSENSUS_VOTE,
            SwarmMessageType.CONSENSUS_RESULT
        ]:
            await self._process_incoming_message(sender_id, message)
    
    async def _handle_status_message(self, sender_id: str, payload: Dict[str, Any]):
        """Handle status/telemetry messages."""
        message = self._deserialize_message(payload)
        if message and message.message_type in [
            SwarmMessageType.HEALTH_STATUS,
            SwarmMessageType.SENSOR_DATA,
            SwarmMessageType.BATTERY_STATUS
        ]:
            await self._process_incoming_message(sender_id, message)
    
    async def _process_incoming_message(self, sender_id: str, message: SwarmMessage):
        """Process incoming swarm message with security validation."""
        self.metrics['messages_received'] += 1
        
        # Validate against replay attacks
        valid, error = self.replay_prevention.validate_message(message)
        if not valid:
            self.metrics['replay_attacks_prevented'] += 1
            logger.warning("Replay attack prevented from %s: %s", sender_id, error)
            await self.audit_logger.log_event(
                "SWARM_REPLAY_ATTACK_PREVENTED",
                classification=message.classification,
                details={
                    "sender": sender_id,
                    "message_id": message.message_id,
                    "error": error
                }
            )
            return
        
        # Send acknowledgment if required
        if message.requires_ack:
            ack = MessageAck(
                message_id=message.message_id,
                sender_id=self.node_id,
                receiver_id=sender_id,
                timestamp=datetime.now(),
                success=True
            )
            await self._send_ack(sender_id, ack)
        
        # Call registered handler
        if message.message_type in self.swarm_handlers:
            try:
                await self.swarm_handlers[message.message_type](sender_id, message)
            except Exception as e:
                logger.error("Handler error for %s: %s", message.message_type, e)
    
    def register_handler(self, message_type: SwarmMessageType, handler: Callable):
        """Register a handler for swarm message type."""
        self.swarm_handlers[message_type] = handler
    
    async def send_message(
        self,
        message_type: SwarmMessageType,
        payload: Dict[str, Any],
        target: Optional[str] = None,
        priority: MessagePriority = MessagePriority.NORMAL,
        requires_ack: bool = False,
        classification: Optional[ClassificationLevel] = None
    ) -> bool:
        """Send a message to target (unicast) or all peers (broadcast)."""
        # Create message
        message = SwarmMessage(
            message_type=message_type,
            sender_id=self.node_id,
            priority=priority,
            classification=classification or self.network.classification_level,
            payload=payload,
            sequence_number=self.sequence_number,
            requires_ack=requires_ack,
            target_members=[target] if target else None
        )
        self.sequence_number += 1
        
        # Handle bandwidth optimization
        if self.bandwidth_optimizer and target:
            messages = self.bandwidth_optimizer.add_message(target, message)
            if not messages:
                return True  # Message buffered
        else:
            messages = [message]
        
        # Send message(s)
        for msg in messages:
            success = await self._send_single_message(msg, target)
            if not success:
                return False
        
        return True
    
    async def _send_single_message(self, message: SwarmMessage, target: Optional[str]) -> bool:
        """Send a single message."""
        self.metrics['messages_sent'] += 1
        
        # Map to network message type based on priority
        network_type = MessageType.EMERGENCY if message.priority == MessagePriority.CRITICAL else MessageType.STATE_SYNC
        
        # Serialize message
        payload = self._serialize_message(message)
        
        # Send via network
        if target:
            success = await self.network.send_encrypted_message(
                target,
                network_type,
                payload
            )
        else:
            success = await self.network.broadcast_message(
                network_type,
                payload
            )
        
        # Handle acknowledgment timeout
        if success and message.requires_ack and target:
            self.pending_acks[message.message_id] = message
            self.ack_timers[message.message_id] = asyncio.create_task(
                self._handle_ack_timeout(message, target)
            )
        
        return success
    
    async def _handle_ack_timeout(self, message: SwarmMessage, target: str):
        """Handle acknowledgment timeout."""
        await asyncio.sleep(message.ack_timeout)
        
        if message.message_id in self.pending_acks:
            del self.pending_acks[message.message_id]
            
            # Retry if under limit
            if message.retry_count < message.max_retries:
                message.retry_count += 1
                logger.warning("Retrying message %s to %s (attempt %d/%d)",
                             message.message_id, target, message.retry_count + 1, message.max_retries + 1)
                await self._send_single_message(message, target)
            else:
                logger.error("Message %s to %s failed after %d retries",
                           message.message_id, target, message.max_retries + 1)
                self.metrics['messages_dropped'] += 1
    
    async def _send_ack(self, target: str, ack: MessageAck):
        """Send acknowledgment message."""
        await self.network.send_encrypted_message(
            target,
            MessageType.STATE_SYNC,
            {"ack": ack.__dict__}
        )
    
    def _serialize_message(self, message: SwarmMessage) -> Dict[str, Any]:
        """Serialize message for transmission."""
        return {
            "message_id": message.message_id,
            "message_type": message.message_type.value,
            "sender_id": message.sender_id,
            "timestamp": message.timestamp.isoformat(),
            "priority": message.priority.value,
            "classification": message.classification.value,
            "ttl": message.ttl,
            "payload": message.payload,
            "sequence_number": message.sequence_number,
            "nonce": message.nonce.hex(),
            "requires_ack": message.requires_ack,
            "target_group": message.target_group,
            "target_members": message.target_members
        }
    
    def _deserialize_message(self, data: Dict[str, Any]) -> Optional[SwarmMessage]:
        """Deserialize message from transmission."""
        try:
            return SwarmMessage(
                message_id=data["message_id"],
                message_type=SwarmMessageType(data["message_type"]),
                sender_id=data["sender_id"],
                timestamp=datetime.fromisoformat(data["timestamp"]),
                priority=MessagePriority(data["priority"]),
                classification=ClassificationLevel(data["classification"]),
                ttl=data["ttl"],
                payload=data["payload"],
                sequence_number=data["sequence_number"],
                nonce=bytes.fromhex(data["nonce"]),
                requires_ack=data.get("requires_ack", False),
                target_group=data.get("target_group"),
                target_members=data.get("target_members")
            )
        except Exception as e:
            logger.error("Failed to deserialize message: %s", e)
            return None
    
    async def send_emergency_stop(self, reason: str):
        """Send emergency stop to all swarm members."""
        await self.send_message(
            SwarmMessageType.EMERGENCY_STOP,
            {"reason": reason, "timestamp": datetime.now().isoformat()},
            priority=MessagePriority.CRITICAL,
            requires_ack=True
        )
    
    async def send_anomaly_alert(
        self,
        anomaly_type: str,
        confidence: float,
        affected_members: List[str],
        details: Dict[str, Any]
    ):
        """Send anomaly alert to swarm."""
        await self.send_message(
            SwarmMessageType.ANOMALY_ALERT,
            {
                "anomaly_type": anomaly_type,
                "confidence": confidence,
                "affected_members": affected_members,
                "details": details,
                "detection_time": datetime.now().isoformat()
            },
            priority=MessagePriority.HIGH,
            classification=ClassificationLevel.SECRET  # Anomalies may reveal vulnerabilities
        )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get communication metrics."""
        return {
            **self.metrics,
            "pending_acks": len(self.pending_acks),
            "active_timers": len(self.ack_timers),
            "bandwidth_optimization_enabled": self.bandwidth_optimizer is not None
        }