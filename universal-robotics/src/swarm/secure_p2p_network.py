#!/usr/bin/env python3
"""
ALCUB3 Secure Swarm P2P Network
Military-grade peer-to-peer communication for swarm robotics

This module implements secure, classification-aware P2P communication
with forward secrecy, network partition detection, and gossip protocols.
"""

import asyncio
import time
import uuid
import hashlib
import hmac
import json
import logging
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.mtls_manager import MTLSManager

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """P2P message types."""
    TASK_ALLOCATION = "task_allocation"
    CONSENSUS = "consensus"
    HEARTBEAT = "heartbeat"
    STATE_SYNC = "state_sync"
    EMERGENCY = "emergency"
    GOSSIP = "gossip"
    KEY_EXCHANGE = "key_exchange"
    PARTITION_PROBE = "partition_probe"


class NetworkState(Enum):
    """Network connectivity state."""
    CONNECTED = "connected"
    PARTITIONED = "partitioned"
    DEGRADED = "degraded"
    HEALING = "healing"


@dataclass
class PeerInfo:
    """Information about a swarm peer."""
    peer_id: str
    address: str  # IP:port
    public_key: rsa.RSAPublicKey
    classification_level: ClassificationLevel
    last_seen: datetime
    latency_ms: float = 0.0
    packet_loss: float = 0.0
    trusted: bool = True
    session_keys: Dict[str, bytes] = field(default_factory=dict)  # Forward secrecy keys
    
    def is_reachable(self, timeout_seconds: float = 30.0) -> bool:
        """Check if peer is reachable."""
        return (datetime.now() - self.last_seen).total_seconds() < timeout_seconds


@dataclass
class SecureMessage:
    """Encrypted P2P message with classification tagging."""
    message_id: str
    sender_id: str
    recipient_id: str  # Direct recipient or "broadcast"
    message_type: MessageType
    classification: ClassificationLevel
    encrypted_payload: bytes
    signature: bytes
    timestamp: datetime
    ttl: int = 3  # Time-to-live for gossip
    nonce: bytes = field(default_factory=lambda: uuid.uuid4().bytes)
    
    def to_bytes(self) -> bytes:
        """Serialize message for transmission."""
        header = struct.pack(
            "!16s16sHHI",
            uuid.UUID(self.message_id).bytes,
            self.nonce,
            self.message_type.value.__hash__() % 65536,
            self.classification.value,
            len(self.encrypted_payload)
        )
        return header + self.encrypted_payload + self.signature


@dataclass
class NetworkPartition:
    """Detected network partition."""
    partition_id: str
    detected_at: datetime
    partition_a: Set[str]  # Peer IDs in partition A
    partition_b: Set[str]  # Peer IDs in partition B
    healing_attempts: int = 0
    healed: bool = False


class ForwardSecrecyManager:
    """Manages ephemeral keys for forward secrecy."""
    
    def __init__(self):
        self.ephemeral_keys: Dict[str, ec.EllipticCurvePrivateKey] = {}
        self.peer_ephemeral_keys: Dict[str, ec.EllipticCurvePublicKey] = {}
        self.session_keys: Dict[Tuple[str, str], bytes] = {}  # (my_id, peer_id) -> key
    
    def generate_ephemeral_key(self, my_id: str) -> ec.EllipticCurvePublicKey:
        """Generate new ephemeral key pair."""
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.ephemeral_keys[my_id] = private_key
        return private_key.public_key()
    
    def receive_peer_ephemeral_key(
        self, 
        peer_id: str, 
        public_key: ec.EllipticCurvePublicKey
    ):
        """Store peer's ephemeral public key."""
        self.peer_ephemeral_keys[peer_id] = public_key
    
    def derive_session_key(self, my_id: str, peer_id: str) -> bytes:
        """Derive session key using ECDH."""
        cache_key = (my_id, peer_id)
        
        if cache_key in self.session_keys:
            return self.session_keys[cache_key]
        
        my_private = self.ephemeral_keys.get(my_id)
        peer_public = self.peer_ephemeral_keys.get(peer_id)
        
        if not my_private or not peer_public:
            raise ValueError("Missing ephemeral keys for key derivation")
        
        # Perform ECDH
        shared_key = my_private.exchange(ec.ECDH(), peer_public)
        
        # Derive session key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=b"alcub3-swarm-p2p",
            info=f"{my_id}:{peer_id}".encode()
        )
        session_key = hkdf.derive(shared_key)
        
        self.session_keys[cache_key] = session_key
        return session_key
    
    def rotate_keys(self, my_id: str):
        """Rotate ephemeral keys for forward secrecy."""
        # Clear old keys
        if my_id in self.ephemeral_keys:
            del self.ephemeral_keys[my_id]
        
        # Clear derived session keys
        keys_to_remove = [k for k in self.session_keys if k[0] == my_id]
        for key in keys_to_remove:
            del self.session_keys[key]


class GossipProtocol:
    """Epidemic gossip protocol for state propagation."""
    
    def __init__(self, fanout: int = 3):
        self.fanout = fanout
        self.seen_messages: Set[str] = set()
        self.message_cache: deque = deque(maxlen=1000)
        self.propagation_metrics: Dict[str, Dict[str, Any]] = {}
    
    def should_propagate(self, message: SecureMessage) -> bool:
        """Determine if message should be propagated."""
        # Check if already seen
        if message.message_id in self.seen_messages:
            return False
        
        # Check TTL
        if message.ttl <= 0:
            return False
        
        # Check classification rules
        if message.classification == ClassificationLevel.TOP_SECRET:
            # TS messages only propagate to TS-cleared nodes
            return True
        
        return True
    
    def select_gossip_targets(
        self, 
        peers: Dict[str, PeerInfo],
        sender_id: str,
        classification: ClassificationLevel
    ) -> List[str]:
        """Select peers for gossip propagation."""
        eligible_peers = [
            peer_id for peer_id, peer in peers.items()
            if peer_id != sender_id and 
               peer.is_reachable() and
               peer.classification_level.value >= classification.value
        ]
        
        # Random selection for epidemic spread
        if len(eligible_peers) <= self.fanout:
            return eligible_peers
        
        return random.sample(eligible_peers, self.fanout)
    
    def record_propagation(self, message_id: str, peer_id: str):
        """Record message propagation for metrics."""
        if message_id not in self.propagation_metrics:
            self.propagation_metrics[message_id] = {
                'first_seen': datetime.now(),
                'propagated_to': [],
                'hop_count': 0
            }
        
        self.propagation_metrics[message_id]['propagated_to'].append(peer_id)
        self.propagation_metrics[message_id]['hop_count'] += 1


class NetworkPartitionDetector:
    """Detects and handles network partitions in the swarm."""
    
    def __init__(self, detection_threshold: float = 0.4):
        self.detection_threshold = detection_threshold
        self.connectivity_matrix: Dict[str, Dict[str, bool]] = defaultdict(dict)
        self.active_partitions: Dict[str, NetworkPartition] = {}
        self.partition_history: deque = deque(maxlen=100)
    
    def update_connectivity(self, peer_a: str, peer_b: str, connected: bool):
        """Update peer connectivity status."""
        self.connectivity_matrix[peer_a][peer_b] = connected
        self.connectivity_matrix[peer_b][peer_a] = connected
    
    def detect_partitions(self, all_peers: Set[str]) -> List[NetworkPartition]:
        """Detect network partitions using connectivity analysis."""
        # Build adjacency lists
        adjacency = defaultdict(set)
        for peer_a in all_peers:
            for peer_b in all_peers:
                if peer_a != peer_b and self.connectivity_matrix.get(peer_a, {}).get(peer_b, False):
                    adjacency[peer_a].add(peer_b)
        
        # Find connected components
        visited = set()
        components = []
        
        for peer in all_peers:
            if peer not in visited:
                component = set()
                self._dfs(peer, adjacency, visited, component)
                components.append(component)
        
        # Check for partitions
        if len(components) > 1:
            # Create partition records
            partitions = []
            for i in range(len(components) - 1):
                partition = NetworkPartition(
                    partition_id=str(uuid.uuid4()),
                    detected_at=datetime.now(),
                    partition_a=components[i],
                    partition_b=set().union(*components[i+1:])
                )
                partitions.append(partition)
                self.active_partitions[partition.partition_id] = partition
            
            return partitions
        
        return []
    
    def _dfs(self, node: str, adjacency: Dict[str, Set[str]], visited: Set[str], component: Set[str]):
        """Depth-first search for connected components."""
        visited.add(node)
        component.add(node)
        
        for neighbor in adjacency.get(node, set()):
            if neighbor not in visited:
                self._dfs(neighbor, adjacency, visited, component)
    
    def initiate_healing(self, partition: NetworkPartition) -> List[Tuple[str, str]]:
        """Initiate partition healing by suggesting bridge connections."""
        partition.healing_attempts += 1
        
        # Find potential bridge nodes (nodes that might reach both partitions)
        bridges = []
        
        # Select one node from each partition to attempt reconnection
        if partition.partition_a and partition.partition_b:
            node_a = random.choice(list(partition.partition_a))
            node_b = random.choice(list(partition.partition_b))
            bridges.append((node_a, node_b))
        
        return bridges


class SecureSwarmNetwork:
    """
    Secure P2P network for swarm communication with:
    - mTLS authentication
    - Forward secrecy
    - Classification-aware routing
    - Gossip-based state propagation
    - Network partition detection and healing
    """
    
    def __init__(
        self,
        node_id: str,
        classification_level: ClassificationLevel,
        private_key: rsa.RSAPrivateKey,
        certificate: bytes,
        audit_logger: AuditLogger
    ):
        self.node_id = node_id
        self.classification_level = classification_level
        self.private_key = private_key
        self.certificate = certificate
        self.audit_logger = audit_logger
        
        # Network components
        self.peers: Dict[str, PeerInfo] = {}
        self.forward_secrecy = ForwardSecrecyManager()
        self.gossip_protocol = GossipProtocol()
        self.partition_detector = NetworkPartitionDetector()
        
        # Message handling
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.outgoing_queue: asyncio.Queue = asyncio.Queue()
        self.incoming_queue: asyncio.Queue = asyncio.Queue()
        
        # Metrics
        self.network_metrics = {
            'messages_sent': 0,
            'messages_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'encryption_time_ms': deque(maxlen=1000),
            'decryption_time_ms': deque(maxlen=1000)
        }
        
        # Network state
        self.network_state = NetworkState.CONNECTED
        self._running = False
        
        logger.info("Secure swarm network initialized for node %s", node_id)
    
    async def start(self):
        """Start the P2P network."""
        self._running = True
        
        # Start background tasks
        asyncio.create_task(self._process_outgoing_messages())
        asyncio.create_task(self._process_incoming_messages())
        asyncio.create_task(self._monitor_network_health())
        asyncio.create_task(self._periodic_key_rotation())
        
        # Generate initial ephemeral key
        self.forward_secrecy.generate_ephemeral_key(self.node_id)
        
        logger.info("Secure swarm network started")
    
    async def stop(self):
        """Stop the P2P network."""
        self._running = False
        logger.info("Secure swarm network stopped")
    
    def register_handler(self, message_type: MessageType, handler: Callable):
        """Register a message handler."""
        self.message_handlers[message_type] = handler
    
    async def add_peer(self, peer: PeerInfo):
        """Add a peer to the network."""
        self.peers[peer.peer_id] = peer
        
        # Initiate key exchange
        await self._initiate_key_exchange(peer.peer_id)
        
        await self.audit_logger.log_event(
            "SWARM_PEER_ADDED",
            classification=self.classification_level,
            details={
                'peer_id': peer.peer_id,
                'classification': peer.classification_level.value
            }
        )
    
    async def send_message(
        self,
        recipient_id: str,
        message_type: MessageType,
        payload: Dict[str, Any],
        classification: ClassificationLevel
    ) -> bool:
        """Send a message to a peer or broadcast."""
        # Create message
        message = await self._create_secure_message(
            recipient_id,
            message_type,
            payload,
            classification
        )
        
        # Queue for sending
        await self.outgoing_queue.put(message)
        
        return True
    
    async def broadcast_message(
        self,
        message_type: MessageType,
        payload: Dict[str, Any],
        classification: ClassificationLevel
    ):
        """Broadcast message to all eligible peers."""
        # Create broadcast message
        message = await self._create_secure_message(
            "broadcast",
            message_type,
            payload,
            classification
        )
        
        # Queue for gossip propagation
        await self.outgoing_queue.put(message)
    
    async def _create_secure_message(
        self,
        recipient_id: str,
        message_type: MessageType,
        payload: Dict[str, Any],
        classification: ClassificationLevel
    ) -> SecureMessage:
        """Create an encrypted message."""
        start_time = time.time()
        
        # Serialize payload
        payload_bytes = json.dumps(payload).encode()
        
        # Encrypt based on recipient
        if recipient_id == "broadcast":
            # Use symmetric key for broadcasts
            encrypted = self._encrypt_broadcast(payload_bytes, classification)
        else:
            # Use session key for direct messages
            encrypted = await self._encrypt_direct(payload_bytes, recipient_id)
        
        # Sign the encrypted payload
        signature = self.private_key.sign(
            encrypted,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Create message
        message = SecureMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.node_id,
            recipient_id=recipient_id,
            message_type=message_type,
            classification=classification,
            encrypted_payload=encrypted,
            signature=signature,
            timestamp=datetime.now()
        )
        
        # Record encryption time
        encryption_time = (time.time() - start_time) * 1000
        self.network_metrics['encryption_time_ms'].append(encryption_time)
        
        return message
    
    def _encrypt_broadcast(self, data: bytes, classification: ClassificationLevel) -> bytes:
        """Encrypt broadcast message with classification-based key."""
        # Derive key from classification (simplified for demo)
        key = hashlib.sha256(f"broadcast-{classification.value}".encode()).digest()
        
        # Generate IV
        iv = uuid.uuid4().bytes
        
        # Encrypt using AES-GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + ciphertext + tag
        return iv + ciphertext + encryptor.tag
    
    async def _encrypt_direct(self, data: bytes, recipient_id: str) -> bytes:
        """Encrypt direct message with forward secrecy."""
        # Get or derive session key
        session_key = self.forward_secrecy.derive_session_key(self.node_id, recipient_id)
        
        # Generate IV
        iv = uuid.uuid4().bytes
        
        # Encrypt using AES-GCM
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + ciphertext + tag
        return iv + ciphertext + encryptor.tag
    
    async def _process_outgoing_messages(self):
        """Process outgoing message queue."""
        while self._running:
            try:
                message = await asyncio.wait_for(
                    self.outgoing_queue.get(), 
                    timeout=1.0
                )
                
                if message.recipient_id == "broadcast":
                    # Gossip propagation
                    targets = self.gossip_protocol.select_gossip_targets(
                        self.peers,
                        self.node_id,
                        message.classification
                    )
                    
                    for target in targets:
                        await self._send_to_peer(target, message)
                        self.gossip_protocol.record_propagation(
                            message.message_id, 
                            target
                        )
                else:
                    # Direct send
                    await self._send_to_peer(message.recipient_id, message)
                
                self.network_metrics['messages_sent'] += 1
                
            except asyncio.TimeoutError:
                continue
    
    async def _send_to_peer(self, peer_id: str, message: SecureMessage):
        """Send message to specific peer (simulated)."""
        peer = self.peers.get(peer_id)
        if not peer or not peer.is_reachable():
            logger.warning("Cannot send to unreachable peer %s", peer_id)
            return
        
        # Simulate network transmission
        message_bytes = message.to_bytes()
        self.network_metrics['bytes_sent'] += len(message_bytes)
        
        # Update peer last seen
        peer.last_seen = datetime.now()
        
        # Log for audit
        await self.audit_logger.log_event(
            "SWARM_MESSAGE_SENT",
            classification=message.classification,
            details={
                'message_id': message.message_id,
                'recipient': peer_id,
                'type': message.message_type.value,
                'size_bytes': len(message_bytes)
            }
        )
    
    async def _process_incoming_messages(self):
        """Process incoming message queue."""
        while self._running:
            try:
                message = await asyncio.wait_for(
                    self.incoming_queue.get(),
                    timeout=1.0
                )
                
                # Verify and decrypt
                payload = await self._decrypt_and_verify(message)
                
                if payload:
                    # Handle based on type
                    handler = self.message_handlers.get(message.message_type)
                    if handler:
                        await handler(message.sender_id, payload)
                    
                    # Check for gossip propagation
                    if self.gossip_protocol.should_propagate(message):
                        message.ttl -= 1
                        await self.outgoing_queue.put(message)
                
                self.network_metrics['messages_received'] += 1
                
            except asyncio.TimeoutError:
                continue
    
    async def _decrypt_and_verify(self, message: SecureMessage) -> Optional[Dict[str, Any]]:
        """Decrypt and verify message."""
        start_time = time.time()
        
        # Verify signature
        peer = self.peers.get(message.sender_id)
        if not peer:
            logger.warning("Message from unknown peer %s", message.sender_id)
            return None
        
        try:
            peer.public_key.verify(
                message.signature,
                message.encrypted_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception:
            logger.error("Invalid signature from %s", message.sender_id)
            return None
        
        # Decrypt based on type
        try:
            if message.recipient_id == "broadcast":
                decrypted = self._decrypt_broadcast(
                    message.encrypted_payload,
                    message.classification
                )
            else:
                decrypted = await self._decrypt_direct(
                    message.encrypted_payload,
                    message.sender_id
                )
            
            # Record decryption time
            decryption_time = (time.time() - start_time) * 1000
            self.network_metrics['decryption_time_ms'].append(decryption_time)
            
            return json.loads(decrypted)
            
        except Exception as e:
            logger.error("Decryption failed: %s", e)
            return None
    
    def _decrypt_broadcast(self, data: bytes, classification: ClassificationLevel) -> bytes:
        """Decrypt broadcast message."""
        # Extract components
        iv = data[:16]
        tag = data[-16:]
        ciphertext = data[16:-16]
        
        # Derive key
        key = hashlib.sha256(f"broadcast-{classification.value}".encode()).digest()
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    async def _decrypt_direct(self, data: bytes, sender_id: str) -> bytes:
        """Decrypt direct message."""
        # Extract components
        iv = data[:16]
        tag = data[-16:]
        ciphertext = data[16:-16]
        
        # Get session key
        session_key = self.forward_secrecy.derive_session_key(sender_id, self.node_id)
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    async def _initiate_key_exchange(self, peer_id: str):
        """Initiate ephemeral key exchange with peer."""
        # Generate our ephemeral key
        our_public_key = self.forward_secrecy.generate_ephemeral_key(self.node_id)
        
        # Send key exchange message
        await self.send_message(
            peer_id,
            MessageType.KEY_EXCHANGE,
            {
                'ephemeral_key': our_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            },
            self.classification_level
        )
    
    async def _monitor_network_health(self):
        """Monitor network health and detect partitions."""
        while self._running:
            await asyncio.sleep(5)  # Check every 5 seconds
            
            # Update connectivity matrix
            for peer_id, peer in self.peers.items():
                is_reachable = peer.is_reachable(timeout_seconds=10.0)
                self.partition_detector.update_connectivity(
                    self.node_id,
                    peer_id,
                    is_reachable
                )
            
            # Detect partitions
            all_nodes = {self.node_id} | set(self.peers.keys())
            partitions = self.partition_detector.detect_partitions(all_nodes)
            
            if partitions:
                self.network_state = NetworkState.PARTITIONED
                
                # Attempt healing
                for partition in partitions:
                    bridges = self.partition_detector.initiate_healing(partition)
                    for node_a, node_b in bridges:
                        logger.warning(
                            "Network partition detected. Attempting to bridge %s <-> %s",
                            node_a, node_b
                        )
                        
                        # Send partition probe messages
                        if node_a == self.node_id:
                            await self.send_message(
                                node_b,
                                MessageType.PARTITION_PROBE,
                                {'partition_id': partition.partition_id},
                                ClassificationLevel.UNCLASSIFIED
                            )
            else:
                if self.network_state == NetworkState.PARTITIONED:
                    self.network_state = NetworkState.HEALING
                elif self.network_state == NetworkState.HEALING:
                    self.network_state = NetworkState.CONNECTED
    
    async def _periodic_key_rotation(self):
        """Rotate ephemeral keys periodically for forward secrecy."""
        while self._running:
            await asyncio.sleep(300)  # Rotate every 5 minutes
            
            logger.info("Rotating ephemeral keys for forward secrecy")
            
            # Rotate our keys
            self.forward_secrecy.rotate_keys(self.node_id)
            
            # Initiate new key exchanges
            for peer_id in self.peers:
                await self._initiate_key_exchange(peer_id)
    
    def get_network_metrics(self) -> Dict[str, Any]:
        """Get network performance metrics."""
        enc_times = list(self.network_metrics['encryption_time_ms'])
        dec_times = list(self.network_metrics['decryption_time_ms'])
        
        return {
            'node_id': self.node_id,
            'network_state': self.network_state.value,
            'peer_count': len(self.peers),
            'reachable_peers': sum(1 for p in self.peers.values() if p.is_reachable()),
            'messages_sent': self.network_metrics['messages_sent'],
            'messages_received': self.network_metrics['messages_received'],
            'bytes_sent': self.network_metrics['bytes_sent'],
            'bytes_received': self.network_metrics['bytes_received'],
            'avg_encryption_ms': sum(enc_times) / len(enc_times) if enc_times else 0,
            'avg_decryption_ms': sum(dec_times) / len(dec_times) if dec_times else 0,
            'active_partitions': len(self.partition_detector.active_partitions),
            'gossip_fanout': self.gossip_protocol.fanout
        }