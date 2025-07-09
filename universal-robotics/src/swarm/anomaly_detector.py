#!/usr/bin/env python3
"""
ALCUB3 Swarm Anomaly Detection System (Task 2.29)
AI-powered anomaly detection for emergent swarm behaviors

This module implements sophisticated anomaly detection specifically designed
for swarm robotics, including compromised member detection, coordination
failure identification, and emergent behavior analysis.
"""

import asyncio
import time
import uuid
import math
import json
import logging
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import numpy as np
from scipy import stats
from scipy.spatial.distance import cdist
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data, Batch

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

# Import swarm components
from .formation_controller import FormationMember, Position3D, Velocity3D
from .byzantine_defense import ByzantineDefenseSystem, NodeReputation, AttackType
from .secure_communication import SecureSwarmCommunication, SwarmMessageType, MessagePriority

# Import AI components
sys.path.append(str(Path(__file__).parent.parent / "ai"))
from models.anomaly_detector import AnomalyDetector, AnomalyMethod, AnomalyType

logger = logging.getLogger(__name__)


class SwarmAnomalyType(Enum):
    """Types of swarm-specific anomalies."""
    # Movement anomalies
    FORMATION_DRIFT = "formation_drift"
    ABNORMAL_TRAJECTORY = "abnormal_trajectory"
    COLLISION_RISK = "collision_risk"
    SPEED_ANOMALY = "speed_anomaly"
    
    # Communication anomalies
    COMMUNICATION_JAMMING = "communication_jamming"
    MESSAGE_FLOODING = "message_flooding"
    SILENT_MEMBER = "silent_member"
    SUSPICIOUS_MESSAGING = "suspicious_messaging"
    
    # Sensor anomalies
    GPS_SPOOFING = "gps_spoofing"
    SENSOR_MALFUNCTION = "sensor_malfunction"
    DATA_MANIPULATION = "data_manipulation"
    
    # Behavioral anomalies
    COMPROMISED_MEMBER = "compromised_member"
    COORDINATED_ATTACK = "coordinated_attack"
    EMERGENT_BEHAVIOR = "emergent_behavior"
    MISSION_DEVIATION = "mission_deviation"
    
    # Hardware anomalies
    POWER_ANOMALY = "power_anomaly"
    HARDWARE_TAMPERING = "hardware_tampering"
    PERFORMANCE_DEGRADATION = "performance_degradation"


@dataclass
class SwarmMemberProfile:
    """Behavioral profile for a swarm member."""
    member_id: str
    
    # Movement profile
    avg_speed: float = 0.0
    speed_variance: float = 0.0
    typical_acceleration: float = 0.0
    movement_patterns: List[np.ndarray] = field(default_factory=list)
    
    # Communication profile
    message_frequency: float = 0.0  # messages per second
    typical_message_types: Dict[str, int] = field(default_factory=dict)
    response_time: float = 0.0  # average response latency
    
    # Sensor profile
    sensor_noise_levels: Dict[str, float] = field(default_factory=dict)
    sensor_update_rates: Dict[str, float] = field(default_factory=dict)
    
    # Performance profile
    avg_power_consumption: float = 0.0
    task_completion_rate: float = 1.0
    error_rate: float = 0.0
    
    # History tracking
    position_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    velocity_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    communication_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    # Trust metrics (from Byzantine defense)
    reputation_score: float = 100.0
    anomaly_count: int = 0
    last_anomaly: Optional[datetime] = None
    
    def update_position(self, position: Position3D, velocity: Velocity3D):
        """Update position and velocity history."""
        self.position_history.append((datetime.now(), position))
        self.velocity_history.append((datetime.now(), velocity))
        
        # Update speed statistics
        speeds = [v.magnitude() for _, v in self.velocity_history]
        if speeds:
            self.avg_speed = np.mean(speeds)
            self.speed_variance = np.var(speeds)


@dataclass
class SwarmAnomaly:
    """Detected swarm anomaly."""
    anomaly_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    anomaly_type: SwarmAnomalyType = SwarmAnomalyType.EMERGENT_BEHAVIOR
    timestamp: datetime = field(default_factory=datetime.now)
    affected_members: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    severity: str = "low"  # low, medium, high, critical
    
    # Detection details
    detection_method: str = ""
    feature_importance: Dict[str, float] = field(default_factory=dict)
    anomaly_score: float = 0.0
    
    # Context
    formation_state: Optional[str] = None
    mission_phase: Optional[str] = None
    environmental_factors: Dict[str, Any] = field(default_factory=dict)
    
    # Response
    recommended_actions: List[str] = field(default_factory=list)
    auto_response_triggered: bool = False


class SwarmTopologyGNN(nn.Module):
    """Graph Neural Network for swarm topology analysis."""
    
    def __init__(self, node_features: int = 10, hidden_dim: int = 64, output_dim: int = 32):
        super(SwarmTopologyGNN, self).__init__()
        self.conv1 = GCNConv(node_features, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, output_dim)
        self.dropout = nn.Dropout(0.2)
        
        # Anomaly detection head
        self.anomaly_head = nn.Sequential(
            nn.Linear(output_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x, edge_index, batch):
        """Forward pass through GNN."""
        # Graph convolutions
        x = F.relu(self.conv1(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.conv2(x, edge_index))
        x = self.dropout(x)
        x = self.conv3(x, edge_index)
        
        # Global pooling
        graph_embedding = global_mean_pool(x, batch)
        
        # Anomaly score
        anomaly_score = self.anomaly_head(graph_embedding)
        
        return x, anomaly_score


class BehaviorSequenceTransformer(nn.Module):
    """Transformer for behavior sequence analysis."""
    
    def __init__(self, input_dim: int = 7, d_model: int = 128, nhead: int = 8, num_layers: int = 3):
        super(BehaviorSequenceTransformer, self).__init__()
        self.input_projection = nn.Linear(input_dim, d_model)
        self.positional_encoding = nn.Parameter(torch.randn(1, 1000, d_model))
        
        encoder_layer = nn.TransformerEncoderLayer(d_model, nhead, dim_feedforward=512)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        
        self.anomaly_head = nn.Sequential(
            nn.Linear(d_model, 64),
            nn.ReLU(),
            nn.Linear(64, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        """Forward pass through transformer."""
        # x shape: (batch, sequence_length, features)
        seq_len = x.size(1)
        
        # Project input
        x = self.input_projection(x)
        
        # Add positional encoding
        x = x + self.positional_encoding[:, :seq_len, :]
        
        # Transformer expects (sequence_length, batch, features)
        x = x.transpose(0, 1)
        
        # Pass through transformer
        x = self.transformer(x)
        
        # Use last sequence output for anomaly detection
        x = x[-1]  # (batch, d_model)
        
        # Anomaly score
        anomaly_score = self.anomaly_head(x)
        
        return anomaly_score


class SwarmBehaviorAnalyzer:
    """Analyze swarm behaviors for anomalies."""
    
    def __init__(self, min_swarm_size: int = 3):
        self.min_swarm_size = min_swarm_size
        self.scaler = StandardScaler()
        
        # Movement analysis
        self.formation_tolerance = 0.2  # 20% deviation allowed
        self.speed_tolerance = 2.0  # standard deviations
        
        # Pattern storage
        self.normal_patterns: Dict[str, List[np.ndarray]] = {
            "formation": [],
            "trajectory": [],
            "coordination": []
        }
        
        # GPS spoofing detection
        self.gps_imu_threshold = 5.0  # meters
        self.gps_jump_threshold = 50.0  # meters per second
    
    def analyze_formation_coherence(
        self,
        members: List[FormationMember],
        expected_formation: Optional[str] = None
    ) -> Tuple[float, List[str]]:
        """Analyze formation coherence and detect drift."""
        if len(members) < self.min_swarm_size:
            return 1.0, []
        
        # Extract positions
        positions = np.array([
            [m.position.x, m.position.y, m.position.z]
            for m in members
        ])
        
        # Calculate pairwise distances
        distances = cdist(positions, positions)
        
        # Analyze formation structure
        # 1. Check variance in distances (should be consistent for formations)
        dist_variance = np.var(distances[distances > 0])
        expected_variance = self._get_expected_variance(expected_formation)
        
        # 2. Check centroid drift
        centroid = np.mean(positions, axis=0)
        member_distances_to_centroid = np.linalg.norm(positions - centroid, axis=1)
        
        # 3. Identify outliers
        outliers = []
        z_scores = stats.zscore(member_distances_to_centroid)
        for i, (z_score, member) in enumerate(zip(z_scores, members)):
            if abs(z_score) > 2.0:
                outliers.append(member.member_id)
        
        # Calculate coherence score
        variance_ratio = dist_variance / expected_variance if expected_variance > 0 else 1.0
        coherence_score = 1.0 / (1.0 + variance_ratio)
        
        return coherence_score, outliers
    
    def detect_gps_spoofing(
        self,
        member: FormationMember,
        gps_position: Position3D,
        imu_estimated_position: Position3D,
        last_known_position: Optional[Position3D] = None,
        dt: float = 0.1
    ) -> Tuple[bool, float, str]:
        """Detect GPS spoofing using sensor fusion."""
        # Method 1: GPS vs IMU discrepancy
        gps_imu_distance = gps_position.distance_to(imu_estimated_position)
        if gps_imu_distance > self.gps_imu_threshold:
            confidence = min(1.0, gps_imu_distance / (self.gps_imu_threshold * 2))
            return True, confidence, f"GPS-IMU mismatch: {gps_imu_distance:.2f}m"
        
        # Method 2: Impossible velocity jump
        if last_known_position:
            distance = gps_position.distance_to(last_known_position)
            implied_velocity = distance / dt
            
            if implied_velocity > self.gps_jump_threshold:
                confidence = min(1.0, implied_velocity / (self.gps_jump_threshold * 2))
                return True, confidence, f"Impossible velocity: {implied_velocity:.2f}m/s"
        
        # Method 3: Statistical anomaly in GPS noise
        # (Would need history of GPS readings)
        
        return False, 0.0, ""
    
    def detect_jamming_pattern(
        self,
        communication_history: List[Tuple[datetime, str, bool]],
        window_seconds: float = 10.0
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """Detect communication jamming patterns."""
        if not communication_history:
            return False, 0.0, {}
        
        now = datetime.now()
        window_start = now - timedelta(seconds=window_seconds)
        
        # Filter recent communications
        recent_comms = [
            (ts, member_id, success)
            for ts, member_id, success in communication_history
            if ts > window_start
        ]
        
        if not recent_comms:
            return False, 0.0, {}
        
        # Calculate failure rate
        failures = sum(1 for _, _, success in recent_comms if not success)
        failure_rate = failures / len(recent_comms)
        
        # Analyze temporal pattern
        failure_times = [ts for ts, _, success in recent_comms if not success]
        
        # Check for periodic jamming
        if len(failure_times) > 2:
            intervals = [
                (failure_times[i+1] - failure_times[i]).total_seconds()
                for i in range(len(failure_times) - 1)
            ]
            interval_variance = np.var(intervals) if intervals else float('inf')
            is_periodic = interval_variance < 1.0  # Low variance suggests periodic
        else:
            is_periodic = False
        
        # Jamming detected if high failure rate
        is_jamming = failure_rate > 0.3
        confidence = failure_rate if is_jamming else 0.0
        
        details = {
            "failure_rate": failure_rate,
            "total_attempts": len(recent_comms),
            "failures": failures,
            "is_periodic": is_periodic,
            "pattern": "periodic" if is_periodic else "random"
        }
        
        return is_jamming, confidence, details
    
    def _get_expected_variance(self, formation_type: Optional[str]) -> float:
        """Get expected distance variance for formation type."""
        variances = {
            "line": 10.0,
            "column": 10.0,
            "wedge": 15.0,
            "diamond": 20.0,
            "circle": 5.0,
            "box": 12.0
        }
        return variances.get(formation_type, 15.0)


class SwarmAnomalyDetector:
    """
    Main swarm anomaly detection system.
    
    Features:
    - Multi-layer behavioral analysis
    - AI/ML-powered detection
    - Byzantine fault correlation
    - Real-time threat assessment
    - Distributed consensus validation
    """
    
    def __init__(
        self,
        swarm_comm: SecureSwarmCommunication,
        byzantine_defense: ByzantineDefenseSystem,
        audit_logger: AuditLogger,
        enable_ml: bool = True
    ):
        self.swarm_comm = swarm_comm
        self.byzantine_defense = byzantine_defense
        self.audit_logger = audit_logger
        self.enable_ml = enable_ml
        
        # Components
        self.behavior_analyzer = SwarmBehaviorAnalyzer()
        self.base_anomaly_detector = AnomalyDetector()
        
        # Member profiles
        self.member_profiles: Dict[str, SwarmMemberProfile] = {}
        
        # ML models
        if self.enable_ml:
            self.gnn_model = SwarmTopologyGNN()
            self.transformer_model = BehaviorSequenceTransformer()
            self.ensemble_detector = IsolationForest(contamination=0.1, random_state=42)
        
        # Detection history
        self.anomaly_history: deque = deque(maxlen=10000)
        self.detection_consensus: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        
        # Metrics
        self.metrics = {
            "anomalies_detected": 0,
            "true_positives": 0,
            "false_positives": 0,
            "detection_latency_ms": deque(maxlen=1000),
            "consensus_time_ms": deque(maxlen=1000)
        }
        
        # Register message handlers
        self._register_handlers()
        
        logger.info("Swarm anomaly detector initialized with ML=%s", enable_ml)
    
    def _register_handlers(self):
        """Register communication handlers."""
        self.swarm_comm.register_handler(
            SwarmMessageType.ANOMALY_ALERT,
            self._handle_anomaly_alert
        )
        self.swarm_comm.register_handler(
            SwarmMessageType.CONSENSUS_REQUEST,
            self._handle_consensus_request
        )
    
    async def _handle_anomaly_alert(self, sender_id: str, message):
        """Handle anomaly alert from another member."""
        # Record in consensus
        anomaly_id = message.payload.get("anomaly_id")
        confidence = message.payload.get("confidence", 0.0)
        
        if anomaly_id:
            self.detection_consensus[anomaly_id].append((sender_id, confidence))
            
            # Check if consensus reached
            await self._check_consensus(anomaly_id)
    
    async def _handle_consensus_request(self, sender_id: str, message):
        """Handle consensus request for anomaly validation."""
        anomaly_data = message.payload.get("anomaly_data", {})
        
        # Perform local validation
        validation_result = await self._validate_anomaly(anomaly_data)
        
        # Send vote
        await self.swarm_comm.send_message(
            SwarmMessageType.CONSENSUS_VOTE,
            {
                "anomaly_id": anomaly_data.get("anomaly_id"),
                "vote": validation_result["is_valid"],
                "confidence": validation_result["confidence"]
            },
            target=sender_id,
            priority=MessagePriority.HIGH
        )
    
    def create_member_profile(self, member_id: str) -> SwarmMemberProfile:
        """Create or get member profile."""
        if member_id not in self.member_profiles:
            self.member_profiles[member_id] = SwarmMemberProfile(member_id=member_id)
        return self.member_profiles[member_id]
    
    async def update_member_state(
        self,
        member: FormationMember,
        sensor_data: Optional[Dict[str, Any]] = None,
        communication_stats: Optional[Dict[str, Any]] = None
    ):
        """Update member profile with latest state."""
        profile = self.create_member_profile(member.member_id)
        
        # Update position/velocity
        profile.update_position(member.position, member.velocity)
        
        # Update sensor data
        if sensor_data:
            for sensor, noise_level in sensor_data.get("noise_levels", {}).items():
                profile.sensor_noise_levels[sensor] = noise_level
        
        # Update communication stats
        if communication_stats:
            profile.message_frequency = communication_stats.get("message_frequency", 0.0)
            profile.response_time = communication_stats.get("avg_response_time", 0.0)
    
    async def detect_anomalies(
        self,
        swarm_members: List[FormationMember],
        formation_type: Optional[str] = None,
        sensor_data: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> List[SwarmAnomaly]:
        """Main anomaly detection pipeline."""
        start_time = time.time()
        detected_anomalies = []
        
        # 1. Formation analysis
        formation_anomalies = await self._detect_formation_anomalies(
            swarm_members, formation_type
        )
        detected_anomalies.extend(formation_anomalies)
        
        # 2. Individual member analysis
        for member in swarm_members:
            member_anomalies = await self._detect_member_anomalies(
                member,
                sensor_data.get(member.member_id, {}) if sensor_data else {}
            )
            detected_anomalies.extend(member_anomalies)
        
        # 3. Communication pattern analysis
        comm_anomalies = await self._detect_communication_anomalies()
        detected_anomalies.extend(comm_anomalies)
        
        # 4. ML-based detection (if enabled)
        if self.enable_ml and len(swarm_members) >= 3:
            ml_anomalies = await self._detect_ml_anomalies(swarm_members)
            detected_anomalies.extend(ml_anomalies)
        
        # 5. Correlate with Byzantine defense
        correlated_anomalies = await self._correlate_with_byzantine_defense(
            detected_anomalies
        )
        
        # Update metrics
        detection_time_ms = (time.time() - start_time) * 1000
        self.metrics["detection_latency_ms"].append(detection_time_ms)
        self.metrics["anomalies_detected"] += len(correlated_anomalies)
        
        # Store in history
        for anomaly in correlated_anomalies:
            self.anomaly_history.append(anomaly)
        
        # Broadcast high-confidence anomalies
        for anomaly in correlated_anomalies:
            if anomaly.confidence > 0.7 and anomaly.severity in ["high", "critical"]:
                await self._broadcast_anomaly(anomaly)
        
        return correlated_anomalies
    
    async def _detect_formation_anomalies(
        self,
        members: List[FormationMember],
        formation_type: Optional[str]
    ) -> List[SwarmAnomaly]:
        """Detect formation-related anomalies."""
        anomalies = []
        
        if len(members) < 3:
            return anomalies
        
        # Check formation coherence
        coherence_score, outliers = self.behavior_analyzer.analyze_formation_coherence(
            members, formation_type
        )
        
        if coherence_score < 0.7:  # Formation breaking apart
            anomaly = SwarmAnomaly(
                anomaly_type=SwarmAnomalyType.FORMATION_DRIFT,
                affected_members=outliers,
                confidence=1.0 - coherence_score,
                severity="medium" if coherence_score > 0.5 else "high",
                detection_method="formation_coherence_analysis",
                anomaly_score=1.0 - coherence_score,
                formation_state=formation_type,
                recommended_actions=[
                    "Verify member communications",
                    "Check for GPS interference",
                    "Initiate formation recovery protocol"
                ]
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    async def _detect_member_anomalies(
        self,
        member: FormationMember,
        sensor_data: Dict[str, Any]
    ) -> List[SwarmAnomaly]:
        """Detect anomalies for individual member."""
        anomalies = []
        profile = self.member_profiles.get(member.member_id)
        
        if not profile or len(profile.position_history) < 10:
            return anomalies
        
        # GPS spoofing detection
        if "gps" in sensor_data and "imu" in sensor_data:
            gps_pos = Position3D(**sensor_data["gps"]["position"])
            imu_pos = Position3D(**sensor_data["imu"]["estimated_position"])
            
            last_pos = profile.position_history[-2][1] if len(profile.position_history) > 1 else None
            
            is_spoofed, confidence, reason = self.behavior_analyzer.detect_gps_spoofing(
                member, gps_pos, imu_pos, last_pos
            )
            
            if is_spoofed:
                anomaly = SwarmAnomaly(
                    anomaly_type=SwarmAnomalyType.GPS_SPOOFING,
                    affected_members=[member.member_id],
                    confidence=confidence,
                    severity="critical",
                    detection_method="sensor_fusion_analysis",
                    anomaly_score=confidence,
                    environmental_factors={"spoofing_reason": reason},
                    recommended_actions=[
                        "Switch to IMU-only navigation",
                        "Alert other swarm members",
                        "Initiate GPS-denied protocol"
                    ]
                )
                anomalies.append(anomaly)
        
        # Speed anomaly detection
        if profile.velocity_history:
            current_speed = member.velocity.magnitude()
            z_score = abs((current_speed - profile.avg_speed) / 
                         (math.sqrt(profile.speed_variance) + 1e-6))
            
            if z_score > 3.0:  # 3 standard deviations
                anomaly = SwarmAnomaly(
                    anomaly_type=SwarmAnomalyType.SPEED_ANOMALY,
                    affected_members=[member.member_id],
                    confidence=min(1.0, z_score / 5.0),
                    severity="medium",
                    detection_method="statistical_analysis",
                    anomaly_score=z_score,
                    environmental_factors={
                        "current_speed": current_speed,
                        "expected_speed": profile.avg_speed,
                        "z_score": z_score
                    }
                )
                anomalies.append(anomaly)
        
        # Power anomaly detection
        if "power" in sensor_data:
            current_power = sensor_data["power"]["consumption"]
            if profile.avg_power_consumption > 0:
                power_ratio = current_power / profile.avg_power_consumption
                
                if power_ratio > 1.5 or power_ratio < 0.5:
                    anomaly = SwarmAnomaly(
                        anomaly_type=SwarmAnomalyType.POWER_ANOMALY,
                        affected_members=[member.member_id],
                        confidence=abs(1.0 - power_ratio) / 2.0,
                        severity="high" if power_ratio > 2.0 else "medium",
                        detection_method="power_analysis",
                        anomaly_score=abs(1.0 - power_ratio),
                        environmental_factors={
                            "current_power": current_power,
                            "expected_power": profile.avg_power_consumption,
                            "power_ratio": power_ratio
                        },
                        recommended_actions=[
                            "Check for hardware malfunction",
                            "Verify computational load",
                            "Inspect for physical damage"
                        ]
                    )
                    anomalies.append(anomaly)
        
        return anomalies
    
    async def _detect_communication_anomalies(self) -> List[SwarmAnomaly]:
        """Detect communication-related anomalies."""
        anomalies = []
        
        # Analyze each member's communication patterns
        for member_id, profile in self.member_profiles.items():
            if not profile.communication_history:
                continue
            
            # Check for jamming
            is_jammed, confidence, details = self.behavior_analyzer.detect_jamming_pattern(
                profile.communication_history
            )
            
            if is_jammed:
                anomaly = SwarmAnomaly(
                    anomaly_type=SwarmAnomalyType.COMMUNICATION_JAMMING,
                    affected_members=[member_id],
                    confidence=confidence,
                    severity="critical" if confidence > 0.7 else "high",
                    detection_method="temporal_pattern_analysis",
                    anomaly_score=confidence,
                    environmental_factors=details,
                    recommended_actions=[
                        "Switch to alternative frequency",
                        "Increase transmission power",
                        "Use mesh routing through other members"
                    ]
                )
                anomalies.append(anomaly)
            
            # Check for silent members
            if profile.message_frequency > 0:
                time_since_last = (datetime.now() - profile.communication_history[-1][0]).total_seconds()
                expected_interval = 1.0 / profile.message_frequency
                
                if time_since_last > expected_interval * 5:  # 5x expected interval
                    anomaly = SwarmAnomaly(
                        anomaly_type=SwarmAnomalyType.SILENT_MEMBER,
                        affected_members=[member_id],
                        confidence=min(1.0, time_since_last / (expected_interval * 10)),
                        severity="high",
                        detection_method="communication_timeout",
                        anomaly_score=time_since_last / expected_interval,
                        environmental_factors={
                            "last_communication": time_since_last,
                            "expected_interval": expected_interval
                        }
                    )
                    anomalies.append(anomaly)
        
        return anomalies
    
    async def _detect_ml_anomalies(self, members: List[FormationMember]) -> List[SwarmAnomaly]:
        """ML-based anomaly detection."""
        anomalies = []
        
        try:
            # Prepare data for GNN
            node_features = []
            edge_list = []
            
            for i, member in enumerate(members):
                profile = self.member_profiles.get(member.member_id)
                if not profile:
                    continue
                
                # Node features: position, velocity, reputation
                features = [
                    member.position.x, member.position.y, member.position.z,
                    member.velocity.vx, member.velocity.vy, member.velocity.vz,
                    profile.reputation_score / 100.0,
                    profile.avg_speed,
                    profile.message_frequency,
                    profile.anomaly_count / 10.0  # Normalized
                ]
                node_features.append(features)
                
                # Create edges based on communication range
                for j, other in enumerate(members):
                    if i != j:
                        distance = member.position.distance_to(other.position)
                        if distance < member.communication_range:
                            edge_list.append([i, j])
            
            if node_features and edge_list:
                # Convert to tensors
                x = torch.tensor(node_features, dtype=torch.float32)
                edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
                batch = torch.zeros(len(node_features), dtype=torch.long)
                
                # Run GNN
                with torch.no_grad():
                    node_embeddings, anomaly_score = self.gnn_model(x, edge_index, batch)
                
                # Check for anomalies
                if anomaly_score.item() > 0.7:
                    # Identify most anomalous nodes
                    node_anomaly_scores = torch.norm(node_embeddings - node_embeddings.mean(0), dim=1)
                    anomalous_indices = torch.where(node_anomaly_scores > node_anomaly_scores.mean() + 2 * node_anomaly_scores.std())[0]
                    
                    affected_members = [members[idx.item()].member_id for idx in anomalous_indices]
                    
                    anomaly = SwarmAnomaly(
                        anomaly_type=SwarmAnomalyType.EMERGENT_BEHAVIOR,
                        affected_members=affected_members,
                        confidence=anomaly_score.item(),
                        severity="high",
                        detection_method="graph_neural_network",
                        anomaly_score=anomaly_score.item(),
                        feature_importance={
                            "topology_score": anomaly_score.item(),
                            "affected_nodes": len(affected_members)
                        }
                    )
                    anomalies.append(anomaly)
            
            # Behavior sequence analysis with transformer
            for member in members:
                profile = self.member_profiles.get(member.member_id)
                if not profile or len(profile.position_history) < 50:
                    continue
                
                # Prepare sequence data
                sequence = []
                for (ts, pos), (_, vel) in zip(
                    list(profile.position_history)[-50:],
                    list(profile.velocity_history)[-50:]
                ):
                    sequence.append([
                        pos.x, pos.y, pos.z,
                        vel.vx, vel.vy, vel.vz,
                        profile.reputation_score / 100.0
                    ])
                
                if len(sequence) >= 10:
                    x = torch.tensor([sequence], dtype=torch.float32)
                    
                    with torch.no_grad():
                        anomaly_score = self.transformer_model(x)
                    
                    if anomaly_score.item() > 0.8:
                        anomaly = SwarmAnomaly(
                            anomaly_type=SwarmAnomalyType.ABNORMAL_TRAJECTORY,
                            affected_members=[member.member_id],
                            confidence=anomaly_score.item(),
                            severity="high",
                            detection_method="transformer_sequence_analysis",
                            anomaly_score=anomaly_score.item()
                        )
                        anomalies.append(anomaly)
        
        except Exception as e:
            logger.error("ML anomaly detection failed: %s", e)
        
        return anomalies
    
    async def _correlate_with_byzantine_defense(
        self,
        anomalies: List[SwarmAnomaly]
    ) -> List[SwarmAnomaly]:
        """Correlate anomalies with Byzantine defense system."""
        correlated_anomalies = []
        
        for anomaly in anomalies:
            # Check if affected members have Byzantine attacks detected
            byzantine_correlation = False
            
            for member_id in anomaly.affected_members:
                # Get attack history from Byzantine defense
                member_attacks = self.byzantine_defense.get_node_attacks(member_id)
                
                if member_attacks:
                    # Recent attacks increase anomaly confidence
                    recent_attacks = [
                        attack for attack, timestamp in member_attacks
                        if (datetime.now() - timestamp).total_seconds() < 60
                    ]
                    
                    if recent_attacks:
                        byzantine_correlation = True
                        anomaly.confidence = min(1.0, anomaly.confidence * 1.2)
                        anomaly.detection_method += "+byzantine_correlation"
                        
                        # Upgrade severity if coordinated attack
                        if AttackType.COLLUSION in recent_attacks:
                            anomaly.severity = "critical"
                            anomaly.anomaly_type = SwarmAnomalyType.COORDINATED_ATTACK
            
            correlated_anomalies.append(anomaly)
        
        return correlated_anomalies
    
    async def _broadcast_anomaly(self, anomaly: SwarmAnomaly):
        """Broadcast high-confidence anomaly to swarm."""
        await self.swarm_comm.send_anomaly_alert(
            anomaly_type=anomaly.anomaly_type.value,
            confidence=anomaly.confidence,
            affected_members=anomaly.affected_members,
            details={
                "anomaly_id": anomaly.anomaly_id,
                "severity": anomaly.severity,
                "detection_method": anomaly.detection_method,
                "recommended_actions": anomaly.recommended_actions
            }
        )
        
        # Log critical anomalies
        if anomaly.severity == "critical":
            await self.audit_logger.log_event(
                "SWARM_CRITICAL_ANOMALY",
                classification=ClassificationLevel.SECRET,
                details={
                    "anomaly_type": anomaly.anomaly_type.value,
                    "affected_members": anomaly.affected_members,
                    "confidence": anomaly.confidence,
                    "detection_method": anomaly.detection_method
                }
            )
    
    async def _check_consensus(self, anomaly_id: str):
        """Check if consensus reached for anomaly."""
        votes = self.detection_consensus.get(anomaly_id, [])
        
        if len(votes) >= 3:  # Minimum votes for consensus
            # Calculate average confidence
            avg_confidence = np.mean([conf for _, conf in votes])
            
            if avg_confidence > 0.6:  # Consensus threshold
                logger.info("Consensus reached for anomaly %s: %.2f confidence",
                          anomaly_id, avg_confidence)
                
                # Clear consensus tracking
                del self.detection_consensus[anomaly_id]
    
    async def _validate_anomaly(self, anomaly_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate anomaly reported by another member."""
        # Perform local checks based on anomaly type
        anomaly_type = anomaly_data.get("anomaly_type")
        affected_members = anomaly_data.get("affected_members", [])
        
        validation_confidence = 0.5  # Default neutral
        
        # Check our local observations
        for member_id in affected_members:
            profile = self.member_profiles.get(member_id)
            if profile:
                # Check if we've seen similar anomalies
                if profile.anomaly_count > 0:
                    validation_confidence += 0.1
                
                # Check reputation
                if profile.reputation_score < 50:
                    validation_confidence += 0.2
        
        return {
            "is_valid": validation_confidence > 0.5,
            "confidence": min(1.0, validation_confidence)
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get detection metrics."""
        avg_latency = np.mean(self.metrics["detection_latency_ms"]) if self.metrics["detection_latency_ms"] else 0
        
        return {
            "anomalies_detected": self.metrics["anomalies_detected"],
            "true_positives": self.metrics["true_positives"],
            "false_positives": self.metrics["false_positives"],
            "avg_detection_latency_ms": avg_latency,
            "active_profiles": len(self.member_profiles),
            "ml_enabled": self.enable_ml
        }