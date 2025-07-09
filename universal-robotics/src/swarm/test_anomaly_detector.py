#!/usr/bin/env python3
"""
Test suite for ALCUB3 Swarm Anomaly Detection System
Tests all major functionality including GPS spoofing detection,
jamming detection, formation analysis, and ML-based detection.
"""

import asyncio
import unittest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
import numpy as np
import torch

# Import components to test
from .anomaly_detector import (
    SwarmAnomalyDetector,
    SwarmBehaviorAnalyzer,
    SwarmMemberProfile,
    SwarmAnomaly,
    SwarmAnomalyType,
    SwarmTopologyGNN,
    BehaviorSequenceTransformer
)
from .formation_controller import FormationMember, Position3D, Velocity3D, FormationRole
from .byzantine_defense import ByzantineDefenseSystem, AttackType
from .secure_communication import SecureSwarmCommunication, SwarmMessageType

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger


class TestSwarmBehaviorAnalyzer(unittest.TestCase):
    """Test SwarmBehaviorAnalyzer class."""
    
    def setUp(self):
        self.analyzer = SwarmBehaviorAnalyzer()
    
    def test_formation_coherence_analysis(self):
        """Test formation coherence analysis."""
        # Create a simple line formation
        members = []
        for i in range(5):
            member = FormationMember(
                member_id=f"drone_{i}",
                position=Position3D(x=i * 10, y=0, z=10),  # 10m spacing
                velocity=Velocity3D(vx=5, vy=0, vz=0),
                heading=0,
                role=FormationRole.CENTER
            )
            members.append(member)
        
        # Test normal formation
        coherence, outliers = self.analyzer.analyze_formation_coherence(members, "line")
        self.assertGreater(coherence, 0.8)
        self.assertEqual(len(outliers), 0)
        
        # Add an outlier
        members[2].position.x = 50  # Way off formation
        coherence, outliers = self.analyzer.analyze_formation_coherence(members, "line")
        self.assertLess(coherence, 0.7)
        self.assertIn("drone_2", outliers)
    
    def test_gps_spoofing_detection(self):
        """Test GPS spoofing detection."""
        member = FormationMember(
            member_id="test_drone",
            position=Position3D(x=0, y=0, z=10),
            velocity=Velocity3D(vx=5, vy=0, vz=0),
            heading=0,
            role=FormationRole.CENTER
        )
        
        # Test case 1: GPS vs IMU mismatch
        gps_pos = Position3D(x=20, y=0, z=10)  # 20m off
        imu_pos = Position3D(x=0, y=0, z=10)
        
        is_spoofed, confidence, reason = self.analyzer.detect_gps_spoofing(
            member, gps_pos, imu_pos
        )
        self.assertTrue(is_spoofed)
        self.assertGreater(confidence, 0.5)
        self.assertIn("GPS-IMU mismatch", reason)
        
        # Test case 2: Impossible velocity jump
        last_pos = Position3D(x=0, y=0, z=10)
        gps_pos = Position3D(x=100, y=0, z=10)  # 100m jump in 0.1s = 1000m/s
        
        is_spoofed, confidence, reason = self.analyzer.detect_gps_spoofing(
            member, gps_pos, imu_pos, last_pos, dt=0.1
        )
        self.assertTrue(is_spoofed)
        self.assertGreater(confidence, 0.8)
        self.assertIn("Impossible velocity", reason)
    
    def test_jamming_pattern_detection(self):
        """Test communication jamming detection."""
        # Create communication history with failures
        now = datetime.now()
        comm_history = []
        
        # Normal pattern - few failures
        for i in range(10):
            comm_history.append((now - timedelta(seconds=i), "drone_1", True))
        comm_history.append((now - timedelta(seconds=5), "drone_1", False))
        
        is_jammed, confidence, details = self.analyzer.detect_jamming_pattern(
            comm_history, window_seconds=10
        )
        self.assertFalse(is_jammed)
        self.assertLess(confidence, 0.3)
        
        # Jamming pattern - many failures
        jamming_history = []
        for i in range(10):
            success = i % 3 != 0  # 30% failure rate
            jamming_history.append((now - timedelta(seconds=i), "drone_1", success))
        
        is_jammed, confidence, details = self.analyzer.detect_jamming_pattern(
            jamming_history, window_seconds=10
        )
        self.assertTrue(is_jammed)
        self.assertGreater(confidence, 0.3)
        self.assertAlmostEqual(details["failure_rate"], 0.3, places=1)


class TestSwarmMemberProfile(unittest.TestCase):
    """Test SwarmMemberProfile class."""
    
    def test_profile_update(self):
        """Test profile updates."""
        profile = SwarmMemberProfile(member_id="test_drone")
        
        # Update positions and velocities
        for i in range(100):
            pos = Position3D(x=i, y=0, z=10)
            vel = Velocity3D(vx=5.0 + np.random.normal(0, 0.1), vy=0, vz=0)
            profile.update_position(pos, vel)
        
        # Check statistics
        self.assertAlmostEqual(profile.avg_speed, 5.0, places=1)
        self.assertGreater(profile.speed_variance, 0)
        self.assertEqual(len(profile.position_history), 100)


class TestSwarmAnomalyDetector(unittest.IsolatedAsyncioTestCase):
    """Test main SwarmAnomalyDetector class."""
    
    async def asyncSetUp(self):
        """Set up test fixtures."""
        # Mock dependencies
        self.mock_comm = Mock(spec=SecureSwarmCommunication)
        self.mock_byzantine = Mock(spec=ByzantineDefenseSystem)
        self.mock_logger = Mock(spec=AuditLogger)
        
        # Mock Byzantine defense methods
        self.mock_byzantine.get_node_attacks = Mock(return_value=[])
        
        # Create detector
        self.detector = SwarmAnomalyDetector(
            swarm_comm=self.mock_comm,
            byzantine_defense=self.mock_byzantine,
            audit_logger=self.mock_logger,
            enable_ml=True
        )
    
    async def test_member_state_update(self):
        """Test member state updates."""
        member = FormationMember(
            member_id="test_drone",
            position=Position3D(x=0, y=0, z=10),
            velocity=Velocity3D(vx=5, vy=0, vz=0),
            heading=0,
            role=FormationRole.CENTER
        )
        
        sensor_data = {
            "noise_levels": {"gps": 0.1, "imu": 0.05},
            "power": {"consumption": 50.0}
        }
        
        await self.detector.update_member_state(member, sensor_data=sensor_data)
        
        profile = self.detector.member_profiles["test_drone"]
        self.assertEqual(profile.member_id, "test_drone")
        self.assertEqual(profile.sensor_noise_levels["gps"], 0.1)
    
    async def test_formation_anomaly_detection(self):
        """Test formation anomaly detection."""
        # Create formation with one outlier
        members = []
        for i in range(5):
            x = i * 10 if i != 2 else 50  # drone_2 is way off
            member = FormationMember(
                member_id=f"drone_{i}",
                position=Position3D(x=x, y=0, z=10),
                velocity=Velocity3D(vx=5, vy=0, vz=0),
                heading=0,
                role=FormationRole.CENTER
            )
            members.append(member)
            
            # Create profiles
            self.detector.create_member_profile(f"drone_{i}")
        
        anomalies = await self.detector._detect_formation_anomalies(members, "line")
        
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, SwarmAnomalyType.FORMATION_DRIFT)
        self.assertIn("drone_2", anomalies[0].affected_members)
        self.assertGreater(anomalies[0].confidence, 0.3)
    
    async def test_gps_spoofing_anomaly_detection(self):
        """Test GPS spoofing anomaly detection."""
        member = FormationMember(
            member_id="test_drone",
            position=Position3D(x=0, y=0, z=10),
            velocity=Velocity3D(vx=5, vy=0, vz=0),
            heading=0,
            role=FormationRole.CENTER
        )
        
        # Create profile with history
        profile = self.detector.create_member_profile("test_drone")
        for i in range(20):
            profile.update_position(
                Position3D(x=i*0.5, y=0, z=10),
                Velocity3D(vx=5, vy=0, vz=0)
            )
        
        # Spoofed GPS data
        sensor_data = {
            "gps": {"position": {"x": 50, "y": 0, "z": 10}},  # Jumped 40m
            "imu": {"estimated_position": {"x": 10, "y": 0, "z": 10}}
        }
        
        anomalies = await self.detector._detect_member_anomalies(member, sensor_data)
        
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, SwarmAnomalyType.GPS_SPOOFING)
        self.assertEqual(anomalies[0].severity, "critical")
        self.assertGreater(anomalies[0].confidence, 0.5)
    
    async def test_power_anomaly_detection(self):
        """Test power anomaly detection."""
        member = FormationMember(
            member_id="test_drone",
            position=Position3D(x=0, y=0, z=10),
            velocity=Velocity3D(vx=5, vy=0, vz=0),
            heading=0,
            role=FormationRole.CENTER
        )
        
        # Create profile with power baseline
        profile = self.detector.create_member_profile("test_drone")
        profile.avg_power_consumption = 50.0
        
        # Abnormal power consumption
        sensor_data = {
            "power": {"consumption": 150.0}  # 3x normal
        }
        
        anomalies = await self.detector._detect_member_anomalies(member, sensor_data)
        
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, SwarmAnomalyType.POWER_ANOMALY)
        self.assertGreater(anomalies[0].confidence, 0.5)
    
    async def test_communication_anomaly_detection(self):
        """Test communication anomaly detection."""
        # Create profile with communication history
        profile = self.detector.create_member_profile("test_drone")
        profile.message_frequency = 10.0  # 10 msgs/sec normally
        
        now = datetime.now()
        # Add normal communication pattern
        for i in range(20):
            profile.communication_history.append(
                (now - timedelta(seconds=i*0.1), "other_drone", True)
            )
        
        # Simulate jamming
        for i in range(10):
            success = i % 3 == 0  # 70% failure
            profile.communication_history.append(
                (now - timedelta(seconds=i*0.05), "other_drone", success)
            )
        
        anomalies = await self.detector._detect_communication_anomalies()
        
        # Should detect jamming
        jamming_anomalies = [a for a in anomalies if a.anomaly_type == SwarmAnomalyType.COMMUNICATION_JAMMING]
        self.assertGreater(len(jamming_anomalies), 0)
    
    async def test_ml_anomaly_detection(self):
        """Test ML-based anomaly detection."""
        # Create swarm with anomalous member
        members = []
        for i in range(5):
            member = FormationMember(
                member_id=f"drone_{i}",
                position=Position3D(x=i*10, y=0, z=10),
                velocity=Velocity3D(vx=5, vy=0, vz=0),
                heading=0,
                role=FormationRole.CENTER
            )
            members.append(member)
            
            # Create profiles
            profile = self.detector.create_member_profile(f"drone_{i}")
            profile.reputation_score = 90.0 if i != 2 else 30.0  # drone_2 has low reputation
            profile.anomaly_count = 0 if i != 2 else 5
            
            # Add position history for transformer
            for j in range(60):
                profile.update_position(
                    Position3D(x=i*10 + j*0.1, y=0, z=10),
                    Velocity3D(vx=5, vy=0, vz=0)
                )
        
        # Test GNN detection
        with patch.object(self.detector.gnn_model, 'forward') as mock_gnn:
            # Mock high anomaly score
            mock_output = torch.randn(5, 32), torch.tensor([0.8])
            mock_gnn.return_value = mock_output
            
            anomalies = await self.detector._detect_ml_anomalies(members)
            
            # Should detect emergent behavior
            self.assertTrue(any(a.anomaly_type == SwarmAnomalyType.EMERGENT_BEHAVIOR for a in anomalies))
    
    async def test_byzantine_correlation(self):
        """Test correlation with Byzantine defense."""
        anomaly = SwarmAnomaly(
            anomaly_type=SwarmAnomalyType.COMPROMISED_MEMBER,
            affected_members=["drone_1"],
            confidence=0.6,
            severity="medium"
        )
        
        # Mock Byzantine attacks
        self.mock_byzantine.get_node_attacks.return_value = [
            (AttackType.DOUBLE_VOTING, datetime.now() - timedelta(seconds=30)),
            (AttackType.COLLUSION, datetime.now() - timedelta(seconds=10))
        ]
        
        correlated = await self.detector._correlate_with_byzantine_defense([anomaly])
        
        # Should upgrade severity and confidence
        self.assertEqual(correlated[0].severity, "critical")
        self.assertGreater(correlated[0].confidence, 0.6)
        self.assertEqual(correlated[0].anomaly_type, SwarmAnomalyType.COORDINATED_ATTACK)
    
    async def test_full_detection_pipeline(self):
        """Test full anomaly detection pipeline."""
        # Create realistic swarm
        members = []
        for i in range(10):
            member = FormationMember(
                member_id=f"drone_{i}",
                position=Position3D(x=i*10, y=0, z=10),
                velocity=Velocity3D(vx=5, vy=0, vz=0),
                heading=0,
                role=FormationRole.CENTER
            )
            members.append(member)
        
        # Create sensor data
        sensor_data = {}
        for i, member in enumerate(members):
            sensor_data[member.member_id] = {
                "gps": {"position": {"x": i*10, "y": 0, "z": 10}},
                "imu": {"estimated_position": {"x": i*10, "y": 0, "z": 10}},
                "power": {"consumption": 50.0}
            }
        
        # Add anomalous data for one drone
        sensor_data["drone_5"]["gps"]["position"]["x"] = 100  # GPS spoofing
        
        # Run detection
        anomalies = await self.detector.detect_anomalies(
            members,
            formation_type="line",
            sensor_data=sensor_data
        )
        
        # Verify metrics updated
        self.assertGreater(self.detector.metrics["anomalies_detected"], 0)
        self.assertGreater(len(self.detector.metrics["detection_latency_ms"]), 0)
        
        # Verify anomaly broadcast called for critical anomalies
        if any(a.severity == "critical" for a in anomalies):
            self.mock_comm.send_anomaly_alert.assert_called()


class TestMLModels(unittest.TestCase):
    """Test ML model architectures."""
    
    def test_gnn_model(self):
        """Test GNN model forward pass."""
        model = SwarmTopologyGNN(node_features=10, hidden_dim=32, output_dim=16)
        
        # Create sample graph
        x = torch.randn(5, 10)  # 5 nodes, 10 features
        edge_index = torch.tensor([[0, 1, 2, 3, 4, 0, 1, 2, 3],
                                  [1, 2, 3, 4, 0, 2, 3, 4, 0]], dtype=torch.long)
        batch = torch.zeros(5, dtype=torch.long)
        
        # Forward pass
        node_embeddings, anomaly_score = model(x, edge_index, batch)
        
        self.assertEqual(node_embeddings.shape, (5, 16))
        self.assertEqual(anomaly_score.shape, (1, 1))
        self.assertTrue(0 <= anomaly_score.item() <= 1)
    
    def test_transformer_model(self):
        """Test transformer model forward pass."""
        model = BehaviorSequenceTransformer(input_dim=7, d_model=64, nhead=4, num_layers=2)
        
        # Create sample sequence
        batch_size = 2
        seq_length = 50
        x = torch.randn(batch_size, seq_length, 7)
        
        # Forward pass
        anomaly_score = model(x)
        
        self.assertEqual(anomaly_score.shape, (batch_size, 1))
        self.assertTrue(all(0 <= score <= 1 for score in anomaly_score.squeeze()))


class TestIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for anomaly detection system."""
    
    async def test_consensus_mechanism(self):
        """Test distributed anomaly consensus."""
        # Create multiple detectors (simulating different swarm members)
        detectors = []
        for i in range(3):
            mock_comm = Mock(spec=SecureSwarmCommunication)
            mock_byzantine = Mock(spec=ByzantineDefenseSystem)
            mock_logger = Mock(spec=AuditLogger)
            mock_byzantine.get_node_attacks = Mock(return_value=[])
            
            detector = SwarmAnomalyDetector(
                swarm_comm=mock_comm,
                byzantine_defense=mock_byzantine,
                audit_logger=mock_logger,
                enable_ml=False
            )
            detectors.append(detector)
        
        # Simulate anomaly detection and consensus
        anomaly_id = "test_anomaly_123"
        
        # Each detector votes
        for i, detector in enumerate(detectors):
            detector.detection_consensus[anomaly_id].append((f"drone_{i}", 0.8))
        
        # Check consensus
        await detectors[0]._check_consensus(anomaly_id)
        
        # Consensus should be cleared after reaching threshold
        self.assertNotIn(anomaly_id, detectors[0].detection_consensus)


if __name__ == "__main__":
    unittest.main()