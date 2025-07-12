#!/usr/bin/env python3
"""
ALCUB3 Formation Controller Test Suite
Comprehensive tests for swarm formation control with Byzantine fault tolerance

This module tests distributed formation algorithms, collision avoidance,
dynamic reconfiguration, and Byzantine resilience.
"""

import asyncio
import time
import uuid
import math
import random
import numpy as np
import pytest
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass

# Import formation components
from .formation_controller import (
    FormationController, FormationType, FormationRole, FormationConstraints,
    FormationMember, FormationState, Position3D, Velocity3D,
    CollisionAvoidanceSystem, CollisionRisk, CollisionType,
    DynamicReconfigurationEngine, FormationPattern,
    LineFormation, WedgeFormation, DiamondFormation, CircleFormation
)

# Import swarm components
from .distributed_task_allocator import SwarmConfiguration
from .consensus_engine import ByzantineFaultTolerantEngine, CryptoCredentials
from .byzantine_defense import ByzantineDefenseSystem

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.real_time_monitor import RealTimeSecurityMonitor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TestScenario:
    """Test scenario configuration."""
    name: str
    num_members: int
    formation_type: FormationType
    constraints: FormationConstraints
    byzantine_members: int = 0
    obstacles: List[Tuple[Position3D, float]] = None
    duration_seconds: int = 30
    
    def __post_init__(self):
        if self.obstacles is None:
            self.obstacles = []


class FormationControllerTestSuite:
    """Comprehensive test suite for formation control."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.monitor = RealTimeSecurityMonitor()
        self.test_results = []
        
    def _create_test_controller(self, node_id: str = "test_node") -> FormationController:
        """Create a test formation controller."""
        # Create minimal consensus engine
        credentials = self._generate_test_credentials(10)
        consensus_engine = ByzantineFaultTolerantEngine(
            node_id,
            credentials,
            ClassificationLevel.UNCLASSIFIED,
            self.audit_logger
        )
        
        # Create swarm configuration
        swarm_config = SwarmConfiguration(
            min_consensus_ratio=0.67,
            max_allocation_time_ms=50.0,
            byzantine_fault_threshold=0.33
        )
        
        return FormationController(
            node_id,
            consensus_engine,
            swarm_config,
            self.audit_logger,
            self.monitor
        )
    
    def _generate_test_credentials(self, num_nodes: int) -> Dict[str, CryptoCredentials]:
        """Generate test credentials for nodes."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        credentials = {}
        
        for i in range(num_nodes):
            node_id = f"node_{i:03d}"
            
            # Generate keys
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            credentials[node_id] = CryptoCredentials(
                member_id=node_id,
                private_key=private_key,
                public_key=private_key.public_key(),
                classification_level=ClassificationLevel.UNCLASSIFIED
            )
        
        return credentials
    
    @pytest.mark.asyncio
    async def test_formation_creation(self):
        """Test basic formation creation."""
        controller = self._create_test_controller()
        
        # Test different formation types
        formation_types = [
            FormationType.LINE,
            FormationType.WEDGE,
            FormationType.DIAMOND,
            FormationType.CIRCLE,
            FormationType.BOX
        ]
        
        for formation_type in formation_types:
            member_ids = [f"member_{i}" for i in range(6)]
            constraints = FormationConstraints(min_separation=5.0, max_separation=20.0)
            
            success, formation_id = await controller.create_formation(
                formation_type,
                member_ids,
                constraints
            )
            
            assert success, f"Failed to create {formation_type.value} formation"
            assert formation_id is not None
            assert controller.current_formation is not None
            assert controller.current_formation.formation_type == formation_type
            assert len(controller.members) == len(member_ids)
            
            # Verify positions
            for member in controller.members.values():
                assert member.target_position is not None
                assert member.role is not None
    
    @pytest.mark.asyncio
    async def test_collision_avoidance(self):
        """Test collision avoidance system."""
        controller = self._create_test_controller()
        collision_system = controller.collision_system
        
        # Create two members on collision course
        member_a = FormationMember(
            member_id="member_a",
            position=Position3D(0, 0, 0),
            velocity=Velocity3D(10, 0, 0),  # Moving right
            heading=0,
            role=FormationRole.CENTER
        )
        
        member_b = FormationMember(
            member_id="member_b",
            position=Position3D(20, 0, 0),
            velocity=Velocity3D(-10, 0, 0),  # Moving left
            heading=math.pi,
            role=FormationRole.CENTER
        )
        
        # Detect collision risks
        risks = await collision_system.detect_collision_risks(
            [member_a, member_b],
            prediction_time=3.0
        )
        
        assert len(risks) > 0, "Should detect collision risk"
        
        risk = risks[0]
        assert risk.risk_type == CollisionType.MEMBER_TO_MEMBER
        assert risk.time_to_collision < 2.0  # Should collide in ~1 second
        assert risk.probability > 0.8
        assert risk.avoidance_vector is not None
    
    @pytest.mark.asyncio
    async def test_formation_maintenance(self):
        """Test formation maintenance with perturbations."""
        controller = self._create_test_controller()
        
        # Create formation
        member_ids = [f"member_{i}" for i in range(5)]
        constraints = FormationConstraints()
        
        success, formation_id = await controller.create_formation(
            FormationType.DIAMOND,
            member_ids,
            constraints
        )
        
        assert success
        
        # Apply perturbations
        for member in controller.members.values():
            # Add random displacement
            member.position.x += random.uniform(-2, 2)
            member.position.y += random.uniform(-2, 2)
        
        # Maintain formation for several steps
        initial_coherence = controller.current_formation.coherence
        
        for _ in range(10):
            await controller.maintain_formation(time_delta=0.1)
        
        # Check formation recovery
        final_coherence = controller.current_formation.coherence
        assert final_coherence > initial_coherence * 0.8, "Formation should recover"
        
        # Verify members moving toward targets
        for member in controller.members.values():
            if member.target_position:
                distance = member.position.distance_to(member.target_position)
                assert distance < 10.0, "Members should approach targets"
    
    @pytest.mark.asyncio
    async def test_formation_morphing(self):
        """Test smooth formation transitions."""
        controller = self._create_test_controller()
        
        # Create initial formation
        member_ids = [f"member_{i}" for i in range(8)]
        constraints = FormationConstraints()
        
        success, _ = await controller.create_formation(
            FormationType.LINE,
            member_ids,
            constraints
        )
        assert success
        
        # Record initial positions
        initial_positions = {
            m_id: m.position for m_id, m in controller.members.items()
        }
        
        # Morph to circle formation
        morph_success = await controller.morph_formation(
            FormationType.CIRCLE,
            transition_time=2.0
        )
        
        assert morph_success
        assert controller.morphing_in_progress
        assert controller.current_formation.formation_type == FormationType.CIRCLE
        
        # Wait for morphing to complete
        await asyncio.sleep(2.5)
        
        assert not controller.morphing_in_progress
        
        # Verify new formation
        for member in controller.members.values():
            assert member.role is not None
            # Check that members moved
            initial_pos = initial_positions[member.member_id]
            assert member.position.distance_to(initial_pos) > 0.1
    
    @pytest.mark.asyncio
    async def test_byzantine_resilience(self):
        """Test formation control with Byzantine members."""
        controller = self._create_test_controller()
        
        # Create formation with some Byzantine members
        member_ids = [f"member_{i}" for i in range(10)]
        constraints = FormationConstraints()
        
        success, _ = await controller.create_formation(
            FormationType.BOX,
            member_ids,
            constraints
        )
        assert success
        
        # Mark 3 members as Byzantine (30%)
        byzantine_ids = random.sample(member_ids, 3)
        for b_id in byzantine_ids:
            if b_id in controller.members:
                controller.members[b_id].is_byzantine = True
        
        # Byzantine members don't follow formation
        for b_id in byzantine_ids:
            if b_id in controller.members:
                member = controller.members[b_id]
                # Move to random position
                member.position = Position3D(
                    random.uniform(-50, 50),
                    random.uniform(-50, 50),
                    0
                )
        
        # Maintain formation
        for _ in range(20):
            await controller.maintain_formation(time_delta=0.1)
        
        # Check that non-Byzantine members maintain formation
        non_byzantine_members = [
            m for m in controller.members.values() 
            if not m.is_byzantine
        ]
        
        formation_errors = []
        for member in non_byzantine_members:
            if member.target_position:
                error = member.position.distance_to(member.target_position)
                formation_errors.append(error)
        
        avg_error = np.mean(formation_errors) if formation_errors else 0
        assert avg_error < 5.0, "Non-Byzantine members should maintain formation"
        
        # Test member failure handling
        failed_member = non_byzantine_members[0].member_id
        handled = await controller.handle_member_failure(failed_member)
        
        assert handled
        assert failed_member not in controller.members
        assert len(controller.members) == 9
    
    @pytest.mark.asyncio
    async def test_obstacle_avoidance(self):
        """Test formation navigation with obstacles."""
        controller = self._create_test_controller()
        
        # Add obstacles
        obstacles = [
            ("obs_1", Position3D(20, 0, 0), 5.0),
            ("obs_2", Position3D(0, 20, 0), 8.0),
            ("obs_3", Position3D(-20, -20, 0), 6.0)
        ]
        
        for obs_id, pos, radius in obstacles:
            controller.collision_system.add_obstacle(obs_id, pos, radius)
        
        # Create formation
        member_ids = [f"member_{i}" for i in range(6)]
        constraints = FormationConstraints()
        
        success, _ = await controller.create_formation(
            FormationType.WEDGE,
            member_ids,
            constraints,
            center_position=Position3D(0, 0, 0)
        )
        assert success
        
        # Move formation toward obstacle
        for member in controller.members.values():
            member.velocity = Velocity3D(5, 0, 0)  # Move toward first obstacle
        
        # Detect risks
        risks = await controller.collision_system.detect_collision_risks(
            list(controller.members.values()),
            prediction_time=5.0
        )
        
        obstacle_risks = [r for r in risks if r.risk_type == CollisionType.MEMBER_TO_OBSTACLE]
        assert len(obstacle_risks) > 0, "Should detect obstacle collision risks"
        
        # Maintain formation with avoidance
        for _ in range(30):
            await controller.maintain_formation(time_delta=0.1)
        
        # Verify no members hit obstacles
        for member in controller.members.values():
            for _, obs_pos, obs_radius in obstacles:
                distance = member.position.distance_to(obs_pos)
                assert distance > obs_radius + member.safety_radius, \
                    f"Member {member.member_id} too close to obstacle"
    
    @pytest.mark.asyncio
    async def test_emergency_maneuvers(self):
        """Test emergency formation maneuvers."""
        controller = self._create_test_controller()
        
        # Create formation
        member_ids = [f"member_{i}" for i in range(8)]
        constraints = FormationConstraints()
        
        success, _ = await controller.create_formation(
            FormationType.DIAMOND,
            member_ids,
            constraints
        )
        assert success
        
        # Test scatter maneuver
        initial_positions = {
            m_id: m.position for m_id, m in controller.members.items()
        }
        
        scatter_success = await controller.execute_emergency_maneuver("scatter")
        assert scatter_success
        
        # Verify members scattered
        for member in controller.members.values():
            initial_pos = initial_positions[member.member_id]
            assert member.target_position.distance_to(initial_pos) > 30.0
        
        # Test defensive circle maneuver
        defense_success = await controller.execute_emergency_maneuver("defensive_circle")
        assert defense_success
        assert controller.current_formation.formation_type == FormationType.DEFENSIVE_RING
    
    @pytest.mark.asyncio
    async def test_formation_patterns(self):
        """Test all formation pattern calculations."""
        patterns = [
            (LineFormation(), FormationType.LINE),
            (WedgeFormation(), FormationType.WEDGE),
            (DiamondFormation(), FormationType.DIAMOND),
            (CircleFormation(), FormationType.CIRCLE)
        ]
        
        constraints = FormationConstraints(min_separation=5.0)
        center = Position3D(0, 0, 0)
        
        for pattern, formation_type in patterns:
            for num_members in [1, 3, 5, 10, 20]:
                positions = pattern.calculate_positions(num_members, constraints, center)
                
                assert len(positions) == num_members, \
                    f"{formation_type.value} should generate {num_members} positions"
                
                # Check minimum separation
                if num_members > 1:
                    for i, pos_a in enumerate(positions):
                        for pos_b in positions[i+1:]:
                            distance = pos_a.distance_to(pos_b)
                            assert distance >= constraints.min_separation * 0.9, \
                                f"{formation_type.value} violates minimum separation"
                
                # Check role assignments
                for i in range(num_members):
                    role = pattern.get_role_for_position(i, num_members)
                    assert role is not None
    
    @pytest.mark.asyncio
    async def test_dynamic_reconfiguration(self):
        """Test dynamic formation optimization."""
        controller = self._create_test_controller()
        reconfig_engine = controller.reconfiguration_engine
        
        # Create formation
        member_ids = [f"member_{i}" for i in range(10)]
        constraints = FormationConstraints()
        
        success, _ = await controller.create_formation(
            FormationType.BOX,
            member_ids,
            constraints
        )
        assert success
        
        # Assess performance
        performance = await reconfig_engine.assess_formation_performance(
            controller.current_formation
        )
        
        assert 'overall' in performance
        assert 0 <= performance['overall'] <= 1
        assert 'coherence' in performance
        assert 'communication_efficiency' in performance
        
        # Test formation recommendation
        recommended = await reconfig_engine.recommend_formation(
            mission_type="patrol",
            environmental_factors={'open_terrain': True},
            threat_level="low"
        )
        
        assert recommended in FormationType
        
        # Test optimization
        optimization_result = await reconfig_engine.optimize_current_formation()
        
        assert 'optimized' in optimization_result
        if optimization_result['optimized']:
            assert 'recommendations' in optimization_result
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self):
        """Test performance tracking and metrics."""
        controller = self._create_test_controller()
        
        # Run several formation operations
        member_ids = [f"member_{i}" for i in range(6)]
        constraints = FormationConstraints()
        
        # Create formations
        for _ in range(3):
            success, _ = await controller.create_formation(
                random.choice(list(FormationType)),
                member_ids,
                constraints
            )
            assert success
        
        # Check metrics
        metrics = controller.metrics
        assert metrics['formations_created'] == 3
        assert metrics['average_coherence'] >= 0
        
        # Get formation status
        status = controller.get_formation_status()
        assert status['active']
        assert 'formation_id' in status
        assert 'metrics' in status
    
    @pytest.mark.asyncio
    async def test_scalability(self):
        """Test formation control with varying swarm sizes."""
        controller = self._create_test_controller()
        
        swarm_sizes = [3, 10, 20, 50, 100]
        
        for size in swarm_sizes:
            member_ids = [f"member_{i}" for i in range(size)]
            constraints = FormationConstraints(
                min_separation=3.0,
                max_separation=50.0
            )
            
            start_time = time.time()
            
            success, formation_id = await controller.create_formation(
                FormationType.CIRCLE,
                member_ids,
                constraints
            )
            
            creation_time = time.time() - start_time
            
            assert success, f"Failed to create formation with {size} members"
            assert len(controller.members) == size
            
            # Performance should scale reasonably
            assert creation_time < size * 0.01 + 1.0, \
                f"Formation creation too slow for {size} members"
            
            logger.info("Created formation with %d members in %.3f seconds",
                       size, creation_time)
            
            # Clear for next test
            controller.members.clear()
            controller.current_formation = None
    
    def run_benchmark_suite(self):
        """Run comprehensive benchmark tests."""
        scenarios = [
            TestScenario(
                name="small_team",
                num_members=5,
                formation_type=FormationType.WEDGE,
                constraints=FormationConstraints()
            ),
            TestScenario(
                name="medium_swarm",
                num_members=20,
                formation_type=FormationType.DIAMOND,
                constraints=FormationConstraints(),
                byzantine_members=5
            ),
            TestScenario(
                name="large_swarm",
                num_members=50,
                formation_type=FormationType.SEARCH_GRID,
                constraints=FormationConstraints(max_separation=100.0)
            ),
            TestScenario(
                name="defensive_scenario",
                num_members=15,
                formation_type=FormationType.DEFENSIVE_RING,
                constraints=FormationConstraints(),
                obstacles=[
                    (Position3D(30, 0, 0), 10),
                    (Position3D(-30, 0, 0), 10)
                ]
            )
        ]
        
        results = []
        
        for scenario in scenarios:
            result = asyncio.run(self._run_scenario(scenario))
            results.append(result)
            
            logger.info("Scenario %s: Creation=%.3fs, Coherence=%.2f, Collisions=%d",
                       scenario.name,
                       result['creation_time'],
                       result['average_coherence'],
                       result['collision_count'])
        
        return results
    
    async def _run_scenario(self, scenario: TestScenario) -> Dict[str, Any]:
        """Run a single test scenario."""
        controller = self._create_test_controller()
        
        # Add obstacles
        for i, (pos, radius) in enumerate(scenario.obstacles):
            controller.collision_system.add_obstacle(f"obs_{i}", pos, radius)
        
        # Create formation
        member_ids = [f"member_{i}" for i in range(scenario.num_members)]
        
        start_time = time.time()
        success, formation_id = await controller.create_formation(
            scenario.formation_type,
            member_ids,
            scenario.constraints
        )
        creation_time = time.time() - start_time
        
        if not success:
            return {'error': 'Formation creation failed'}
        
        # Set Byzantine members
        if scenario.byzantine_members > 0:
            byzantine_ids = random.sample(member_ids, scenario.byzantine_members)
            for b_id in byzantine_ids:
                if b_id in controller.members:
                    controller.members[b_id].is_byzantine = True
        
        # Run simulation
        coherence_samples = []
        collision_count = 0
        
        for step in range(scenario.duration_seconds * 10):  # 10Hz update
            await controller.maintain_formation(time_delta=0.1)
            
            if controller.current_formation:
                coherence_samples.append(controller.current_formation.coherence)
            
            # Check for collisions
            risks = await controller.collision_system.detect_collision_risks(
                list(controller.members.values()),
                prediction_time=0.5
            )
            
            high_risk_collisions = [r for r in risks if r.probability > 0.8]
            collision_count += len(high_risk_collisions)
        
        return {
            'scenario': scenario.name,
            'creation_time': creation_time,
            'average_coherence': np.mean(coherence_samples) if coherence_samples else 0,
            'min_coherence': np.min(coherence_samples) if coherence_samples else 0,
            'collision_count': collision_count,
            'final_member_count': len(controller.members)
        }


def test_formation_math():
    """Test formation mathematical calculations."""
    # Test Position3D
    pos_a = Position3D(0, 0, 0)
    pos_b = Position3D(3, 4, 0)
    
    assert pos_a.distance_to(pos_b) == 5.0
    
    # Test Velocity3D
    vel = Velocity3D(3, 4, 0)
    assert vel.magnitude() == 5.0
    
    # Test formation pattern spacing
    constraints = FormationConstraints(min_separation=5.0)
    center = Position3D(0, 0, 0)
    
    line = LineFormation()
    positions = line.calculate_positions(5, constraints, center)
    
    # Check spacing
    for i in range(len(positions) - 1):
        distance = positions[i].distance_to(positions[i+1])
        assert distance >= constraints.min_separation


if __name__ == "__main__":
    # Run all tests
    suite = FormationControllerTestSuite()
    
    # Basic tests
    asyncio.run(suite.test_formation_creation())
    asyncio.run(suite.test_collision_avoidance())
    asyncio.run(suite.test_formation_maintenance())
    asyncio.run(suite.test_formation_morphing())
    
    # Advanced tests
    asyncio.run(suite.test_byzantine_resilience())
    asyncio.run(suite.test_obstacle_avoidance())
    asyncio.run(suite.test_emergency_maneuvers())
    asyncio.run(suite.test_formation_patterns())
    
    # Performance tests
    asyncio.run(suite.test_dynamic_reconfiguration())
    asyncio.run(suite.test_performance_metrics())
    asyncio.run(suite.test_scalability())
    
    # Mathematical tests
    test_formation_math()
    
    # Run benchmarks
    logger.info("Running benchmark suite...")
    benchmark_results = suite.run_benchmark_suite()
    
    logger.info("All tests completed successfully!")