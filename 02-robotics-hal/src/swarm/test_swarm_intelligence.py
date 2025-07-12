#!/usr/bin/env python3
"""
ALCUB3 Swarm Intelligence Testing Framework
Comprehensive testing with Byzantine fault injection and performance validation

This module provides extensive testing capabilities for the swarm intelligence
platform including fault injection, performance benchmarking, and security validation.
"""

import asyncio
import time
import uuid
import random
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import numpy as np
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.real_time_monitor import RealTimeSecurityMonitor
from shared.mtls_manager import MTLSManager

# Import swarm components
from .distributed_task_allocator import (
    DistributedTaskAllocator, SwarmTask, SwarmMember, SwarmCapability,
    TaskStatus, TaskPriority, SwarmConfiguration
)
from .consensus_protocol import (
    EnhancedConsensusProtocol, CryptoCredentials, FaultType
)
from .secure_p2p_network import SecureSwarmNetwork, PeerInfo
from .dynamic_load_balancer import (
    DynamicLoadBalancer, LoadBalancingStrategy, LoadMetrics
)
from .maestro_integration import SwarmMAESTROIntegration

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestScenario(Enum):
    """Test scenario types."""
    BASIC_ALLOCATION = "basic_allocation"
    BYZANTINE_CONSENSUS = "byzantine_consensus"
    NETWORK_PARTITION = "network_partition"
    LOAD_BALANCING = "load_balancing"
    CASCADING_FAILURE = "cascading_failure"
    SECURITY_BREACH = "security_breach"
    PERFORMANCE_STRESS = "performance_stress"
    FULL_INTEGRATION = "full_integration"


class FaultInjectionType(Enum):
    """Types of faults to inject."""
    MEMBER_CRASH = "member_crash"
    BYZANTINE_BEHAVIOR = "byzantine_behavior"
    NETWORK_DELAY = "network_delay"
    NETWORK_PARTITION = "network_partition"
    TASK_FAILURE = "task_failure"
    CONSENSUS_MANIPULATION = "consensus_manipulation"
    ATTESTATION_FAILURE = "attestation_failure"
    CLASSIFICATION_VIOLATION = "classification_violation"


@dataclass
class TestResult:
    """Test execution result."""
    scenario: TestScenario
    passed: bool
    metrics: Dict[str, Any]
    errors: List[str]
    start_time: datetime
    end_time: datetime
    
    @property
    def duration_seconds(self) -> float:
        """Get test duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()


@dataclass
class PerformanceMetrics:
    """Performance metrics collection."""
    allocation_times: List[float] = field(default_factory=list)
    consensus_times: List[float] = field(default_factory=list)
    throughput_tps: List[float] = field(default_factory=list)  # Tasks per second
    success_rates: List[float] = field(default_factory=list)
    network_latencies: List[float] = field(default_factory=list)
    cpu_usage: List[float] = field(default_factory=list)
    memory_usage: List[float] = field(default_factory=list)
    
    def calculate_summary(self) -> Dict[str, float]:
        """Calculate summary statistics."""
        def safe_percentile(data: List[float], p: float) -> float:
            return np.percentile(data, p) if data else 0.0
        
        return {
            'avg_allocation_ms': np.mean(self.allocation_times) if self.allocation_times else 0,
            'p99_allocation_ms': safe_percentile(self.allocation_times, 99),
            'avg_consensus_ms': np.mean(self.consensus_times) if self.consensus_times else 0,
            'p99_consensus_ms': safe_percentile(self.consensus_times, 99),
            'avg_throughput_tps': np.mean(self.throughput_tps) if self.throughput_tps else 0,
            'avg_success_rate': np.mean(self.success_rates) if self.success_rates else 0,
            'avg_network_latency_ms': np.mean(self.network_latencies) if self.network_latencies else 0
        }


class SwarmSimulator:
    """Simulates swarm environment for testing."""
    
    def __init__(self, num_members: int = 10):
        self.num_members = num_members
        self.members: Dict[str, SwarmMember] = {}
        self.fault_injections: Dict[str, FaultInjectionType] = {}
        self.network_delays: Dict[Tuple[str, str], float] = {}
        
    def create_swarm_members(self) -> Dict[str, SwarmMember]:
        """Create simulated swarm members."""
        member_types = [
            ('drone', ['aerial_surveillance', 'navigation', 'communication']),
            ('ugv', ['ground_patrol', 'cargo_transport', 'sensor_platform']),
            ('static_sensor', ['area_monitoring', 'threat_detection', 'data_relay']),
            ('compute_node', ['data_processing', 'ai_inference', 'coordination'])
        ]
        
        for i in range(self.num_members):
            member_type, capabilities = random.choice(member_types)
            member_id = f"{member_type}_{i:03d}"
            
            # Create capabilities
            swarm_caps = []
            for cap_id in capabilities:
                swarm_caps.append(SwarmCapability(
                    capability_id=cap_id,
                    category='sensor' if 'sensor' in cap_id else 'actuator',
                    specifications={'range': random.randint(10, 100)},
                    performance_metrics={'accuracy': random.uniform(0.8, 0.99)},
                    classification_level=random.choice([
                        ClassificationLevel.UNCLASSIFIED,
                        ClassificationLevel.SECRET
                    ])
                ))
            
            # Create member
            member = SwarmMember(
                member_id=member_id,
                platform_type=member_type,
                capabilities=swarm_caps,
                classification_clearance=random.choice([
                    ClassificationLevel.UNCLASSIFIED,
                    ClassificationLevel.SECRET,
                    ClassificationLevel.TOP_SECRET
                ]),
                current_load=random.uniform(0.1, 0.3),
                reliability_score=random.uniform(0.85, 0.99),
                location={'lat': random.uniform(-90, 90), 'lon': random.uniform(-180, 180)}
            )
            
            self.members[member_id] = member
        
        return self.members
    
    def inject_fault(self, member_id: str, fault_type: FaultInjectionType):
        """Inject a fault into a member."""
        self.fault_injections[member_id] = fault_type
        
        if fault_type == FaultInjectionType.MEMBER_CRASH:
            if member_id in self.members:
                self.members[member_id].is_byzantine = True
                self.members[member_id].reliability_score = 0.0
        
        elif fault_type == FaultInjectionType.BYZANTINE_BEHAVIOR:
            if member_id in self.members:
                self.members[member_id].is_byzantine = True
    
    def inject_network_delay(self, member_a: str, member_b: str, delay_ms: float):
        """Inject network delay between members."""
        self.network_delays[(member_a, member_b)] = delay_ms
        self.network_delays[(member_b, member_a)] = delay_ms
    
    def generate_test_tasks(self, num_tasks: int) -> List[SwarmTask]:
        """Generate test tasks with various characteristics."""
        tasks = []
        
        task_templates = [
            {
                'type': 'surveillance',
                'capabilities': ['aerial_surveillance', 'threat_detection'],
                'priority': TaskPriority.HIGH,
                'duration': 120
            },
            {
                'type': 'transport',
                'capabilities': ['ground_patrol', 'cargo_transport'],
                'priority': TaskPriority.MEDIUM,
                'duration': 300
            },
            {
                'type': 'emergency_response',
                'capabilities': ['communication', 'coordination'],
                'priority': TaskPriority.CRITICAL,
                'duration': 60
            },
            {
                'type': 'data_analysis',
                'capabilities': ['data_processing', 'ai_inference'],
                'priority': TaskPriority.LOW,
                'duration': 180
            }
        ]
        
        for i in range(num_tasks):
            template = random.choice(task_templates)
            
            task = SwarmTask(
                task_id=f"test_task_{i:04d}",
                task_type=template['type'],
                required_capabilities=template['capabilities'],
                priority=template['priority'],
                classification=random.choice([
                    ClassificationLevel.UNCLASSIFIED,
                    ClassificationLevel.SECRET
                ]),
                payload={'test_data': f'payload_{i}'},
                constraints={
                    'max_duration': template['duration'],
                    'location': {
                        'lat': random.uniform(-90, 90),
                        'lon': random.uniform(-180, 180)
                    }
                },
                created_at=datetime.now(),
                deadline=datetime.now() + timedelta(seconds=template['duration'] * 2)
            )
            
            tasks.append(task)
        
        return tasks


class SwarmTestFramework:
    """Comprehensive testing framework for swarm intelligence."""
    
    def __init__(self):
        self.simulator = SwarmSimulator()
        self.test_results: List[TestResult] = []
        self.performance_metrics = PerformanceMetrics()
        
        # Components under test
        self.task_allocator: Optional[DistributedTaskAllocator] = None
        self.consensus_protocol: Optional[EnhancedConsensusProtocol] = None
        self.p2p_network: Optional[SecureSwarmNetwork] = None
        self.load_balancer: Optional[DynamicLoadBalancer] = None
        self.maestro_integration: Optional[SwarmMAESTROIntegration] = None
        
        # Test configuration
        self.enable_visualization = True
        self.enable_detailed_logging = True
        
    async def setup_test_environment(self, scenario: TestScenario):
        """Set up test environment for specific scenario."""
        logger.info("Setting up test environment for scenario: %s", scenario.value)
        
        # Create swarm members
        members = self.simulator.create_swarm_members()
        
        # Initialize components
        config = SwarmConfiguration(
            min_consensus_ratio=0.67,
            max_allocation_time_ms=50.0,
            byzantine_fault_threshold=0.33
        )
        
        audit_logger = AuditLogger()
        
        # Task allocator
        self.task_allocator = DistributedTaskAllocator(config, audit_logger)
        
        # Register members
        for member in members.values():
            await self.task_allocator.register_swarm_member(member)
        
        # Consensus protocol
        credentials = {}
        for member_id in members:
            private_key, public_key = self._generate_test_keys()
            credentials[member_id] = CryptoCredentials(
                member_id=member_id,
                private_key=private_key,
                public_key=public_key,
                classification_level=members[member_id].classification_clearance
            )
        
        self.consensus_protocol = EnhancedConsensusProtocol(
            credentials,
            config.classification_weight_multipliers,
            audit_logger
        )
        
        # Load balancer
        self.load_balancer = DynamicLoadBalancer(
            LoadBalancingStrategy.PREDICTIVE,
            audit_logger
        )
        
        # P2P Network (simplified for testing)
        # In real implementation, would initialize full network
        
        logger.info("Test environment setup complete")
    
    def _generate_test_keys(self):
        """Generate test cryptographic keys."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()
    
    async def run_test_scenario(self, scenario: TestScenario) -> TestResult:
        """Run a specific test scenario."""
        logger.info("Running test scenario: %s", scenario.value)
        start_time = datetime.now()
        errors = []
        metrics = {}
        
        try:
            # Set up environment
            await self.setup_test_environment(scenario)
            
            # Run scenario-specific tests
            if scenario == TestScenario.BASIC_ALLOCATION:
                passed, scenario_metrics = await self._test_basic_allocation()
            
            elif scenario == TestScenario.BYZANTINE_CONSENSUS:
                passed, scenario_metrics = await self._test_byzantine_consensus()
            
            elif scenario == TestScenario.NETWORK_PARTITION:
                passed, scenario_metrics = await self._test_network_partition()
            
            elif scenario == TestScenario.LOAD_BALANCING:
                passed, scenario_metrics = await self._test_load_balancing()
            
            elif scenario == TestScenario.CASCADING_FAILURE:
                passed, scenario_metrics = await self._test_cascading_failure()
            
            elif scenario == TestScenario.SECURITY_BREACH:
                passed, scenario_metrics = await self._test_security_breach()
            
            elif scenario == TestScenario.PERFORMANCE_STRESS:
                passed, scenario_metrics = await self._test_performance_stress()
            
            elif scenario == TestScenario.FULL_INTEGRATION:
                passed, scenario_metrics = await self._test_full_integration()
            
            else:
                passed = False
                scenario_metrics = {}
                errors.append(f"Unknown scenario: {scenario}")
            
            metrics.update(scenario_metrics)
            
        except Exception as e:
            logger.error("Test scenario failed: %s", e)
            passed = False
            errors.append(str(e))
        
        end_time = datetime.now()
        
        result = TestResult(
            scenario=scenario,
            passed=passed,
            metrics=metrics,
            errors=errors,
            start_time=start_time,
            end_time=end_time
        )
        
        self.test_results.append(result)
        return result
    
    async def _test_basic_allocation(self) -> Tuple[bool, Dict[str, Any]]:
        """Test basic task allocation without faults."""
        logger.info("Testing basic task allocation...")
        
        # Generate test tasks
        tasks = self.simulator.generate_test_tasks(50)
        
        # Submit tasks
        for task in tasks:
            await self.task_allocator.submit_task(task)
        
        # Allocate tasks
        start_time = time.time()
        allocation_results = await self.task_allocator.allocate_tasks()
        allocation_time = (time.time() - start_time) * 1000
        
        # Verify allocations
        success_count = sum(1 for r in allocation_results if r.consensus_achieved)
        success_rate = success_count / len(tasks)
        
        # Record metrics
        self.performance_metrics.allocation_times.extend(
            [r.allocation_time_ms for r in allocation_results]
        )
        self.performance_metrics.success_rates.append(success_rate)
        
        metrics = {
            'total_tasks': len(tasks),
            'allocated_tasks': len(allocation_results),
            'success_rate': success_rate,
            'total_allocation_time_ms': allocation_time,
            'avg_allocation_time_ms': np.mean([r.allocation_time_ms for r in allocation_results])
        }
        
        # Pass if success rate > 95%
        passed = success_rate > 0.95
        
        logger.info("Basic allocation test %s. Metrics: %s", 
                   "PASSED" if passed else "FAILED", metrics)
        
        return passed, metrics
    
    async def _test_byzantine_consensus(self) -> Tuple[bool, Dict[str, Any]]:
        """Test consensus with Byzantine members."""
        logger.info("Testing Byzantine fault-tolerant consensus...")
        
        # Inject Byzantine faults (up to 33%)
        num_byzantine = int(self.simulator.num_members * 0.3)
        byzantine_members = random.sample(list(self.simulator.members.keys()), num_byzantine)
        
        for member_id in byzantine_members:
            self.simulator.inject_fault(member_id, FaultInjectionType.BYZANTINE_BEHAVIOR)
        
        # Test consensus rounds
        num_rounds = 20
        successful_rounds = 0
        consensus_times = []
        
        for i in range(num_rounds):
            task_id = f"consensus_test_{i}"
            value = f"allocation_{random.choice(list(self.simulator.members.keys()))}"
            
            start_time = time.time()
            success, consensus_value, proof = await self.consensus_protocol.propose_consensus(
                task_id,
                value,
                ClassificationLevel.UNCLASSIFIED,
                timeout_ms=100.0
            )
            consensus_time = (time.time() - start_time) * 1000
            
            if success:
                successful_rounds += 1
                consensus_times.append(consensus_time)
        
        success_rate = successful_rounds / num_rounds
        self.performance_metrics.consensus_times.extend(consensus_times)
        
        metrics = {
            'num_byzantine': num_byzantine,
            'byzantine_ratio': num_byzantine / self.simulator.num_members,
            'consensus_rounds': num_rounds,
            'successful_rounds': successful_rounds,
            'success_rate': success_rate,
            'avg_consensus_time_ms': np.mean(consensus_times) if consensus_times else 0,
            'view_changes': self.consensus_protocol.view_change_count
        }
        
        # Pass if success rate > 80% with Byzantine members
        passed = success_rate > 0.8
        
        logger.info("Byzantine consensus test %s. Metrics: %s",
                   "PASSED" if passed else "FAILED", metrics)
        
        return passed, metrics
    
    async def _test_network_partition(self) -> Tuple[bool, Dict[str, Any]]:
        """Test handling of network partitions."""
        logger.info("Testing network partition handling...")
        
        # Create network partition
        partition_size = self.simulator.num_members // 2
        partition_a = list(self.simulator.members.keys())[:partition_size]
        partition_b = list(self.simulator.members.keys())[partition_size:]
        
        # Inject infinite delays between partitions
        for member_a in partition_a:
            for member_b in partition_b:
                self.simulator.inject_network_delay(member_a, member_b, float('inf'))
        
        # Try to allocate tasks in partitioned network
        tasks = self.simulator.generate_test_tasks(20)
        allocation_results = []
        
        for task in tasks:
            await self.task_allocator.submit_task(task)
        
        allocation_results = await self.task_allocator.allocate_tasks()
        
        # Check how many tasks were allocated despite partition
        allocated_count = sum(1 for r in allocation_results if r.consensus_achieved)
        
        metrics = {
            'partition_size_a': len(partition_a),
            'partition_size_b': len(partition_b),
            'total_tasks': len(tasks),
            'allocated_tasks': allocated_count,
            'allocation_rate': allocated_count / len(tasks) if tasks else 0
        }
        
        # Pass if some tasks were still allocated (partition tolerance)
        passed = allocated_count > 0
        
        logger.info("Network partition test %s. Metrics: %s",
                   "PASSED" if passed else "FAILED", metrics)
        
        return passed, metrics
    
    async def _test_load_balancing(self) -> Tuple[bool, Dict[str, Any]]:
        """Test dynamic load balancing."""
        logger.info("Testing dynamic load balancing...")
        
        # Create initial load imbalance
        members_list = list(self.simulator.members.values())
        for i, member in enumerate(members_list):
            if i < len(members_list) // 3:
                member.current_load = random.uniform(0.8, 0.95)  # Overloaded
            else:
                member.current_load = random.uniform(0.1, 0.3)   # Underloaded
        
        # Update load metrics
        for member in members_list:
            metrics = LoadMetrics(
                member_id=member.member_id,
                timestamp=datetime.now(),
                cpu_usage=member.current_load,
                memory_usage=member.current_load * 0.8,
                task_queue_length=int(member.current_load * 10),
                active_task_count=len(member.active_tasks),
                average_task_duration=60.0,
                failure_rate=0.05
            )
            await self.load_balancer.update_member_load(member.member_id, metrics)
        
        # Get initial load variance
        initial_variance = self.load_balancer.balancing_metrics['average_load_variance']
        
        # Submit tasks to trigger rebalancing
        tasks = self.simulator.generate_test_tasks(30)
        for task in tasks:
            member_id = await self.load_balancer.allocate_task(
                task,
                self.simulator.members
            )
            if member_id:
                self.task_allocator.task_assignments[task.task_id] = member_id
        
        # Wait for rebalancing
        await asyncio.sleep(2)
        
        # Get final load variance
        final_metrics = self.load_balancer.get_load_balancing_metrics()
        
        metrics = {
            'initial_variance': initial_variance,
            'final_variance': final_metrics['load_variance'],
            'variance_reduction': (
                (initial_variance - final_metrics['load_variance']) / 
                initial_variance if initial_variance > 0 else 0
            ),
            'total_migrations': final_metrics['total_migrations'],
            'migration_success_rate': final_metrics['migration_success_rate'],
            'average_load': final_metrics['average_load']
        }
        
        # Pass if variance reduced by at least 30%
        passed = metrics['variance_reduction'] > 0.3
        
        logger.info("Load balancing test %s. Metrics: %s",
                   "PASSED" if passed else "FAILED", metrics)
        
        return passed, metrics
    
    async def _test_cascading_failure(self) -> Tuple[bool, Dict[str, Any]]:
        """Test handling of cascading failures."""
        logger.info("Testing cascading failure handling...")
        
        # Submit initial tasks
        tasks = self.simulator.generate_test_tasks(40)
        for task in tasks:
            await self.task_allocator.submit_task(task)
        
        initial_allocations = await self.task_allocator.allocate_tasks()
        initial_success = sum(1 for r in initial_allocations if r.consensus_achieved)
        
        # Create cascading failures
        failure_waves = 3
        members_per_wave = 2
        failed_members = []
        
        for wave in range(failure_waves):
            # Select members to fail
            available_members = [
                m for m in self.simulator.members.keys()
                if m not in failed_members
            ]
            
            if len(available_members) < members_per_wave:
                break
            
            wave_failures = random.sample(available_members, members_per_wave)
            
            # Inject failures
            for member_id in wave_failures:
                self.simulator.inject_fault(member_id, FaultInjectionType.MEMBER_CRASH)
                failed_members.append(member_id)
                
                # Trigger failure handling
                await self.load_balancer.handle_member_failure(member_id)
            
            # Wait for system to stabilize
            await asyncio.sleep(1)
        
        # Check system recovery
        recovery_tasks = self.simulator.generate_test_tasks(10)
        for task in recovery_tasks:
            await self.task_allocator.submit_task(task)
        
        recovery_allocations = await self.task_allocator.allocate_tasks()
        recovery_success = sum(1 for r in recovery_allocations if r.consensus_achieved)
        
        metrics = {
            'total_failures': len(failed_members),
            'failure_ratio': len(failed_members) / self.simulator.num_members,
            'initial_success_count': initial_success,
            'recovery_success_count': recovery_success,
            'recovery_rate': recovery_success / len(recovery_tasks) if recovery_tasks else 0,
            'remaining_active_members': self.simulator.num_members - len(failed_members)
        }
        
        # Pass if system recovered with >50% success rate after failures
        passed = metrics['recovery_rate'] > 0.5
        
        logger.info("Cascading failure test %s. Metrics: %s",
                   "PASSED" if passed else "FAILED", metrics)
        
        return passed, metrics
    
    async def _test_security_breach(self) -> Tuple[bool, Dict[str, Any]]:
        """Test security breach detection and response."""
        logger.info("Testing security breach handling...")
        
        # This would require full MAESTRO integration
        # For now, simulate classification violations
        
        violations_detected = 0
        violations_injected = 5
        
        for i in range(violations_injected):
            # Create task with TS classification
            task = SwarmTask(
                task_id=f"security_test_{i}",
                task_type="classified_operation",
                required_capabilities=['data_processing'],
                priority=TaskPriority.HIGH,
                classification=ClassificationLevel.TOP_SECRET,
                payload={'sensitive_data': 'classified'},
                constraints={},
                created_at=datetime.now()
            )
            
            # Try to assign to uncleared member
            uncleared_members = [
                m for m in self.simulator.members.values()
                if m.classification_clearance == ClassificationLevel.UNCLASSIFIED
            ]
            
            if uncleared_members:
                # This should fail
                result = await self.task_allocator._allocate_task(task)
                if result is None:
                    violations_detected += 1
        
        metrics = {
            'violations_injected': violations_injected,
            'violations_detected': violations_detected,
            'detection_rate': violations_detected / violations_injected if violations_injected > 0 else 0
        }
        
        # Pass if all violations detected
        passed = violations_detected == violations_injected
        
        logger.info("Security breach test %s. Metrics: %s",
                   "PASSED" if passed else "FAILED", metrics)
        
        return passed, metrics
    
    async def _test_performance_stress(self) -> Tuple[bool, Dict[str, Any]]:
        """Test system under high load."""
        logger.info("Testing performance under stress...")
        
        # Generate large number of tasks
        num_tasks = 1000
        tasks = self.simulator.generate_test_tasks(num_tasks)
        
        # Measure throughput
        start_time = time.time()
        
        # Submit tasks in batches
        batch_size = 100
        allocation_times = []
        
        for i in range(0, num_tasks, batch_size):
            batch = tasks[i:i+batch_size]
            
            # Submit batch
            for task in batch:
                await self.task_allocator.submit_task(task)
            
            # Allocate batch
            batch_start = time.time()
            results = await self.task_allocator.allocate_tasks()
            batch_time = (time.time() - batch_start) * 1000
            
            allocation_times.append(batch_time)
            
            # Record individual allocation times
            self.performance_metrics.allocation_times.extend(
                [r.allocation_time_ms for r in results if r.allocation_time_ms < 1000]
            )
        
        total_time = time.time() - start_time
        throughput = num_tasks / total_time
        
        # Get allocation statistics
        allocation_stats = self.task_allocator.allocation_metrics
        
        metrics = {
            'total_tasks': num_tasks,
            'total_time_seconds': total_time,
            'throughput_tps': throughput,
            'avg_batch_time_ms': np.mean(allocation_times),
            'p99_allocation_ms': np.percentile(self.performance_metrics.allocation_times, 99),
            'success_rate': allocation_stats['successful_allocations'] / allocation_stats['total_allocations']
        }
        
        self.performance_metrics.throughput_tps.append(throughput)
        
        # Pass if throughput > 100 TPS and P99 < 100ms
        passed = throughput > 100 and metrics['p99_allocation_ms'] < 100
        
        logger.info("Performance stress test %s. Metrics: %s",
                   "PASSED" if passed else "FAILED", metrics)
        
        return passed, metrics
    
    async def _test_full_integration(self) -> Tuple[bool, Dict[str, Any]]:
        """Test full system integration with all components."""
        logger.info("Testing full system integration...")
        
        # Run mixed workload with various fault conditions
        test_duration = 60  # seconds
        start_time = time.time()
        
        # Fault injection schedule
        fault_schedule = [
            (10, FaultInjectionType.BYZANTINE_BEHAVIOR),
            (20, FaultInjectionType.NETWORK_DELAY),
            (30, FaultInjectionType.MEMBER_CRASH),
            (40, FaultInjectionType.TASK_FAILURE)
        ]
        
        # Metrics collection
        task_count = 0
        success_count = 0
        consensus_count = 0
        migration_count = 0
        
        # Background task generation
        async def generate_continuous_tasks():
            nonlocal task_count
            while time.time() - start_time < test_duration:
                tasks = self.simulator.generate_test_tasks(random.randint(5, 15))
                for task in tasks:
                    await self.task_allocator.submit_task(task)
                    task_count += 1
                await asyncio.sleep(random.uniform(0.5, 2.0))
        
        # Background fault injection
        async def inject_scheduled_faults():
            for delay, fault_type in fault_schedule:
                await asyncio.sleep(delay)
                if time.time() - start_time < test_duration:
                    member_id = random.choice(list(self.simulator.members.keys()))
                    self.simulator.inject_fault(member_id, fault_type)
                    logger.info("Injected fault %s on member %s", fault_type.value, member_id)
        
        # Run test
        tasks = [
            asyncio.create_task(generate_continuous_tasks()),
            asyncio.create_task(inject_scheduled_faults())
        ]
        
        # Main allocation loop
        while time.time() - start_time < test_duration:
            # Allocate pending tasks
            results = await self.task_allocator.allocate_tasks()
            success_count += sum(1 for r in results if r.consensus_achieved)
            
            # Update load metrics
            for member in self.simulator.members.values():
                metrics = LoadMetrics(
                    member_id=member.member_id,
                    timestamp=datetime.now(),
                    cpu_usage=member.current_load,
                    memory_usage=member.current_load * 0.8,
                    task_queue_length=len(member.active_tasks),
                    active_task_count=len(member.active_tasks),
                    average_task_duration=60.0,
                    failure_rate=0.1 if member.is_byzantine else 0.01
                )
                await self.load_balancer.update_member_load(member.member_id, metrics)
            
            await asyncio.sleep(1)
        
        # Cancel background tasks
        for task in tasks:
            task.cancel()
        
        # Collect final metrics
        final_metrics = {
            'test_duration_seconds': test_duration,
            'total_tasks_submitted': task_count,
            'successful_allocations': success_count,
            'success_rate': success_count / task_count if task_count > 0 else 0,
            'faults_injected': len(fault_schedule),
            'final_active_members': sum(
                1 for m in self.simulator.members.values()
                if not m.is_byzantine
            ),
            'allocator_metrics': self.task_allocator.allocation_metrics,
            'balancer_metrics': self.load_balancer.get_load_balancing_metrics()
        }
        
        # Pass if success rate > 70% despite faults
        passed = final_metrics['success_rate'] > 0.7
        
        logger.info("Full integration test %s. Metrics: %s",
                   "PASSED" if passed else "FAILED", final_metrics)
        
        return passed, final_metrics
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        report = {
            'test_summary': {
                'total_scenarios': len(self.test_results),
                'passed_scenarios': sum(1 for r in self.test_results if r.passed),
                'failed_scenarios': sum(1 for r in self.test_results if not r.passed),
                'pass_rate': sum(1 for r in self.test_results if r.passed) / len(self.test_results) if self.test_results else 0
            },
            'scenario_results': [
                {
                    'scenario': r.scenario.value,
                    'passed': r.passed,
                    'duration_seconds': r.duration_seconds,
                    'metrics': r.metrics,
                    'errors': r.errors
                }
                for r in self.test_results
            ],
            'performance_summary': self.performance_metrics.calculate_summary(),
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        # Check allocation performance
        if self.performance_metrics.allocation_times:
            p99_allocation = np.percentile(self.performance_metrics.allocation_times, 99)
            if p99_allocation > 100:
                recommendations.append(
                    f"Task allocation P99 latency ({p99_allocation:.2f}ms) exceeds target of 50ms. "
                    "Consider optimizing consensus protocol or reducing task complexity."
                )
        
        # Check success rates
        if self.performance_metrics.success_rates:
            avg_success = np.mean(self.performance_metrics.success_rates)
            if avg_success < 0.95:
                recommendations.append(
                    f"Average success rate ({avg_success:.2%}) is below target of 95%. "
                    "Review fault tolerance mechanisms and member reliability."
                )
        
        # Check Byzantine tolerance
        byzantine_test = next(
            (r for r in self.test_results if r.scenario == TestScenario.BYZANTINE_CONSENSUS),
            None
        )
        if byzantine_test and not byzantine_test.passed:
            recommendations.append(
                "Byzantine consensus test failed. Review consensus protocol implementation "
                "and ensure proper vote weighting for classification levels."
            )
        
        return recommendations
    
    def visualize_results(self):
        """Create visualizations of test results."""
        if not self.enable_visualization:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        
        # Allocation times histogram
        if self.performance_metrics.allocation_times:
            axes[0, 0].hist(self.performance_metrics.allocation_times, bins=50)
            axes[0, 0].set_title('Task Allocation Times')
            axes[0, 0].set_xlabel('Time (ms)')
            axes[0, 0].set_ylabel('Count')
            axes[0, 0].axvline(50, color='r', linestyle='--', label='Target (50ms)')
            axes[0, 0].legend()
        
        # Success rates by scenario
        scenario_names = [r.scenario.value for r in self.test_results]
        success_rates = [
            r.metrics.get('success_rate', 0) if r.passed else 0
            for r in self.test_results
        ]
        axes[0, 1].bar(scenario_names, success_rates)
        axes[0, 1].set_title('Success Rates by Scenario')
        axes[0, 1].set_xlabel('Scenario')
        axes[0, 1].set_ylabel('Success Rate')
        axes[0, 1].tick_params(axis='x', rotation=45)
        
        # Throughput over time
        if self.performance_metrics.throughput_tps:
            axes[1, 0].plot(self.performance_metrics.throughput_tps)
            axes[1, 0].set_title('System Throughput')
            axes[1, 0].set_xlabel('Test Iteration')
            axes[1, 0].set_ylabel('Tasks per Second')
            axes[1, 0].axhline(100, color='r', linestyle='--', label='Target (100 TPS)')
            axes[1, 0].legend()
        
        # Test duration comparison
        durations = [r.duration_seconds for r in self.test_results]
        axes[1, 1].bar(scenario_names, durations)
        axes[1, 1].set_title('Test Durations')
        axes[1, 1].set_xlabel('Scenario')
        axes[1, 1].set_ylabel('Duration (seconds)')
        axes[1, 1].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig('swarm_test_results.png')
        logger.info("Test results visualization saved to swarm_test_results.png")


async def run_comprehensive_tests():
    """Run all test scenarios and generate report."""
    framework = SwarmTestFramework()
    
    # Define test scenarios to run
    scenarios = [
        TestScenario.BASIC_ALLOCATION,
        TestScenario.BYZANTINE_CONSENSUS,
        TestScenario.NETWORK_PARTITION,
        TestScenario.LOAD_BALANCING,
        TestScenario.CASCADING_FAILURE,
        TestScenario.SECURITY_BREACH,
        TestScenario.PERFORMANCE_STRESS,
        TestScenario.FULL_INTEGRATION
    ]
    
    # Run each scenario
    for scenario in scenarios:
        logger.info("\n" + "="*60)
        logger.info("Starting scenario: %s", scenario.value)
        logger.info("="*60)
        
        result = await framework.run_test_scenario(scenario)
        
        logger.info("Scenario %s completed: %s", 
                   scenario.value, 
                   "PASSED" if result.passed else "FAILED")
    
    # Generate report
    report = framework.generate_test_report()
    
    # Save report
    with open('swarm_test_report.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    # Visualize results
    framework.visualize_results()
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Total Scenarios: {report['test_summary']['total_scenarios']}")
    print(f"Passed: {report['test_summary']['passed_scenarios']}")
    print(f"Failed: {report['test_summary']['failed_scenarios']}")
    print(f"Pass Rate: {report['test_summary']['pass_rate']:.2%}")
    print("\nPerformance Summary:")
    for key, value in report['performance_summary'].items():
        print(f"  {key}: {value:.2f}")
    
    if report['recommendations']:
        print("\nRecommendations:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")


if __name__ == "__main__":
    # Run comprehensive tests
    asyncio.run(run_comprehensive_tests())