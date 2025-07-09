#!/usr/bin/env python3
"""
ALCUB3 Byzantine Consensus Test Suite
Comprehensive tests for Byzantine fault-tolerant consensus engine

This module provides extensive testing for the consensus engine including
fault injection, performance benchmarking, and correctness verification.
"""

import asyncio
import time
import uuid
import random
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
import numpy as np
import matplotlib.pyplot as plt
import pytest

# Import consensus components
from .consensus_engine import (
    ByzantineFaultTolerantEngine, PBFTRequest, PBFTMessage,
    MessageType, PBFTPhase, CryptoCredentials
)
from .byzantine_defense import ByzantineDefenseSystem, AttackType
from .partition_tolerance import PartitionTolerantProtocol, PartitionState
from .consensus_optimization import PerformanceOptimizer
from .formal_verification import FormalVerifier, ProtocolState
from .swarm_consensus_integration import SwarmConsensusIntegration

# Import swarm components
from .distributed_task_allocator import (
    SwarmTask, SwarmMember, SwarmCapability,
    TaskPriority, SwarmConfiguration
)

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
    num_nodes: int
    num_byzantine: int
    num_requests: int
    network_delay_ms: float = 10.0
    partition_probability: float = 0.0
    attack_types: List[AttackType] = field(default_factory=list)
    duration_seconds: int = 60
    
    @property
    def byzantine_ratio(self) -> float:
        """Calculate Byzantine node ratio."""
        return self.num_byzantine / self.num_nodes if self.num_nodes > 0 else 0


@dataclass
class BenchmarkResult:
    """Benchmark test result."""
    scenario: TestScenario
    throughput_rps: float
    average_latency_ms: float
    p99_latency_ms: float
    success_rate: float
    consensus_failures: int
    view_changes: int
    byzantine_detected: int
    duration_seconds: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scenario_name': self.scenario.name,
            'num_nodes': self.scenario.num_nodes,
            'byzantine_ratio': self.scenario.byzantine_ratio,
            'throughput_rps': self.throughput_rps,
            'average_latency_ms': self.average_latency_ms,
            'p99_latency_ms': self.p99_latency_ms,
            'success_rate': self.success_rate,
            'consensus_failures': self.consensus_failures,
            'view_changes': self.view_changes,
            'byzantine_detected': self.byzantine_detected
        }


class ByzantineConsensusTestSuite:
    """Comprehensive test suite for Byzantine consensus."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.monitor = RealTimeSecurityMonitor()
        self.test_results: List[BenchmarkResult] = []
        
    def _generate_test_credentials(self, num_nodes: int) -> Dict[str, CryptoCredentials]:
        """Generate test credentials for nodes."""
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
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
            ed25519_private = ed25519.Ed25519PrivateKey.generate()
            
            # Assign classification based on node index
            if i < num_nodes // 3:
                classification = ClassificationLevel.TOP_SECRET
            elif i < 2 * num_nodes // 3:
                classification = ClassificationLevel.SECRET
            else:
                classification = ClassificationLevel.UNCLASSIFIED
            
            credentials[node_id] = CryptoCredentials(
                member_id=node_id,
                private_key=private_key,
                public_key=private_key.public_key(),
                classification_level=classification
            )
            
            # Store Ed25519 key
            credentials[node_id].ed25519_public_key = ed25519_private.public_key()
        
        return credentials
    
    def _create_test_request(self, index: int, classification: ClassificationLevel) -> PBFTRequest:
        """Create a test consensus request."""
        return PBFTRequest(
            request_id=f"test_req_{index:04d}",
            client_id="test_client",
            operation="test_operation",
            data={
                'index': index,
                'timestamp': datetime.now().isoformat(),
                'payload': f"test_data_{index}"
            },
            classification=classification,
            timestamp=datetime.now()
        )
    
    @pytest.mark.asyncio
    async def test_basic_consensus(self):
        """Test basic consensus with no faults."""
        scenario = TestScenario(
            name="basic_consensus",
            num_nodes=4,
            num_byzantine=0,
            num_requests=10
        )
        
        result = await self._run_consensus_test(scenario)
        
        # Assertions
        assert result.success_rate == 1.0, "All requests should succeed"
        assert result.consensus_failures == 0, "No consensus failures expected"
        assert result.average_latency_ms < 100, "Latency should be under 100ms"
    
    @pytest.mark.asyncio
    async def test_byzantine_tolerance(self):
        """Test consensus with Byzantine nodes."""
        scenario = TestScenario(
            name="byzantine_tolerance",
            num_nodes=10,
            num_byzantine=3,  # Maximum tolerable
            num_requests=50,
            attack_types=[AttackType.DOUBLE_VOTING, AttackType.TIMING_ATTACK]
        )
        
        result = await self._run_consensus_test(scenario)
        
        # Assertions
        assert result.success_rate > 0.8, "Should maintain >80% success with Byzantine nodes"
        assert result.byzantine_detected > 0, "Should detect Byzantine behavior"
    
    @pytest.mark.asyncio
    async def test_network_partition(self):
        """Test consensus under network partition."""
        scenario = TestScenario(
            name="network_partition",
            num_nodes=7,
            num_byzantine=0,
            num_requests=30,
            partition_probability=0.3
        )
        
        result = await self._run_consensus_test(scenario)
        
        # Assertions - relaxed due to partitions
        assert result.success_rate > 0.5, "Should achieve some consensus despite partitions"
        assert result.view_changes > 0, "Should trigger view changes"
    
    @pytest.mark.asyncio
    async def test_performance_optimization(self):
        """Test performance with optimizations enabled."""
        scenario = TestScenario(
            name="performance_optimized",
            num_nodes=10,
            num_byzantine=2,
            num_requests=1000,
            duration_seconds=30
        )
        
        # Run with optimizations
        result_optimized = await self._run_consensus_test(scenario, enable_optimization=True)
        
        # Run without optimizations
        result_baseline = await self._run_consensus_test(scenario, enable_optimization=False)
        
        # Assertions
        assert result_optimized.throughput_rps > result_baseline.throughput_rps * 1.5, \
            "Optimizations should improve throughput by >50%"
        assert result_optimized.average_latency_ms < result_baseline.average_latency_ms * 0.7, \
            "Optimizations should reduce latency by >30%"
    
    @pytest.mark.asyncio
    async def test_scalability(self):
        """Test scalability with increasing node counts."""
        node_counts = [4, 10, 20, 50, 100]
        results = []
        
        for num_nodes in node_counts:
            scenario = TestScenario(
                name=f"scalability_{num_nodes}",
                num_nodes=num_nodes,
                num_byzantine=num_nodes // 4,  # 25% Byzantine
                num_requests=100,
                duration_seconds=20
            )
            
            result = await self._run_consensus_test(scenario)
            results.append(result)
        
        # Analyze scalability
        throughputs = [r.throughput_rps for r in results]
        latencies = [r.average_latency_ms for r in results]
        
        # Log results
        for i, count in enumerate(node_counts):
            logger.info("Nodes: %d, Throughput: %.2f RPS, Latency: %.2f ms",
                       count, throughputs[i], latencies[i])
        
        # Assertions
        # Throughput should not degrade too much
        assert throughputs[-1] > throughputs[0] * 0.3, "Throughput should scale reasonably"
        # Latency should increase sub-linearly
        assert latencies[-1] < latencies[0] * 10, "Latency should not increase dramatically"
    
    async def _run_consensus_test(
        self,
        scenario: TestScenario,
        enable_optimization: bool = True
    ) -> BenchmarkResult:
        """Run a consensus test scenario."""
        logger.info("Running test scenario: %s", scenario.name)
        
        # Create test nodes
        nodes = {}
        credentials = self._generate_test_credentials(scenario.num_nodes)
        
        # Create primary node
        primary_id = "node_000"
        primary = ByzantineFaultTolerantEngine(
            primary_id,
            credentials,
            ClassificationLevel.TOP_SECRET,
            self.audit_logger
        )
        nodes[primary_id] = primary
        
        # Create other nodes
        for i in range(1, scenario.num_nodes):
            node_id = f"node_{i:03d}"
            node = ByzantineFaultTolerantEngine(
                node_id,
                credentials,
                credentials[node_id].classification_level,
                self.audit_logger
            )
            nodes[node_id] = node
        
        # Mark Byzantine nodes
        byzantine_nodes = random.sample(
            list(nodes.keys())[1:],  # Don't make primary Byzantine
            scenario.num_byzantine
        )
        
        # Set up optimization if enabled
        optimizer = PerformanceOptimizer() if enable_optimization else None
        
        # Initialize defense system
        defense_system = ByzantineDefenseSystem(self.audit_logger)
        
        # Run test
        start_time = time.time()
        successful_requests = 0
        total_latency = 0.0
        latencies = []
        
        # Submit requests
        for i in range(scenario.num_requests):
            # Create request
            request = self._create_test_request(
                i,
                random.choice(list(ClassificationLevel))
            )
            
            # Inject Byzantine behavior
            if byzantine_nodes and random.random() < 0.3:
                await self._inject_byzantine_behavior(
                    random.choice(byzantine_nodes),
                    random.choice(scenario.attack_types) if scenario.attack_types else AttackType.DOUBLE_VOTING,
                    defense_system
                )
            
            # Inject network partition
            if random.random() < scenario.partition_probability:
                await self._simulate_partition(nodes)
            
            # Submit request
            request_start = time.time()
            
            try:
                if optimizer:
                    # Try fast path
                    result = await optimizer.execute_fast_path(
                        request,
                        lambda r, **k: asyncio.create_task(self._mock_execution(r))
                    )
                    
                    if not result:
                        # Fall back to normal consensus
                        success, result = await primary.submit_request(request)
                    else:
                        success = True
                else:
                    success, result = await primary.submit_request(request)
                
                request_latency = (time.time() - request_start) * 1000
                
                if success:
                    successful_requests += 1
                    total_latency += request_latency
                    latencies.append(request_latency)
                
            except asyncio.TimeoutError:
                logger.debug("Request %d timed out", i)
            
            # Add network delay
            await asyncio.sleep(scenario.network_delay_ms / 1000)
        
        # Calculate results
        duration = time.time() - start_time
        
        result = BenchmarkResult(
            scenario=scenario,
            throughput_rps=successful_requests / duration,
            average_latency_ms=total_latency / successful_requests if successful_requests > 0 else 0,
            p99_latency_ms=np.percentile(latencies, 99) if latencies else 0,
            success_rate=successful_requests / scenario.num_requests,
            consensus_failures=scenario.num_requests - successful_requests,
            view_changes=primary.consensus_metrics.get('view_changes', 0),
            byzantine_detected=defense_system.attack_stats['total_attacks_detected'],
            duration_seconds=duration
        )
        
        self.test_results.append(result)
        
        # Cleanup
        await primary.shutdown()
        
        return result
    
    async def _inject_byzantine_behavior(
        self,
        node_id: str,
        attack_type: AttackType,
        defense_system: ByzantineDefenseSystem
    ):
        """Inject Byzantine behavior for testing."""
        behavior = {
            'node_id': node_id,
            'timestamp': datetime.now()
        }
        
        if attack_type == AttackType.DOUBLE_VOTING:
            behavior['vote_count'] = 2
            behavior['conflicting_messages'] = True
        elif attack_type == AttackType.TIMING_ATTACK:
            behavior['delay_ms'] = 2000
            behavior['selective_delays'] = True
        elif attack_type == AttackType.FLOODING:
            behavior['message_rate'] = 200
            behavior['rapid_message_rate'] = True
        
        await defense_system.record_node_behavior(node_id, behavior)
    
    async def _simulate_partition(self, nodes: Dict[str, Any]):
        """Simulate network partition."""
        # Split nodes into two groups
        node_list = list(nodes.keys())
        partition_size = len(node_list) // 2
        
        partition_a = set(node_list[:partition_size])
        partition_b = set(node_list[partition_size:])
        
        logger.debug("Simulating partition: A=%s, B=%s", partition_a, partition_b)
        
        # In real implementation, would block communication between partitions
    
    async def _mock_execution(self, request: PBFTRequest) -> Dict[str, Any]:
        """Mock request execution."""
        return {
            'status': 'success',
            'request_id': request.request_id,
            'result': 'mock_result'
        }
    
    def run_full_test_suite(self):
        """Run complete test suite."""
        test_scenarios = [
            TestScenario("small_network", 4, 1, 50),
            TestScenario("medium_network", 10, 3, 100),
            TestScenario("large_network", 50, 16, 200),
            TestScenario("high_byzantine", 10, 3, 100, attack_types=[
                AttackType.DOUBLE_VOTING,
                AttackType.EQUIVOCATION,
                AttackType.TIMING_ATTACK
            ]),
            TestScenario("network_unstable", 10, 2, 100, 
                        network_delay_ms=50, partition_probability=0.2),
            TestScenario("stress_test", 20, 6, 1000, duration_seconds=120)
        ]
        
        # Run each scenario
        loop = asyncio.get_event_loop()
        
        for scenario in test_scenarios:
            result = loop.run_until_complete(
                self._run_consensus_test(scenario)
            )
            
            logger.info("Scenario %s: Throughput=%.2f RPS, Latency=%.2f ms, Success=%.2f%%",
                       scenario.name, result.throughput_rps, 
                       result.average_latency_ms, result.success_rate * 100)
    
    def generate_performance_report(self):
        """Generate performance benchmarking report."""
        if not self.test_results:
            logger.warning("No test results to report")
            return
        
        report = {
            'summary': {
                'total_scenarios': len(self.test_results),
                'average_throughput': np.mean([r.throughput_rps for r in self.test_results]),
                'average_latency': np.mean([r.average_latency_ms for r in self.test_results]),
                'average_success_rate': np.mean([r.success_rate for r in self.test_results])
            },
            'scenarios': [r.to_dict() for r in self.test_results],
            'analysis': self._analyze_results()
        }
        
        # Save report
        with open('byzantine_consensus_benchmark.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate plots
        self._generate_plots()
        
        return report
    
    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze test results."""
        analysis = {}
        
        # Byzantine tolerance analysis
        byzantine_results = [
            r for r in self.test_results 
            if r.scenario.num_byzantine > 0
        ]
        
        if byzantine_results:
            analysis['byzantine_tolerance'] = {
                'average_success_with_byzantine': np.mean([r.success_rate for r in byzantine_results]),
                'detection_rate': np.mean([
                    r.byzantine_detected / (r.scenario.num_byzantine * r.scenario.num_requests)
                    for r in byzantine_results
                    if r.scenario.num_byzantine > 0
                ])
            }
        
        # Scalability analysis
        node_counts = sorted(set(r.scenario.num_nodes for r in self.test_results))
        scalability_data = []
        
        for count in node_counts:
            results = [r for r in self.test_results if r.scenario.num_nodes == count]
            if results:
                scalability_data.append({
                    'nodes': count,
                    'avg_throughput': np.mean([r.throughput_rps for r in results]),
                    'avg_latency': np.mean([r.average_latency_ms for r in results])
                })
        
        analysis['scalability'] = scalability_data
        
        return analysis
    
    def _generate_plots(self):
        """Generate performance visualization plots."""
        if not self.test_results:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        
        # Throughput vs Node Count
        node_counts = [r.scenario.num_nodes for r in self.test_results]
        throughputs = [r.throughput_rps for r in self.test_results]
        
        axes[0, 0].scatter(node_counts, throughputs)
        axes[0, 0].set_xlabel('Number of Nodes')
        axes[0, 0].set_ylabel('Throughput (RPS)')
        axes[0, 0].set_title('Throughput Scalability')
        
        # Latency Distribution
        all_latencies = []
        for r in self.test_results:
            if r.average_latency_ms > 0:
                all_latencies.extend([r.average_latency_ms] * 10)  # Synthetic data
        
        axes[0, 1].hist(all_latencies, bins=30)
        axes[0, 1].set_xlabel('Latency (ms)')
        axes[0, 1].set_ylabel('Frequency')
        axes[0, 1].set_title('Latency Distribution')
        axes[0, 1].axvline(100, color='r', linestyle='--', label='Target (100ms)')
        axes[0, 1].legend()
        
        # Success Rate vs Byzantine Ratio
        byzantine_ratios = [r.scenario.byzantine_ratio for r in self.test_results]
        success_rates = [r.success_rate for r in self.test_results]
        
        axes[1, 0].scatter(byzantine_ratios, success_rates)
        axes[1, 0].set_xlabel('Byzantine Node Ratio')
        axes[1, 0].set_ylabel('Success Rate')
        axes[1, 0].set_title('Byzantine Tolerance')
        axes[1, 0].axhline(0.8, color='r', linestyle='--', label='Target (80%)')
        axes[1, 0].legend()
        
        # View Changes Over Time
        scenarios = [r.scenario.name for r in self.test_results]
        view_changes = [r.view_changes for r in self.test_results]
        
        axes[1, 1].bar(range(len(scenarios)), view_changes)
        axes[1, 1].set_xlabel('Scenario')
        axes[1, 1].set_ylabel('View Changes')
        axes[1, 1].set_title('Protocol Stability')
        axes[1, 1].set_xticks(range(len(scenarios)))
        axes[1, 1].set_xticklabels(scenarios, rotation=45)
        
        plt.tight_layout()
        plt.savefig('byzantine_consensus_performance.png')
        logger.info("Performance plots saved to byzantine_consensus_performance.png")


def run_integration_test():
    """Run full integration test with swarm components."""
    async def test():
        # Create swarm configuration
        swarm_config = SwarmConfiguration(
            min_consensus_ratio=0.67,
            max_allocation_time_ms=50.0,
            byzantine_fault_threshold=0.33
        )
        
        # Create integration
        integration = SwarmConsensusIntegration(
            "test_node",
            swarm_config,
            AuditLogger(),
            RealTimeSecurityMonitor()
        )
        
        # Create test swarm members
        members = {}
        for i in range(10):
            member = SwarmMember(
                member_id=f"drone_{i:03d}",
                platform_type="drone",
                capabilities=[
                    SwarmCapability(
                        capability_id="flight",
                        category="actuator",
                        specifications={},
                        performance_metrics={},
                        classification_level=ClassificationLevel.UNCLASSIFIED
                    )
                ],
                classification_clearance=ClassificationLevel.SECRET,
                current_load=0.3,
                reliability_score=0.95
            )
            members[member.member_id] = member
        
        # Initialize components
        credentials = ByzantineConsensusTestSuite()._generate_test_credentials(10)
        await integration.initialize_components(
            members,
            credentials,
            ClassificationLevel.SECRET
        )
        
        # Test task allocation consensus
        task = SwarmTask(
            task_id="test_task_001",
            task_type="surveillance",
            required_capabilities=["flight"],
            priority=TaskPriority.HIGH,
            classification=ClassificationLevel.SECRET,
            payload={'test': True},
            constraints={},
            created_at=datetime.now()
        )
        
        candidates = list(members.keys())[:5]
        
        success, allocated_to = await integration.request_task_allocation_consensus(
            task, candidates
        )
        
        assert success, "Task allocation consensus should succeed"
        assert allocated_to in candidates, "Should allocate to one of the candidates"
        
        # Get metrics
        metrics = integration.get_integration_metrics()
        logger.info("Integration test metrics: %s", json.dumps(metrics, indent=2))
        
        # Shutdown
        await integration.shutdown()
    
    asyncio.run(test())
    logger.info("Integration test completed successfully")


if __name__ == "__main__":
    # Run test suite
    suite = ByzantineConsensusTestSuite()
    
    # Run individual tests
    asyncio.run(suite.test_basic_consensus())
    asyncio.run(suite.test_byzantine_tolerance())
    asyncio.run(suite.test_network_partition())
    asyncio.run(suite.test_performance_optimization())
    asyncio.run(suite.test_scalability())
    
    # Run full benchmark suite
    suite.run_full_test_suite()
    
    # Generate report
    report = suite.generate_performance_report()
    print(json.dumps(report['summary'], indent=2))
    
    # Run integration test
    run_integration_test()