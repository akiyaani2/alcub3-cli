#!/usr/bin/env python3
"""
ALCUB3 Swarm Intelligence Security Platform
Patent-Pending Distributed Task Allocation System

This module implements the core swarm intelligence platform with
Byzantine fault-tolerant task allocation for defense-grade robotics.

Key Innovations:
- Hierarchical consensus with classification awareness
- Predictive task allocation using swarm intelligence
- Zero-trust swarm architecture with continuous attestation
- Dynamic load balancing with <50ms decision time
- Byzantine fault tolerance with 33% adversarial nodes

Patent Applications:
- Classification-weighted consensus for military swarms
- Predictive task reallocation with ML-based failure prediction
- Zero-trust task validation with cryptographic proofs
- Self-organizing task clustering for swarm optimization
"""

from .distributed_task_allocator import (
    DistributedTaskAllocator,
    SwarmTask,
    SwarmMember,
    TaskAllocationResult,
    ConsensusProtocol,
    SwarmConfiguration
)

__all__ = [
    'DistributedTaskAllocator',
    'SwarmTask',
    'SwarmMember',
    'TaskAllocationResult',
    'ConsensusProtocol',
    'SwarmConfiguration'
]

__version__ = '1.0.0'
__author__ = 'ALCUB3 Team'
__classification__ = 'UNCLASSIFIED'  # Module itself is unclassified