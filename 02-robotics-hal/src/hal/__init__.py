#!/usr/bin/env python3
"""
@license
Copyright 2024 ALCUB3 Systems
SPDX-License-Identifier: Apache-2.0

ALCUB3 Universal Security HAL - Core Architecture Package
Patent-Pending Universal Robotics Security Interface

This package implements the foundational Hardware Abstraction Layer (HAL)
for unified security interfaces across all robotics platforms with MAESTRO
L1-L3 integration and defense-grade classification handling.

Task 20: Universal Security HAL Core Architecture
Key Innovations:
- Abstract base classes for security operations, authentication, and command validation
- SecurityHAL class with platform registration and security policy enforcement
- Unified logging with MAESTRO classification awareness
- Real-time performance monitoring with sub-50ms response targets
- Cross-platform compatibility for 20+ robotics platforms

Patent Applications:
- Universal security interface abstraction for heterogeneous robotics platforms
- Classification-aware security inheritance for robotics command validation
- Real-time security state synchronization across multi-platform fleets
- Hardware-agnostic emergency response coordination system
"""

from .core_hal import (
    # Core HAL interfaces
    RoboticsHAL,
    SecurityOperations,
    AuthenticationProvider,
    CommandValidator,
    
    # Platform abstractions
    PlatformAdapter,
    SecurityAdapter,
    
    # Security enums and types
    SecurityLevel,
    ValidationResult,
    AuthenticationResult,
    SecurityStatus,
    EmergencyStopReason,
    
    # Core data structures
    RobotPlatform,
    SecurityCommand,
    SecurityProfile,
    SecurityEvent,
    PerformanceMetrics
)

from .security_hal import (
    UniversalSecurityHAL,
    RobotSecurityProfile,
    SecurityValidationLevel,
    RobotPlatformType,
    RobotOperationStatus,
    EmergencyStopEvent
)

from .platform_adapter import (
    BasePlatformAdapter,
    PlatformAdapterFactory,
    AdapterRegistry
)

from .performance_monitor import (
    HALPerformanceMonitor,
    PerformanceCollector,
    MetricType,
    PerformanceThreshold
)

# Version information
__version__ = "1.0.0"
__title__ = "ALCUB3 Universal Security HAL"
__description__ = "Patent-pending universal robotics security interface"
__author__ = "ALCUB3 Systems"
__license__ = "Apache-2.0"

# Export main HAL interface
__all__ = [
    # Core interfaces
    'RoboticsHAL',
    'SecurityOperations', 
    'AuthenticationProvider',
    'CommandValidator',
    'PlatformAdapter',
    'SecurityAdapter',
    
    # Main HAL implementation
    'UniversalSecurityHAL',
    
    # Platform support
    'BasePlatformAdapter',
    'PlatformAdapterFactory',
    'AdapterRegistry',
    
    # Performance monitoring
    'HALPerformanceMonitor',
    'PerformanceCollector',
    
    # Types and enums
    'SecurityLevel',
    'ValidationResult',
    'AuthenticationResult',
    'SecurityStatus',
    'EmergencyStopReason',
    'SecurityValidationLevel',
    'RobotPlatformType',
    'RobotOperationStatus',
    'MetricType',
    'PerformanceThreshold',
    
    # Data structures
    'RobotPlatform',
    'SecurityCommand',
    'SecurityProfile',
    'SecurityEvent',
    'PerformanceMetrics',
    'RobotSecurityProfile',
    'EmergencyStopEvent'
] 