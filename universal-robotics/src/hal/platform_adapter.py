#!/usr/bin/env python3
"""
@license
Copyright 2024 ALCUB3 Systems
SPDX-License-Identifier: Apache-2.0

ALCUB3 Universal Security HAL - Platform Adapter Framework
Patent-Pending Platform Adapter Management System

This module implements the platform adapter framework for the Universal
Security HAL, providing a factory pattern and registry system for managing
platform-specific security adapters across heterogeneous robotics platforms.

Task 20: Platform Adapter Framework Implementation
Key Innovations:
- Universal platform adapter factory with dynamic loading
- Registry system for platform-specific security adapters
- Abstract base classes for standardized platform integration
- Plugin architecture for extensible platform support

Patent Applications:
- Universal platform adapter framework for heterogeneous robotics systems
- Dynamic adapter loading and registration system
- Standardized security interface abstraction for robotics platforms
- Plugin-based architecture for extensible platform support
"""

import asyncio
import importlib
import inspect
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Type, Callable
from enum import Enum
from dataclasses import dataclass
import logging
from pathlib import Path

from .core_hal import (
    PlatformAdapter, SecurityAdapter, RobotPlatform, SecurityCommand,
    SecurityProfile, SecurityEvent, ValidationResult, EmergencyStopReason,
    PlatformException
)


class AdapterStatus(Enum):
    """Platform adapter status."""
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    DEGRADED = "degraded"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class AdapterInfo:
    """Platform adapter information."""
    adapter_id: str
    adapter_name: str
    platform_type: str
    version: str
    supported_operations: List[str]
    security_features: List[str]
    status: AdapterStatus
    last_health_check: Optional[str] = None
    error_message: Optional[str] = None


class BasePlatformAdapter(PlatformAdapter):
    """
    Base implementation of platform adapter with common functionality.
    
    Provides standard implementations for common platform operations
    while allowing platform-specific customization through inheritance.
    """
    
    def __init__(self, adapter_id: str, config: Optional[Dict[str, Any]] = None):
        """Initialize base platform adapter."""
        self.adapter_id = adapter_id
        self.config = config or {}
        self.logger = logging.getLogger(f"PlatformAdapter.{adapter_id}")
        self.status = AdapterStatus.UNINITIALIZED
        self.platform = None
        self.security_profile = None
        self.last_command_time = None
        self.command_history = []
        self.error_count = 0
        
    async def initialize_platform(self, platform: RobotPlatform) -> bool:
        """Initialize platform adapter."""
        try:
            self.status = AdapterStatus.INITIALIZING
            self.platform = platform
            
            # Perform platform-specific initialization
            success = await self._platform_specific_init()
            
            if success:
                self.status = AdapterStatus.ACTIVE
                self.logger.info(f"Platform adapter {self.adapter_id} initialized successfully")
            else:
                self.status = AdapterStatus.ERROR
                self.logger.error(f"Platform adapter {self.adapter_id} initialization failed")
            
            return success
            
        except Exception as e:
            self.status = AdapterStatus.ERROR
            self.logger.error(f"Error initializing platform adapter {self.adapter_id}: {e}")
            return False
    
    @abstractmethod
    async def _platform_specific_init(self) -> bool:
        """Platform-specific initialization logic."""
        pass
    
    async def execute_command(self, command: SecurityCommand) -> bool:
        """Execute validated command on platform."""
        try:
            if self.status != AdapterStatus.ACTIVE:
                raise PlatformException(f"Adapter {self.adapter_id} not active")
            
            # Record command
            self.last_command_time = command.timestamp
            self.command_history.append(command.command_id)
            
            # Execute platform-specific command
            success = await self._execute_platform_command(command)
            
            if not success:
                self.error_count += 1
                if self.error_count > 5:
                    self.status = AdapterStatus.DEGRADED
            
            return success
            
        except Exception as e:
            self.error_count += 1
            self.logger.error(f"Error executing command on {self.adapter_id}: {e}")
            return False
    
    @abstractmethod
    async def _execute_platform_command(self, command: SecurityCommand) -> bool:
        """Platform-specific command execution."""
        pass
    
    async def emergency_stop(self, platform_id: str, reason: EmergencyStopReason) -> bool:
        """Execute emergency stop on platform."""
        try:
            self.logger.warning(f"Emergency stop triggered on {platform_id}: {reason.value}")
            
            # Execute platform-specific emergency stop
            success = await self._execute_emergency_stop(reason)
            
            if success:
                self.logger.info(f"Emergency stop completed on {platform_id}")
            else:
                self.logger.error(f"Emergency stop failed on {platform_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error executing emergency stop on {platform_id}: {e}")
            return False
    
    @abstractmethod
    async def _execute_emergency_stop(self, reason: EmergencyStopReason) -> bool:
        """Platform-specific emergency stop implementation."""
        pass
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get current platform status."""
        try:
            # Get platform-specific status
            platform_status = await self._get_platform_specific_status()
            
            return {
                "adapter_id": self.adapter_id,
                "adapter_status": self.status.value,
                "platform_id": self.platform.platform_id if self.platform else None,
                "last_command_time": self.last_command_time.isoformat() if self.last_command_time else None,
                "error_count": self.error_count,
                "command_history_count": len(self.command_history),
                "platform_specific": platform_status
            }
            
        except Exception as e:
            self.logger.error(f"Error getting platform status for {self.adapter_id}: {e}")
            return {"adapter_id": self.adapter_id, "status": "error", "error": str(e)}
    
    async def _get_platform_specific_status(self) -> Dict[str, Any]:
        """Get platform-specific status information."""
        return {}
    
    async def update_security_profile(self, profile: SecurityProfile) -> bool:
        """Update platform security profile."""
        try:
            self.security_profile = profile
            
            # Apply security profile to platform
            success = await self._apply_security_profile(profile)
            
            if success:
                self.logger.info(f"Security profile updated for {self.adapter_id}")
            else:
                self.logger.error(f"Failed to update security profile for {self.adapter_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error updating security profile for {self.adapter_id}: {e}")
            return False
    
    async def _apply_security_profile(self, profile: SecurityProfile) -> bool:
        """Apply security profile to platform."""
        return True  # Default implementation
    
    async def health_check(self) -> bool:
        """Perform health check on adapter."""
        try:
            # Check adapter status
            if self.status != AdapterStatus.ACTIVE:
                return False
            
            # Perform platform-specific health check
            platform_healthy = await self._platform_health_check()
            
            if not platform_healthy:
                self.status = AdapterStatus.DEGRADED
            
            return platform_healthy
            
        except Exception as e:
            self.logger.error(f"Health check failed for {self.adapter_id}: {e}")
            self.status = AdapterStatus.ERROR
            return False
    
    async def _platform_health_check(self) -> bool:
        """Platform-specific health check."""
        return True  # Default implementation


class AdapterRegistry:
    """Registry for platform adapters."""
    
    def __init__(self):
        """Initialize adapter registry."""
        self.adapters: Dict[str, Type[PlatformAdapter]] = {}
        self.adapter_info: Dict[str, AdapterInfo] = {}
        self.logger = logging.getLogger("AdapterRegistry")
        
    def register_adapter(self, platform_type: str, adapter_class: Type[PlatformAdapter], 
                        adapter_info: AdapterInfo):
        """Register a platform adapter."""
        try:
            # Validate adapter class
            if not issubclass(adapter_class, PlatformAdapter):
                raise ValueError(f"Adapter class must inherit from PlatformAdapter")
            
            self.adapters[platform_type] = adapter_class
            self.adapter_info[platform_type] = adapter_info
            
            self.logger.info(f"Registered adapter for platform type: {platform_type}")
            
        except Exception as e:
            self.logger.error(f"Error registering adapter for {platform_type}: {e}")
            raise
    
    def unregister_adapter(self, platform_type: str):
        """Unregister a platform adapter."""
        try:
            if platform_type in self.adapters:
                del self.adapters[platform_type]
                del self.adapter_info[platform_type]
                self.logger.info(f"Unregistered adapter for platform type: {platform_type}")
            
        except Exception as e:
            self.logger.error(f"Error unregistering adapter for {platform_type}: {e}")
    
    def get_adapter_class(self, platform_type: str) -> Optional[Type[PlatformAdapter]]:
        """Get adapter class for platform type."""
        return self.adapters.get(platform_type)
    
    def get_adapter_info(self, platform_type: str) -> Optional[AdapterInfo]:
        """Get adapter information for platform type."""
        return self.adapter_info.get(platform_type)
    
    def list_adapters(self) -> List[str]:
        """List all registered platform types."""
        return list(self.adapters.keys())
    
    def get_all_adapter_info(self) -> Dict[str, AdapterInfo]:
        """Get all adapter information."""
        return self.adapter_info.copy()


class PlatformAdapterFactory:
    """Factory for creating platform adapters."""
    
    def __init__(self, registry: Optional[AdapterRegistry] = None):
        """Initialize platform adapter factory."""
        self.registry = registry or AdapterRegistry()
        self.logger = logging.getLogger("PlatformAdapterFactory")
        self._load_builtin_adapters()
    
    def _load_builtin_adapters(self):
        """Load built-in platform adapters."""
        try:
            # Register mock adapter for testing
            self.registry.register_adapter(
                "mock",
                MockPlatformAdapter,
                AdapterInfo(
                    adapter_id="mock_adapter",
                    adapter_name="Mock Platform Adapter",
                    platform_type="mock",
                    version="1.0.0",
                    supported_operations=["move", "stop", "status"],
                    security_features=["authentication", "encryption"],
                    status=AdapterStatus.UNINITIALIZED
                )
            )
            
        except Exception as e:
            self.logger.error(f"Error loading builtin adapters: {e}")
    
    async def create_adapter(self, platform_type: str, adapter_id: str, 
                           config: Optional[Dict[str, Any]] = None) -> Optional[PlatformAdapter]:
        """Create a platform adapter instance."""
        try:
            adapter_class = self.registry.get_adapter_class(platform_type)
            
            if not adapter_class:
                self.logger.error(f"No adapter registered for platform type: {platform_type}")
                return None
            
            # Create adapter instance
            if config:
                adapter = adapter_class(adapter_id, config)
            else:
                adapter = adapter_class(adapter_id)
            
            self.logger.info(f"Created adapter instance for {platform_type}: {adapter_id}")
            return adapter
            
        except Exception as e:
            self.logger.error(f"Error creating adapter for {platform_type}: {e}")
            return None
    
    def load_adapter_from_module(self, module_path: str, platform_type: str):
        """Load adapter from external module."""
        try:
            # Import module
            module = importlib.import_module(module_path)
            
            # Find adapter class in module
            adapter_class = None
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, PlatformAdapter) and 
                    obj != PlatformAdapter and 
                    obj != BasePlatformAdapter):
                    adapter_class = obj
                    break
            
            if not adapter_class:
                raise ValueError(f"No valid adapter class found in module {module_path}")
            
            # Create adapter info
            adapter_info = AdapterInfo(
                adapter_id=f"{platform_type}_adapter",
                adapter_name=getattr(adapter_class, '__name__', platform_type),
                platform_type=platform_type,
                version=getattr(adapter_class, '__version__', '1.0.0'),
                supported_operations=getattr(adapter_class, 'SUPPORTED_OPERATIONS', []),
                security_features=getattr(adapter_class, 'SECURITY_FEATURES', []),
                status=AdapterStatus.UNINITIALIZED
            )
            
            # Register adapter
            self.registry.register_adapter(platform_type, adapter_class, adapter_info)
            
            self.logger.info(f"Loaded adapter from module {module_path} for platform {platform_type}")
            
        except Exception as e:
            self.logger.error(f"Error loading adapter from module {module_path}: {e}")
            raise
    
    def get_registry(self) -> AdapterRegistry:
        """Get the adapter registry."""
        return self.registry


class MockPlatformAdapter(BasePlatformAdapter):
    """Mock platform adapter for testing."""
    
    SUPPORTED_OPERATIONS = ["move", "stop", "status", "emergency_stop"]
    SECURITY_FEATURES = ["authentication", "encryption", "audit_logging"]
    
    async def _platform_specific_init(self) -> bool:
        """Mock platform initialization."""
        self.logger.info(f"Mock platform {self.adapter_id} initialized")
        return True
    
    async def _execute_platform_command(self, command: SecurityCommand) -> bool:
        """Mock command execution."""
        self.logger.info(f"Mock platform executing command: {command.command_type}")
        await asyncio.sleep(0.01)  # Simulate processing time
        return True
    
    async def _execute_emergency_stop(self, reason: EmergencyStopReason) -> bool:
        """Mock emergency stop."""
        self.logger.warning(f"Mock platform emergency stop: {reason.value}")
        return True
    
    async def _get_platform_specific_status(self) -> Dict[str, Any]:
        """Mock platform status."""
        return {
            "connection_status": "connected",
            "battery_level": 85,
            "position": {"x": 0, "y": 0, "z": 0},
            "mock_data": True
        }
    
    async def _platform_health_check(self) -> bool:
        """Mock health check."""
        return True


# Global factory instance
_global_factory: Optional[PlatformAdapterFactory] = None

def get_adapter_factory() -> PlatformAdapterFactory:
    """Get global adapter factory instance."""
    global _global_factory
    if _global_factory is None:
        _global_factory = PlatformAdapterFactory()
    return _global_factory


def register_adapter(platform_type: str, adapter_class: Type[PlatformAdapter], 
                    adapter_info: AdapterInfo):
    """Convenience function to register adapter globally."""
    factory = get_adapter_factory()
    factory.get_registry().register_adapter(platform_type, adapter_class, adapter_info) 