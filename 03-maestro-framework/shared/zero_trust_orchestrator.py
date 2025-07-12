#!/usr/bin/env python3
"""
ALCUB3 Zero-Trust Orchestrator
High-level orchestration interface for zero-trust architecture

This module provides the main entry point for using the zero-trust
system, offering simplified APIs and example usage patterns.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path

# Import the integration layer
from zero_trust_integration import (
    ZeroTrustOrchestrator,
    ZeroTrustContext,
    SecurityPosture,
    SecurityEvent
)

# Import MAESTRO components
import sys
sys.path.append(str(Path(__file__).parent.parent))

from classification import ClassificationLevel
from audit_logger import AuditLogger
from real_time_monitor import RealTimeMonitor

logger = logging.getLogger(__name__)


class AlcubZeroTrust:
    """
    Main interface for ALCUB3 Zero-Trust Architecture.
    
    This class provides simplified access to all zero-trust capabilities
    with sensible defaults and easy-to-use methods.
    """
    
    def __init__(
        self,
        config_path: Optional[str] = None,
        enable_monitoring: bool = True
    ):
        """
        Initialize ALCUB3 Zero-Trust system.
        
        Args:
            config_path: Path to configuration file
            enable_monitoring: Enable real-time monitoring
        """
        self.config = self._load_config(config_path)
        
        # Initialize audit logger
        self.audit_logger = AuditLogger()
        
        # Initialize monitoring if enabled
        self.monitor = None
        if enable_monitoring:
            self.monitor = RealTimeMonitor()
        
        # Create orchestrator
        self.orchestrator = ZeroTrustOrchestrator(
            orchestrator_id="alcub3_zt_main",
            audit_logger=self.audit_logger,
            monitor=self.monitor,
            config=self.config
        )
        
        self._initialized = False
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        default_config = {
            'enable_hsm': True,
            'enable_pfd': False,
            'hardware_acceleration': True,
            'enable_policy_cache': True,
            'ml_model_path': None,
            'attestation_ca_path': '/etc/alcub3/attestation/cas',
            'challenge_threshold': 60.0,
            'maestro_integrations': ['jit_privilege', 'mtls', 'clearance_control']
        }
        
        # TODO: Load from file if provided
        return default_config
    
    async def initialize(self):
        """Initialize the zero-trust system."""
        if self._initialized:
            logger.warning("Zero-trust system already initialized")
            return
        
        logger.info("Initializing ALCUB3 Zero-Trust Architecture...")
        
        try:
            # Initialize orchestrator and all components
            await self.orchestrator.initialize()
            
            # Register default event handlers
            self._register_default_handlers()
            
            # Set initial security posture
            await self.orchestrator.update_security_posture(
                SecurityPosture.BASELINE,
                "System initialization"
            )
            
            self._initialized = True
            logger.info("ALCUB3 Zero-Trust Architecture initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize zero-trust system: %s", str(e))
            raise
    
    def _register_default_handlers(self):
        """Register default security event handlers."""
        # Handler for critical events
        async def critical_event_handler(event: SecurityEvent):
            if event.severity == 'critical':
                logger.critical("Critical security event: %s - %s",
                              event.event_type, event.details)
                
                # Escalate to high alert if multiple critical events
                recent_critical = sum(
                    1 for e in self.orchestrator.security_events[-10:]
                    if e.severity == 'critical'
                )
                
                if recent_critical >= 3:
                    await self.orchestrator.update_security_posture(
                        SecurityPosture.HIGH_ALERT,
                        "Multiple critical security events detected"
                    )
        
        self.orchestrator.register_event_handler(
            'component_failure',
            critical_event_handler
        )
    
    async def evaluate_access(
        self,
        user_id: Optional[str] = None,
        device_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate an access request through zero-trust policies.
        
        This is the main entry point for access control decisions.
        
        Args:
            user_id: User identifier
            device_id: Device identifier
            resource_id: Resource being accessed
            action: Action to perform (read, write, etc.)
            source_ip: Source IP address
            destination_ip: Destination IP address
            classification: Data classification level
            metadata: Additional context metadata
            
        Returns:
            Tuple of (allowed, decision_details)
        """
        if not self._initialized:
            raise RuntimeError("Zero-trust system not initialized")
        
        # Create context
        context = ZeroTrustContext(
            request_id=f"req_{hash((user_id, resource_id, time.time()))}",
            timestamp=datetime.utcnow(),
            user_id=user_id,
            device_id=device_id,
            resource_id=resource_id,
            action=action,
            source_ip=source_ip,
            destination_ip=destination_ip,
            classification=classification,
            metadata=metadata or {}
        )
        
        # Evaluate through orchestrator
        return await self.orchestrator.evaluate_access(context)
    
    async def register_device(
        self,
        device_id: str,
        device_type: str,
        manufacturer: str,
        model: str,
        serial_number: str,
        attestation_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Register a device for zero-trust scoring.
        
        Args:
            device_id: Unique device identifier
            device_type: Type of device
            manufacturer: Device manufacturer
            model: Device model
            serial_number: Serial number
            attestation_data: Hardware attestation data
            
        Returns:
            Device registration result
        """
        device_trust = self.orchestrator.components.get('device_trust')
        if not device_trust:
            raise RuntimeError("Device trust component not available")
        
        # Convert device type string to enum
        from zero_trust.device_trust_scorer import DeviceType
        device_type_enum = DeviceType[device_type.upper()]
        
        # Register device
        device_profile = await device_trust.register_device(
            device_id=device_id,
            device_type=device_type_enum,
            manufacturer=manufacturer,
            model=model,
            serial_number=serial_number,
            hardware_attestation=attestation_data
        )
        
        # Calculate initial trust score
        trust_score = await device_trust.calculate_trust_score(device_id)
        
        return {
            'device_id': device_id,
            'registration_date': device_profile.registration_date.isoformat(),
            'trust_score': trust_score.overall_score,
            'trust_level': trust_score.trust_level.value
        }
    
    async def create_session(
        self,
        user_id: str,
        device_id: str,
        auth_method: str,
        classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a continuous verification session.
        
        Args:
            user_id: User identifier
            device_id: Device identifier
            auth_method: Initial authentication method
            classification_level: Session classification
            metadata: Additional session metadata
            
        Returns:
            Session creation result
        """
        continuous_verification = self.orchestrator.components.get('continuous_verification')
        if not continuous_verification:
            raise RuntimeError("Continuous verification component not available")
        
        # Convert auth method string to enum
        from zero_trust.continuous_verification import AuthenticationMethod
        auth_method_enum = AuthenticationMethod[auth_method.upper()]
        
        # Create session
        session = await continuous_verification.create_session(
            user_id=user_id,
            device_id=device_id,
            classification_level=classification_level,
            initial_auth_method=auth_method_enum,
            metadata=metadata
        )
        
        return {
            'session_id': session.session_id,
            'created_at': session.start_time.isoformat(),
            'risk_score': session.risk_score,
            'state': session.state.value
        }
    
    async def create_network_zone(
        self,
        zone_name: str,
        ip_ranges: List[str],
        description: Optional[str] = None
    ):
        """
        Create a network zone for microsegmentation.
        
        Args:
            zone_name: Name of the zone
            ip_ranges: List of IP ranges (CIDR notation)
            description: Optional zone description
        """
        network_gateway = self.orchestrator.components.get('network_gateway')
        if network_gateway:
            await network_gateway.create_network_zone(
                zone_name=zone_name,
                ip_ranges=ip_ranges,
                metadata={'description': description}
            )
        
        microsegmentation = self.orchestrator.components.get('microsegmentation')
        if microsegmentation:
            # Create corresponding segment
            from zero_trust.microsegmentation_engine import SegmentType
            
            await microsegmentation.create_segment(
                name=f"Zone: {zone_name}",
                segment_type=SegmentType.UNCLASSIFIED,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                subnet=ip_ranges[0] if ip_ranges else None,
                metadata={'zone_name': zone_name, 'description': description}
            )
    
    async def set_security_posture(self, posture: str, reason: str):
        """
        Update the system security posture.
        
        Args:
            posture: New posture (baseline, elevated, high_alert, lockdown, emergency)
            reason: Reason for posture change
        """
        posture_enum = SecurityPosture[posture.upper()]
        await self.orchestrator.update_security_posture(posture_enum, reason)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        status = self.orchestrator.get_status()
        
        # Add component-specific statistics
        component_stats = {}
        for name, component in self.orchestrator.components.items():
            if hasattr(component, 'get_statistics'):
                component_stats[name] = component.get_statistics()
        
        status['component_statistics'] = component_stats
        
        return status
    
    async def shutdown(self):
        """Shutdown the zero-trust system."""
        if not self._initialized:
            return
        
        logger.info("Shutting down ALCUB3 Zero-Trust Architecture...")
        
        await self.orchestrator.stop()
        
        if self.monitor:
            # Stop monitoring
            pass
        
        self._initialized = False
        logger.info("ALCUB3 Zero-Trust Architecture shutdown complete")


# Example usage and demonstration
async def demonstrate_zero_trust():
    """Demonstrate zero-trust capabilities."""
    import time
    from datetime import datetime
    
    # Initialize system
    zt = AlcubZeroTrust()
    await zt.initialize()
    
    try:
        # 1. Register a device
        print("\n1. Registering device...")
        device_result = await zt.register_device(
            device_id="laptop-001",
            device_type="laptop",
            manufacturer="Dell",
            model="Latitude 7420",
            serial_number="DL7420X123"
        )
        print(f"Device registered with trust score: {device_result['trust_score']}")
        
        # 2. Create a session
        print("\n2. Creating session...")
        session_result = await zt.create_session(
            user_id="user-123",
            device_id="laptop-001",
            auth_method="password",
            classification_level=ClassificationLevel.SECRET
        )
        print(f"Session created: {session_result['session_id']}")
        
        # 3. Create network zones
        print("\n3. Creating network zones...")
        await zt.create_network_zone(
            zone_name="corporate",
            ip_ranges=["10.0.0.0/8"],
            description="Corporate network"
        )
        await zt.create_network_zone(
            zone_name="dmz",
            ip_ranges=["172.16.0.0/24"],
            description="DMZ network"
        )
        print("Network zones created")
        
        # 4. Evaluate access requests
        print("\n4. Evaluating access requests...")
        
        # Allowed access
        allowed, details = await zt.evaluate_access(
            user_id="user-123",
            device_id="laptop-001",
            resource_id="file-server",
            action="read",
            source_ip="10.0.1.100",
            destination_ip="10.0.2.200",
            classification=ClassificationLevel.SECRET
        )
        print(f"Access decision: {'ALLOWED' if allowed else 'DENIED'}")
        print(f"Risk score: {details.get('overall_risk_score', 0)}")
        
        # Simulate suspicious activity
        print("\n5. Simulating suspicious activity...")
        for i in range(5):
            await zt.evaluate_access(
                user_id="user-456",
                device_id="unknown-device",
                resource_id="sensitive-db",
                action="write",
                source_ip="192.168.1.100",
                destination_ip="10.0.3.50",
                classification=ClassificationLevel.TOP_SECRET
            )
            await asyncio.sleep(0.1)
        
        # Get system status
        print("\n6. System status:")
        status = await zt.get_system_status()
        print(f"Security posture: {status['security_posture']}")
        print(f"Active incidents: {status['active_incidents']}")
        print(f"Total requests: {status['metrics']['requests_processed']}")
        
        # Demonstrate posture change
        print("\n7. Elevating security posture...")
        await zt.set_security_posture("elevated", "Demonstration of manual posture change")
        
    finally:
        # Shutdown
        print("\n8. Shutting down...")
        await zt.shutdown()
        print("Shutdown complete")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run demonstration
    asyncio.run(demonstrate_zero_trust())