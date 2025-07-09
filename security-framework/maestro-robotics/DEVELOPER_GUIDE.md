# ALCUB3 Universal Security HAL - Developer Guide

## Overview

The ALCUB3 Universal Security HAL provides a unified security interface for controlling heterogeneous robotics platforms with MAESTRO L1-L3 security integration. This guide covers how to integrate new platforms and use the HAL effectively.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Universal Security HAL                 │
├─────────────────────────────────────────────────────────┤
│  Command Validation Pipeline │ Security Policy Engine   │
├─────────────────────────────────────────────────────────┤
│              Platform Security Adapters                  │
├──────────┬──────────┬──────────┬──────────┬───────────┤
│  Boston  │   ROS2   │   DJI    │  Ghost   │  Custom   │
│ Dynamics │  /SROS2  │  Drones  │ Robotics │ Platform  │
└──────────┴──────────┴──────────┴──────────┴───────────┘
```

## Quick Start

### 1. Initialize the HAL

```python
from maestro_robotics import UniversalSecurityHAL, ClassificationLevel

# Initialize with appropriate classification level
hal = UniversalSecurityHAL(
    classification_level=ClassificationLevel.SECRET,
    config_path="hal_config.json"  # Optional
)
```

### 2. Register a Robot

```python
# Register a Boston Dynamics Spot robot
success = await hal.register_robot(
    robot_id="spot_001",
    platform_type=PlatformType.BOSTON_DYNAMICS,
    classification_level=ClassificationLevel.SECRET,
    connection_params={
        "robot_ip": "192.168.1.100",
        "username": "operator",
        "password": "secure_password"
    }
)
```

### 3. Execute Commands

```python
# Execute a simple command
success, result = await hal.execute_command(
    robot_id="spot_001",
    command_type="stand",
    parameters={},
    issuer_id="operator_001",
    issuer_clearance=ClassificationLevel.SECRET
)

# Execute with specific classification
success, result = await hal.execute_command(
    robot_id="spot_001",
    command_type="navigate",
    parameters={"waypoints": [{"x": 10, "y": 10}]},
    issuer_id="operator_001",
    issuer_clearance=ClassificationLevel.TOP_SECRET,
    classification=ClassificationLevel.SECRET  # Command classification
)
```

### 4. Fleet Operations

```python
# Execute synchronized fleet command
fleet_command = await hal.execute_fleet_command(
    target_robots=["spot_001", "spot_002", "ros_001"],
    command_type="emergency_stop",
    parameters={},
    coordination_mode=FleetCoordinationMode.SYNCHRONIZED,
    issuer_id="fleet_commander",
    issuer_clearance=ClassificationLevel.TOP_SECRET
)
```

## Creating Platform Adapters

### 1. Inherit from PlatformSecurityAdapter

```python
from maestro_robotics.core import PlatformSecurityAdapter, PlatformType

class MyRobotAdapter(PlatformSecurityAdapter):
    def __init__(self, adapter_id, classification_level, audit_logger=None):
        super().__init__(
            adapter_id=adapter_id,
            platform_type=PlatformType.CUSTOM,
            classification_level=classification_level,
            audit_logger=audit_logger
        )
```

### 2. Implement Required Methods

```python
async def connect_platform(self, connection_params: Dict[str, Any]) -> bool:
    """Establish connection to your robot."""
    try:
        # Your connection logic here
        self.robot_client = MyRobotSDK.connect(
            ip=connection_params["ip"],
            port=connection_params.get("port", 9559)
        )
        return True
    except Exception as e:
        self.logger.error(f"Connection failed: {e}")
        return False

async def translate_command(self, secure_command: SecureCommand) -> Tuple[bool, Any]:
    """Translate MAESTRO command to platform format."""
    # Apply security restrictions
    # Validate against platform capabilities
    # Return translated command
    
async def execute_platform_command(self, platform_command: Any) -> CommandResult:
    """Execute on actual robot."""
    # Send to robot
    # Monitor execution
    # Return result
```

### 3. Define Platform Capabilities

```python
def _initialize_capabilities(self):
    """Define what your robot can do."""
    self.capabilities = {
        "move_forward": PlatformCapability(
            name="move_forward",
            command_type=CommandType.MOVEMENT,
            min_classification=ClassificationLevel.UNCLASSIFIED,
            risk_level=3,
            constraints={
                "distance_m": {"min": 0, "max": 100},
                "speed_mps": {"min": 0, "max": 2.0}
            }
        ),
        "emergency_stop": PlatformCapability(
            name="emergency_stop",
            command_type=CommandType.EMERGENCY,
            min_classification=ClassificationLevel.UNCLASSIFIED,
            risk_level=1,
            requires_authorization=False
        )
    }
```

### 4. Register Your Adapter

```python
# Register adapter class with HAL
hal.register_platform_adapter(PlatformType.CUSTOM, MyRobotAdapter)

# Now you can register robots of this type
await hal.register_robot(
    robot_id="my_robot_001",
    platform_type=PlatformType.CUSTOM,
    classification_level=ClassificationLevel.SECRET,
    connection_params={"ip": "192.168.1.200"}
)
```

## Security Policies

### Adding Custom Policies

```python
from maestro_robotics.core import PolicyRule, PolicyType, PolicyPriority, PolicyAction

# Create custom policy
geofence_policy = PolicyRule(
    rule_id="POL_CUSTOM_001",
    name="Restricted Area Geofence",
    description="Prevent robots from entering restricted areas",
    policy_type=PolicyType.OPERATIONAL_BOUNDARY,
    priority=PolicyPriority.HIGH,
    classification_levels=[ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET],
    conditions={
        "restricted_zones": [
            {"center": {"lat": 38.8977, "lon": -77.0365}, "radius_m": 1000}
        ]
    },
    action=PolicyAction.DENY
)

# Add to policy engine
hal.policy_engine.add_policy(geofence_policy)
```

### Policy Evaluation Hook

```python
# Custom policy evaluation
async def custom_policy_check(command_data, context):
    # Your custom logic
    if risky_operation(command_data):
        return PolicyAction.REQUIRE_AUTHORIZATION
    return PolicyAction.ALLOW

# Register hook
hal.policy_engine.register_custom_evaluator(custom_policy_check)
```

## Classification Handling

### Classification Levels

- **UNCLASSIFIED**: Public operations, basic functionality
- **CUI**: Controlled Unclassified Information, limited capabilities
- **SECRET**: Classified operations, enhanced capabilities
- **TOP SECRET**: Highest security, full capabilities

### Automatic Restrictions

```python
# Speed limits by classification
UNCLASSIFIED: max_speed = 0.5 m/s, max_range = 100m
CUI:          max_speed = 1.0 m/s, max_range = 500m  
SECRET:       max_speed = 1.6 m/s, max_range = 1000m
TOP_SECRET:   max_speed = unlimited, max_range = unlimited
```

## Performance Optimization

### Command Caching

```python
# Enable command caching (enabled by default)
hal.command_validator.cache_ttl = timedelta(minutes=5)

# Clear cache when needed
hal.command_validator.clear_cache()
```

### Parallel Execution

```python
# Fleet commands automatically parallelize
# For custom parallel operations:
import asyncio

tasks = [
    hal.execute_command(robot_id=f"robot_{i}", ...)
    for i in range(10)
]
results = await asyncio.gather(*tasks)
```

## Monitoring and Metrics

### Get Fleet Status

```python
status = await hal.get_fleet_status()
print(f"Active robots: {status['active_robots']}/{status['fleet_size']}")
print(f"Average response time: {status['security_metrics']['average_response_time_ms']}ms")
```

### Security Metrics

```python
metrics = hal.security_metrics
print(f"Total commands: {metrics['total_commands']}")
print(f"Success rate: {metrics['successful_commands'] / metrics['total_commands'] * 100:.1f}%")
print(f"Security violations: {metrics['policy_violations']}")
```

## Error Handling

### Command Failures

```python
try:
    success, result = await hal.execute_command(...)
    if not success:
        if result:
            print(f"Command failed: {result.error_message}")
        else:
            print("Command validation failed")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Connection Issues

```python
# Automatic reconnection
hal.config["fleet"]["heartbeat_timeout_seconds"] = 60

# Manual heartbeat update
await hal.update_robot_heartbeat("robot_001")
```

## Testing

### Unit Testing Your Adapter

```python
import pytest
from unittest.mock import Mock, AsyncMock

@pytest.mark.asyncio
async def test_my_adapter():
    adapter = MyRobotAdapter("test_001", ClassificationLevel.SECRET)
    
    # Test connection
    connected = await adapter.connect_platform({"ip": "test"})
    assert connected
    
    # Test command translation
    command = create_test_command()
    success, translated = await adapter.translate_command(command)
    assert success
```

### Integration Testing

```python
# Test with mock HAL
mock_hal = UniversalSecurityHAL()
await mock_hal.register_robot("test_bot", PlatformType.CUSTOM, ...)

# Execute test scenarios
result = await mock_hal.execute_command(...)
assert result.success
```

## Best Practices

1. **Always specify classification** - Don't rely on defaults
2. **Handle emergency stops** - Implement sub-50ms response
3. **Validate inputs** - Check parameters before sending to robot
4. **Log security events** - Use audit logger for compliance
5. **Test classification boundaries** - Ensure restrictions work
6. **Monitor performance** - Keep validation under 100ms
7. **Implement heartbeats** - Detect disconnected robots
8. **Use fleet coordination** - Leverage built-in modes

## Troubleshooting

### Common Issues

**Q: Robot registration fails**
- Check network connectivity
- Verify connection parameters
- Ensure classification level is appropriate

**Q: Commands timing out**
- Check robot heartbeat status
- Verify platform adapter connection
- Review performance metrics

**Q: Policy violations**
- Check operator clearance level
- Review active policies
- Check robot classification

**Q: Emergency stop slow**
- Ensure adapter implements fast path
- Check network latency
- Verify parallel execution

## API Reference

See complete API documentation in `/docs/api/` including:
- `PlatformSecurityAdapter` - Base adapter class
- `SecurityPolicyEngine` - Policy management
- `CommandValidationPipeline` - Validation stages
- `UniversalSecurityHAL` - Main interface

## Support

- GitHub Issues: `https://github.com/your-org/alcub3`
- Documentation: `/docs/`
- Examples: `/examples/`