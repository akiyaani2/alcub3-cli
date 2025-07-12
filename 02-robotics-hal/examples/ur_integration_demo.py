#!/usr/bin/env python3
"""
Universal Robots Integration Demo
Task 2.30 - Industrial Robot Orchestration

Demonstrates:
1. UR adapter integration with Universal HAL
2. Fleet coordination with multiple UR robots
3. Task allocation using Byzantine consensus
4. Real-time safety monitoring
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

# Add paths for imports
import sys
sys.path.append(str(Path(__file__).parent.parent / "core"))
sys.path.append(str(Path(__file__).parent.parent / "adapters"))
sys.path.append(str(Path(__file__).parent.parent / "src" / "swarm"))
sys.path.append(str(Path(__file__).parent.parent.parent / "02-security-maestro" / "src"))

from universal_hal import UniversalSecurityHAL, FleetCoordinationMode
from ur_adapter import UniversalRobotsAdapter, URModel
from distributed_task_allocator import (
    DistributedTaskAllocator, SwarmTask, SwarmMember, SwarmCapability,
    TaskPriority, SwarmConfiguration
)
from platform_adapter import PlatformType
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IndustrialRobotOrchestrator:
    """
    Orchestrator for industrial robot fleet operations.
    Integrates UR robots with ALCUB3's security framework.
    """
    
    def __init__(self):
        """Initialize orchestrator components."""
        self.audit_logger = AuditLogger(ClassificationLevel.SECRET)
        self.hal = UniversalSecurityHAL(
            classification_level=ClassificationLevel.SECRET,
            config_path=None
        )
        self.task_allocator = DistributedTaskAllocator(
            SwarmConfiguration(),
            self.audit_logger
        )
        self.ur_robots: Dict[str, UniversalRobotsAdapter] = {}
        
    async def setup_robot_fleet(self, robot_configs: List[Dict[str, Any]]):
        """Set up fleet of UR robots."""
        logger.info("Setting up industrial robot fleet...")
        
        for config in robot_configs:
            robot_id = config["robot_id"]
            model = URModel(config["model"])
            ip_address = config["ip_address"]
            
            # Create UR adapter
            adapter = UniversalRobotsAdapter(
                robot_id=robot_id,
                model=model,
                classification_level=ClassificationLevel.SECRET,
                audit_logger=self.audit_logger
            )
            
            # Connect to robot (simulator mode for demo)
            connected = await adapter.connect_platform({
                "ip_address": ip_address,
                "use_simulator": True
            })
            
            if connected:
                # Register adapter with HAL
                self.hal.register_platform_adapter(PlatformType.INDUSTRIAL_ROBOT, type(adapter))
                
                # Register robot with HAL
                registered = await self.hal.register_robot(
                    robot_id=robot_id,
                    platform_type=PlatformType.INDUSTRIAL_ROBOT,
                    classification_level=ClassificationLevel.SECRET,
                    connection_params={
                        "ip_address": ip_address,
                        "use_simulator": True
                    },
                    metadata={
                        "model": model.value,
                        "location": config.get("location", "factory_floor")
                    }
                )
                
                if registered:
                    self.ur_robots[robot_id] = adapter
                    
                    # Register with task allocator
                    swarm_member = SwarmMember(
                        member_id=robot_id,
                        platform_type=PlatformType.INDUSTRIAL_ROBOT,
                        capabilities=[
                            SwarmCapability(
                                capability_id="move_joint",
                                category="actuator",
                                specifications={"dof": 6, "max_velocity": 3.14},
                                performance_metrics={"accuracy": 0.001},
                                classification_level=ClassificationLevel.SECRET
                            ),
                            SwarmCapability(
                                capability_id="pick_place",
                                category="actuator",
                                specifications={"payload": config.get("payload", 5.0)},
                                performance_metrics={"cycle_time": 2.5},
                                classification_level=ClassificationLevel.SECRET
                            ),
                            SwarmCapability(
                                capability_id="weld",
                                category="actuator",
                                specifications={"type": "MIG"},
                                performance_metrics={"quality": 0.95},
                                classification_level=ClassificationLevel.SECRET
                            )
                        ],
                        classification_clearance=ClassificationLevel.SECRET,
                        current_load=0.0,
                        reliability_score=0.95,
                        location={"lat": 0, "lon": 0}
                    )
                    
                    await self.task_allocator.register_swarm_member(swarm_member)
                    logger.info(f"✓ Robot {robot_id} ({model.value}) registered successfully")
                    
        logger.info(f"Fleet setup complete: {len(self.ur_robots)} robots online")
    
    async def demonstrate_coordinated_operation(self):
        """Demonstrate coordinated fleet operation."""
        logger.info("\n=== DEMONSTRATING COORDINATED FLEET OPERATION ===")
        
        # Create a manufacturing task
        task = SwarmTask(
            task_id="WELD_TASK_001",
            task_type="welding_operation",
            required_capabilities=["move_joint", "weld"],
            priority=TaskPriority.HIGH,
            classification=ClassificationLevel.SECRET,
            payload={
                "weld_points": [
                    {"x": 0.5, "y": 0.2, "z": 0.3},
                    {"x": 0.6, "y": 0.2, "z": 0.3},
                    {"x": 0.7, "y": 0.2, "z": 0.3}
                ],
                "weld_parameters": {
                    "speed": 0.005,  # m/s
                    "power": 150,    # watts
                    "gas_flow": 15   # l/min
                }
            },
            constraints={
                "time_limit": 300,  # 5 minutes
                "quality_threshold": 0.9
            },
            created_at=datetime.utcnow()
        )
        
        # Submit task for allocation
        logger.info(f"Submitting task: {task.task_id}")
        await self.task_allocator.submit_task(task)
        
        # Allocate tasks
        allocations = await self.task_allocator.allocate_tasks()
        
        if allocations:
            allocation = allocations[0]
            logger.info(f"Task allocated to robot: {allocation.allocated_to}")
            logger.info(f"Allocation score: {allocation.allocation_score:.2f}")
            logger.info(f"Consensus achieved: {allocation.consensus_achieved}")
            
            # Execute welding operation
            robot_id = allocation.allocated_to
            if robot_id in self.hal.robots:
                # Move to first weld point
                weld_point = task.payload["weld_points"][0]
                tcp_pose = [weld_point["x"], weld_point["y"], weld_point["z"], 0, 3.14, 0]
                
                success, result = await self.hal.execute_command(
                    robot_id=robot_id,
                    command_type="move_linear",
                    parameters={"tcp_pose": tcp_pose, "velocity": 0.1},
                    issuer_id="orchestrator",
                    issuer_clearance=ClassificationLevel.SECRET
                )
                
                if success:
                    logger.info(f"✓ Robot moved to weld position in {result.execution_time_ms:.2f}ms")
                
                # Simulate welding
                await asyncio.sleep(1.0)
                logger.info("✓ Welding operation completed")
                
                # Mark task complete
                await self.task_allocator.handle_task_completion(
                    task.task_id,
                    robot_id,
                    success=True,
                    metrics={
                        "weld_quality": 0.95,
                        "cycle_time": 2.3,
                        "power_consumed": 340
                    }
                )
    
    async def demonstrate_fleet_coordination(self):
        """Demonstrate synchronized fleet movements."""
        logger.info("\n=== DEMONSTRATING FLEET COORDINATION ===")
        
        robot_ids = list(self.ur_robots.keys())
        
        if len(robot_ids) < 2:
            logger.warning("Need at least 2 robots for fleet coordination demo")
            return
        
        # Execute synchronized movement
        logger.info("Executing synchronized fleet movement...")
        
        fleet_command = await self.hal.execute_fleet_command(
            target_robots=robot_ids[:2],  # First 2 robots
            command_type="move_joint",
            parameters={
                "joint_positions": [0, -1.57, 1.57, -1.57, -1.57, 0],
                "velocity": 0.5,
                "acceleration": 1.0
            },
            coordination_mode=FleetCoordinationMode.SYNCHRONIZED,
            issuer_id="orchestrator",
            issuer_clearance=ClassificationLevel.SECRET
        )
        
        # Check results
        successful = sum(1 for r in fleet_command.execution_results.values() if r.success)
        logger.info(f"Fleet command completed: {successful}/{len(fleet_command.target_robots)} robots succeeded")
        
        # Leader-follower demonstration
        logger.info("\nExecuting leader-follower pattern...")
        
        leader_follower_command = await self.hal.execute_fleet_command(
            target_robots=robot_ids,
            command_type="move_joint",
            parameters={
                "joint_positions": [0.5, -1.0, 1.0, -1.0, -1.0, 0.5],
                "velocity": 0.3
            },
            coordination_mode=FleetCoordinationMode.LEADER_FOLLOWER,
            issuer_id="orchestrator",
            issuer_clearance=ClassificationLevel.SECRET
        )
        
        logger.info("✓ Leader-follower movement completed")
    
    async def demonstrate_safety_features(self):
        """Demonstrate safety and emergency response."""
        logger.info("\n=== DEMONSTRATING SAFETY FEATURES ===")
        
        robot_id = list(self.ur_robots.keys())[0] if self.ur_robots else None
        
        if not robot_id:
            logger.warning("No robots available for safety demo")
            return
        
        # Simulate safety zone violation
        logger.info("Simulating safety zone violation...")
        
        # Protective stop
        success, result = await self.hal.execute_command(
            robot_id=robot_id,
            command_type="protective_stop",
            parameters={},
            issuer_id="safety_system",
            issuer_clearance=ClassificationLevel.SECRET
        )
        
        if success:
            logger.info(f"✓ Protective stop executed in {result.execution_time_ms:.2f}ms")
        
        await asyncio.sleep(1.0)
        
        # Fleet-wide emergency stop
        logger.info("\nTesting fleet-wide emergency stop...")
        
        stop_results = await self.hal.emergency_stop(
            reason="safety_demonstration"
        )
        
        stopped_count = sum(1 for success in stop_results.values() if success)
        logger.info(f"✓ Emergency stop completed: {stopped_count}/{len(stop_results)} robots stopped")
    
    async def get_orchestration_status(self):
        """Get current orchestration status."""
        fleet_status = await self.hal.get_fleet_status()
        swarm_status = await self.task_allocator.get_swarm_status()
        
        logger.info("\n=== ORCHESTRATION STATUS ===")
        logger.info(f"Active robots: {fleet_status['active_robots']}/{fleet_status['fleet_size']}")
        logger.info(f"Security state: {fleet_status['fleet_state']}")
        logger.info(f"Pending tasks: {swarm_status['pending_tasks']}")
        logger.info(f"Active tasks: {swarm_status['active_tasks']}")
        logger.info(f"Average robot load: {swarm_status['average_member_load']:.2%}")
        logger.info(f"Total commands executed: {fleet_status['security_metrics']['total_commands']}")
        logger.info(f"Average response time: {fleet_status['security_metrics']['average_response_time_ms']:.2f}ms")
    
    async def shutdown(self):
        """Shutdown orchestrator."""
        logger.info("\nShutting down orchestrator...")
        
        # Disconnect all robots
        for robot_id, adapter in self.ur_robots.items():
            await adapter.disconnect_platform()
        
        # Shutdown HAL and task allocator
        await self.hal.shutdown()
        await self.task_allocator.shutdown()
        
        logger.info("✓ Orchestrator shutdown complete")


async def main():
    """Run the industrial robot orchestration demo."""
    logger.info("""
    ╔══════════════════════════════════════════════════════════════╗
    ║        ALCUB3 Industrial Robot Orchestration Demo            ║
    ║                    Task 2.30 - Phase 1                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    orchestrator = IndustrialRobotOrchestrator()
    
    try:
        # Configure robot fleet
        robot_configs = [
            {
                "robot_id": "UR5_WELD_01",
                "model": "ur5e",
                "ip_address": "192.168.1.101",
                "payload": 5.0,
                "location": "welding_station_1"
            },
            {
                "robot_id": "UR10_PICK_01",
                "model": "ur10e",
                "ip_address": "192.168.1.102",
                "payload": 10.0,
                "location": "pick_place_station_1"
            },
            {
                "robot_id": "UR5_WELD_02",
                "model": "ur5e",
                "ip_address": "192.168.1.103",
                "payload": 5.0,
                "location": "welding_station_2"
            }
        ]
        
        # Set up fleet
        await orchestrator.setup_robot_fleet(robot_configs)
        
        # Run demonstrations
        await orchestrator.demonstrate_coordinated_operation()
        await asyncio.sleep(2.0)
        
        await orchestrator.demonstrate_fleet_coordination()
        await asyncio.sleep(2.0)
        
        await orchestrator.demonstrate_safety_features()
        await asyncio.sleep(2.0)
        
        # Show final status
        await orchestrator.get_orchestration_status()
        
    except Exception as e:
        logger.error(f"Demo error: {e}")
        
    finally:
        await orchestrator.shutdown()


if __name__ == "__main__":
    asyncio.run(main())