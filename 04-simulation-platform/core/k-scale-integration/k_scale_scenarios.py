"""
K-Scale Scenario Library for ALCUB3
Pre-built scenarios for defense, industrial, and space domains
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import numpy as np


class DomainType(Enum):
    DEFENSE = "defense"
    INDUSTRIAL = "industrial"
    SPACE = "space"
    MARITIME = "maritime"
    AERIAL = "aerial"


@dataclass
class PhysicsParameters:
    """Domain-specific physics parameters"""
    gravity: float = 9.81  # m/s^2
    air_density: float = 1.225  # kg/m^3
    temperature: float = 293.15  # Kelvin
    pressure: float = 101325  # Pascals
    magnetic_field: np.ndarray = None  # Tesla
    radiation_level: float = 0.0  # Sieverts/hour


@dataclass
class ScenarioConfig:
    """Configuration for a training scenario"""
    name: str
    domain: DomainType
    description: str
    physics: PhysicsParameters
    duration_minutes: int
    complexity_level: int  # 1-10
    classification_required: str
    success_criteria: Dict[str, Any]


class DefenseScenarios:
    """Pre-built defense training scenarios"""
    
    @staticmethod
    def contested_environment_patrol() -> ScenarioConfig:
        """Urban patrol in GPS-denied, jamming environment"""
        return ScenarioConfig(
            name="contested_environment_patrol",
            domain=DomainType.DEFENSE,
            description="Navigate urban environment under electronic warfare conditions",
            physics=PhysicsParameters(
                gravity=9.81,
                temperature=308.15,  # Hot urban environment
                magnetic_field=np.array([0.000025, 0, 0.000043])  # Earth magnetic field
            ),
            duration_minutes=30,
            complexity_level=8,
            classification_required="SECRET",
            success_criteria={
                "area_coverage": 0.95,  # Cover 95% of patrol route
                "threat_detection": 0.99,  # Detect 99% of threats
                "jamming_resilience": True,  # Operate under jamming
                "civilian_avoidance": 1.0  # Zero civilian interactions
            }
        )
    
    @staticmethod
    def multi_domain_coordination() -> ScenarioConfig:
        """Coordinate ground, air, and maritime assets"""
        return ScenarioConfig(
            name="multi_domain_coordination",
            domain=DomainType.DEFENSE,
            description="Simultaneous control of heterogeneous robot teams",
            physics=PhysicsParameters(gravity=9.81),
            duration_minutes=25,
            complexity_level=9,
            classification_required="SECRET",
            success_criteria={
                "sync_accuracy": 0.001,  # 1ms synchronization
                "mission_completion": 0.98,
                "asset_coordination": 20,  # Coordinate 20 assets
                "communication_integrity": 0.95
            }
        )
    
    @staticmethod
    def scif_security_response() -> ScenarioConfig:
        """SCIF intrusion response scenario"""
        return ScenarioConfig(
            name="scif_security_response",
            domain=DomainType.DEFENSE,
            description="Respond to security breach in classified facility",
            physics=PhysicsParameters(gravity=9.81),
            duration_minutes=15,
            complexity_level=10,
            classification_required="TOP_SECRET",
            success_criteria={
                "response_time": 30,  # 30 second response
                "threat_neutralization": 1.0,  # 100% success
                "data_protection": 1.0,  # No data compromise
                "false_positive_rate": 0.001  # 0.1% false positives
            }
        )


class IndustrialScenarios:
    """Manufacturing and industrial automation scenarios"""
    
    @staticmethod
    def factory_optimization() -> ScenarioConfig:
        """Optimize manufacturing line efficiency"""
        return ScenarioConfig(
            name="factory_optimization",
            domain=DomainType.INDUSTRIAL,
            description="Maximize throughput while maintaining quality",
            physics=PhysicsParameters(
                gravity=9.81,
                temperature=298.15,  # Controlled factory environment
                air_density=1.2
            ),
            duration_minutes=30,
            complexity_level=6,
            classification_required="UNCLASSIFIED",
            success_criteria={
                "throughput_increase": 0.15,  # 15% improvement
                "defect_rate": 0.001,  # 0.1% defects
                "energy_efficiency": 0.20,  # 20% energy savings
                "safety_incidents": 0  # Zero incidents
            }
        )
    
    @staticmethod
    def warehouse_swarm_coordination() -> ScenarioConfig:
        """Coordinate robot swarm in warehouse"""
        return ScenarioConfig(
            name="warehouse_swarm_coordination",
            domain=DomainType.INDUSTRIAL,
            description="Manage 50+ robots for order fulfillment",
            physics=PhysicsParameters(gravity=9.81),
            duration_minutes=20,
            complexity_level=7,
            classification_required="UNCLASSIFIED",
            success_criteria={
                "order_accuracy": 0.999,  # 99.9% accurate
                "collision_rate": 0.0,  # Zero collisions
                "throughput": 1000,  # Orders per hour
                "robot_utilization": 0.85  # 85% utilization
            }
        )
    
    @staticmethod
    def hazmat_response() -> ScenarioConfig:
        """Respond to hazardous material spill"""
        return ScenarioConfig(
            name="hazmat_response",
            domain=DomainType.INDUSTRIAL,
            description="Contain and clean hazardous material safely",
            physics=PhysicsParameters(
                gravity=9.81,
                temperature=298.15,
                radiation_level=0.01  # Elevated radiation
            ),
            duration_minutes=25,
            complexity_level=8,
            classification_required="UNCLASSIFIED",
            success_criteria={
                "containment_time": 300,  # 5 minutes
                "exposure_limit": 0.0,  # Zero human exposure
                "cleanup_efficiency": 0.99,  # 99% cleaned
                "secondary_contamination": 0.0
            }
        )


class SpaceScenarios:
    """Space operations training scenarios"""
    
    @staticmethod
    def lunar_surface_operations() -> ScenarioConfig:
        """Lunar regolith excavation and base construction"""
        return ScenarioConfig(
            name="lunar_surface_operations",
            domain=DomainType.SPACE,
            description="Operate in 1/6 gravity with regolith interaction",
            physics=PhysicsParameters(
                gravity=1.625,  # Moon gravity
                air_density=0.0,  # Vacuum
                temperature=100.0,  # Extreme cold (night side)
                pressure=0.0,  # No atmosphere
                radiation_level=0.0003  # Solar radiation
            ),
            duration_minutes=30,
            complexity_level=9,
            classification_required="UNCLASSIFIED",
            success_criteria={
                "excavation_volume": 10.0,  # 10 cubic meters
                "structure_integrity": 0.99,  # 99% stable
                "power_efficiency": 0.80,  # 80% power efficiency
                "dust_mitigation": 0.95  # 95% dust controlled
            }
        )
    
    @staticmethod
    def orbital_servicing() -> ScenarioConfig:
        """Service satellite in GEO orbit"""
        return ScenarioConfig(
            name="orbital_servicing",
            domain=DomainType.SPACE,
            description="Approach, dock, and service satellite",
            physics=PhysicsParameters(
                gravity=0.0,  # Microgravity
                air_density=0.0,
                temperature=250.0,  # Space temperature varies
                pressure=0.0,
                radiation_level=0.001  # Higher in GEO
            ),
            duration_minutes=25,
            complexity_level=10,
            classification_required="UNCLASSIFIED",
            success_criteria={
                "approach_precision": 0.001,  # 1mm precision
                "docking_success": 1.0,  # 100% success
                "fuel_efficiency": 0.90,  # 90% fuel efficiency
                "operation_time": 1500  # 25 minutes max
            }
        )
    
    @staticmethod
    def mars_sample_collection() -> ScenarioConfig:
        """Collect and process Mars samples"""
        return ScenarioConfig(
            name="mars_sample_collection",
            domain=DomainType.SPACE,
            description="Navigate Mars terrain and collect samples",
            physics=PhysicsParameters(
                gravity=3.71,  # Mars gravity
                air_density=0.020,  # Thin atmosphere
                temperature=210.0,  # Cold
                pressure=610,  # Low pressure
                radiation_level=0.0007
            ),
            duration_minutes=30,
            complexity_level=8,
            classification_required="UNCLASSIFIED",
            success_criteria={
                "sample_diversity": 10,  # 10 different types
                "contamination_prevention": 1.0,  # 100% clean
                "navigation_accuracy": 0.95,  # 95% on target
                "communication_delay": 14  # Handle 14min delay
            }
        )


class ScenarioBuilder:
    """Build custom scenarios by combining elements"""
    
    def __init__(self):
        self.scenario_library = {
            DomainType.DEFENSE: DefenseScenarios(),
            DomainType.INDUSTRIAL: IndustrialScenarios(),
            DomainType.SPACE: SpaceScenarios()
        }
        
    def get_scenario(self, name: str) -> Optional[ScenarioConfig]:
        """Retrieve scenario by name"""
        for domain_scenarios in self.scenario_library.values():
            for method in dir(domain_scenarios):
                if not method.startswith('_'):
                    scenario_method = getattr(domain_scenarios, method)
                    if callable(scenario_method):
                        scenario = scenario_method()
                        if scenario.name == name:
                            return scenario
        return None
        
    def create_hybrid_scenario(
        self,
        base_scenario: str,
        modifications: Dict[str, Any]
    ) -> ScenarioConfig:
        """Create custom scenario based on existing one"""
        base = self.get_scenario(base_scenario)
        if not base:
            raise ValueError(f"Base scenario {base_scenario} not found")
            
        # Apply modifications
        for key, value in modifications.items():
            if hasattr(base, key):
                setattr(base, key, value)
                
        return base
        
    def list_scenarios_by_clearance(self, clearance: str) -> List[str]:
        """List scenarios accessible with given clearance"""
        clearance_levels = {
            "UNCLASSIFIED": 0,
            "SECRET": 1,
            "TOP_SECRET": 2
        }
        
        user_level = clearance_levels.get(clearance, 0)
        accessible_scenarios = []
        
        for domain_scenarios in self.scenario_library.values():
            for method in dir(domain_scenarios):
                if not method.startswith('_'):
                    scenario_method = getattr(domain_scenarios, method)
                    if callable(scenario_method):
                        scenario = scenario_method()
                        required_level = clearance_levels.get(
                            scenario.classification_required, 0
                        )
                        if user_level >= required_level:
                            accessible_scenarios.append(scenario.name)
                            
        return accessible_scenarios


# Quick demonstration
if __name__ == "__main__":
    builder = ScenarioBuilder()
    
    print("🎯 ALCUB3 K-Scale Scenario Library")
    print("=" * 50)
    
    # Show scenarios by clearance level
    for clearance in ["UNCLASSIFIED", "SECRET", "TOP_SECRET"]:
        scenarios = builder.list_scenarios_by_clearance(clearance)
        print(f"\n{clearance} Clearance - Available Scenarios:")
        for scenario in scenarios:
            s = builder.get_scenario(scenario)
            print(f"  • {s.name} ({s.domain.value})")
            print(f"    {s.description}")
            print(f"    Complexity: {s.complexity_level}/10, Time: {s.duration_minutes} min")