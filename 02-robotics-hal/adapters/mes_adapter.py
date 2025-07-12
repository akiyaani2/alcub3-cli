#!/usr/bin/env python3
"""
ALCUB3 MES Adapter Framework
Task 2.35 - Manufacturing Execution System Integration

This module provides a generic adapter framework for integrating with various
Manufacturing Execution Systems (MES) and Enterprise Resource Planning (ERP)
systems, featuring:

- Production schedule synchronization
- Work order management with classification
- Quality data collection and reporting
- ISA-95 compliant data modeling
- Real-time production metrics
- Byzantine-validated production changes

Patent-Pending Innovations:
- Classification-aware production scheduling
- Byzantine consensus for work order validation
- Air-gapped MES synchronization
- ML-enhanced production optimization

Supported MES Platforms:
- SAP ME/MII
- Siemens Opcenter
- Rockwell FactoryTalk
- Generic REST/SOAP APIs
"""

import asyncio
import logging
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import uuid
from abc import ABC, abstractmethod
import xml.etree.ElementTree as ET

# Import security components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "02-security-maestro" / "src"))
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.crypto_utils import CryptoUtils

# Import OPC UA components
sys.path.append(str(Path(__file__).parent.parent / "opcua"))
from opcua_client import SecureOPCUAClient, ConnectionConfig, SubscriptionMode

# Import HAL components
sys.path.append(str(Path(__file__).parent.parent / "core"))
from platform_adapter import SecurityState

logger = logging.getLogger(__name__)


class MESType(Enum):
    """Supported MES platform types."""
    SAP_ME = "sap_me"
    SAP_MII = "sap_mii"
    SIEMENS_OPCENTER = "siemens_opcenter"
    ROCKWELL_FACTORYTALK = "rockwell_factorytalk"
    CUSTOM_REST = "custom_rest"
    CUSTOM_SOAP = "custom_soap"
    OPCUA_GENERIC = "opcua_generic"


class WorkOrderStatus(Enum):
    """Work order execution status."""
    CREATED = "created"
    SCHEDULED = "scheduled"
    RELEASED = "released"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ON_HOLD = "on_hold"


class ProductionMode(Enum):
    """Production operation modes."""
    MANUAL = "manual"
    SEMI_AUTOMATIC = "semi_automatic"
    AUTOMATIC = "automatic"
    MAINTENANCE = "maintenance"
    CHANGEOVER = "changeover"


@dataclass
class MaterialRequirement:
    """Material requirement for production."""
    material_id: str
    material_name: str
    quantity_required: float
    unit_of_measure: str
    classification: ClassificationLevel
    lot_number: Optional[str] = None
    expiry_date: Optional[datetime] = None


@dataclass
class QualitySpecification:
    """Quality specification for production."""
    parameter_name: str
    nominal_value: float
    lower_limit: float
    upper_limit: float
    unit_of_measure: str
    critical: bool = False


@dataclass
class WorkOrder:
    """Manufacturing work order with security metadata."""
    order_id: str
    product_id: str
    product_name: str
    quantity_ordered: float
    quantity_completed: float = 0.0
    unit_of_measure: str = "EA"
    priority: int = 5  # 1-10
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    status: WorkOrderStatus = WorkOrderStatus.CREATED
    scheduled_start: Optional[datetime] = None
    scheduled_end: Optional[datetime] = None
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    materials: List[MaterialRequirement] = field(default_factory=list)
    quality_specs: List[QualitySpecification] = field(default_factory=list)
    routing_steps: List[Dict[str, Any]] = field(default_factory=list)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    byzantine_validated: bool = False
    validation_token: Optional[str] = None


@dataclass
class ProductionSchedule:
    """Production schedule container."""
    schedule_id: str
    schedule_version: str
    effective_date: datetime
    classification: ClassificationLevel
    work_orders: List[WorkOrder]
    constraints: Dict[str, Any] = field(default_factory=dict)
    optimization_goals: List[str] = field(default_factory=list)
    created_by: str = "MES_SYSTEM"
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ProductionMetrics:
    """Real-time production metrics."""
    timestamp: datetime
    production_rate: float  # units/hour
    cycle_time: float  # seconds
    efficiency: float  # percentage
    quality_rate: float  # percentage
    availability: float  # percentage
    oee: float  # Overall Equipment Effectiveness
    scrap_rate: float  # percentage
    energy_consumption: float  # kWh
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED


@dataclass
class QualityData:
    """Quality inspection data."""
    inspection_id: str
    work_order_id: str
    product_id: str
    inspection_time: datetime
    measurements: Dict[str, float]
    pass_fail: bool
    defect_codes: List[str] = field(default_factory=list)
    inspector_id: Optional[str] = None
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED


class MESAdapter(ABC):
    """
    Abstract base class for MES adapters.
    
    All MES platform adapters must inherit from this class and implement
    the required methods for production integration.
    """
    
    def __init__(
        self,
        adapter_id: str,
        mes_type: MESType,
        classification_level: ClassificationLevel,
        audit_logger: AuditLogger,
        enable_byzantine: bool = True
    ):
        """Initialize MES adapter."""
        self.adapter_id = adapter_id
        self.mes_type = mes_type
        self.classification_level = classification_level
        self.audit_logger = audit_logger
        self.enable_byzantine = enable_byzantine
        
        # Core components
        self.crypto = CryptoUtils()
        self.is_connected = False
        
        # Data storage
        self.active_schedule: Optional[ProductionSchedule] = None
        self.work_orders: Dict[str, WorkOrder] = {}
        self.production_metrics: List[ProductionMetrics] = []
        self.quality_data: List[QualityData] = []
        
        # Performance tracking
        self.sync_latency_buffer = []
        self.max_sync_latency_ms = 5000  # 5 second target
        
        logger.info(
            f"Initialized MES adapter '{adapter_id}' "
            f"for {mes_type.value} with {classification_level.value} classification"
        )
    
    @abstractmethod
    async def connect(self, connection_params: Dict[str, Any]) -> bool:
        """Connect to MES platform."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Disconnect from MES platform."""
        pass
    
    @abstractmethod
    async def fetch_production_schedule(self) -> Optional[ProductionSchedule]:
        """Fetch current production schedule from MES."""
        pass
    
    @abstractmethod
    async def update_work_order_status(
        self,
        order_id: str,
        status: WorkOrderStatus,
        quantity_completed: Optional[float] = None
    ) -> bool:
        """Update work order status in MES."""
        pass
    
    @abstractmethod
    async def submit_quality_data(self, quality_data: QualityData) -> bool:
        """Submit quality inspection data to MES."""
        pass
    
    @abstractmethod
    async def submit_production_metrics(self, metrics: ProductionMetrics) -> bool:
        """Submit production metrics to MES."""
        pass
    
    async def synchronize_schedule(self) -> bool:
        """Synchronize production schedule with MES."""
        start_time = time.time()
        
        try:
            # Fetch latest schedule
            schedule = await self.fetch_production_schedule()
            if not schedule:
                logger.warning("No production schedule available from MES")
                return False
            
            # Validate classification
            if schedule.classification.value > self.classification_level.value:
                logger.error(
                    f"Schedule classification {schedule.classification.value} "
                    f"exceeds adapter level {self.classification_level.value}"
                )
                return False
            
            # Byzantine validation for critical schedules
            if self.enable_byzantine and schedule.classification >= ClassificationLevel.SECRET:
                valid = await self._validate_schedule_byzantine(schedule)
                if not valid:
                    logger.warning("Schedule failed Byzantine validation")
                    return False
            
            # Update local schedule
            self.active_schedule = schedule
            
            # Update work orders
            for work_order in schedule.work_orders:
                self.work_orders[work_order.order_id] = work_order
            
            # Calculate sync latency
            sync_latency = (time.time() - start_time) * 1000
            self.sync_latency_buffer.append(sync_latency)
            
            # Audit log
            await self.audit_logger.log_event(
                "MES_SCHEDULE_SYNCHRONIZED",
                classification=schedule.classification,
                details={
                    "schedule_id": schedule.schedule_id,
                    "version": schedule.schedule_version,
                    "work_orders": len(schedule.work_orders),
                    "sync_latency_ms": sync_latency
                }
            )
            
            logger.info(
                f"Synchronized production schedule {schedule.schedule_id} "
                f"with {len(schedule.work_orders)} work orders"
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Schedule synchronization failed: {e}")
            return False
    
    async def _validate_schedule_byzantine(self, schedule: ProductionSchedule) -> bool:
        """Validate production schedule using Byzantine consensus."""
        # In production, this would use the distributed consensus protocol
        # For now, simulate validation
        await asyncio.sleep(0.1)  # Simulate consensus time
        
        # Generate validation token
        schedule_hash = hashlib.sha256(
            f"{schedule.schedule_id}:{schedule.schedule_version}".encode()
        ).hexdigest()
        
        # Mark work orders as validated
        for work_order in schedule.work_orders:
            work_order.byzantine_validated = True
            work_order.validation_token = schedule_hash[:16]
        
        return True
    
    async def start_work_order(self, order_id: str) -> bool:
        """Start production for a work order."""
        try:
            work_order = self.work_orders.get(order_id)
            if not work_order:
                logger.error(f"Work order {order_id} not found")
                return False
            
            # Check status
            if work_order.status not in [WorkOrderStatus.SCHEDULED, WorkOrderStatus.RELEASED]:
                logger.warning(
                    f"Cannot start work order {order_id} in status {work_order.status.value}"
                )
                return False
            
            # Update status
            work_order.status = WorkOrderStatus.IN_PROGRESS
            work_order.actual_start = datetime.utcnow()
            
            # Update in MES
            success = await self.update_work_order_status(
                order_id, WorkOrderStatus.IN_PROGRESS
            )
            
            if success:
                await self.audit_logger.log_event(
                    "WORK_ORDER_STARTED",
                    classification=work_order.classification,
                    details={
                        "order_id": order_id,
                        "product_id": work_order.product_id,
                        "quantity": work_order.quantity_ordered
                    }
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to start work order {order_id}: {e}")
            return False
    
    async def complete_work_order(
        self,
        order_id: str,
        quantity_completed: float,
        quality_data: Optional[QualityData] = None
    ) -> bool:
        """Complete production for a work order."""
        try:
            work_order = self.work_orders.get(order_id)
            if not work_order:
                logger.error(f"Work order {order_id} not found")
                return False
            
            # Update work order
            work_order.quantity_completed = quantity_completed
            work_order.status = WorkOrderStatus.COMPLETED
            work_order.actual_end = datetime.utcnow()
            
            # Submit quality data if provided
            if quality_data:
                await self.submit_quality_data(quality_data)
            
            # Update in MES
            success = await self.update_work_order_status(
                order_id, WorkOrderStatus.COMPLETED, quantity_completed
            )
            
            if success:
                # Calculate production time
                production_time = (
                    work_order.actual_end - work_order.actual_start
                ).total_seconds() / 3600  # hours
                
                await self.audit_logger.log_event(
                    "WORK_ORDER_COMPLETED",
                    classification=work_order.classification,
                    details={
                        "order_id": order_id,
                        "quantity_completed": quantity_completed,
                        "production_hours": production_time,
                        "efficiency": quantity_completed / work_order.quantity_ordered
                    }
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to complete work order {order_id}: {e}")
            return False
    
    async def calculate_oee(
        self,
        availability: float,
        performance: float,
        quality: float
    ) -> float:
        """Calculate Overall Equipment Effectiveness (OEE)."""
        return (availability / 100) * (performance / 100) * (quality / 100) * 100
    
    async def get_active_work_orders(
        self,
        status_filter: Optional[List[WorkOrderStatus]] = None
    ) -> List[WorkOrder]:
        """Get active work orders with optional status filter."""
        if status_filter:
            return [
                wo for wo in self.work_orders.values()
                if wo.status in status_filter
            ]
        else:
            return [
                wo for wo in self.work_orders.values()
                if wo.status in [
                    WorkOrderStatus.SCHEDULED,
                    WorkOrderStatus.RELEASED,
                    WorkOrderStatus.IN_PROGRESS
                ]
            ]
    
    async def get_production_metrics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[ProductionMetrics]:
        """Get production metrics for time range."""
        metrics = self.production_metrics
        
        if start_time:
            metrics = [m for m in metrics if m.timestamp >= start_time]
        
        if end_time:
            metrics = [m for m in metrics if m.timestamp <= end_time]
        
        return metrics
    
    async def handle_air_gap_sync(self, sync_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle air-gapped MES synchronization."""
        try:
            # Extract offline updates
            work_order_updates = sync_data.get("work_order_updates", [])
            quality_submissions = sync_data.get("quality_data", [])
            metric_submissions = sync_data.get("production_metrics", [])
            
            # Process work order updates
            for update in work_order_updates:
                await self.update_work_order_status(
                    update["order_id"],
                    WorkOrderStatus(update["status"]),
                    update.get("quantity_completed")
                )
            
            # Process quality data
            for quality_dict in quality_submissions:
                quality_data = QualityData(**quality_dict)
                await self.submit_quality_data(quality_data)
            
            # Process production metrics
            for metrics_dict in metric_submissions:
                metrics = ProductionMetrics(**metrics_dict)
                await self.submit_production_metrics(metrics)
            
            # Prepare response with current state
            response = {
                "sync_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "active_schedule": None,
                "work_orders": [],
                "sync_status": "success"
            }
            
            # Include current schedule if available
            if self.active_schedule:
                response["active_schedule"] = {
                    "schedule_id": self.active_schedule.schedule_id,
                    "version": self.active_schedule.schedule_version,
                    "work_order_count": len(self.active_schedule.work_orders)
                }
            
            # Include active work orders
            active_orders = await self.get_active_work_orders()
            response["work_orders"] = [
                {
                    "order_id": wo.order_id,
                    "product_id": wo.product_id,
                    "status": wo.status.value,
                    "quantity_ordered": wo.quantity_ordered,
                    "quantity_completed": wo.quantity_completed
                }
                for wo in active_orders
            ]
            
            return response
            
        except Exception as e:
            logger.error(f"Air gap sync failed: {e}")
            return {"sync_status": "failed", "error": str(e)}


class OPCUAMESAdapter(MESAdapter):
    """
    Generic OPC UA based MES adapter.
    
    Uses OPC UA protocol for MES integration, suitable for modern
    Industry 4.0 systems that support OPC UA.
    """
    
    def __init__(
        self,
        adapter_id: str,
        classification_level: ClassificationLevel,
        audit_logger: AuditLogger,
        enable_byzantine: bool = True
    ):
        """Initialize OPC UA MES adapter."""
        super().__init__(
            adapter_id=adapter_id,
            mes_type=MESType.OPCUA_GENERIC,
            classification_level=classification_level,
            audit_logger=audit_logger,
            enable_byzantine=enable_byzantine
        )
        
        self.opcua_client: Optional[SecureOPCUAClient] = None
        self.node_mappings: Dict[str, str] = {}
    
    async def connect(self, connection_params: Dict[str, Any]) -> bool:
        """Connect to MES via OPC UA."""
        try:
            # Create OPC UA client configuration
            config = ConnectionConfig(
                server_url=connection_params["server_url"],
                username=connection_params.get("username"),
                password=connection_params.get("password"),
                security_policy=connection_params.get("security_policy", "Basic256Sha256"),
                message_mode=connection_params.get("message_mode", "SignAndEncrypt"),
                classification_level=self.classification_level
            )
            
            # Create OPC UA client
            self.opcua_client = SecureOPCUAClient(
                client_id=f"MES_Adapter_{self.adapter_id}",
                config=config,
                audit_logger=self.audit_logger,
                enable_byzantine=self.enable_byzantine
            )
            
            # Connect
            if await self.opcua_client.connect():
                self.is_connected = True
                
                # Configure node mappings
                self.node_mappings = connection_params.get("node_mappings", {
                    "schedule_version": "ns=3;s=schedule_version",
                    "active_work_order": "ns=3;s=active_work_order",
                    "production_rate": "ns=3;s=production_rate",
                    "quality_score": "ns=3;s=quality_score",
                    "oee": "ns=3;s=oee"
                })
                
                # Subscribe to key nodes
                await self._subscribe_to_mes_nodes()
                
                logger.info(f"Connected to MES via OPC UA at {config.server_url}")
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to MES via OPC UA: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from MES."""
        try:
            if self.opcua_client:
                await self.opcua_client.disconnect()
            
            self.is_connected = False
            logger.info("Disconnected from MES")
            return True
            
        except Exception as e:
            logger.error(f"Error disconnecting from MES: {e}")
            return False
    
    async def _subscribe_to_mes_nodes(self):
        """Subscribe to important MES nodes."""
        if not self.opcua_client:
            return
        
        # Subscribe to schedule version changes
        if "schedule_version" in self.node_mappings:
            await self.opcua_client.subscribe_node(
                node_id="schedule_version",
                browse_path=self.node_mappings["schedule_version"],
                mode=SubscriptionMode.MONITORING,
                interval_ms=5000,
                classification=ClassificationLevel.SECRET,
                callback=self._on_schedule_change
            )
    
    async def _on_schedule_change(self, node_id: str, value: Any):
        """Handle schedule version change notification."""
        logger.info(f"Schedule version changed to: {value}")
        # Trigger schedule synchronization
        asyncio.create_task(self.synchronize_schedule())
    
    async def fetch_production_schedule(self) -> Optional[ProductionSchedule]:
        """Fetch production schedule via OPC UA."""
        try:
            if not self.opcua_client:
                return None
            
            # Call GetProductionSchedule method on MES
            result = await self.opcua_client.call_method(
                "ns=2;i=1",  # MES methods object
                "GetProductionSchedule",
                datetime.utcnow().isoformat()  # Request timestamp
            )
            
            if result and len(result) > 0:
                schedule_json = result[0]
                schedule_data = json.loads(schedule_json)
                
                # Parse schedule
                schedule = ProductionSchedule(
                    schedule_id=schedule_data["schedule_id"],
                    schedule_version=schedule_data["version"],
                    effective_date=datetime.fromisoformat(schedule_data["effective_date"]),
                    classification=ClassificationLevel(schedule_data.get("classification", "UNCLASSIFIED")),
                    work_orders=[]
                )
                
                # Parse work orders
                for wo_data in schedule_data.get("work_orders", []):
                    work_order = WorkOrder(
                        order_id=wo_data["order_id"],
                        product_id=wo_data["product_id"],
                        product_name=wo_data["product_name"],
                        quantity_ordered=wo_data["quantity_ordered"],
                        priority=wo_data.get("priority", 5),
                        classification=ClassificationLevel(
                            wo_data.get("classification", "UNCLASSIFIED")
                        ),
                        scheduled_start=datetime.fromisoformat(wo_data["scheduled_start"])
                        if wo_data.get("scheduled_start") else None,
                        scheduled_end=datetime.fromisoformat(wo_data["scheduled_end"])
                        if wo_data.get("scheduled_end") else None
                    )
                    
                    # Add materials
                    for mat_data in wo_data.get("materials", []):
                        material = MaterialRequirement(
                            material_id=mat_data["material_id"],
                            material_name=mat_data["material_name"],
                            quantity_required=mat_data["quantity_required"],
                            unit_of_measure=mat_data["unit_of_measure"],
                            classification=ClassificationLevel(
                                mat_data.get("classification", "UNCLASSIFIED")
                            )
                        )
                        work_order.materials.append(material)
                    
                    schedule.work_orders.append(work_order)
                
                return schedule
                
            return None
            
        except Exception as e:
            logger.error(f"Failed to fetch production schedule: {e}")
            return None
    
    async def update_work_order_status(
        self,
        order_id: str,
        status: WorkOrderStatus,
        quantity_completed: Optional[float] = None
    ) -> bool:
        """Update work order status via OPC UA."""
        try:
            if not self.opcua_client:
                return False
            
            # Prepare update data
            update_data = {
                "order_id": order_id,
                "status": status.value,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if quantity_completed is not None:
                update_data["quantity_completed"] = quantity_completed
            
            # Call UpdateWorkOrder method
            result = await self.opcua_client.call_method(
                "ns=2;i=1",  # MES methods object
                "UpdateWorkOrder",
                json.dumps(update_data),
                validate_byzantine=self.enable_byzantine
            )
            
            if result and len(result) > 0:
                return result[0]  # Success boolean
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to update work order status: {e}")
            return False
    
    async def submit_quality_data(self, quality_data: QualityData) -> bool:
        """Submit quality data via OPC UA."""
        try:
            if not self.opcua_client:
                return False
            
            # Prepare quality data
            quality_json = json.dumps({
                "inspection_id": quality_data.inspection_id,
                "work_order_id": quality_data.work_order_id,
                "product_id": quality_data.product_id,
                "inspection_time": quality_data.inspection_time.isoformat(),
                "measurements": quality_data.measurements,
                "pass_fail": quality_data.pass_fail,
                "defect_codes": quality_data.defect_codes,
                "classification": quality_data.classification.value
            })
            
            # Call SubmitQualityData method
            result = await self.opcua_client.call_method(
                "ns=2;i=1",  # MES methods object
                "SubmitQualityData",
                quality_json
            )
            
            if result and len(result) > 0:
                success = result[0]
                
                if success:
                    # Store locally
                    self.quality_data.append(quality_data)
                
                return success
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to submit quality data: {e}")
            return False
    
    async def submit_production_metrics(self, metrics: ProductionMetrics) -> bool:
        """Submit production metrics via OPC UA."""
        try:
            if not self.opcua_client:
                return False
            
            # Write individual metric nodes
            success = True
            
            if "production_rate" in self.node_mappings:
                success &= await self.opcua_client.write_node(
                    self.node_mappings["production_rate"],
                    metrics.production_rate
                )
            
            if "quality_score" in self.node_mappings:
                success &= await self.opcua_client.write_node(
                    self.node_mappings["quality_score"],
                    metrics.quality_rate
                )
            
            if "oee" in self.node_mappings:
                success &= await self.opcua_client.write_node(
                    self.node_mappings["oee"],
                    metrics.oee
                )
            
            if success:
                # Store locally
                self.production_metrics.append(metrics)
                
                # Keep only last 1000 metrics
                if len(self.production_metrics) > 1000:
                    self.production_metrics = self.production_metrics[-1000:]
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to submit production metrics: {e}")
            return False


# Example usage
async def demonstrate_mes_adapter():
    """Demonstrate MES adapter capabilities."""
    # Initialize audit logger
    audit_logger = AuditLogger()
    
    # Create OPC UA MES adapter
    adapter = OPCUAMESAdapter(
        adapter_id="MES_001",
        classification_level=ClassificationLevel.SECRET,
        audit_logger=audit_logger,
        enable_byzantine=True
    )
    
    # Connect to MES
    connection_params = {
        "server_url": "opc.tcp://mes.factory.local:4840/mes",
        "username": "production_operator",
        "password": "secure_password",
        "security_policy": "Basic256Sha256",
        "node_mappings": {
            "schedule_version": "ns=3;s=ProductionSchedule.Version",
            "active_work_order": "ns=3;s=Production.ActiveWorkOrder",
            "production_rate": "ns=3;s=Production.Rate",
            "quality_score": "ns=3;s=Quality.Score",
            "oee": "ns=3;s=Performance.OEE"
        }
    }
    
    if await adapter.connect(connection_params):
        logger.info("Connected to MES successfully")
        
        # Synchronize production schedule
        if await adapter.synchronize_schedule():
            logger.info("Production schedule synchronized")
            
            # Get active work orders
            active_orders = await adapter.get_active_work_orders()
            logger.info(f"Active work orders: {len(active_orders)}")
            
            for order in active_orders[:2]:  # Show first 2
                logger.info(
                    f"  Order {order.order_id}: {order.product_name} "
                    f"({order.quantity_ordered} {order.unit_of_measure})"
                )
        
        # Start a work order
        if active_orders:
            first_order = active_orders[0]
            if await adapter.start_work_order(first_order.order_id):
                logger.info(f"Started work order {first_order.order_id}")
        
        # Submit production metrics
        metrics = ProductionMetrics(
            timestamp=datetime.utcnow(),
            production_rate=85.5,
            cycle_time=45.2,
            efficiency=92.3,
            quality_rate=98.5,
            availability=95.0,
            oee=await adapter.calculate_oee(95.0, 92.3, 98.5),
            scrap_rate=1.5,
            energy_consumption=125.7,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        if await adapter.submit_production_metrics(metrics):
            logger.info("Production metrics submitted")
        
        # Submit quality data
        quality = QualityData(
            inspection_id=str(uuid.uuid4()),
            work_order_id=first_order.order_id if active_orders else "WO-001",
            product_id="PROD-001",
            inspection_time=datetime.utcnow(),
            measurements={
                "length": 100.2,
                "width": 50.1,
                "weight": 2.53
            },
            pass_fail=True,
            defect_codes=[]
        )
        
        if await adapter.submit_quality_data(quality):
            logger.info("Quality data submitted")
        
        # Simulate air-gap sync
        sync_data = {
            "work_order_updates": [
                {
                    "order_id": first_order.order_id if active_orders else "WO-001",
                    "status": "in_progress",
                    "quantity_completed": 50
                }
            ],
            "quality_data": [],
            "production_metrics": []
        }
        
        sync_response = await adapter.handle_air_gap_sync(sync_data)
        logger.info(f"Air-gap sync response: {json.dumps(sync_response, indent=2)}")
        
        # Keep running for a bit
        await asyncio.sleep(5)
        
        # Disconnect
        await adapter.disconnect()
        
    else:
        logger.error("Failed to connect to MES")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(demonstrate_mes_adapter())