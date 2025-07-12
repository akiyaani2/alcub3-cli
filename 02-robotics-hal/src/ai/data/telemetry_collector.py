"""
Telemetry Collection System

Comprehensive telemetry collection for security forecasting, gathering data
from multiple sources including security monitors, system metrics, and
Byzantine consensus systems.
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from collections import defaultdict, deque
import psutil
import socket
import uuid

# Import security components (with fallback for missing modules)
try:
    from ...security.tpm_crypto_integration import TPMCryptoIntegration
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False

try:
    from ...swarm.consensus_engine import ConsensusEngine
    CONSENSUS_AVAILABLE = True
except ImportError:
    CONSENSUS_AVAILABLE = False


class TelemetrySource(Enum):
    """Available telemetry sources."""
    SECURITY_MONITOR = "security_monitor"
    SYSTEM_METRICS = "system_metrics"
    BYZANTINE_CONSENSUS = "byzantine_consensus"
    NETWORK_MONITOR = "network_monitor"
    THREAT_INTELLIGENCE = "threat_intelligence"
    AUDIT_LOGS = "audit_logs"
    PERFORMANCE_METRICS = "performance_metrics"
    CLASSIFICATION_MONITOR = "classification_monitor"


@dataclass
class TelemetryRecord:
    """Individual telemetry record."""
    timestamp: datetime
    source: TelemetrySource
    event_type: str
    data: Dict[str, Any]
    severity: int
    classification: str
    metadata: Dict[str, Any]


@dataclass
class SecurityMetrics:
    """Security-related metrics."""
    active_threats: int
    threat_level: float
    authentication_failures: int
    access_violations: int
    anomaly_count: int
    risk_score: float
    classification_level: str
    byzantine_nodes: int


@dataclass
class SystemMetrics:
    """System performance metrics."""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_traffic: float
    process_count: int
    uptime: float
    load_average: float


@dataclass
class NetworkMetrics:
    """Network-related metrics."""
    connections_active: int
    connections_established: int
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    errors: int
    dropped_packets: int


class TelemetryCollector:
    """
    Comprehensive telemetry collection system for security forecasting.
    
    Features:
    - Multi-source data collection
    - Real-time monitoring
    - Classification-aware data handling
    - Byzantine consensus integration
    - Performance metrics
    - Threat intelligence aggregation
    """
    
    def __init__(self, 
                 collection_interval: int = 30,
                 buffer_size: int = 1000,
                 sources: Optional[List[TelemetrySource]] = None):
        """
        Initialize telemetry collector.
        
        Args:
            collection_interval: Collection interval in seconds
            buffer_size: Size of telemetry buffer
            sources: List of sources to collect from
        """
        self.collection_interval = collection_interval
        self.buffer_size = buffer_size
        self.sources = sources or list(TelemetrySource)
        
        self.logger = logging.getLogger(__name__)
        
        # Data storage
        self.telemetry_buffer = deque(maxlen=buffer_size)
        self.source_handlers = {}
        self.collection_stats = defaultdict(int)
        
        # Threading
        self.collection_thread = None
        self.running = False
        self.lock = threading.RLock()
        
        # Performance tracking
        self.performance_metrics = {
            'total_records': 0,
            'collection_errors': 0,
            'avg_collection_time': 0.0,
            'last_collection_time': None
        }
        
        # Integration components
        self.tpm_integration = None
        self.consensus_engine = None
        
        # Initialize handlers
        self._initialize_handlers()
        
        # Initialize integrations
        self._initialize_integrations()
        
        self.logger.info(f"Telemetry Collector initialized with {len(self.sources)} sources")
    
    def _initialize_handlers(self) -> None:
        """Initialize telemetry source handlers."""
        self.source_handlers = {
            TelemetrySource.SECURITY_MONITOR: self._collect_security_metrics,
            TelemetrySource.SYSTEM_METRICS: self._collect_system_metrics,
            TelemetrySource.BYZANTINE_CONSENSUS: self._collect_byzantine_metrics,
            TelemetrySource.NETWORK_MONITOR: self._collect_network_metrics,
            TelemetrySource.THREAT_INTELLIGENCE: self._collect_threat_intelligence,
            TelemetrySource.AUDIT_LOGS: self._collect_audit_logs,
            TelemetrySource.PERFORMANCE_METRICS: self._collect_performance_metrics,
            TelemetrySource.CLASSIFICATION_MONITOR: self._collect_classification_metrics
        }
    
    def _initialize_integrations(self) -> None:
        """Initialize integration components."""
        try:
            if TPM_AVAILABLE:
                self.tpm_integration = TPMCryptoIntegration()
                self.logger.info("TPM integration initialized")
        except Exception as e:
            self.logger.warning(f"TPM integration failed: {e}")
        
        try:
            if CONSENSUS_AVAILABLE:
                self.consensus_engine = ConsensusEngine()
                self.logger.info("Consensus engine initialized")
        except Exception as e:
            self.logger.warning(f"Consensus engine initialization failed: {e}")
    
    async def start_collection(self) -> None:
        """Start continuous telemetry collection."""
        if self.running:
            self.logger.warning("Telemetry collection already running")
            return
        
        self.running = True
        self.logger.info("Starting telemetry collection")
        
        # Start collection thread
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            daemon=True
        )
        self.collection_thread.start()
    
    async def stop_collection(self) -> None:
        """Stop telemetry collection."""
        self.running = False
        
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        
        self.logger.info("Telemetry collection stopped")
    
    def _collection_loop(self) -> None:
        """Main collection loop (runs in separate thread)."""
        while self.running:
            try:
                start_time = time.time()
                
                # Collect from all sources
                asyncio.run(self._collect_from_all_sources())
                
                # Update performance metrics
                collection_time = time.time() - start_time
                self._update_performance_metrics(collection_time)
                
                # Wait for next collection interval
                time.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in collection loop: {e}")
                self.performance_metrics['collection_errors'] += 1
                time.sleep(self.collection_interval)
    
    async def _collect_from_all_sources(self) -> None:
        """Collect telemetry from all configured sources."""
        tasks = []
        
        for source in self.sources:
            if source in self.source_handlers:
                handler = self.source_handlers[source]
                task = asyncio.create_task(self._safe_collect(source, handler))
                tasks.append(task)
        
        # Wait for all collections to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _safe_collect(self, source: TelemetrySource, handler: Callable) -> None:
        """Safely collect from a single source with error handling."""
        try:
            records = await handler()
            
            if records:
                with self.lock:
                    for record in records:
                        self.telemetry_buffer.append(record)
                        self.performance_metrics['total_records'] += 1
                
                self.collection_stats[source] += len(records)
                self.logger.debug(f"Collected {len(records)} records from {source.value}")
            
        except Exception as e:
            self.logger.error(f"Error collecting from {source.value}: {e}")
            self.performance_metrics['collection_errors'] += 1
    
    async def _collect_security_metrics(self) -> List[TelemetryRecord]:
        """Collect security monitoring metrics."""
        try:
            # Generate security metrics (placeholder - would integrate with actual security monitor)
            metrics = SecurityMetrics(
                active_threats=self._get_active_threats(),
                threat_level=self._calculate_threat_level(),
                authentication_failures=self._get_auth_failures(),
                access_violations=self._get_access_violations(),
                anomaly_count=self._get_anomaly_count(),
                risk_score=self._calculate_risk_score(),
                classification_level=self._get_classification_level(),
                byzantine_nodes=self._get_byzantine_node_count()
            )
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.SECURITY_MONITOR,
                event_type="security_metrics",
                data=asdict(metrics),
                severity=self._calculate_severity(metrics.threat_level),
                classification=metrics.classification_level,
                metadata={
                    'collector_version': '1.0.0',
                    'collection_method': 'real_time'
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting security metrics: {e}")
            return []
    
    async def _collect_system_metrics(self) -> List[TelemetryRecord]:
        """Collect system performance metrics."""
        try:
            # Get system metrics using psutil
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            metrics = SystemMetrics(
                cpu_usage=cpu_percent,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                network_traffic=network.bytes_sent + network.bytes_recv,
                process_count=len(psutil.pids()),
                uptime=time.time() - psutil.boot_time(),
                load_average=psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0
            )
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.SYSTEM_METRICS,
                event_type="system_metrics",
                data=asdict(metrics),
                severity=self._calculate_system_severity(metrics),
                classification="U",  # Unclassified system metrics
                metadata={
                    'hostname': socket.gethostname(),
                    'platform': psutil.os.name if hasattr(psutil, 'os') else 'unknown'
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return []
    
    async def _collect_byzantine_metrics(self) -> List[TelemetryRecord]:
        """Collect Byzantine consensus metrics."""
        try:
            if not self.consensus_engine:
                return []
            
            # Get consensus metrics (placeholder)
            consensus_data = {
                'consensus_round': self._get_consensus_round(),
                'participating_nodes': self._get_participating_nodes(),
                'byzantine_nodes_detected': self._get_byzantine_nodes(),
                'consensus_time': self._get_consensus_time(),
                'agreement_percentage': self._get_agreement_percentage(),
                'fault_tolerance': self._get_fault_tolerance()
            }
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.BYZANTINE_CONSENSUS,
                event_type="consensus_metrics",
                data=consensus_data,
                severity=self._calculate_consensus_severity(consensus_data),
                classification="S",  # Secret classification for consensus
                metadata={
                    'consensus_algorithm': 'pbft',
                    'node_id': str(uuid.uuid4())[:8]
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting Byzantine metrics: {e}")
            return []
    
    async def _collect_network_metrics(self) -> List[TelemetryRecord]:
        """Collect network monitoring metrics."""
        try:
            # Get network statistics
            network_stats = psutil.net_io_counters()
            connections = psutil.net_connections()
            
            metrics = NetworkMetrics(
                connections_active=len(connections),
                connections_established=len([c for c in connections if c.status == 'ESTABLISHED']),
                packets_sent=network_stats.packets_sent,
                packets_received=network_stats.packets_recv,
                bytes_sent=network_stats.bytes_sent,
                bytes_received=network_stats.bytes_recv,
                errors=network_stats.errin + network_stats.errout,
                dropped_packets=network_stats.dropin + network_stats.dropout
            )
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.NETWORK_MONITOR,
                event_type="network_metrics",
                data=asdict(metrics),
                severity=self._calculate_network_severity(metrics),
                classification="U",
                metadata={
                    'interface_count': len(psutil.net_if_addrs()),
                    'collection_method': 'psutil'
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting network metrics: {e}")
            return []
    
    async def _collect_threat_intelligence(self) -> List[TelemetryRecord]:
        """Collect threat intelligence data."""
        try:
            # Generate threat intelligence data (placeholder)
            threat_data = {
                'threat_feeds_active': self._get_threat_feeds_count(),
                'new_threats_detected': self._get_new_threats(),
                'threat_severity_distribution': self._get_threat_distribution(),
                'ioc_matches': self._get_ioc_matches(),
                'threat_actor_activity': self._get_threat_actor_activity(),
                'attack_patterns': self._get_attack_patterns()
            }
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.THREAT_INTELLIGENCE,
                event_type="threat_intelligence",
                data=threat_data,
                severity=self._calculate_threat_severity(threat_data),
                classification="S",  # Secret classification for threat intelligence
                metadata={
                    'feed_sources': ['internal', 'external', 'commercial'],
                    'update_frequency': 'real_time'
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting threat intelligence: {e}")
            return []
    
    async def _collect_audit_logs(self) -> List[TelemetryRecord]:
        """Collect audit log data."""
        try:
            # Generate audit log metrics (placeholder)
            audit_data = {
                'total_events': self._get_audit_events_count(),
                'failed_logins': self._get_failed_logins(),
                'privilege_escalations': self._get_privilege_escalations(),
                'file_access_violations': self._get_file_violations(),
                'policy_violations': self._get_policy_violations(),
                'compliance_score': self._get_compliance_score()
            }
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.AUDIT_LOGS,
                event_type="audit_metrics",
                data=audit_data,
                severity=self._calculate_audit_severity(audit_data),
                classification="S",  # Secret classification for audit logs
                metadata={
                    'log_retention_period': '7_years',
                    'compliance_frameworks': ['FISMA', 'STIG', 'NIST']
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting audit logs: {e}")
            return []
    
    async def _collect_performance_metrics(self) -> List[TelemetryRecord]:
        """Collect performance monitoring metrics."""
        try:
            # Generate performance metrics (placeholder)
            perf_data = {
                'response_times': self._get_response_times(),
                'throughput': self._get_throughput(),
                'error_rates': self._get_error_rates(),
                'availability': self._get_availability(),
                'resource_utilization': self._get_resource_utilization(),
                'sla_compliance': self._get_sla_compliance()
            }
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.PERFORMANCE_METRICS,
                event_type="performance_metrics",
                data=perf_data,
                severity=self._calculate_performance_severity(perf_data),
                classification="U",
                metadata={
                    'monitoring_tools': ['prometheus', 'grafana', 'custom'],
                    'collection_interval': self.collection_interval
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting performance metrics: {e}")
            return []
    
    async def _collect_classification_metrics(self) -> List[TelemetryRecord]:
        """Collect classification-related metrics."""
        try:
            # Generate classification metrics (placeholder)
            classification_data = {
                'classified_events': self._get_classified_events(),
                'classification_violations': self._get_classification_violations(),
                'clearance_levels_active': self._get_clearance_levels(),
                'data_spillage_incidents': self._get_spillage_incidents(),
                'compartment_access_requests': self._get_compartment_requests(),
                'classification_accuracy': self._get_classification_accuracy()
            }
            
            record = TelemetryRecord(
                timestamp=datetime.now(),
                source=TelemetrySource.CLASSIFICATION_MONITOR,
                event_type="classification_metrics",
                data=classification_data,
                severity=self._calculate_classification_severity(classification_data),
                classification="TS",  # Top Secret for classification monitoring
                metadata={
                    'classification_guide': 'ALCUB3-CG-001',
                    'monitoring_scope': 'platform_wide'
                }
            )
            
            return [record]
            
        except Exception as e:
            self.logger.error(f"Error collecting classification metrics: {e}")
            return []
    
    async def collect_all(self) -> Dict[str, Any]:
        """Collect telemetry from all sources and return aggregated data."""
        await self._collect_from_all_sources()
        
        # Get recent records
        with self.lock:
            recent_records = list(self.telemetry_buffer)[-100:]  # Last 100 records
        
        # Aggregate data
        aggregated_data = {
            'timestamp': datetime.now().isoformat(),
            'total_records': len(recent_records),
            'sources': {},
            'summary': self._generate_summary(recent_records),
            'performance': self.performance_metrics.copy(),
            'collection_stats': dict(self.collection_stats)
        }
        
        # Group by source
        for record in recent_records:
            source_name = record.source.value
            if source_name not in aggregated_data['sources']:
                aggregated_data['sources'][source_name] = []
            
            aggregated_data['sources'][source_name].append({
                'timestamp': record.timestamp.isoformat(),
                'event_type': record.event_type,
                'data': record.data,
                'severity': record.severity,
                'classification': record.classification
            })
        
        return aggregated_data
    
    def _generate_summary(self, records: List[TelemetryRecord]) -> Dict[str, Any]:
        """Generate summary statistics from records."""
        if not records:
            return {}
        
        summary = {
            'total_records': len(records),
            'time_range': {
                'start': min(r.timestamp for r in records).isoformat(),
                'end': max(r.timestamp for r in records).isoformat()
            },
            'sources': {},
            'severity_distribution': defaultdict(int),
            'classification_distribution': defaultdict(int),
            'avg_severity': 0.0
        }
        
        # Calculate distributions
        for record in records:
            source_name = record.source.value
            summary['sources'][source_name] = summary['sources'].get(source_name, 0) + 1
            summary['severity_distribution'][record.severity] += 1
            summary['classification_distribution'][record.classification] += 1
        
        # Calculate average severity
        if records:
            summary['avg_severity'] = sum(r.severity for r in records) / len(records)
        
        return summary
    
    def _update_performance_metrics(self, collection_time: float) -> None:
        """Update performance metrics."""
        self.performance_metrics['last_collection_time'] = datetime.now().isoformat()
        
        # Update average collection time
        current_avg = self.performance_metrics['avg_collection_time']
        if current_avg == 0:
            self.performance_metrics['avg_collection_time'] = collection_time
        else:
            # Exponential moving average
            self.performance_metrics['avg_collection_time'] = 0.9 * current_avg + 0.1 * collection_time
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        return {
            'collection_stats': dict(self.collection_stats),
            'performance_metrics': self.performance_metrics.copy(),
            'buffer_size': len(self.telemetry_buffer),
            'sources_configured': [s.value for s in self.sources],
            'running': self.running
        }
    
    # Placeholder methods for metric calculations
    # These would be replaced with actual implementation
    
    def _get_active_threats(self) -> int:
        return max(0, int(time.time() % 10))
    
    def _calculate_threat_level(self) -> float:
        return min(1.0, (time.time() % 100) / 100.0)
    
    def _get_auth_failures(self) -> int:
        return max(0, int(time.time() % 5))
    
    def _get_access_violations(self) -> int:
        return max(0, int(time.time() % 3))
    
    def _get_anomaly_count(self) -> int:
        return max(0, int(time.time() % 7))
    
    def _calculate_risk_score(self) -> float:
        return min(1.0, (time.time() % 50) / 50.0)
    
    def _get_classification_level(self) -> str:
        levels = ['U', 'S', 'TS']
        return levels[int(time.time()) % len(levels)]
    
    def _get_byzantine_node_count(self) -> int:
        return max(0, int(time.time() % 3))
    
    def _calculate_severity(self, threat_level: float) -> int:
        return min(5, max(1, int(threat_level * 5)))
    
    def _calculate_system_severity(self, metrics: SystemMetrics) -> int:
        # High CPU/Memory usage increases severity
        severity = 1
        if metrics.cpu_usage > 80 or metrics.memory_usage > 80:
            severity = 3
        elif metrics.cpu_usage > 60 or metrics.memory_usage > 60:
            severity = 2
        return severity
    
    def _calculate_consensus_severity(self, data: Dict[str, Any]) -> int:
        byzantine_count = data.get('byzantine_nodes_detected', 0)
        return min(5, max(1, byzantine_count + 1))
    
    def _calculate_network_severity(self, metrics: NetworkMetrics) -> int:
        if metrics.errors > 100 or metrics.dropped_packets > 50:
            return 4
        elif metrics.errors > 50 or metrics.dropped_packets > 20:
            return 3
        elif metrics.errors > 10 or metrics.dropped_packets > 5:
            return 2
        else:
            return 1
    
    def _calculate_threat_severity(self, data: Dict[str, Any]) -> int:
        new_threats = data.get('new_threats_detected', 0)
        return min(5, max(1, new_threats + 1))
    
    def _calculate_audit_severity(self, data: Dict[str, Any]) -> int:
        violations = data.get('policy_violations', 0)
        return min(5, max(1, violations + 1))
    
    def _calculate_performance_severity(self, data: Dict[str, Any]) -> int:
        error_rate = data.get('error_rates', 0)
        return min(5, max(1, int(error_rate * 5)))
    
    def _calculate_classification_severity(self, data: Dict[str, Any]) -> int:
        violations = data.get('classification_violations', 0)
        return min(5, max(1, violations + 1))
    
    # Additional placeholder methods
    def _get_consensus_round(self) -> int:
        return int(time.time() % 1000)
    
    def _get_participating_nodes(self) -> int:
        return max(3, int(time.time() % 10))
    
    def _get_byzantine_nodes(self) -> int:
        return max(0, int(time.time() % 2))
    
    def _get_consensus_time(self) -> float:
        return min(10.0, (time.time() % 100) / 10.0)
    
    def _get_agreement_percentage(self) -> float:
        return max(0.5, min(1.0, (time.time() % 50) / 50.0 + 0.5))
    
    def _get_fault_tolerance(self) -> float:
        return max(0.3, min(0.5, (time.time() % 20) / 100.0 + 0.3))
    
    def _get_threat_feeds_count(self) -> int:
        return max(3, int(time.time() % 10))
    
    def _get_new_threats(self) -> int:
        return max(0, int(time.time() % 5))
    
    def _get_threat_distribution(self) -> Dict[str, int]:
        return {
            'low': max(0, int(time.time() % 10)),
            'medium': max(0, int(time.time() % 7)),
            'high': max(0, int(time.time() % 3)),
            'critical': max(0, int(time.time() % 2))
        }
    
    def _get_ioc_matches(self) -> int:
        return max(0, int(time.time() % 3))
    
    def _get_threat_actor_activity(self) -> Dict[str, int]:
        return {
            'nation_state': max(0, int(time.time() % 2)),
            'criminal': max(0, int(time.time() % 3)),
            'hacktivist': max(0, int(time.time() % 2)),
            'insider': max(0, int(time.time() % 1))
        }
    
    def _get_attack_patterns(self) -> Dict[str, int]:
        return {
            'malware': max(0, int(time.time() % 5)),
            'phishing': max(0, int(time.time() % 3)),
            'ddos': max(0, int(time.time() % 2)),
            'lateral_movement': max(0, int(time.time() % 2))
        }
    
    def _get_audit_events_count(self) -> int:
        return max(100, int(time.time() % 1000))
    
    def _get_failed_logins(self) -> int:
        return max(0, int(time.time() % 10))
    
    def _get_privilege_escalations(self) -> int:
        return max(0, int(time.time() % 3))
    
    def _get_file_violations(self) -> int:
        return max(0, int(time.time() % 5))
    
    def _get_policy_violations(self) -> int:
        return max(0, int(time.time() % 3))
    
    def _get_compliance_score(self) -> float:
        return max(0.7, min(1.0, (time.time() % 30) / 30.0 + 0.7))
    
    def _get_response_times(self) -> Dict[str, float]:
        return {
            'avg': max(0.1, (time.time() % 10) / 10.0),
            'p95': max(0.2, (time.time() % 20) / 10.0),
            'p99': max(0.3, (time.time() % 30) / 10.0)
        }
    
    def _get_throughput(self) -> float:
        return max(100, (time.time() % 1000))
    
    def _get_error_rates(self) -> float:
        return max(0.001, min(0.1, (time.time() % 100) / 1000.0))
    
    def _get_availability(self) -> float:
        return max(0.95, min(1.0, (time.time() % 50) / 1000.0 + 0.95))
    
    def _get_resource_utilization(self) -> Dict[str, float]:
        return {
            'cpu': max(10, min(90, (time.time() % 80) + 10)),
            'memory': max(20, min(80, (time.time() % 60) + 20)),
            'disk': max(10, min(70, (time.time() % 60) + 10))
        }
    
    def _get_sla_compliance(self) -> float:
        return max(0.95, min(1.0, (time.time() % 50) / 1000.0 + 0.95))
    
    def _get_classified_events(self) -> Dict[str, int]:
        return {
            'U': max(100, int(time.time() % 500)),
            'S': max(10, int(time.time() % 50)),
            'TS': max(1, int(time.time() % 10))
        }
    
    def _get_classification_violations(self) -> int:
        return max(0, int(time.time() % 2))
    
    def _get_clearance_levels(self) -> Dict[str, int]:
        return {
            'U': max(100, int(time.time() % 200)),
            'S': max(20, int(time.time() % 50)),
            'TS': max(5, int(time.time() % 15))
        }
    
    def _get_spillage_incidents(self) -> int:
        return max(0, int(time.time() % 1))
    
    def _get_compartment_requests(self) -> int:
        return max(0, int(time.time() % 5))
    
    def _get_classification_accuracy(self) -> float:
        return max(0.95, min(1.0, (time.time() % 50) / 1000.0 + 0.95))


# Example usage
async def demo_telemetry_collector():
    """Demonstrate telemetry collector capabilities."""
    
    # Initialize collector
    collector = TelemetryCollector(
        collection_interval=10,  # 10 seconds for demo
        buffer_size=100,
        sources=[
            TelemetrySource.SECURITY_MONITOR,
            TelemetrySource.SYSTEM_METRICS,
            TelemetrySource.NETWORK_MONITOR,
            TelemetrySource.PERFORMANCE_METRICS
        ]
    )
    
    try:
        # Start collection
        print("Starting telemetry collection...")
        await collector.start_collection()
        
        # Let it collect for a bit
        await asyncio.sleep(30)
        
        # Get aggregated data
        print("\nCollecting aggregated data...")
        aggregated = await collector.collect_all()
        
        print(f"Total records: {aggregated['total_records']}")
        print(f"Sources: {list(aggregated['sources'].keys())}")
        print(f"Performance: {aggregated['performance']}")
        
        # Show some sample records
        for source_name, records in aggregated['sources'].items():
            if records:
                print(f"\n{source_name} sample:")
                print(f"  Event type: {records[0]['event_type']}")
                print(f"  Severity: {records[0]['severity']}")
                print(f"  Classification: {records[0]['classification']}")
        
        # Get collection stats
        stats = collector.get_collection_stats()
        print(f"\nCollection stats: {stats}")
        
    except Exception as e:
        print(f"Error in demo: {e}")
    
    finally:
        # Stop collection
        await collector.stop_collection()
        print("Telemetry collection stopped")


if __name__ == "__main__":
    asyncio.run(demo_telemetry_collector()) 