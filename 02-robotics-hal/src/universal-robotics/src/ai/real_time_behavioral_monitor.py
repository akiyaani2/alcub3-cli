#!/usr/bin/env python3
"""
ALCUB3 Real-Time Behavioral Monitoring System
Defense-Grade Real-Time Behavioral Analysis with <50ms Response

This module implements high-performance real-time behavioral monitoring
with sub-50ms response times for defense-grade applications.

Key Features:
- Sub-50ms behavioral analysis response time
- Streaming behavioral data processing
- Real-time anomaly detection and alerting
- High-throughput behavioral pattern recognition
- Memory-efficient streaming algorithms
- Concurrent processing with asyncio

Author: ALCUB3 Development Team
Classification: For Official Use Only
"""

import asyncio
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import numpy as np
import json
from pathlib import Path
import sys
import queue
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

# High-performance computing imports
import uvloop  # High-performance asyncio event loop
from numba import jit, njit
import cupy as cp  # GPU acceleration (optional)

# Import behavioral analysis components
from .behavioral_analyzer import (
    BehavioralAnalysisEngine, BehavioralFeature, BehavioralAnomaly, 
    BehavioralPattern, BehavioralPatternType, BehavioralAnomalyType
)
from .cross_platform_correlator import CrossPlatformBehavioralCorrelator, RobotPlatformType

# Import security components
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "02-security-maestro" / "src"))
from shared.classification import ClassificationLevel

logger = logging.getLogger(__name__)


class StreamingMode(Enum):
    """Streaming processing modes."""
    REAL_TIME = "real_time"      # <50ms response time
    NEAR_REAL_TIME = "near_real_time"  # <100ms response time
    BATCH = "batch"              # Batch processing mode
    ADAPTIVE = "adaptive"        # Adaptive based on load


class ProcessingPriority(Enum):
    """Processing priority levels."""
    CRITICAL = "critical"    # Emergency/security alerts
    HIGH = "high"           # Important behavioral changes
    MEDIUM = "medium"       # Normal monitoring
    LOW = "low"            # Background analysis


@dataclass
class StreamingDataPoint:
    """Single streaming data point."""
    robot_id: str
    timestamp: datetime
    sensor_data: Dict[str, Any]
    priority: ProcessingPriority = ProcessingPriority.MEDIUM
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'robot_id': self.robot_id,
            'timestamp': self.timestamp.isoformat(),
            'sensor_data': self.sensor_data,
            'priority': self.priority.value,
            'classification_level': self.classification_level.value
        }


@dataclass
class ProcessingResult:
    """Result of behavioral processing."""
    robot_id: str
    processing_time_ms: float
    behavioral_features: Dict[str, BehavioralFeature]
    anomalies: List[BehavioralAnomaly]
    correlations: Dict[str, float]
    timestamp: datetime = field(default_factory=datetime.now)
    
    def is_critical(self) -> bool:
        """Check if result contains critical anomalies."""
        return any(anomaly.severity == "critical" for anomaly in self.anomalies)


@dataclass
class PerformanceMetrics:
    """Real-time performance metrics."""
    avg_processing_time_ms: float = 0.0
    max_processing_time_ms: float = 0.0
    min_processing_time_ms: float = float('inf')
    throughput_per_second: float = 0.0
    queue_size: int = 0
    dropped_frames: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    # SLA metrics
    sub_50ms_success_rate: float = 0.0
    sub_25ms_success_rate: float = 0.0
    
    def update(self, processing_time_ms: float):
        """Update metrics with new processing time."""
        self.avg_processing_time_ms = 0.9 * self.avg_processing_time_ms + 0.1 * processing_time_ms
        self.max_processing_time_ms = max(self.max_processing_time_ms, processing_time_ms)
        self.min_processing_time_ms = min(self.min_processing_time_ms, processing_time_ms)
        
        # Update SLA metrics
        if processing_time_ms < 50.0:
            self.sub_50ms_success_rate = 0.95 * self.sub_50ms_success_rate + 0.05 * 1.0
        else:
            self.sub_50ms_success_rate = 0.95 * self.sub_50ms_success_rate + 0.05 * 0.0
        
        if processing_time_ms < 25.0:
            self.sub_25ms_success_rate = 0.95 * self.sub_25ms_success_rate + 0.05 * 1.0
        else:
            self.sub_25ms_success_rate = 0.95 * self.sub_25ms_success_rate + 0.05 * 0.0


class StreamingProcessor:
    """High-performance streaming processor for behavioral data."""
    
    def __init__(self, max_queue_size: int = 10000, num_workers: int = 4):
        self.max_queue_size = max_queue_size
        self.num_workers = num_workers
        
        # Processing queues with priority
        self.critical_queue = asyncio.Queue(maxsize=1000)
        self.high_queue = asyncio.Queue(maxsize=2000)
        self.medium_queue = asyncio.Queue(maxsize=5000)
        self.low_queue = asyncio.Queue(maxsize=2000)
        
        # Worker pool
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
        
        # Processing state
        self.is_running = False
        self.worker_tasks = []
        
        # Performance tracking
        self.metrics = PerformanceMetrics()
        self.processing_times = deque(maxlen=1000)
        
        # Memory-efficient data structures
        self.feature_cache = {}
        self.pattern_cache = {}
        
        logger.info(f"StreamingProcessor initialized with {num_workers} workers")
    
    async def start(self):
        """Start the streaming processor."""
        self.is_running = True
        
        # Start worker tasks
        for i in range(self.num_workers):
            task = asyncio.create_task(self._worker_loop(i))
            self.worker_tasks.append(task)
        
        # Start metrics updater
        asyncio.create_task(self._metrics_updater())
        
        logger.info("StreamingProcessor started")
    
    async def stop(self):
        """Stop the streaming processor."""
        self.is_running = False
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        logger.info("StreamingProcessor stopped")
    
    async def submit_data(self, data_point: StreamingDataPoint) -> bool:
        """Submit data for processing."""
        try:
            # Select appropriate queue based on priority
            if data_point.priority == ProcessingPriority.CRITICAL:
                queue_to_use = self.critical_queue
            elif data_point.priority == ProcessingPriority.HIGH:
                queue_to_use = self.high_queue
            elif data_point.priority == ProcessingPriority.MEDIUM:
                queue_to_use = self.medium_queue
            else:
                queue_to_use = self.low_queue
            
            # Non-blocking put
            queue_to_use.put_nowait(data_point)
            return True
            
        except asyncio.QueueFull:
            # Drop data if queue is full
            self.metrics.dropped_frames += 1
            logger.warning(f"Queue full, dropping data point for robot {data_point.robot_id}")
            return False
    
    async def _worker_loop(self, worker_id: int):
        """Main worker loop for processing data."""
        logger.info(f"Worker {worker_id} started")
        
        while self.is_running:
            try:
                # Process by priority
                data_point = await self._get_next_data_point()
                
                if data_point:
                    # Process the data point
                    await self._process_data_point(data_point, worker_id)
                else:
                    # No data available, short sleep to prevent busy waiting
                    await asyncio.sleep(0.001)  # 1ms sleep
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                await asyncio.sleep(0.01)  # Brief pause before retry
        
        logger.info(f"Worker {worker_id} stopped")
    
    async def _get_next_data_point(self) -> Optional[StreamingDataPoint]:
        """Get next data point respecting priority."""
        # Try critical queue first
        try:
            return self.critical_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        
        # Try high priority queue
        try:
            return self.high_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        
        # Try medium priority queue
        try:
            return self.medium_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        
        # Try low priority queue
        try:
            return self.low_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        
        return None
    
    async def _process_data_point(self, data_point: StreamingDataPoint, worker_id: int):
        """Process a single data point."""
        start_time = time.time()
        
        try:
            # This would integrate with the behavioral analysis engine
            # For now, simulate processing
            await asyncio.sleep(0.001)  # Simulate 1ms processing time
            
            # Update metrics
            processing_time_ms = (time.time() - start_time) * 1000
            self.processing_times.append(processing_time_ms)
            self.metrics.update(processing_time_ms)
            
            # Update queue sizes
            self.metrics.queue_size = (
                self.critical_queue.qsize() + 
                self.high_queue.qsize() + 
                self.medium_queue.qsize() + 
                self.low_queue.qsize()
            )
            
        except Exception as e:
            logger.error(f"Error processing data point: {e}")
    
    async def _metrics_updater(self):
        """Update performance metrics periodically."""
        while self.is_running:
            try:
                # Calculate throughput
                if len(self.processing_times) > 0:
                    # Throughput based on processing times in last second
                    recent_times = [t for t in self.processing_times if t > 0]
                    if recent_times:
                        avg_time_s = np.mean(recent_times) / 1000.0
                        self.metrics.throughput_per_second = 1.0 / avg_time_s if avg_time_s > 0 else 0.0
                
                await asyncio.sleep(1.0)  # Update every second
                
            except Exception as e:
                logger.error(f"Error updating metrics: {e}")
                await asyncio.sleep(1.0)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        return {
            'avg_processing_time_ms': self.metrics.avg_processing_time_ms,
            'max_processing_time_ms': self.metrics.max_processing_time_ms,
            'min_processing_time_ms': self.metrics.min_processing_time_ms,
            'throughput_per_second': self.metrics.throughput_per_second,
            'queue_size': self.metrics.queue_size,
            'dropped_frames': self.metrics.dropped_frames,
            'sub_50ms_success_rate': self.metrics.sub_50ms_success_rate,
            'sub_25ms_success_rate': self.metrics.sub_25ms_success_rate,
            'worker_count': self.num_workers,
            'is_running': self.is_running
        }


class RealTimeBehavioralMonitor:
    """
    Main real-time behavioral monitoring system.
    
    Features:
    - Sub-50ms behavioral analysis response time
    - High-throughput streaming processing
    - Real-time anomaly detection
    - Concurrent multi-robot monitoring
    - Memory-efficient algorithms
    """
    
    def __init__(self, 
                 target_response_time_ms: float = 25.0,
                 max_concurrent_robots: int = 100,
                 enable_gpu_acceleration: bool = False):
        
        self.target_response_time_ms = target_response_time_ms
        self.max_concurrent_robots = max_concurrent_robots
        self.enable_gpu_acceleration = enable_gpu_acceleration
        
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.behavioral_engine = BehavioralAnalysisEngine(enable_ml=True)
        self.cross_platform_correlator = CrossPlatformBehavioralCorrelator()
        self.streaming_processor = StreamingProcessor(num_workers=8)
        
        # Real-time data structures
        self.active_robots: Dict[str, Dict[str, Any]] = {}
        self.streaming_features: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Performance optimization
        self.feature_cache: Dict[str, BehavioralFeature] = {}
        self.pattern_cache: Dict[str, BehavioralPattern] = {}
        
        # Callback system for real-time alerts
        self.alert_callbacks: List[Callable[[BehavioralAnomaly], Awaitable[None]]] = []
        
        # Performance monitoring
        self.monitor_metrics = {
            'total_processed': 0,
            'total_anomalies': 0,
            'avg_response_time_ms': 0.0,
            'sla_violations': 0,
            'start_time': datetime.now()
        }
        
        # Configure asyncio for high performance
        if hasattr(asyncio, 'set_event_loop_policy'):
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        
        self.logger.info(f"RealTimeBehavioralMonitor initialized with {target_response_time_ms}ms target")
    
    async def start_monitoring(self):
        """Start real-time monitoring."""
        try:
            # Start streaming processor
            await self.streaming_processor.start()
            
            # Start background tasks
            asyncio.create_task(self._performance_monitor())
            asyncio.create_task(self._cleanup_task())
            
            self.logger.info("Real-time behavioral monitoring started")
            
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {e}")
            raise
    
    async def stop_monitoring(self):
        """Stop real-time monitoring."""
        try:
            await self.streaming_processor.stop()
            self.logger.info("Real-time behavioral monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
    
    async def register_robot(self, robot_id: str, platform_type: RobotPlatformType, 
                           metadata: Optional[Dict[str, Any]] = None):
        """Register a robot for monitoring."""
        self.active_robots[robot_id] = {
            'platform_type': platform_type,
            'metadata': metadata or {},
            'last_activity': datetime.now(),
            'processing_times': deque(maxlen=100),
            'anomaly_count': 0
        }
        
        # Register with cross-platform correlator
        self.cross_platform_correlator.register_robot(robot_id, platform_type, metadata)
        
        self.logger.info(f"Registered robot {robot_id} for real-time monitoring")
    
    async def process_sensor_data(self, robot_id: str, sensor_data: Dict[str, Any], 
                                priority: ProcessingPriority = ProcessingPriority.MEDIUM) -> Optional[ProcessingResult]:
        """
        Process sensor data in real-time.
        
        Args:
            robot_id: Robot identifier
            sensor_data: Sensor data dictionary
            priority: Processing priority
            
        Returns:
            Processing result or None if queued for later processing
        """
        start_time = time.time()
        
        try:
            # Create streaming data point
            data_point = StreamingDataPoint(
                robot_id=robot_id,
                timestamp=datetime.now(),
                sensor_data=sensor_data,
                priority=priority
            )
            
            # For critical priority, process immediately
            if priority == ProcessingPriority.CRITICAL:
                result = await self._process_immediately(data_point)
                
                # Check SLA compliance
                processing_time_ms = (time.time() - start_time) * 1000
                if processing_time_ms > self.target_response_time_ms:
                    self.monitor_metrics['sla_violations'] += 1
                
                return result
            
            # For other priorities, queue for processing
            else:
                queued = await self.streaming_processor.submit_data(data_point)
                if not queued:
                    self.logger.warning(f"Failed to queue data for robot {robot_id}")
                
                return None
                
        except Exception as e:
            self.logger.error(f"Error processing sensor data for robot {robot_id}: {e}")
            return None
    
    async def _process_immediately(self, data_point: StreamingDataPoint) -> ProcessingResult:
        """Process data point immediately for critical priority."""
        start_time = time.time()
        
        try:
            # Extract behavioral features
            features = await self.behavioral_engine.extract_behavioral_features(
                data_point.robot_id, data_point.sensor_data, data_point.timestamp
            )
            
            # Detect anomalies
            anomalies = await self.behavioral_engine.detect_behavioral_anomalies(
                data_point.robot_id, features
            )
            
            # Compute correlations (simplified for speed)
            correlations = await self._compute_fast_correlations(data_point.robot_id, features)
            
            # Update metrics
            processing_time_ms = (time.time() - start_time) * 1000
            self.monitor_metrics['total_processed'] += 1
            self.monitor_metrics['total_anomalies'] += len(anomalies)
            
            # Update robot-specific metrics
            if data_point.robot_id in self.active_robots:
                self.active_robots[data_point.robot_id]['processing_times'].append(processing_time_ms)
                self.active_robots[data_point.robot_id]['anomaly_count'] += len(anomalies)
                self.active_robots[data_point.robot_id]['last_activity'] = datetime.now()
            
            # Create result
            result = ProcessingResult(
                robot_id=data_point.robot_id,
                processing_time_ms=processing_time_ms,
                behavioral_features=features,
                anomalies=anomalies,
                correlations=correlations
            )
            
            # Trigger alerts for critical anomalies
            if result.is_critical():
                await self._trigger_alerts(anomalies)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in immediate processing: {e}")
            processing_time_ms = (time.time() - start_time) * 1000
            
            return ProcessingResult(
                robot_id=data_point.robot_id,
                processing_time_ms=processing_time_ms,
                behavioral_features={},
                anomalies=[],
                correlations={}
            )
    
    async def _compute_fast_correlations(self, robot_id: str, 
                                       features: Dict[str, BehavioralFeature]) -> Dict[str, float]:
        """Compute fast correlations for real-time processing."""
        correlations = {}
        
        try:
            # Use cached patterns for speed
            if robot_id in self.pattern_cache:
                cached_pattern = self.pattern_cache[robot_id]
                
                # Simple correlation computation
                for feature_name, feature in features.items():
                    if len(feature.values) > 0:
                        # Simplified correlation based on feature similarity
                        correlation = np.corrcoef(
                            feature.values[:min(len(feature.values), len(cached_pattern.pattern_signature))],
                            cached_pattern.pattern_signature[:min(len(feature.values), len(cached_pattern.pattern_signature))]
                        )[0, 1] if len(feature.values) > 1 else 0.0
                        
                        if not np.isnan(correlation):
                            correlations[feature_name] = abs(correlation)
            
        except Exception as e:
            self.logger.error(f"Error computing fast correlations: {e}")
        
        return correlations
    
    async def _trigger_alerts(self, anomalies: List[BehavioralAnomaly]):
        """Trigger alerts for detected anomalies."""
        for anomaly in anomalies:
            if anomaly.severity in ['critical', 'high']:
                # Call registered callbacks
                for callback in self.alert_callbacks:
                    try:
                        await callback(anomaly)
                    except Exception as e:
                        self.logger.error(f"Error in alert callback: {e}")
    
    def register_alert_callback(self, callback: Callable[[BehavioralAnomaly], Awaitable[None]]):
        """Register a callback for real-time alerts."""
        self.alert_callbacks.append(callback)
        self.logger.info("Alert callback registered")
    
    async def _performance_monitor(self):
        """Monitor performance metrics."""
        while True:
            try:
                # Update average response time
                total_times = []
                for robot_info in self.active_robots.values():
                    total_times.extend(robot_info['processing_times'])
                
                if total_times:
                    self.monitor_metrics['avg_response_time_ms'] = np.mean(total_times)
                
                # Log performance metrics periodically
                if self.monitor_metrics['total_processed'] % 1000 == 0:
                    self.logger.info(
                        f"Performance: avg_response={self.monitor_metrics['avg_response_time_ms']:.2f}ms, "
                        f"processed={self.monitor_metrics['total_processed']}, "
                        f"anomalies={self.monitor_metrics['total_anomalies']}, "
                        f"sla_violations={self.monitor_metrics['sla_violations']}"
                    )
                
                await asyncio.sleep(10.0)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error in performance monitor: {e}")
                await asyncio.sleep(10.0)
    
    async def _cleanup_task(self):
        """Cleanup inactive robots and old data."""
        while True:
            try:
                current_time = datetime.now()
                inactive_threshold = timedelta(minutes=5)
                
                # Remove inactive robots
                inactive_robots = [
                    robot_id for robot_id, robot_info in self.active_robots.items()
                    if current_time - robot_info['last_activity'] > inactive_threshold
                ]
                
                for robot_id in inactive_robots:
                    del self.active_robots[robot_id]
                    if robot_id in self.streaming_features:
                        del self.streaming_features[robot_id]
                    
                    self.logger.info(f"Removed inactive robot {robot_id}")
                
                # Clear old cache entries
                if len(self.feature_cache) > 1000:
                    # Keep only recent entries
                    self.feature_cache.clear()
                
                await asyncio.sleep(60.0)  # Cleanup every minute
                
            except Exception as e:
                self.logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(60.0)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        streaming_metrics = self.streaming_processor.get_metrics()
        
        return {
            'monitor_metrics': self.monitor_metrics,
            'streaming_metrics': streaming_metrics,
            'active_robots': len(self.active_robots),
            'target_response_time_ms': self.target_response_time_ms,
            'uptime_seconds': (datetime.now() - self.monitor_metrics['start_time']).total_seconds(),
            'sla_compliance_rate': 1.0 - (self.monitor_metrics['sla_violations'] / 
                                         max(1, self.monitor_metrics['total_processed'])),
            'memory_usage_mb': self._get_memory_usage()
        }
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0
    
    async def get_robot_status(self, robot_id: str) -> Optional[Dict[str, Any]]:
        """Get status for a specific robot."""
        if robot_id not in self.active_robots:
            return None
        
        robot_info = self.active_robots[robot_id]
        processing_times = list(robot_info['processing_times'])
        
        return {
            'robot_id': robot_id,
            'platform_type': robot_info['platform_type'].value,
            'last_activity': robot_info['last_activity'].isoformat(),
            'anomaly_count': robot_info['anomaly_count'],
            'avg_processing_time_ms': np.mean(processing_times) if processing_times else 0.0,
            'max_processing_time_ms': np.max(processing_times) if processing_times else 0.0,
            'min_processing_time_ms': np.min(processing_times) if processing_times else 0.0,
            'total_processed': len(processing_times)
        }


# High-performance utility functions
@njit
def fast_correlation(x: np.ndarray, y: np.ndarray) -> float:
    """Fast correlation computation using Numba."""
    n = min(len(x), len(y))
    if n < 2:
        return 0.0
    
    # Compute means
    mean_x = np.mean(x[:n])
    mean_y = np.mean(y[:n])
    
    # Compute correlation
    numerator = np.sum((x[:n] - mean_x) * (y[:n] - mean_y))
    denominator = np.sqrt(np.sum((x[:n] - mean_x)**2) * np.sum((y[:n] - mean_y)**2))
    
    if denominator == 0:
        return 0.0
    
    return numerator / denominator


@njit
def fast_anomaly_score(values: np.ndarray, baseline: np.ndarray) -> float:
    """Fast anomaly score computation using Numba."""
    if len(values) == 0 or len(baseline) == 0:
        return 0.0
    
    # Compute normalized distance
    n = min(len(values), len(baseline))
    distance = 0.0
    
    for i in range(n):
        distance += (values[i] - baseline[i]) ** 2
    
    return np.sqrt(distance / n)


# Example usage and testing
async def demo_real_time_monitoring():
    """Demonstrate real-time behavioral monitoring."""
    
    # Initialize monitor
    monitor = RealTimeBehavioralMonitor(target_response_time_ms=25.0)
    
    # Register alert callback
    async def alert_callback(anomaly: BehavioralAnomaly):
        print(f"ALERT: {anomaly.anomaly_type.value} detected for robot {anomaly.affected_robots[0]} "
              f"with {anomaly.severity} severity")
    
    monitor.register_alert_callback(alert_callback)
    
    # Start monitoring
    await monitor.start_monitoring()
    
    # Register test robots
    await monitor.register_robot('test_robot_1', RobotPlatformType.BOSTON_DYNAMICS_SPOT)
    await monitor.register_robot('test_robot_2', RobotPlatformType.DJI_DRONE)
    
    try:
        # Simulate real-time data processing
        print("Starting real-time data simulation...")
        
        for i in range(100):
            # Simulate sensor data
            sensor_data = {
                'position': {'x': 10.0 + i, 'y': 20.0, 'z': 1.0},
                'velocity': {'vx': 1.0, 'vy': 0.5, 'vz': 0.0},
                'sensors': {
                    'gps': {'value': 1.0, 'confidence': 0.95, 'noise_level': 0.02},
                    'imu': {'value': 0.98, 'confidence': 0.99, 'noise_level': 0.01}
                },
                'power': {'consumption': 150.0, 'battery_level': 0.8}
            }
            
            # Process with critical priority for some data
            priority = ProcessingPriority.CRITICAL if i % 10 == 0 else ProcessingPriority.MEDIUM
            
            result = await monitor.process_sensor_data('test_robot_1', sensor_data, priority)
            
            if result:
                print(f"Processed frame {i}: {result.processing_time_ms:.2f}ms, "
                      f"{len(result.anomalies)} anomalies")
            
            # Small delay to simulate real-time data
            await asyncio.sleep(0.01)  # 10ms intervals
        
        # Get performance metrics
        metrics = monitor.get_performance_metrics()
        print(f"Performance metrics: {metrics}")
        
        # Get robot status
        robot_status = await monitor.get_robot_status('test_robot_1')
        print(f"Robot status: {robot_status}")
        
    finally:
        # Stop monitoring
        await monitor.stop_monitoring()
        
    return True


if __name__ == "__main__":
    # Run demo
    asyncio.run(demo_real_time_monitoring())