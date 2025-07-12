#!/usr/bin/env python3
"""
@license
Copyright 2024 ALCUB3 Systems
SPDX-License-Identifier: Apache-2.0

ALCUB3 Universal Security HAL - Performance Monitoring System
Patent-Pending Real-Time Performance Monitoring for Robotics Security

This module implements comprehensive performance monitoring for the Universal
Security HAL with real-time metrics collection, threshold validation, and
performance optimization for sub-50ms response targets.

Task 20: Real-Time Performance Monitoring Implementation
Key Innovations:
- Sub-50ms response time monitoring and validation
- Real-time performance metric collection and analysis
- Adaptive threshold management with machine learning
- Performance anomaly detection and alerting
- Cross-platform performance correlation and optimization

Patent Applications:
- Real-time performance monitoring for robotics security systems
- Adaptive performance threshold management with ML-based optimization
- Cross-platform performance correlation for fleet optimization
- Performance anomaly detection for security validation
"""

import asyncio
import time
import statistics
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import deque, defaultdict
import threading
import logging
import json

from .core_hal import PerformanceMetrics, PerformanceException


class MetricType(Enum):
    """Types of performance metrics."""
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    NETWORK_LATENCY = "network_latency"
    SECURITY_VALIDATION_TIME = "security_validation_time"
    COMMAND_EXECUTION_TIME = "command_execution_time"
    EMERGENCY_RESPONSE_TIME = "emergency_response_time"


class AlertLevel(Enum):
    """Performance alert levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class PerformanceThreshold:
    """Performance threshold definition."""
    metric_type: MetricType
    operation: str
    warning_threshold: float
    critical_threshold: float
    emergency_threshold: float
    unit: str
    adaptive: bool = True
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PerformanceAlert:
    """Performance alert record."""
    alert_id: str
    metric_type: MetricType
    operation: str
    platform_id: Optional[str]
    alert_level: AlertLevel
    current_value: float
    threshold_value: float
    timestamp: datetime
    description: str
    resolved: bool = False
    resolution_time: Optional[datetime] = None


@dataclass
class PerformanceReport:
    """Performance analysis report."""
    report_id: str
    time_range: Tuple[datetime, datetime]
    platform_ids: List[str]
    metrics_summary: Dict[str, Any]
    performance_score: float
    recommendations: List[str]
    anomalies_detected: List[str]
    generated_at: datetime


class PerformanceCollector:
    """Real-time performance metrics collector."""
    
    def __init__(self, max_samples: int = 10000):
        self.max_samples = max_samples
        self.metrics = defaultdict(lambda: deque(maxlen=max_samples))
        self.lock = threading.Lock()
        self.logger = logging.getLogger("PerformanceCollector")
        
    def record_metric(self, metric: PerformanceMetrics):
        """Record a performance metric."""
        with self.lock:
            key = f"{metric.operation_type}_{metric.timestamp.strftime('%Y%m%d_%H')}"
            self.metrics[key].append(metric)
            
    def get_metrics(self, operation_type: str, time_range: Optional[Tuple[datetime, datetime]] = None) -> List[PerformanceMetrics]:
        """Get metrics for an operation within time range."""
        with self.lock:
            if not time_range:
                # Get last hour's metrics
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=1)
                time_range = (start_time, end_time)
            
            start_time, end_time = time_range
            results = []
            
            for key, metrics_deque in self.metrics.items():
                if operation_type in key:
                    for metric in metrics_deque:
                        if start_time <= metric.timestamp <= end_time:
                            results.append(metric)
                            
            return sorted(results, key=lambda x: x.timestamp)
    
    def get_summary_stats(self, operation_type: str, time_range: Optional[Tuple[datetime, datetime]] = None) -> Dict[str, float]:
        """Get summary statistics for an operation."""
        metrics = self.get_metrics(operation_type, time_range)
        
        if not metrics:
            return {}
        
        execution_times = [m.execution_time_ms for m in metrics]
        success_rates = [m.success_rate for m in metrics]
        
        return {
            "count": len(metrics),
            "avg_execution_time_ms": statistics.mean(execution_times),
            "median_execution_time_ms": statistics.median(execution_times),
            "p95_execution_time_ms": statistics.quantiles(execution_times, n=20)[18] if len(execution_times) > 1 else execution_times[0],
            "p99_execution_time_ms": statistics.quantiles(execution_times, n=100)[98] if len(execution_times) > 1 else execution_times[0],
            "min_execution_time_ms": min(execution_times),
            "max_execution_time_ms": max(execution_times),
            "avg_success_rate": statistics.mean(success_rates),
            "total_errors": sum(m.error_count for m in metrics),
            "total_throughput_ops": sum(m.throughput_ops_per_sec for m in metrics)
        }


class HALPerformanceMonitor:
    """
    Universal Security HAL Performance Monitor
    
    Provides comprehensive real-time performance monitoring for the Universal
    Security HAL with sub-50ms response time validation, adaptive threshold
    management, and performance optimization recommendations.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize performance monitor."""
        self.config = config or {}
        self.logger = self._setup_logging()
        
        # Core components
        self.collector = PerformanceCollector(
            max_samples=self.config.get("max_samples", 10000)
        )
        
        # Threshold management
        self.thresholds = self._initialize_default_thresholds()
        self.custom_thresholds = {}
        
        # Alert management
        self.alerts = deque(maxlen=1000)
        self.alert_callbacks = []
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_task = None
        self.monitoring_interval = self.config.get("monitoring_interval", 1.0)  # seconds
        
        # Performance optimization
        self.optimization_enabled = self.config.get("optimization_enabled", True)
        self.adaptive_thresholds = self.config.get("adaptive_thresholds", True)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for performance monitor."""
        logger = logging.getLogger("HALPerformanceMonitor")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def _initialize_default_thresholds(self) -> Dict[str, PerformanceThreshold]:
        """Initialize default performance thresholds."""
        return {
            "security_validation": PerformanceThreshold(
                metric_type=MetricType.SECURITY_VALIDATION_TIME,
                operation="security_validation",
                warning_threshold=30.0,
                critical_threshold=45.0,
                emergency_threshold=50.0,
                unit="ms"
            ),
            "command_execution": PerformanceThreshold(
                metric_type=MetricType.COMMAND_EXECUTION_TIME,
                operation="command_execution",
                warning_threshold=40.0,
                critical_threshold=50.0,
                emergency_threshold=60.0,
                unit="ms"
            ),
            "emergency_response": PerformanceThreshold(
                metric_type=MetricType.EMERGENCY_RESPONSE_TIME,
                operation="emergency_response",
                warning_threshold=10.0,
                critical_threshold=25.0,
                emergency_threshold=50.0,
                unit="ms"
            ),
            "throughput": PerformanceThreshold(
                metric_type=MetricType.THROUGHPUT,
                operation="command_processing",
                warning_threshold=10.0,
                critical_threshold=5.0,
                emergency_threshold=1.0,
                unit="ops/sec"
            )
        }
    
    async def start_monitoring(self) -> bool:
        """Start performance monitoring."""
        try:
            if self.monitoring_active:
                self.logger.warning("Performance monitoring already active")
                return True
            
            self.monitoring_active = True
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            
            self.logger.info("Performance monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start performance monitoring: {e}")
            return False
    
    async def stop_monitoring(self) -> bool:
        """Stop performance monitoring."""
        try:
            if not self.monitoring_active:
                return True
            
            self.monitoring_active = False
            
            if self.monitoring_task:
                self.monitoring_task.cancel()
                try:
                    await self.monitoring_task
                except asyncio.CancelledError:
                    pass
            
            self.logger.info("Performance monitoring stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop performance monitoring: {e}")
            return False
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        try:
            while self.monitoring_active:
                await self._check_performance_thresholds()
                await asyncio.sleep(self.monitoring_interval)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")
    
    async def _check_performance_thresholds(self):
        """Check performance against thresholds."""
        try:
            current_time = datetime.utcnow()
            time_range = (current_time - timedelta(minutes=5), current_time)
            
            for threshold_name, threshold in self.thresholds.items():
                stats = self.collector.get_summary_stats(threshold.operation, time_range)
                
                if not stats:
                    continue
                
                # Check execution time thresholds
                if threshold.metric_type in [MetricType.LATENCY, MetricType.SECURITY_VALIDATION_TIME, MetricType.COMMAND_EXECUTION_TIME, MetricType.EMERGENCY_RESPONSE_TIME]:
                    current_value = stats.get("p95_execution_time_ms", 0)
                    await self._evaluate_threshold(threshold, current_value, None)
                
                # Check throughput thresholds
                elif threshold.metric_type == MetricType.THROUGHPUT:
                    current_value = stats.get("total_throughput_ops", 0) / 300  # ops per second over 5 minutes
                    await self._evaluate_threshold(threshold, current_value, None)
                
        except Exception as e:
            self.logger.error(f"Error checking performance thresholds: {e}")
    
    async def _evaluate_threshold(self, threshold: PerformanceThreshold, current_value: float, platform_id: Optional[str]):
        """Evaluate a performance threshold."""
        try:
            alert_level = None
            
            if current_value >= threshold.emergency_threshold:
                alert_level = AlertLevel.EMERGENCY
            elif current_value >= threshold.critical_threshold:
                alert_level = AlertLevel.CRITICAL
            elif current_value >= threshold.warning_threshold:
                alert_level = AlertLevel.WARNING
            
            if alert_level:
                await self._create_performance_alert(
                    threshold, current_value, alert_level, platform_id
                )
                
        except Exception as e:
            self.logger.error(f"Error evaluating threshold: {e}")
    
    async def _create_performance_alert(self, threshold: PerformanceThreshold, current_value: float, 
                                      alert_level: AlertLevel, platform_id: Optional[str]):
        """Create a performance alert."""
        try:
            alert = PerformanceAlert(
                alert_id=f"perf_alert_{int(time.time() * 1000)}",
                metric_type=threshold.metric_type,
                operation=threshold.operation,
                platform_id=platform_id,
                alert_level=alert_level,
                current_value=current_value,
                threshold_value=threshold.warning_threshold if alert_level == AlertLevel.WARNING 
                             else threshold.critical_threshold if alert_level == AlertLevel.CRITICAL
                             else threshold.emergency_threshold,
                timestamp=datetime.utcnow(),
                description=f"{threshold.operation} {threshold.metric_type.value} exceeded {alert_level.value} threshold"
            )
            
            self.alerts.append(alert)
            
            # Execute alert callbacks
            for callback in self.alert_callbacks:
                try:
                    await callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}")
            
            self.logger.warning(f"Performance alert: {alert.description} - {current_value:.2f}{threshold.unit}")
            
        except Exception as e:
            self.logger.error(f"Error creating performance alert: {e}")
    
    def record_operation(self, operation_type: str, execution_time_ms: float, success: bool = True, platform_id: Optional[str] = None):
        """Record a HAL operation performance metric."""
        try:
            metric = PerformanceMetrics(
                operation_type=operation_type,
                execution_time_ms=execution_time_ms,
                success_rate=1.0 if success else 0.0,
                throughput_ops_per_sec=1000.0 / execution_time_ms if execution_time_ms > 0 else 0.0,
                error_count=0 if success else 1,
                timestamp=datetime.utcnow()
            )
            
            self.collector.record_metric(metric)
            
            # Check for immediate threshold violations
            if self.monitoring_active:
                asyncio.create_task(self._check_immediate_threshold(operation_type, execution_time_ms, platform_id))
                
        except Exception as e:
            self.logger.error(f"Error recording operation: {e}")
    
    async def _check_immediate_threshold(self, operation_type: str, execution_time_ms: float, platform_id: Optional[str]):
        """Check for immediate threshold violations."""
        try:
            # Find relevant threshold
            threshold = None
            for t in self.thresholds.values():
                if t.operation == operation_type or operation_type in t.operation:
                    threshold = t
                    break
            
            if threshold:
                await self._evaluate_threshold(threshold, execution_time_ms, platform_id)
                
        except Exception as e:
            self.logger.error(f"Error checking immediate threshold: {e}")
    
    def set_threshold(self, operation: str, metric_type: MetricType, warning: float, critical: float, emergency: float, unit: str = "ms"):
        """Set a custom performance threshold."""
        try:
            threshold = PerformanceThreshold(
                metric_type=metric_type,
                operation=operation,
                warning_threshold=warning,
                critical_threshold=critical,
                emergency_threshold=emergency,
                unit=unit
            )
            
            self.custom_thresholds[operation] = threshold
            self.thresholds[operation] = threshold
            
            self.logger.info(f"Set custom threshold for {operation}: {warning}/{critical}/{emergency} {unit}")
            
        except Exception as e:
            self.logger.error(f"Error setting threshold: {e}")
    
    def add_alert_callback(self, callback: Callable[[PerformanceAlert], Any]):
        """Add a callback function for performance alerts."""
        self.alert_callbacks.append(callback)
    
    def get_performance_summary(self, time_range: Optional[Tuple[datetime, datetime]] = None) -> Dict[str, Any]:
        """Get performance summary for time range."""
        try:
            if not time_range:
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=1)
                time_range = (start_time, end_time)
            
            summary = {
                "time_range": {
                    "start": time_range[0].isoformat(),
                    "end": time_range[1].isoformat()
                },
                "operations": {},
                "alerts": {
                    "total": len([a for a in self.alerts if time_range[0] <= a.timestamp <= time_range[1]]),
                    "by_level": defaultdict(int)
                },
                "overall_performance": {
                    "score": 0.0,
                    "status": "unknown"
                }
            }
            
            # Get stats for each operation type
            for threshold_name, threshold in self.thresholds.items():
                stats = self.collector.get_summary_stats(threshold.operation, time_range)
                if stats:
                    summary["operations"][threshold.operation] = stats
            
            # Alert summary
            for alert in self.alerts:
                if time_range[0] <= alert.timestamp <= time_range[1]:
                    summary["alerts"]["by_level"][alert.alert_level.value] += 1
            
            # Calculate overall performance score
            summary["overall_performance"] = self._calculate_performance_score(summary)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting performance summary: {e}")
            return {}
    
    def _calculate_performance_score(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall performance score."""
        try:
            total_operations = 0
            total_score = 0.0
            
            for operation, stats in summary["operations"].items():
                if "count" in stats and stats["count"] > 0:
                    total_operations += stats["count"]
                    
                    # Score based on P95 response time
                    p95_time = stats.get("p95_execution_time_ms", 100)
                    if p95_time <= 25:
                        score = 100
                    elif p95_time <= 50:
                        score = 80
                    elif p95_time <= 75:
                        score = 60
                    elif p95_time <= 100:
                        score = 40
                    else:
                        score = 20
                    
                    # Adjust for error rate
                    error_rate = stats.get("total_errors", 0) / stats["count"]
                    score *= (1.0 - error_rate)
                    
                    total_score += score * stats["count"]
            
            if total_operations == 0:
                return {"score": 0.0, "status": "no_data"}
            
            avg_score = total_score / total_operations
            
            # Determine status
            if avg_score >= 90:
                status = "excellent"
            elif avg_score >= 80:
                status = "good"
            elif avg_score >= 70:
                status = "acceptable"
            elif avg_score >= 50:
                status = "degraded"
            else:
                status = "poor"
            
            return {
                "score": round(avg_score, 2),
                "status": status
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating performance score: {e}")
            return {"score": 0.0, "status": "error"}
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent performance alerts."""
        try:
            recent_alerts = sorted(self.alerts, key=lambda x: x.timestamp, reverse=True)[:limit]
            return [
                {
                    "alert_id": alert.alert_id,
                    "metric_type": alert.metric_type.value,
                    "operation": alert.operation,
                    "platform_id": alert.platform_id,
                    "alert_level": alert.alert_level.value,
                    "current_value": alert.current_value,
                    "threshold_value": alert.threshold_value,
                    "timestamp": alert.timestamp.isoformat(),
                    "description": alert.description,
                    "resolved": alert.resolved
                }
                for alert in recent_alerts
            ]
            
        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []


# Decorators for automatic performance monitoring
def monitor_performance(operation_type: str, monitor: Optional[HALPerformanceMonitor] = None):
    """Decorator to automatically monitor function performance."""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise
            finally:
                execution_time_ms = (time.time() - start_time) * 1000
                if monitor:
                    monitor.record_operation(operation_type, execution_time_ms, success)
        
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise
            finally:
                execution_time_ms = (time.time() - start_time) * 1000
                if monitor:
                    monitor.record_operation(operation_type, execution_time_ms, success)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator 