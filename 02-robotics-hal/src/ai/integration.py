"""
Security Forecasting Integration Module

Integration layer connecting the security forecasting system with existing
ALCUB3 security infrastructure, including audit logging, CISA remediation,
and Byzantine consensus systems.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
import threading
from pathlib import Path

# Import security forecasting components
from .security_forecaster import SecurityForecaster, SecurityEvent, ThreatForecast, SecurityPosture

# Import existing security infrastructure
try:
    from ..shared.audit_logger import AuditLogger
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False

try:
    from ...src.cisa_remediation_engine import CISARemediationEngine
    CISA_AVAILABLE = True
except ImportError:
    CISA_AVAILABLE = False

try:
    from ..swarm.consensus_engine import ConsensusEngine
    CONSENSUS_AVAILABLE = True
except ImportError:
    CONSENSUS_AVAILABLE = False

try:
    from ..shared.classification_monitor import ClassificationMonitor
    CLASSIFICATION_AVAILABLE = True
except ImportError:
    CLASSIFICATION_AVAILABLE = False


@dataclass
class ForecastingAlert:
    """Security forecasting alert."""
    alert_id: str
    timestamp: datetime
    severity: str
    forecast: ThreatForecast
    triggered_by: List[str]
    remediation_suggestions: List[str]
    classification: str


@dataclass
class IntegrationMetrics:
    """Integration performance metrics."""
    total_forecasts: int
    alerts_generated: int
    remediation_actions: int
    consensus_validations: int
    processing_latency_avg: float
    integration_errors: int


class SecurityForecastingIntegration:
    """
    Integration layer for security forecasting system.
    
    Features:
    - Event routing from existing systems
    - Automated alert generation
    - CISA remediation integration
    - Byzantine consensus validation
    - Audit logging integration
    - Classification-aware processing
    """
    
    def __init__(self, 
                 forecaster_config: Optional[Dict[str, Any]] = None,
                 integration_config: Optional[Dict[str, Any]] = None):
        """
        Initialize integration layer.
        
        Args:
            forecaster_config: Configuration for security forecaster
            integration_config: Configuration for integration components
        """
        self.forecaster_config = forecaster_config or {}
        self.integration_config = integration_config or {
            'alert_threshold': 0.7,
            'remediation_threshold': 0.8,
            'consensus_required': True,
            'audit_all_forecasts': True
        }
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize security forecaster
        self.forecaster = SecurityForecaster(self.forecaster_config)
        
        # Initialize integration components
        self.audit_logger = None
        self.cisa_engine = None
        self.consensus_engine = None
        self.classification_monitor = None
        
        # Event routing
        self.event_handlers = {}
        self.alert_callbacks = []
        
        # Metrics tracking
        self.metrics = IntegrationMetrics(
            total_forecasts=0,
            alerts_generated=0,
            remediation_actions=0,
            consensus_validations=0,
            processing_latency_avg=0.0,
            integration_errors=0
        )
        
        # Threading
        self.running = False
        self.background_tasks = []
        
        # Initialize integrations
        self._initialize_integrations()
        
        self.logger.info("Security Forecasting Integration initialized")
    
    def _initialize_integrations(self) -> None:
        """Initialize integration with existing systems."""
        try:
            if AUDIT_AVAILABLE:
                self.audit_logger = AuditLogger()
                self.logger.info("Audit logging integration initialized")
        except Exception as e:
            self.logger.warning(f"Audit integration failed: {e}")
        
        try:
            if CISA_AVAILABLE:
                self.cisa_engine = CISARemediationEngine()
                self.logger.info("CISA remediation integration initialized")
        except Exception as e:
            self.logger.warning(f"CISA integration failed: {e}")
        
        try:
            if CONSENSUS_AVAILABLE:
                self.consensus_engine = ConsensusEngine()
                self.logger.info("Consensus engine integration initialized")
        except Exception as e:
            self.logger.warning(f"Consensus integration failed: {e}")
        
        try:
            if CLASSIFICATION_AVAILABLE:
                self.classification_monitor = ClassificationMonitor()
                self.logger.info("Classification monitoring integration initialized")
        except Exception as e:
            self.logger.warning(f"Classification integration failed: {e}")
    
    async def start(self) -> None:
        """Start the integration layer."""
        if self.running:
            self.logger.warning("Integration already running")
            return
        
        self.running = True
        
        # Start security forecaster
        await self.forecaster.start()
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._forecast_monitoring_loop()),
            asyncio.create_task(self._alert_processing_loop()),
            asyncio.create_task(self._metrics_collection_loop())
        ]
        
        self.logger.info("Security Forecasting Integration started")
    
    async def stop(self) -> None:
        """Stop the integration layer."""
        self.running = False
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        self.background_tasks = []
        
        # Stop security forecaster
        await self.forecaster.stop()
        
        self.logger.info("Security Forecasting Integration stopped")
    
    async def ingest_security_event(self, 
                                   event_data: Dict[str, Any],
                                   source_system: str) -> None:
        """
        Ingest security event from external system.
        
        Args:
            event_data: Raw event data
            source_system: Source system identifier
        """
        try:
            start_time = datetime.now()
            
            # Convert to SecurityEvent
            security_event = self._convert_to_security_event(event_data, source_system)
            
            # Validate classification
            if self.classification_monitor:
                await self._validate_classification(security_event)
            
            # Update forecaster
            await self.forecaster.update_security_event(security_event)
            
            # Log processing
            processing_time = (datetime.now() - start_time).total_seconds()
            self._update_processing_metrics(processing_time)
            
            # Audit log
            if self.audit_logger:
                await self._audit_log_event(security_event, source_system)
            
            self.logger.debug(f"Ingested event from {source_system}: {security_event.event_type}")
            
        except Exception as e:
            self.logger.error(f"Error ingesting event from {source_system}: {e}")
            self.metrics.integration_errors += 1
    
    async def generate_forecast(self, 
                               horizon: timedelta = timedelta(hours=24),
                               classification: Optional[str] = None) -> ThreatForecast:
        """
        Generate security forecast.
        
        Args:
            horizon: Forecast time horizon
            classification: Classification level filter
            
        Returns:
            Generated threat forecast
        """
        try:
            start_time = datetime.now()
            
            # Generate forecast using security forecaster
            forecast = await self.forecaster.forecast_security_posture(
                horizon=horizon,
                classification=classification
            )
            
            # Validate forecast with consensus if required
            if self.integration_config.get('consensus_required') and self.consensus_engine:
                forecast = await self._validate_forecast_consensus(forecast)
            
            # Update metrics
            self.metrics.total_forecasts += 1
            processing_time = (datetime.now() - start_time).total_seconds()
            self._update_processing_metrics(processing_time)
            
            # Audit log forecast
            if self.integration_config.get('audit_all_forecasts') and self.audit_logger:
                await self._audit_log_forecast(forecast)
            
            # Check for alerts
            await self._check_forecast_alerts(forecast)
            
            return forecast
            
        except Exception as e:
            self.logger.error(f"Error generating forecast: {e}")
            self.metrics.integration_errors += 1
            raise
    
    async def trigger_remediation(self, 
                                 alert: ForecastingAlert,
                                 auto_execute: bool = False) -> Dict[str, Any]:
        """
        Trigger CISA remediation based on forecast alert.
        
        Args:
            alert: Forecasting alert
            auto_execute: Whether to auto-execute remediation
            
        Returns:
            Remediation result
        """
        try:
            if not self.cisa_engine:
                return {'error': 'CISA remediation engine not available'}
            
            # Convert alert to CISA remediation request
            remediation_request = {
                'alert_id': alert.alert_id,
                'severity': alert.severity,
                'threat_probability': alert.forecast.threat_probability,
                'predicted_events': alert.forecast.predicted_events,
                'recommendations': alert.remediation_suggestions,
                'classification': alert.classification,
                'auto_execute': auto_execute
            }
            
            # Execute remediation
            result = await self.cisa_engine.execute_remediation(remediation_request)
            
            # Update metrics
            self.metrics.remediation_actions += 1
            
            # Audit log remediation
            if self.audit_logger:
                await self._audit_log_remediation(alert, result)
            
            self.logger.info(f"Triggered remediation for alert {alert.alert_id}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error triggering remediation: {e}")
            self.metrics.integration_errors += 1
            return {'error': str(e)}
    
    def register_alert_callback(self, callback: Callable[[ForecastingAlert], None]) -> None:
        """Register callback for forecast alerts."""
        self.alert_callbacks.append(callback)
    
    def register_event_handler(self, 
                              source_system: str, 
                              handler: Callable[[Dict[str, Any]], None]) -> None:
        """Register event handler for specific source system."""
        self.event_handlers[source_system] = handler
    
    async def get_integration_status(self) -> Dict[str, Any]:
        """Get integration status and metrics."""
        status = {
            'running': self.running,
            'forecaster_status': await self.forecaster.get_system_status(),
            'integration_metrics': asdict(self.metrics),
            'components': {
                'audit_logger': self.audit_logger is not None,
                'cisa_engine': self.cisa_engine is not None,
                'consensus_engine': self.consensus_engine is not None,
                'classification_monitor': self.classification_monitor is not None
            },
            'configuration': self.integration_config.copy()
        }
        
        return status
    
    # Background tasks
    
    async def _forecast_monitoring_loop(self) -> None:
        """Background task for continuous forecast monitoring."""
        while self.running:
            try:
                # Generate periodic forecasts
                forecast = await self.generate_forecast()
                
                # Process forecast
                await self._process_forecast(forecast)
                
                # Wait for next interval
                await asyncio.sleep(300)  # 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in forecast monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait before retry
    
    async def _alert_processing_loop(self) -> None:
        """Background task for processing alerts."""
        while self.running:
            try:
                # Check for pending alerts
                await self._process_pending_alerts()
                
                # Wait for next interval
                await asyncio.sleep(30)  # 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in alert processing loop: {e}")
                await asyncio.sleep(30)
    
    async def _metrics_collection_loop(self) -> None:
        """Background task for metrics collection."""
        while self.running:
            try:
                # Collect and update metrics
                await self._collect_integration_metrics()
                
                # Wait for next interval
                await asyncio.sleep(60)  # 1 minute
                
            except Exception as e:
                self.logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(60)
    
    # Helper methods
    
    def _convert_to_security_event(self, 
                                  event_data: Dict[str, Any], 
                                  source_system: str) -> SecurityEvent:
        """Convert raw event data to SecurityEvent."""
        # Default values
        timestamp = event_data.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_data.get('event_type', 'unknown'),
            severity=event_data.get('severity', 1),
            classification=event_data.get('classification', 'U'),
            source=source_system,
            description=event_data.get('description', ''),
            risk_score=event_data.get('risk_score', 0.0),
            metadata=event_data.get('metadata', {})
        )
    
    async def _validate_classification(self, event: SecurityEvent) -> None:
        """Validate event classification."""
        if self.classification_monitor:
            try:
                validation_result = await self.classification_monitor.validate_event(event)
                if not validation_result.get('valid', True):
                    self.logger.warning(f"Classification validation failed for event {event.event_type}")
            except Exception as e:
                self.logger.error(f"Error validating classification: {e}")
    
    async def _validate_forecast_consensus(self, forecast: ThreatForecast) -> ThreatForecast:
        """Validate forecast using Byzantine consensus."""
        try:
            if self.consensus_engine:
                consensus_result = await self.consensus_engine.validate_prediction({
                    'threat_probability': forecast.threat_probability,
                    'risk_level': forecast.risk_level.value,
                    'predicted_events': forecast.predicted_events
                })
                
                # Update forecast with consensus validation
                if consensus_result.get('consensus_reached'):
                    forecast.confidence_score *= consensus_result.get('agreement_factor', 1.0)
                    self.metrics.consensus_validations += 1
                
                return forecast
        except Exception as e:
            self.logger.error(f"Error in consensus validation: {e}")
        
        return forecast
    
    async def _check_forecast_alerts(self, forecast: ThreatForecast) -> None:
        """Check if forecast should trigger alerts."""
        try:
            alert_threshold = self.integration_config.get('alert_threshold', 0.7)
            
            if forecast.threat_probability >= alert_threshold:
                alert = ForecastingAlert(
                    alert_id=f"FA_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    timestamp=datetime.now(),
                    severity=self._calculate_alert_severity(forecast),
                    forecast=forecast,
                    triggered_by=['threat_probability_threshold'],
                    remediation_suggestions=forecast.recommendations,
                    classification=forecast.classification.value
                )
                
                # Notify callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        self.logger.error(f"Error in alert callback: {e}")
                
                # Check for auto-remediation
                remediation_threshold = self.integration_config.get('remediation_threshold', 0.8)
                if forecast.threat_probability >= remediation_threshold:
                    await self.trigger_remediation(alert, auto_execute=True)
                
                self.metrics.alerts_generated += 1
                
        except Exception as e:
            self.logger.error(f"Error checking forecast alerts: {e}")
    
    def _calculate_alert_severity(self, forecast: ThreatForecast) -> str:
        """Calculate alert severity based on forecast."""
        if forecast.threat_probability >= 0.9:
            return 'critical'
        elif forecast.threat_probability >= 0.7:
            return 'high'
        elif forecast.threat_probability >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    async def _process_forecast(self, forecast: ThreatForecast) -> None:
        """Process generated forecast."""
        try:
            # Additional processing logic can be added here
            self.logger.debug(f"Processed forecast: {forecast.threat_probability:.3f} threat probability")
        except Exception as e:
            self.logger.error(f"Error processing forecast: {e}")
    
    async def _process_pending_alerts(self) -> None:
        """Process any pending alerts."""
        # Placeholder for alert processing logic
        pass
    
    async def _collect_integration_metrics(self) -> None:
        """Collect integration metrics."""
        try:
            # Update average processing latency
            # This would be calculated from actual processing times
            pass
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
    
    def _update_processing_metrics(self, processing_time: float) -> None:
        """Update processing time metrics."""
        current_avg = self.metrics.processing_latency_avg
        if current_avg == 0:
            self.metrics.processing_latency_avg = processing_time
        else:
            # Exponential moving average
            self.metrics.processing_latency_avg = 0.9 * current_avg + 0.1 * processing_time
    
    # Audit logging methods
    
    async def _audit_log_event(self, event: SecurityEvent, source_system: str) -> None:
        """Audit log security event."""
        if self.audit_logger:
            try:
                await self.audit_logger.log({
                    'action': 'security_event_ingested',
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'source_system': source_system,
                    'severity': event.severity,
                    'classification': event.classification.value,
                    'risk_score': event.risk_score
                })
            except Exception as e:
                self.logger.error(f"Error audit logging event: {e}")
    
    async def _audit_log_forecast(self, forecast: ThreatForecast) -> None:
        """Audit log forecast generation."""
        if self.audit_logger:
            try:
                await self.audit_logger.log({
                    'action': 'security_forecast_generated',
                    'timestamp': forecast.timestamp.isoformat(),
                    'threat_probability': forecast.threat_probability,
                    'risk_level': forecast.risk_level.value,
                    'confidence_score': forecast.confidence_score,
                    'classification': forecast.classification.value,
                    'predicted_events_count': len(forecast.predicted_events),
                    'recommendations_count': len(forecast.recommendations)
                })
            except Exception as e:
                self.logger.error(f"Error audit logging forecast: {e}")
    
    async def _audit_log_remediation(self, 
                                   alert: ForecastingAlert, 
                                   result: Dict[str, Any]) -> None:
        """Audit log remediation action."""
        if self.audit_logger:
            try:
                await self.audit_logger.log({
                    'action': 'remediation_triggered',
                    'alert_id': alert.alert_id,
                    'severity': alert.severity,
                    'classification': alert.classification,
                    'remediation_result': result,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                self.logger.error(f"Error audit logging remediation: {e}")


# Integration utilities

class ForecastingAlertManager:
    """Manager for forecasting alerts."""
    
    def __init__(self):
        self.active_alerts = {}
        self.alert_history = []
    
    def add_alert(self, alert: ForecastingAlert) -> None:
        """Add new alert."""
        self.active_alerts[alert.alert_id] = alert
        self.alert_history.append(alert)
    
    def get_active_alerts(self) -> List[ForecastingAlert]:
        """Get list of active alerts."""
        return list(self.active_alerts.values())
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        if alert_id in self.active_alerts:
            del self.active_alerts[alert_id]
            return True
        return False


# Example usage and integration factory

class SecurityForecastingFactory:
    """Factory for creating security forecasting integrations."""
    
    @staticmethod
    def create_default_integration() -> SecurityForecastingIntegration:
        """Create default integration configuration."""
        forecaster_config = {
            'sequence_length': 100,
            'features': 50,
            'collection_interval': 60,
            'risk_model': 'random_forest',
            'anomaly_method': 'ensemble'
        }
        
        integration_config = {
            'alert_threshold': 0.7,
            'remediation_threshold': 0.8,
            'consensus_required': True,
            'audit_all_forecasts': True
        }
        
        return SecurityForecastingIntegration(forecaster_config, integration_config)
    
    @staticmethod
    def create_high_security_integration() -> SecurityForecastingIntegration:
        """Create high-security integration for classified environments."""
        forecaster_config = {
            'sequence_length': 200,
            'features': 100,
            'collection_interval': 30,
            'risk_model': 'ensemble',
            'anomaly_method': 'ensemble'
        }
        
        integration_config = {
            'alert_threshold': 0.5,  # Lower threshold for higher sensitivity
            'remediation_threshold': 0.6,
            'consensus_required': True,
            'audit_all_forecasts': True
        }
        
        return SecurityForecastingIntegration(forecaster_config, integration_config)


# Demo and testing

async def demo_integration():
    """Demonstrate security forecasting integration."""
    print("Security Forecasting Integration Demo")
    print("=" * 50)
    
    # Create integration
    integration = SecurityForecastingFactory.create_default_integration()
    
    # Register alert callback
    def alert_handler(alert: ForecastingAlert):
        print(f"🚨 ALERT: {alert.severity.upper()} - {alert.alert_id}")
        print(f"   Threat Probability: {alert.forecast.threat_probability:.3f}")
        print(f"   Classification: {alert.classification}")
    
    integration.register_alert_callback(alert_handler)
    
    try:
        # Start integration
        await integration.start()
        print("✓ Integration started")
        
        # Simulate security events
        sample_events = [
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'authentication_failure',
                'severity': 3,
                'classification': 'S',
                'risk_score': 0.6,
                'metadata': {'user': 'test_user'}
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'anomalous_behavior',
                'severity': 4,
                'classification': 'TS',
                'risk_score': 0.8,
                'metadata': {'pattern': 'unusual_access'}
            }
        ]
        
        # Ingest events
        for i, event in enumerate(sample_events):
            await integration.ingest_security_event(event, f"test_system_{i}")
            print(f"✓ Ingested event: {event['event_type']}")
        
        # Generate forecast
        forecast = await integration.generate_forecast(horizon=timedelta(hours=24))
        print(f"✓ Generated forecast: {forecast.threat_probability:.3f} threat probability")
        
        # Get status
        status = await integration.get_integration_status()
        print(f"✓ Integration status: {status['running']}")
        print(f"   Total forecasts: {status['integration_metrics']['total_forecasts']}")
        print(f"   Alerts generated: {status['integration_metrics']['alerts_generated']}")
        
        # Wait a bit to see background processing
        await asyncio.sleep(5)
        
    except Exception as e:
        print(f"✗ Demo error: {e}")
    
    finally:
        # Stop integration
        await integration.stop()
        print("✓ Integration stopped")


if __name__ == "__main__":
    asyncio.run(demo_integration()) 