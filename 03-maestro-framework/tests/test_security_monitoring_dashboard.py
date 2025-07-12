#!/usr/bin/env python3
"""
Test Suite for ALCUB3 Security Monitoring Dashboard - Task 2.15
Comprehensive validation of real-time security monitoring capabilities

This test suite validates:
- Real-time security event processing (<30 second anomaly detection)
- Automated incident response and escalation
- Performance targets (<100ms query response)
- Cross-layer security correlation
- Classification-aware security handling
- Patent-defensible monitoring innovations
"""

import pytest
import asyncio
import time
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import List, Dict, Any

# Import the security monitoring dashboard
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from l3_agent.security_monitoring_dashboard import (
    SecurityMonitoringDashboard,
    SecurityEvent,
    SecurityIncident,
    SecurityEventType,
    SeverityLevel,
    IncidentStatus,
    ClassificationLevel,
    SecurityCorrelationEngine,
    IncidentResponseEngine
)

class TestSecurityMonitoringDashboard:
    """Test suite for Security Monitoring Dashboard."""
    
    @pytest.fixture
    async def dashboard(self):
        """Create dashboard instance for testing."""
        dashboard = SecurityMonitoringDashboard()
        yield dashboard
        if dashboard.is_running:
            await dashboard.stop_monitoring()
    
    @pytest.fixture
    def sample_security_event(self):
        """Create sample security event for testing."""
        return SecurityEvent(
            event_id="test_001",
            event_type=SecurityEventType.PROMPT_INJECTION,
            severity=SeverityLevel.HIGH,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            timestamp=datetime.utcnow(),
            source_component="test_component",
            source_layer="l1_foundation",
            description="Test security event",
            details={"test_key": "test_value"},
            indicators=[],
            affected_systems=["test_system"]
        )
    
    @pytest.fixture
    def sample_critical_event(self):
        """Create sample critical security event."""
        return SecurityEvent(
            event_id="crit_001",
            event_type=SecurityEventType.SYSTEM_COMPROMISE,
            severity=SeverityLevel.CRITICAL,
            classification_level=ClassificationLevel.SECRET,
            timestamp=datetime.utcnow(),
            source_component="security_monitor",
            source_layer="l3_agent",
            description="Critical system compromise detected",
            details={"attack_vector": "unknown", "affected_data": "classified"},
            indicators=[],
            affected_systems=["core_system", "data_store"]
        )
    
    def test_dashboard_initialization(self, dashboard):
        """Test dashboard proper initialization."""
        assert dashboard is not None
        assert dashboard.is_running is False
        assert dashboard.events is not None
        assert dashboard.active_incidents == {}
        assert dashboard.metrics is not None
        assert dashboard.correlation_engine is not None
        assert dashboard.incident_response is not None
        assert dashboard.logger is not None
    
    def test_configuration_loading(self):
        """Test configuration loading and defaults."""
        dashboard = SecurityMonitoringDashboard()
        
        # Verify default configuration
        assert "monitoring" in dashboard.config
        assert "alerts" in dashboard.config
        assert "security" in dashboard.config
        assert "performance" in dashboard.config
        
        # Verify specific defaults
        assert dashboard.config["monitoring"]["event_buffer_size"] == 50000
        assert dashboard.config["performance"]["max_query_time_ms"] == 100
        assert dashboard.config["security"]["classification_enforcement"] is True
    
    @pytest.mark.asyncio
    async def test_event_addition(self, dashboard, sample_security_event):
        """Test adding security events to dashboard."""
        initial_count = dashboard.metrics.total_events
        
        await dashboard.add_security_event(sample_security_event)
        
        # Verify event was added
        assert dashboard.metrics.total_events == initial_count + 1
        assert len(dashboard.events) == 1
        assert dashboard.events[0].event_id == "test_001"
        
        # Verify metrics updated
        assert dashboard.metrics.events_by_severity[SeverityLevel.HIGH.value] == 1
        assert dashboard.metrics.events_by_type[SecurityEventType.PROMPT_INJECTION.value] == 1
        assert dashboard.metrics.events_by_layer["l1_foundation"] == 1
    
    @pytest.mark.asyncio
    async def test_critical_event_handling(self, dashboard, sample_critical_event):
        """Test handling of critical security events."""
        await dashboard.add_security_event(sample_critical_event)
        
        # Verify critical event metrics
        assert dashboard.metrics.events_by_severity[SeverityLevel.CRITICAL.value] == 1
        assert dashboard.metrics.events_by_type[SecurityEventType.SYSTEM_COMPROMISE.value] == 1
        
        # Verify event classification handling
        assert sample_critical_event.classification_level == ClassificationLevel.SECRET
    
    @pytest.mark.asyncio
    async def test_performance_metrics_tracking(self, dashboard, sample_security_event):
        """Test performance metrics tracking."""
        # Add multiple events and measure performance
        start_time = time.time()
        
        for i in range(10):
            event = SecurityEvent(
                event_id=f"perf_test_{i}",
                event_type=SecurityEventType.THREAT_DETECTED,
                severity=SeverityLevel.MEDIUM,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow(),
                source_component="test_component",
                source_layer="l2_data",
                description=f"Performance test event {i}",
                details={},
                indicators=[],
                affected_systems=["test_system"]
            )
            await dashboard.add_security_event(event)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Verify performance targets
        assert processing_time < 500  # Should process 10 events in under 500ms
        assert len(dashboard.performance_metrics["event_processing_times"]) > 0
        
        # Test query performance
        start_time = time.time()
        metrics = await dashboard.get_security_metrics()
        query_time = (time.time() - start_time) * 1000
        
        assert query_time < 100  # Target: <100ms query response
        assert metrics is not None
        assert "total_events" in metrics
    
    @pytest.mark.asyncio
    async def test_security_metrics_retrieval(self, dashboard, sample_security_event):
        """Test security metrics retrieval."""
        # Add some events
        await dashboard.add_security_event(sample_security_event)
        
        metrics = await dashboard.get_security_metrics()
        
        # Verify metrics structure
        assert "total_events" in metrics
        assert "events_by_severity" in metrics
        assert "events_by_type" in metrics
        assert "events_by_layer" in metrics
        assert "active_incidents" in metrics
        assert "threat_detection_rate" in metrics
        assert "system_availability" in metrics
        assert "compliance_score" in metrics
        assert "last_updated" in metrics
        
        # Verify metrics values
        assert metrics["total_events"] == 1
        assert metrics["events_by_severity"][SeverityLevel.HIGH.value] == 1
    
    @pytest.mark.asyncio
    async def test_recent_events_filtering(self, dashboard):
        """Test recent events retrieval with filtering."""
        # Create events with different severities and types
        events = [
            SecurityEvent(
                event_id=f"filter_test_{i}",
                event_type=SecurityEventType.PROMPT_INJECTION if i % 2 == 0 else SecurityEventType.THREAT_DETECTED,
                severity=SeverityLevel.HIGH if i % 3 == 0 else SeverityLevel.MEDIUM,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow(),
                source_component="test_component",
                source_layer="l1_foundation",
                description=f"Filter test event {i}",
                details={},
                indicators=[],
                affected_systems=["test_system"]
            )
            for i in range(10)
        ]
        
        for event in events:
            await dashboard.add_security_event(event)
        
        # Test unfiltered retrieval
        all_events = await dashboard.get_recent_events(limit=20)
        assert len(all_events) == 10
        
        # Test severity filtering
        high_severity_events = await dashboard.get_recent_events(
            limit=20, 
            severity_filter=SeverityLevel.HIGH
        )
        expected_high_count = len([e for e in events if e.severity == SeverityLevel.HIGH])
        assert len(high_severity_events) == expected_high_count
        
        # Test event type filtering
        injection_events = await dashboard.get_recent_events(
            limit=20,
            event_type_filter=SecurityEventType.PROMPT_INJECTION
        )
        expected_injection_count = len([e for e in events if e.event_type == SecurityEventType.PROMPT_INJECTION])
        assert len(injection_events) == expected_injection_count
        
        # Test limit
        limited_events = await dashboard.get_recent_events(limit=5)
        assert len(limited_events) == 5
    
    @pytest.mark.asyncio
    async def test_threat_intelligence_generation(self, dashboard):
        """Test threat intelligence summary generation."""
        # Create various threat events
        threat_events = [
            SecurityEvent(
                event_id=f"threat_{i}",
                event_type=SecurityEventType.THREAT_DETECTED,
                severity=SeverityLevel.HIGH,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow(),
                source_component="threat_detector",
                source_layer="l1_foundation",
                description=f"Threat event {i}",
                details={},
                indicators=[],
                affected_systems=[f"system_{i % 3}"]
            )
            for i in range(5)
        ]
        
        for event in threat_events:
            await dashboard.add_security_event(event)
        
        threat_intel = await dashboard.get_threat_intelligence()
        
        # Verify threat intelligence structure
        assert "total_threats_24h" in threat_intel
        assert "threat_types" in threat_intel
        assert "severity_distribution" in threat_intel
        assert "affected_systems" in threat_intel
        assert "threat_trends" in threat_intel
        
        # Verify content
        assert threat_intel["total_threats_24h"] == 5
        assert SecurityEventType.THREAT_DETECTED.value in threat_intel["threat_types"]
        assert SeverityLevel.HIGH.value in threat_intel["severity_distribution"]
        assert len(threat_intel["affected_systems"]) == 3  # system_0, system_1, system_2
    
    @pytest.mark.asyncio
    async def test_security_report_export(self, dashboard, sample_security_event):
        """Test security report generation and export."""
        # Add test events
        await dashboard.add_security_event(sample_security_event)
        
        report = await dashboard.export_security_report(format_type="json", timeframe_hours=24)
        
        # Verify report structure
        assert "report_metadata" in report
        assert "executive_summary" in report
        assert "detailed_metrics" in report
        assert "incident_summary" in report
        assert "threat_intelligence" in report
        assert "performance_metrics" in report
        
        # Verify metadata
        metadata = report["report_metadata"]
        assert "generated_at" in metadata
        assert "timeframe_hours" in metadata
        assert "format" in metadata
        assert "total_events" in metadata
        
        assert metadata["timeframe_hours"] == 24
        assert metadata["format"] == "json"
        assert metadata["total_events"] == 1

class TestSecurityCorrelationEngine:
    """Test suite for Security Correlation Engine."""
    
    @pytest.fixture
    def correlation_engine(self):
        """Create correlation engine for testing."""
        return SecurityCorrelationEngine(correlation_window=300)
    
    def test_correlation_engine_initialization(self, correlation_engine):
        """Test correlation engine initialization."""
        assert correlation_engine is not None
        assert correlation_engine.correlation_window == 300
        assert correlation_engine.event_buffer is not None
        assert correlation_engine.correlation_rules is not None
        assert len(correlation_engine.correlation_rules) > 0
    
    def test_correlation_rules_loading(self, correlation_engine):
        """Test correlation rules are properly loaded."""
        rules = correlation_engine.correlation_rules
        
        # Verify expected rules exist
        assert "authentication_failures" in rules
        assert "prompt_injection_patterns" in rules
        assert "classification_violations" in rules
        assert "cross_layer_attacks" in rules
        
        # Verify rule structure
        auth_rule = rules["authentication_failures"]
        assert "threshold" in auth_rule
        assert "window" in auth_rule
        assert "severity" in auth_rule
        assert "actions" in auth_rule
    
    def test_authentication_failure_correlation(self, correlation_engine):
        """Test authentication failure pattern detection."""
        # Create multiple authentication failure events
        auth_events = []
        current_time = datetime.utcnow()
        
        for i in range(6):  # Above threshold of 5
            event = SecurityEvent(
                event_id=f"auth_fail_{i}",
                event_type=SecurityEventType.AUTHENTICATION_FAILURE,
                severity=SeverityLevel.MEDIUM,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=current_time - timedelta(seconds=30),  # Within 60-second window
                source_component="auth_system",
                source_layer="l2_data",
                description=f"Authentication failure {i}",
                details={"source_ip": "192.168.1.100"},
                indicators=[],
                affected_systems=["auth_server"]
            )
            auth_events.append(event)
        
        correlations = correlation_engine.correlate_events(auth_events)
        
        # Should detect authentication attack pattern
        assert len(correlations) > 0
        correlation = correlations[0]
        assert correlation["type"] == "authentication_attack"
        assert correlation["severity"] == SeverityLevel.HIGH
        assert len(correlation["events"]) == 6
        assert "block_source" in correlation["actions"]
    
    def test_prompt_injection_correlation(self, correlation_engine):
        """Test prompt injection pattern detection."""
        # Create multiple prompt injection events
        injection_events = []
        current_time = datetime.utcnow()
        
        for i in range(4):  # Above threshold of 3
            event = SecurityEvent(
                event_id=f"injection_{i}",
                event_type=SecurityEventType.PROMPT_INJECTION,
                severity=SeverityLevel.HIGH,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=current_time - timedelta(seconds=15),  # Within 30-second window
                source_component="model_security",
                source_layer="l1_foundation",
                description=f"Prompt injection attempt {i}",
                details={"injection_type": "role_confusion"},
                indicators=[],
                affected_systems=["ai_model"]
            )
            injection_events.append(event)
        
        correlations = correlation_engine.correlate_events(injection_events)
        
        # Should detect prompt injection attack pattern
        assert len(correlations) > 0
        correlation = correlations[0]
        assert correlation["type"] == "prompt_injection_attack"
        assert correlation["severity"] == SeverityLevel.CRITICAL
        assert len(correlation["events"]) == 4
        assert "isolate_session" in correlation["actions"]
    
    def test_cross_layer_attack_correlation(self, correlation_engine):
        """Test cross-layer attack pattern detection."""
        # Create events across multiple MAESTRO layers
        cross_layer_events = [
            SecurityEvent(
                event_id="l1_attack",
                event_type=SecurityEventType.ADVERSARIAL_INPUT,
                severity=SeverityLevel.HIGH,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow() - timedelta(seconds=60),
                source_component="model_security",
                source_layer="l1_foundation",
                description="L1 adversarial attack",
                details={},
                indicators=[],
                affected_systems=["ai_model"]
            ),
            SecurityEvent(
                event_id="l2_attack",
                event_type=SecurityEventType.CLASSIFICATION_VIOLATION,
                severity=SeverityLevel.CRITICAL,
                classification_level=ClassificationLevel.SECRET,
                timestamp=datetime.utcnow() - timedelta(seconds=45),
                source_component="data_operations",
                source_layer="l2_data",
                description="L2 classification breach",
                details={},
                indicators=[],
                affected_systems=["data_store"]
            ),
            SecurityEvent(
                event_id="l3_attack",
                event_type=SecurityEventType.SANDBOX_BREACH,
                severity=SeverityLevel.CRITICAL,
                classification_level=ClassificationLevel.TOP_SECRET,
                timestamp=datetime.utcnow() - timedelta(seconds=30),
                source_component="agent_sandboxing",
                source_layer="l3_agent",
                description="L3 sandbox compromise",
                details={},
                indicators=[],
                affected_systems=["agent_sandbox"]
            )
        ]
        
        correlations = correlation_engine.correlate_events(cross_layer_events)
        
        # Should detect cross-layer attack pattern
        assert len(correlations) > 0
        correlation = correlations[0]
        assert correlation["type"] == "cross_layer_attack"
        assert correlation["severity"] == SeverityLevel.CRITICAL
        assert len(correlation["events"]) == 3
        assert "system_lockdown" in correlation["actions"]

class TestIncidentResponseEngine:
    """Test suite for Incident Response Engine."""
    
    @pytest.fixture
    def dashboard_mock(self):
        """Create mock dashboard for testing."""
        dashboard = Mock()
        dashboard.logger = Mock()
        return dashboard
    
    @pytest.fixture
    def incident_response(self, dashboard_mock):
        """Create incident response engine for testing."""
        return IncidentResponseEngine(dashboard_mock)
    
    @pytest.fixture
    def sample_incident(self, sample_security_event):
        """Create sample incident for testing."""
        return SecurityIncident(
            incident_id="inc_test_001",
            title="Test Security Incident",
            status=IncidentStatus.ACTIVE,
            severity=SeverityLevel.HIGH,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            assigned_to="security_team",
            events=[sample_security_event],
            timeline=[],
            containment_actions=["alert_security_team", "audit_access"]
        )
    
    def test_incident_response_initialization(self, incident_response):
        """Test incident response engine initialization."""
        assert incident_response is not None
        assert incident_response.response_actions is not None
        assert incident_response.escalation_rules is not None
        
        # Verify expected response actions
        expected_actions = [
            "block_source", "alert_security_team", "isolate_session",
            "emergency_alert", "audit_access", "escalate_to_admin",
            "system_lockdown", "incident_response"
        ]
        
        for action in expected_actions:
            assert action in incident_response.response_actions
    
    def test_escalation_rules_loading(self, incident_response):
        """Test escalation rules are properly loaded."""
        rules = incident_response.escalation_rules
        
        # Verify all severity levels have rules
        assert SeverityLevel.CRITICAL in rules
        assert SeverityLevel.HIGH in rules
        assert SeverityLevel.MEDIUM in rules
        assert SeverityLevel.LOW in rules
        
        # Verify rule structure
        critical_rule = rules[SeverityLevel.CRITICAL]
        assert "response_time" in critical_rule
        assert "escalation_chain" in critical_rule
        assert "actions" in critical_rule
        
        # Verify critical incidents have fastest response time
        assert critical_rule["response_time"] == 60  # 1 minute
    
    @pytest.mark.asyncio
    async def test_incident_response_execution(self, incident_response, sample_incident):
        """Test automated incident response execution."""
        # Mock the action execution
        with patch.object(incident_response, '_execute_action', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = {"action": "test_action", "status": "completed"}
            
            with patch.object(incident_response, '_handle_escalation', new_callable=AsyncMock) as mock_escalate:
                mock_escalate.return_value = {"escalation_status": "completed"}
                
                response_log = await incident_response.respond_to_incident(sample_incident)
                
                # Verify response log structure
                assert "incident_id" in response_log
                assert "response_timestamp" in response_log
                assert "actions_taken" in response_log
                assert "escalations" in response_log
                assert "status" in response_log
                
                assert response_log["incident_id"] == sample_incident.incident_id
                assert response_log["status"] == "completed"
    
    @pytest.mark.asyncio
    async def test_notification_sending(self, incident_response, sample_incident):
        """Test incident notification system."""
        notification_result = await incident_response._send_notification(sample_incident, "security_manager")
        
        # Verify notification structure
        assert "recipient" in notification_result
        assert "incident_id" in notification_result
        assert "severity" in notification_result
        assert "classification" in notification_result
        assert "summary" in notification_result
        assert "timestamp" in notification_result
        assert "status" in notification_result
        
        assert notification_result["recipient"] == "security_manager"
        assert notification_result["incident_id"] == sample_incident.incident_id
        assert notification_result["status"] == "sent"

class TestPerformanceTargets:
    """Test suite for performance target validation."""
    
    @pytest.mark.asyncio
    async def test_anomaly_detection_performance(self):
        """Test anomaly detection meets <30 second target."""
        dashboard = SecurityMonitoringDashboard()
        
        # Create test event
        test_event = SecurityEvent(
            event_id="perf_anomaly_test",
            event_type=SecurityEventType.THREAT_DETECTED,
            severity=SeverityLevel.HIGH,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            timestamp=datetime.utcnow(),
            source_component="test_component",
            source_layer="l1_foundation",
            description="Performance test event",
            details={},
            indicators=[],
            affected_systems=["test_system"]
        )
        
        # Measure anomaly detection time
        start_time = time.time()
        anomaly_detected = await dashboard._detect_anomalies(test_event)
        detection_time = (time.time() - start_time) * 1000
        
        # Verify performance target
        assert detection_time < 30000  # <30 seconds (30,000ms)
        assert isinstance(anomaly_detected, bool)
    
    @pytest.mark.asyncio
    async def test_query_response_performance(self):
        """Test query response meets <100ms target."""
        dashboard = SecurityMonitoringDashboard()
        
        # Add some test data
        for i in range(100):
            event = SecurityEvent(
                event_id=f"query_perf_test_{i}",
                event_type=SecurityEventType.THREAT_DETECTED,
                severity=SeverityLevel.MEDIUM,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow(),
                source_component="test_component",
                source_layer="l1_foundation",
                description=f"Query performance test event {i}",
                details={},
                indicators=[],
                affected_systems=["test_system"]
            )
            await dashboard.add_security_event(event)
        
        # Test various query operations
        queries = [
            lambda: dashboard.get_security_metrics(),
            lambda: dashboard.get_recent_events(limit=50),
            lambda: dashboard.get_threat_intelligence(),
            lambda: dashboard.get_active_incidents()
        ]
        
        for query_func in queries:
            start_time = time.time()
            result = await query_func()
            query_time = (time.time() - start_time) * 1000
            
            # Verify performance target
            assert query_time < 100  # <100ms target
            assert result is not None
    
    @pytest.mark.asyncio 
    async def test_event_processing_performance(self):
        """Test event processing performance targets."""
        dashboard = SecurityMonitoringDashboard()
        
        # Process batch of events and measure performance
        events = []
        for i in range(50):
            event = SecurityEvent(
                event_id=f"batch_test_{i}",
                event_type=SecurityEventType.THREAT_DETECTED,
                severity=SeverityLevel.MEDIUM,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow(),
                source_component="test_component",
                source_layer="l1_foundation",
                description=f"Batch processing test event {i}",
                details={},
                indicators=[],
                affected_systems=["test_system"]
            )
            events.append(event)
        
        # Measure batch processing time
        start_time = time.time()
        
        for event in events:
            await dashboard.add_security_event(event)
        
        processing_time = (time.time() - start_time) * 1000
        average_time_per_event = processing_time / len(events)
        
        # Verify performance targets
        assert processing_time < 5000  # Process 50 events in under 5 seconds
        assert average_time_per_event < 50  # <50ms per event target

# Integration tests
class TestSecurityMonitoringIntegration:
    """Integration tests for complete security monitoring workflow."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_workflow(self):
        """Test complete security monitoring workflow."""
        dashboard = SecurityMonitoringDashboard()
        
        try:
            # Start monitoring
            monitoring_task = asyncio.create_task(dashboard.start_monitoring())
            
            # Wait for initialization
            await asyncio.sleep(1)
            
            # Create simulated attack scenario
            attack_events = []
            
            # Phase 1: Initial reconnaissance
            recon_event = SecurityEvent(
                event_id="attack_phase_1",
                event_type=SecurityEventType.NETWORK_INTRUSION,
                severity=SeverityLevel.MEDIUM,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow(),
                source_component="network_monitor",
                source_layer="l2_data",
                description="Suspicious network scanning detected",
                details={"source_ip": "192.168.1.100", "scan_type": "port_scan"},
                indicators=[],
                affected_systems=["network_perimeter"]
            )
            attack_events.append(recon_event)
            
            # Phase 2: Authentication attacks
            for i in range(6):  # Trigger authentication failure correlation
                auth_event = SecurityEvent(
                    event_id=f"attack_phase_2_{i}",
                    event_type=SecurityEventType.AUTHENTICATION_FAILURE,
                    severity=SeverityLevel.HIGH,
                    classification_level=ClassificationLevel.UNCLASSIFIED,
                    timestamp=datetime.utcnow(),
                    source_component="auth_system",
                    source_layer="l2_data",
                    description=f"Authentication failure attempt {i}",
                    details={"source_ip": "192.168.1.100", "username": f"user_{i}"},
                    indicators=[],
                    affected_systems=["auth_server"]
                )
                attack_events.append(auth_event)
            
            # Phase 3: AI model attacks
            for i in range(4):  # Trigger prompt injection correlation
                injection_event = SecurityEvent(
                    event_id=f"attack_phase_3_{i}",
                    event_type=SecurityEventType.PROMPT_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    classification_level=ClassificationLevel.SECRET,
                    timestamp=datetime.utcnow(),
                    source_component="model_security",
                    source_layer="l1_foundation",
                    description=f"Advanced prompt injection attempt {i}",
                    details={"injection_type": "jailbreak", "payload_size": 1024},
                    indicators=[],
                    affected_systems=["ai_model", "data_store"]
                )
                attack_events.append(injection_event)
            
            # Add all attack events to dashboard
            for event in attack_events:
                await dashboard.add_security_event(event)
                await asyncio.sleep(0.1)  # Small delay to simulate real-time
            
            # Wait for correlation and incident creation
            await asyncio.sleep(2)
            
            # Verify dashboard state
            metrics = await dashboard.get_security_metrics()
            incidents = await dashboard.get_active_incidents()
            threat_intel = await dashboard.get_threat_intelligence()
            
            # Verify attack was detected and correlated
            assert metrics["total_events"] >= len(attack_events)
            assert len(incidents) > 0  # Should have created incidents from correlations
            assert threat_intel["total_threats_24h"] > 0
            
            # Verify incident severity and classification
            critical_incidents = [
                incident for incident in incidents
                if incident["severity"] == SeverityLevel.CRITICAL.value
            ]
            assert len(critical_incidents) > 0
            
            # Verify performance during attack
            if dashboard.performance_metrics["event_processing_times"]:
                avg_processing_time = sum(dashboard.performance_metrics["event_processing_times"]) / len(dashboard.performance_metrics["event_processing_times"])
                assert avg_processing_time < 100  # Maintain performance during attack
            
            # Generate security report
            report = await dashboard.export_security_report(timeframe_hours=1)
            assert report["executive_summary"]["critical_events"] > 0
            
        finally:
            # Clean up
            await dashboard.stop_monitoring()
    
    @pytest.mark.asyncio
    async def test_classification_aware_security_handling(self):
        """Test classification-aware security event handling."""
        dashboard = SecurityMonitoringDashboard()
        
        # Create events with different classification levels
        classification_events = [
            SecurityEvent(
                event_id="unclass_event",
                event_type=SecurityEventType.THREAT_DETECTED,
                severity=SeverityLevel.MEDIUM,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                timestamp=datetime.utcnow(),
                source_component="test_component",
                source_layer="l1_foundation",
                description="Unclassified threat event",
                details={},
                indicators=[],
                affected_systems=["public_system"]
            ),
            SecurityEvent(
                event_id="secret_event",
                event_type=SecurityEventType.CLASSIFICATION_VIOLATION,
                severity=SeverityLevel.CRITICAL,
                classification_level=ClassificationLevel.SECRET,
                timestamp=datetime.utcnow(),
                source_component="classification_engine",
                source_layer="l2_data",
                description="Secret classification violation",
                details={"violation_type": "unauthorized_access"},
                indicators=[],
                affected_systems=["classified_system"]
            ),
            SecurityEvent(
                event_id="topsecret_event",
                event_type=SecurityEventType.SYSTEM_COMPROMISE,
                severity=SeverityLevel.CRITICAL,
                classification_level=ClassificationLevel.TOP_SECRET,
                timestamp=datetime.utcnow(),
                source_component="security_monitor",
                source_layer="l3_agent",
                description="Top Secret system compromise",
                details={"compromise_level": "full_system"},
                indicators=[],
                affected_systems=["topsecret_system"]
            )
        ]
        
        # Add events to dashboard
        for event in classification_events:
            await dashboard.add_security_event(event)
        
        # Verify classification handling
        metrics = await dashboard.get_security_metrics()
        recent_events = await dashboard.get_recent_events(limit=10)
        
        # Verify all classification levels are tracked
        assert len(recent_events) == 3
        
        # Verify highest classification events are handled appropriately
        topsecret_events = [
            event for event in recent_events
            if event["classification_level"] == ClassificationLevel.TOP_SECRET.value
        ]
        assert len(topsecret_events) == 1
        
        # Verify classification-aware metrics
        assert metrics["total_events"] == 3

# Test runner
if __name__ == "__main__":
    # Run specific test categories
    import subprocess
    import sys
    
    print("🧪 Running ALCUB3 Security Monitoring Dashboard Tests...")
    
    # Run all tests with coverage
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        __file__, 
        "-v", 
        "--tb=short",
        "--durations=10"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    exit(result.returncode)