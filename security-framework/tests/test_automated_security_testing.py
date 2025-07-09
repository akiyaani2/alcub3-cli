#!/usr/bin/env python3
"""
Tests for ALCUB3 Automated Security Testing Infrastructure
Validates automated test orchestration, scheduling, and reporting capabilities.
"""

import pytest
import asyncio
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from automated_security_testing import (
    AutomatedSecurityTestingOrchestrator,
    SecurityTest,
    TestExecution,
    SecurityMetrics,
    TestCategory,
    TestPriority,
    TestStatus
)
from shared.classification import ClassificationLevel

class TestAutomatedSecurityTestingOrchestrator:
    """Test the automated security testing orchestrator."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create test orchestrator instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.yaml"
            orchestrator = AutomatedSecurityTestingOrchestrator(str(config_path))
            yield orchestrator
            orchestrator.stop()
    
    @pytest.fixture
    def mock_test(self):
        """Create a mock security test."""
        async def mock_test_function(test, params):
            await asyncio.sleep(0.1)
            return {
                'vulnerabilities': [
                    {'severity': 'high', 'description': 'Test vulnerability'}
                ],
                'scan_coverage': 0.95
            }
        
        return SecurityTest(
            test_id="test_mock",
            name="Mock Security Test",
            category=TestCategory.VULNERABILITY_SCAN,
            priority=TestPriority.HIGH,
            target_components=["test_component"],
            classification_levels=[ClassificationLevel.SECRET],
            test_function=mock_test_function,
            parameters={'test_param': 'value'},
            schedule="0 * * * *",
            timeout=60,
            success_criteria={'max_high_vulns': 2},
            created_at=datetime.utcnow(),
            last_run=None,
            next_run=None
        )
    
    def test_orchestrator_initialization(self, orchestrator):
        """Test orchestrator initialization."""
        assert orchestrator is not None
        assert len(orchestrator.test_registry) > 0
        assert orchestrator.metrics.total_tests_run == 0
        assert orchestrator.metrics.security_score == 100.0
        assert not orchestrator.is_running
    
    def test_test_registration(self, orchestrator, mock_test):
        """Test security test registration."""
        initial_count = len(orchestrator.test_registry)
        
        orchestrator.register_test(mock_test)
        
        assert len(orchestrator.test_registry) == initial_count + 1
        assert mock_test.test_id in orchestrator.test_registry
        assert orchestrator.test_registry[mock_test.test_id] == mock_test
    
    @pytest.mark.asyncio
    async def test_test_execution(self, orchestrator, mock_test):
        """Test individual test execution."""
        orchestrator.register_test(mock_test)
        
        # Execute test
        execution = await orchestrator.execute_test(mock_test)
        
        assert execution is not None
        assert execution.test_id == mock_test.test_id
        assert execution.status == TestStatus.COMPLETED
        assert execution.vulnerabilities_found == 1
        assert execution.severity_breakdown['high'] == 1
        assert execution.duration > 0
        assert len(execution.logs) > 0
    
    @pytest.mark.asyncio
    async def test_test_timeout(self, orchestrator):
        """Test that tests timeout correctly."""
        async def slow_test_function(test, params):
            await asyncio.sleep(10)  # Longer than timeout
            return {}
        
        timeout_test = SecurityTest(
            test_id="test_timeout",
            name="Timeout Test",
            category=TestCategory.VULNERABILITY_SCAN,
            priority=TestPriority.LOW,
            target_components=["test"],
            classification_levels=[ClassificationLevel.UNCLASSIFIED],
            test_function=slow_test_function,
            parameters={},
            schedule=None,
            timeout=1,  # 1 second timeout
            success_criteria={},
            created_at=datetime.utcnow(),
            last_run=None,
            next_run=None
        )
        
        orchestrator.register_test(timeout_test)
        execution = await orchestrator.execute_test(timeout_test)
        
        assert execution.status == TestStatus.FAILED
        assert "timed out" in execution.logs[-1]
    
    def test_test_queueing(self, orchestrator, mock_test):
        """Test test queueing functionality."""
        orchestrator.register_test(mock_test)
        
        # Queue test
        orchestrator.queue_test(mock_test.test_id, TestPriority.CRITICAL)
        
        assert len(orchestrator.test_queue) == 1
        queued_test = orchestrator.test_queue[0]
        assert queued_test.test_id == mock_test.test_id
        assert queued_test.priority == TestPriority.CRITICAL
    
    def test_metrics_update(self, orchestrator):
        """Test metrics update after test execution."""
        # Create mock execution
        execution = TestExecution(
            execution_id="exec_test",
            test_id="test_id",
            status=TestStatus.COMPLETED,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            duration=10.5,
            results={},
            vulnerabilities_found=5,
            severity_breakdown={
                'critical': 1,
                'high': 2,
                'medium': 2,
                'low': 0
            },
            remediation_applied=False,
            logs=[]
        )
        
        # Update metrics
        orchestrator._update_metrics(execution)
        
        assert orchestrator.metrics.total_tests_run == 1
        assert orchestrator.metrics.successful_tests == 1
        assert orchestrator.metrics.vulnerabilities_found == 5
        assert orchestrator.metrics.critical_vulnerabilities == 1
        assert orchestrator.metrics.high_vulnerabilities == 2
        assert orchestrator.metrics.medium_vulnerabilities == 2
        assert orchestrator.metrics.average_test_duration == 10.5
        assert orchestrator.metrics.security_score < 100
    
    def test_security_score_calculation(self, orchestrator):
        """Test security score calculation."""
        # Set up metrics
        orchestrator.metrics.critical_vulnerabilities = 2
        orchestrator.metrics.high_vulnerabilities = 3
        orchestrator.metrics.medium_vulnerabilities = 5
        orchestrator.metrics.low_vulnerabilities = 10
        orchestrator.metrics.total_tests_run = 10
        orchestrator.metrics.failed_tests = 2
        
        # Calculate score
        orchestrator._calculate_security_score()
        
        # Score should be reduced based on vulnerabilities and failures
        assert orchestrator.metrics.security_score < 100
        assert orchestrator.metrics.security_score >= 0
        
        # Expected: 100 - (2*10 + 3*5 + 5*2 + 10*0.5) - (0.2*20) = 100 - 50 - 4 = 46
        assert abs(orchestrator.metrics.security_score - 46) < 0.1
    
    def test_success_criteria_validation(self, orchestrator, mock_test):
        """Test success criteria validation."""
        execution = TestExecution(
            execution_id="exec_test",
            test_id=mock_test.test_id,
            status=TestStatus.RUNNING,
            start_time=datetime.utcnow(),
            end_time=None,
            duration=None,
            results={'successful_attacks': 0},
            vulnerabilities_found=3,
            severity_breakdown={
                'critical': 0,
                'high': 3,  # Exceeds max_high_vulns: 2
                'medium': 0,
                'low': 0
            },
            remediation_applied=False,
            logs=[]
        )
        
        # Check criteria
        success = orchestrator._check_success_criteria(mock_test, execution)
        
        assert not success  # Should fail due to too many high vulnerabilities
    
    def test_schedule_calculation(self, orchestrator):
        """Test schedule calculation for cron-like patterns."""
        current = datetime.utcnow()
        
        # Test every 4 hours
        next_run = orchestrator._calculate_next_run("0 */4 * * *")
        assert next_run > current
        assert (next_run - current).total_seconds() <= 4 * 3600
        
        # Test daily
        next_run = orchestrator._calculate_next_run("0 0 * * *")
        assert next_run > current
        assert next_run.hour == 0
        assert next_run.minute == 0
    
    def test_security_report_generation(self, orchestrator):
        """Test security report generation."""
        # Add some test history
        execution = TestExecution(
            execution_id="exec_test",
            test_id="test_id",
            status=TestStatus.COMPLETED,
            start_time=datetime.utcnow() - timedelta(minutes=5),
            end_time=datetime.utcnow(),
            duration=300,
            results={},
            vulnerabilities_found=2,
            severity_breakdown={
                'critical': 0,
                'high': 1,
                'medium': 1,
                'low': 0
            },
            remediation_applied=False,
            logs=["Test completed successfully"]
        )
        orchestrator.test_history.append(execution)
        orchestrator._update_metrics(execution)
        
        # Generate report
        report = orchestrator.get_security_report()
        
        assert 'generated_at' in report
        assert 'metrics' in report
        assert 'vulnerability_summary' in report
        assert 'compliance_status' in report
        assert 'recommendations' in report
        assert len(report['recent_executions']) > 0
    
    def test_recommendations_generation(self, orchestrator):
        """Test security recommendations generation."""
        # Set up concerning metrics
        orchestrator.metrics.critical_vulnerabilities = 3
        orchestrator.metrics.high_vulnerabilities = 5
        orchestrator.metrics.security_score = 45
        orchestrator.metrics.total_tests_run = 10
        orchestrator.metrics.failed_tests = 3
        
        recommendations = orchestrator._generate_recommendations()
        
        assert len(recommendations) > 0
        assert any("CRITICAL" in r for r in recommendations)
        assert any("high-severity" in r for r in recommendations)
        assert any("security posture" in r for r in recommendations)
    
    @pytest.mark.asyncio
    async def test_vulnerability_scan_implementation(self, orchestrator):
        """Test vulnerability scanning test implementation."""
        test = orchestrator.test_registry.get("vuln_scan_maestro")
        assert test is not None
        
        # Mock the penetration testing framework
        with patch.object(orchestrator.pen_test_framework.vulnerability_scanner, 
                         'scan_target', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = {
                'vulnerabilities': [
                    {'severity': 'medium', 'cve': 'CVE-2024-TEST'}
                ],
                'risk_score': 0.6
            }
            
            results = await orchestrator._run_vulnerability_scan(test, {'deep_scan': False})
            
            assert 'vulnerabilities' in results
            assert 'scan_coverage' in results
            assert 'components_scanned' in results
            assert len(results['vulnerabilities']) > 0
    
    @pytest.mark.asyncio
    async def test_penetration_test_implementation(self, orchestrator):
        """Test penetration testing implementation."""
        test = orchestrator.test_registry.get("pen_test_prompt_injection")
        assert test is not None
        
        # Mock attack scenario and execution
        mock_scenario = MagicMock()
        mock_scenario.name = "Test Attack"
        mock_scenario.attack_type = MagicMock(value="prompt_injection")
        
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.vulnerabilities = []
        mock_result.severity = MagicMock(value="medium")
        
        with patch.object(orchestrator.pen_test_framework.attack_generator,
                         'generate_attack_scenarios', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = [mock_scenario]
            
            with patch.object(orchestrator.pen_test_framework,
                             'execute_penetration_test', new_callable=AsyncMock) as mock_exec:
                mock_exec.return_value = mock_result
                
                results = await orchestrator._run_penetration_test(
                    test, 
                    {'attack_types': ['PROMPT_INJECTION']}
                )
                
                assert 'attacks_executed' in results
                assert 'successful_attacks' in results
                assert 'blocked_attacks' in results
                assert results['attacks_executed'] > 0
    
    @pytest.mark.asyncio
    async def test_compliance_check_implementation(self, orchestrator):
        """Test compliance checking implementation."""
        test = orchestrator.test_registry.get("compliance_fips_validation")
        assert test is not None
        
        results = await orchestrator._run_compliance_check(
            test,
            {'standard': 'FIPS_140_2', 'level': 3}
        )
        
        assert 'standard' in results
        assert 'compliance_rate' in results
        assert 'passed_checks' in results
        assert 'failed_checks' in results
        assert results['standard'] == 'FIPS_140_2'
    
    def test_export_metrics(self, orchestrator):
        """Test metrics export functionality."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            # Export metrics
            orchestrator.export_metrics(filepath)
            
            # Verify file contents
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            assert 'generated_at' in data
            assert 'metrics' in data
            assert 'vulnerability_summary' in data
            
        finally:
            os.unlink(filepath)
    
    def test_orchestrator_start_stop(self, orchestrator):
        """Test orchestrator start and stop functionality."""
        # Start orchestrator
        orchestrator.start()
        assert orchestrator.is_running
        assert orchestrator.scheduler_thread is not None
        assert orchestrator.scheduler_thread.is_alive()
        
        # Stop orchestrator
        orchestrator.stop()
        assert not orchestrator.is_running

class TestSecurityMetricsDashboard:
    """Test the security metrics dashboard."""
    
    @pytest.fixture
    def dashboard(self):
        """Create test dashboard instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dashboard = sys.modules.get('security_metrics_dashboard')
            if dashboard:
                return dashboard.SecurityMetricsDashboard(tmpdir)
            return None
    
    @pytest.mark.skipif(not sys.modules.get('security_metrics_dashboard'), 
                       reason="Dashboard module not available")
    def test_dashboard_initialization(self, dashboard):
        """Test dashboard initialization."""
        assert dashboard is not None
        assert dashboard.data_dir.exists()
    
    @pytest.mark.skipif(not sys.modules.get('security_metrics_dashboard'), 
                       reason="Dashboard module not available")
    def test_html_report_generation(self, dashboard):
        """Test HTML report generation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            filepath = f.name
        
        try:
            # Generate report
            dashboard.generate_html_report(filepath)
            
            # Verify file exists and contains expected content
            assert Path(filepath).exists()
            
            with open(filepath, 'r') as f:
                content = f.read()
            
            assert 'ALCUB3 Security Assessment Report' in content
            assert 'Security Score' in content
            assert 'Vulnerability Breakdown' in content
            assert 'Compliance Status' in content
            
        finally:
            os.unlink(filepath)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])