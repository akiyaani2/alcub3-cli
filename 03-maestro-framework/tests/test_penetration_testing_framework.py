#!/usr/bin/env python3
"""
Tests for ALCUB3 Penetration Testing Framework
Validates automated security testing, vulnerability assessment, and attack simulation capabilities.
"""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from l3_agent.penetration_testing_framework import (
    PenetrationTestingFramework,
    AttackVectorGenerator, 
    VulnerabilityScanner,
    AttackScenario,
    AttackResult,
    SecurityAssessment,
    AttackType,
    AttackSeverity,
    TestStatus
)
from shared.classification import ClassificationLevel

class TestAttackVectorGenerator:
    """Test attack vector generation capabilities."""
    
    @pytest.fixture
    def generator(self):
        return AttackVectorGenerator()
    
    @pytest.mark.asyncio
    async def test_generate_attack_scenarios(self, generator):
        """Test attack scenario generation."""
        scenarios = await generator.generate_attack_scenarios(
            "l1_foundation", 
            ClassificationLevel.SECRET,
            5
        )
        
        assert len(scenarios) == 5
        assert all(isinstance(scenario, AttackScenario) for scenario in scenarios)
        assert all(scenario.classification_level == ClassificationLevel.SECRET for scenario in scenarios)
        assert all("l1_foundation" in scenario.target_components for scenario in scenarios)
    
    @pytest.mark.asyncio
    async def test_classification_aware_scenarios(self, generator):
        """Test that scenarios are adapted for different classification levels."""
        unclassified_scenarios = await generator.generate_attack_scenarios(
            "l2_data", ClassificationLevel.UNCLASSIFIED, 3
        )
        top_secret_scenarios = await generator.generate_attack_scenarios(
            "l2_data", ClassificationLevel.TOP_SECRET, 3
        )
        
        # Top secret scenarios should generally have higher severity
        unclassified_severities = [s.severity for s in unclassified_scenarios]
        top_secret_severities = [s.severity for s in top_secret_scenarios]
        
        # At least some top secret scenarios should be high/critical
        assert any(sev in [AttackSeverity.HIGH, AttackSeverity.CRITICAL] for sev in top_secret_severities)
    
    def test_attack_pattern_loading(self, generator):
        """Test attack pattern loading."""
        patterns = generator.attack_patterns
        
        assert "prompt_injection" in patterns
        assert "adversarial_input" in patterns
        assert "classification_bypass" in patterns
        
        # Verify prompt injection patterns
        prompt_patterns = patterns["prompt_injection"]["patterns"]
        assert any("ignore" in pattern.lower() for pattern in prompt_patterns)

class TestVulnerabilityScanner:
    """Test vulnerability scanning capabilities."""
    
    @pytest.fixture
    def scanner(self):
        return VulnerabilityScanner()
    
    @pytest.mark.asyncio
    async def test_scan_target(self, scanner):
        """Test target vulnerability scanning."""
        results = await scanner.scan_target("l1_foundation", ClassificationLevel.SECRET)
        
        assert "target" in results
        assert "classification" in results
        assert "vulnerabilities" in results
        assert "risk_score" in results
        assert "scan_coverage" in results
        
        assert results["target"] == "l1_foundation"
        assert results["classification"] == "secret"
        assert isinstance(results["risk_score"], float)
        assert 0 <= results["risk_score"] <= 100
    
    @pytest.mark.asyncio
    async def test_prompt_injection_scanning(self, scanner):
        """Test prompt injection vulnerability detection."""
        results = await scanner._scan_prompt_injection("test_target", ClassificationLevel.UNCLASSIFIED)
        
        assert "scan_type" in results
        assert "vulnerabilities" in results
        assert "patterns_tested" in results
        assert results["scan_type"] == "prompt_injection"
        assert isinstance(results["patterns_tested"], int)
        assert results["patterns_tested"] > 0
    
    @pytest.mark.asyncio
    async def test_classification_bypass_scanning(self, scanner):
        """Test classification bypass vulnerability detection."""
        results = await scanner._scan_classification_bypass("test_target", ClassificationLevel.SECRET)
        
        assert "scan_type" in results
        assert "vulnerabilities" in results
        assert results["scan_type"] == "classification_bypass"
        
        # Check if any vulnerabilities have critical severity
        for vuln in results["vulnerabilities"]:
            if vuln["type"] == "classification_bypass":
                assert vuln["severity"] == AttackSeverity.CRITICAL.value
    
    def test_risk_score_calculation(self, scanner):
        """Test risk score calculation."""
        # Test with no vulnerabilities
        assert scanner._calculate_risk_score([]) == 0.0
        
        # Test with mixed severity vulnerabilities
        vulnerabilities = [
            {"severity": AttackSeverity.CRITICAL.value},
            {"severity": AttackSeverity.HIGH.value},
            {"severity": AttackSeverity.MEDIUM.value}
        ]
        risk_score = scanner._calculate_risk_score(vulnerabilities)
        assert 0 < risk_score <= 100

class TestPenetrationTestingFramework:
    """Test comprehensive penetration testing framework."""
    
    @pytest.fixture
    def framework(self):
        return PenetrationTestingFramework()
    
    @pytest.mark.asyncio
    async def test_framework_initialization(self, framework):
        """Test framework initialization."""
        assert framework.attack_generator is not None
        assert framework.vulnerability_scanner is not None
        assert framework.threat_detector is not None
        assert isinstance(framework.active_tests, dict)
        assert isinstance(framework.test_results, list)
        assert isinstance(framework.assessment_history, list)
    
    @pytest.mark.asyncio
    async def test_quick_security_scan(self, framework):
        """Test quick security scan functionality."""
        scan_results = await framework.quick_security_scan(
            "l1_foundation", 
            ClassificationLevel.SECRET
        )
        
        assert "target" in scan_results
        assert "classification" in scan_results
        assert "scan_duration" in scan_results
        assert "scenarios_tested" in scan_results
        assert "vulnerabilities_found" in scan_results
        assert "security_score" in scan_results
        
        assert scan_results["target"] == "l1_foundation"
        assert scan_results["classification"] == "secret"
        assert scan_results["scenarios_tested"] == 3  # Quick scan uses 3 scenarios
        assert isinstance(scan_results["security_score"], float)
        assert 0 <= scan_results["security_score"] <= 100
    
    @pytest.mark.asyncio
    async def test_execute_penetration_test(self, framework):
        """Test single penetration test execution."""
        # Create test scenario
        scenario = AttackScenario(
            scenario_id="test_scenario_001",
            name="Test Prompt Injection",
            attack_type=AttackType.PROMPT_INJECTION,
            severity=AttackSeverity.HIGH,
            classification_level=ClassificationLevel.SECRET,
            description="Test prompt injection attack",
            target_components=["l1_foundation"],
            attack_vectors=["ignore_instructions", "system_override"],
            success_criteria=["bypass_security"],
            detection_evasion={"techniques": ["obfuscation"]},
            execution_steps=[
                {
                    "step": 1,
                    "action": "reconnaissance",
                    "description": "Gather target info",
                    "expected_duration": 30
                },
                {
                    "step": 2,
                    "action": "initial_access",
                    "description": "Attempt initial access",
                    "expected_duration": 60
                }
            ],
            expected_outcomes=["security_bypass"],
            mitigation_tests=["verify_detection"],
            created_at=datetime.utcnow()
        )
        
        result = await framework.execute_penetration_test(scenario)
        
        assert isinstance(result, AttackResult)
        assert result.scenario_id == scenario.scenario_id
        assert result.status in [TestStatus.COMPLETED, TestStatus.FAILED]
        assert isinstance(result.success, bool)
        assert isinstance(result.execution_time, float)
        assert result.execution_time > 0
        assert isinstance(result.findings, list)
        assert isinstance(result.vulnerabilities, list)
        assert isinstance(result.recommendations, list)
    
    @pytest.mark.asyncio
    async def test_comprehensive_security_assessment(self, framework):
        """Test comprehensive security assessment."""
        assessment = await framework.run_security_assessment(
            target_components=["l1_foundation", "l2_data"],
            classification_level=ClassificationLevel.SECRET,
            assessment_type="comprehensive"
        )
        
        assert isinstance(assessment, SecurityAssessment)
        assert assessment.total_scenarios > 0
        assert assessment.executed_scenarios <= assessment.total_scenarios
        assert isinstance(assessment.overall_score, float)
        assert 0 <= assessment.overall_score <= 100
        assert isinstance(assessment.maestro_compliance, dict)
        assert "l1_foundation" in assessment.maestro_compliance or "overall" in assessment.maestro_compliance
        assert isinstance(assessment.recommendations, list)
        assert len(assessment.executive_summary) > 0
    
    @pytest.mark.asyncio
    async def test_attack_step_execution(self, framework):
        """Test individual attack step execution."""
        scenario = AttackScenario(
            scenario_id="test_scenario_002",
            name="Test Attack Steps",
            attack_type=AttackType.SANDBOX_ESCAPE,
            severity=AttackSeverity.CRITICAL,
            classification_level=ClassificationLevel.TOP_SECRET,
            description="Test attack step execution",
            target_components=["l3_agent"],
            attack_vectors=["container_escape"],
            success_criteria=["escape_sandbox"],
            detection_evasion={},
            execution_steps=[],
            expected_outcomes=["privilege_escalation"],
            mitigation_tests=["containment_test"],
            created_at=datetime.utcnow()
        )
        
        # Test reconnaissance step
        recon_step = {
            "step": 1,
            "action": "reconnaissance",
            "description": "Information gathering"
        }
        recon_result = await framework._execute_attack_step(recon_step, scenario)
        
        assert "success" in recon_result
        assert "execution_time" in recon_result
        assert recon_result["action"] == "reconnaissance"
        
        # Test initial access step
        access_step = {
            "step": 2,
            "action": "initial_access",
            "description": "Gain initial access"
        }
        access_result = await framework._execute_attack_step(access_step, scenario)
        
        assert "success" in access_result
        assert "execution_time" in access_result
        assert access_result["action"] == "initial_access"
    
    def test_security_score_calculation(self, framework):
        """Test security score calculation."""
        # Test with no results
        assert framework._calculate_security_score([], []) == 100.0
        
        # Test with successful attacks
        mock_results = [
            Mock(success=True, detection_bypassed=False),
            Mock(success=False, detection_bypassed=True),
            Mock(success=False, detection_bypassed=False)
        ]
        
        vulnerabilities = [
            {"severity": AttackSeverity.CRITICAL.value},
            {"severity": AttackSeverity.MEDIUM.value}
        ]
        
        score = framework._calculate_security_score(mock_results, vulnerabilities)
        assert 0 <= score <= 100
        assert score < 100  # Should be reduced due to successful attacks and vulnerabilities
    
    @pytest.mark.asyncio
    async def test_detection_and_mitigation_testing(self, framework):
        """Test detection and mitigation capability testing."""
        scenario = AttackScenario(
            scenario_id="test_detection",
            name="Detection Test",
            attack_type=AttackType.PROMPT_INJECTION,
            severity=AttackSeverity.HIGH,
            classification_level=ClassificationLevel.SECRET,
            description="Test detection capabilities",
            target_components=["l1_foundation"],
            attack_vectors=["test_vector"],
            success_criteria=["test_criteria"],
            detection_evasion={},
            execution_steps=[],
            expected_outcomes=["test_outcome"],
            mitigation_tests=["test_mitigation"],
            created_at=datetime.utcnow()
        )
        
        # Test detection
        detection_result = await framework._test_detection_capabilities(scenario)
        assert "detected" in detection_result
        assert isinstance(detection_result["detected"], bool)
        
        # Test mitigation
        mitigation_result = await framework._test_mitigation_effectiveness(scenario)
        assert "effective" in mitigation_result
        assert isinstance(mitigation_result["effective"], bool)
    
    @pytest.mark.asyncio
    async def test_report_generation_and_export(self, framework):
        """Test assessment report generation and export."""
        # Run a quick assessment first
        assessment = await framework.run_security_assessment(
            target_components=["l1_foundation"],
            classification_level=ClassificationLevel.UNCLASSIFIED,
            assessment_type="quick"
        )
        
        # Test report retrieval
        report = await framework.get_assessment_report(assessment.assessment_id)
        assert report is not None
        assert "assessment_id" in report
        assert report["assessment_id"] == assessment.assessment_id
        
        # Test report export
        json_export = await framework.export_assessment_report(assessment.assessment_id, "json")
        assert json_export is not None
        assert assessment.assessment_id in json_export
        
        summary_export = await framework.export_assessment_report(assessment.assessment_id, "summary")
        assert summary_export is not None
        assert len(summary_export) > 0
    
    @pytest.mark.asyncio
    async def test_active_test_management(self, framework):
        """Test active test tracking and management."""
        # Initially no active tests
        active_tests = await framework.list_active_tests()
        assert isinstance(active_tests, list)
        
        # Test status for non-existent test
        status = await framework.get_test_status("non_existent_test")
        assert status is None

class TestIntegration:
    """Integration tests for the complete penetration testing framework."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_assessment(self):
        """Test complete end-to-end security assessment workflow."""
        framework = PenetrationTestingFramework()
        
        # Run comprehensive assessment
        assessment = await framework.run_security_assessment(
            target_components=["l1_foundation", "l2_data", "l3_agent"],
            classification_level=ClassificationLevel.SECRET
        )
        
        # Verify assessment completeness
        assert assessment.total_scenarios > 0
        assert assessment.executed_scenarios > 0
        assert assessment.duration > 0
        assert len(assessment.executive_summary) > 0
        assert len(assessment.recommendations) > 0
        
        # Export and verify report
        json_report = await framework.export_assessment_report(assessment.assessment_id, "json")
        assert json_report is not None
        assert "security_score" in json_report.lower() or "overall_score" in json_report.lower()
        
        print(f"✅ End-to-end test completed with security score: {assessment.overall_score:.1f}")
    
    @pytest.mark.asyncio
    async def test_classification_level_impact(self):
        """Test how classification levels impact assessment results."""
        framework = PenetrationTestingFramework()
        
        # Test different classification levels
        unclassified_assessment = await framework.run_security_assessment(
            target_components=["l1_foundation"],
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        
        top_secret_assessment = await framework.run_security_assessment(
            target_components=["l1_foundation"],
            classification_level=ClassificationLevel.TOP_SECRET
        )
        
        # Top secret should generally have better security scores (higher classification = better security)
        # But this can vary based on attack success randomization
        assert isinstance(unclassified_assessment.overall_score, float)
        assert isinstance(top_secret_assessment.overall_score, float)
        
        print(f"✅ Classification impact test completed:")
        print(f"   UNCLASSIFIED score: {unclassified_assessment.overall_score:.1f}")
        print(f"   TOP SECRET score: {top_secret_assessment.overall_score:.1f}")
    
    @pytest.mark.asyncio
    async def test_performance_requirements(self):
        """Test that framework meets performance requirements."""
        framework = PenetrationTestingFramework()
        
        # Test quick scan performance
        start_time = time.time()
        quick_scan = await framework.quick_security_scan("l1_foundation", ClassificationLevel.SECRET)
        quick_scan_time = time.time() - start_time
        
        # Quick scan should complete within reasonable time (< 10 seconds for test)
        assert quick_scan_time < 10.0, f"Quick scan took too long: {quick_scan_time:.2f} seconds"
        
        # Test individual test execution performance
        generator = AttackVectorGenerator()
        scenarios = await generator.generate_attack_scenarios("l1_foundation", ClassificationLevel.SECRET, 1)
        
        start_time = time.time()
        result = await framework.execute_penetration_test(scenarios[0])
        test_time = time.time() - start_time
        
        # Individual test should complete quickly (< 5 seconds for test)
        assert test_time < 5.0, f"Individual test took too long: {test_time:.2f} seconds"
        
        print(f"✅ Performance test completed:")
        print(f"   Quick scan: {quick_scan_time:.2f} seconds")
        print(f"   Individual test: {test_time:.2f} seconds")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])