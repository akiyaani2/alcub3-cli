#!/usr/bin/env python3
"""
Test Suite for MAESTRO OWASP Security Controls
Comprehensive validation of SAST/DAST capabilities and OWASP Top 10 compliance

This test suite validates the complete OWASP security controls implementation,
including static analysis, dynamic testing, and compliance validation.

Test Coverage:
- SAST engine functionality and vulnerability detection
- DAST simulation and payload testing
- OWASP Top 10 compliance validation
- ASD STIG V5R1 compliance checking
- Performance validation (<100ms overhead target)
- Classification-aware security controls
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
import json
import time
from unittest.mock import Mock, patch

# Import the module under test
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from shared.owasp_security_controls import (
        OWASPSecurityControls, OWASPCategory, VulnerabilitySeverity, 
        TestingMode, SecurityVulnerability, SASTAnalysisResult, DASTAnalysisResult
    )
except ImportError as e:
    print(f"Import error: {e}")
    # Create mock classes for testing
    class OWASPSecurityControls:
        pass

class TestOWASPSecurityControls:
    """Test suite for OWASP security controls implementation."""
    
    @pytest.fixture
    def security_controls(self):
        """Create OWASP security controls instance for testing."""
        return OWASPSecurityControls(classification_level="secret")
    
    @pytest.fixture
    def vulnerable_code_file(self):
        """Create temporary file with vulnerable code for testing."""
        vulnerable_code = '''
import hashlib
import subprocess

# A01: Broken Access Control
admin = True
if admin:
    print("Admin access granted")

# A02: Cryptographic Failures  
password = "hardcoded_password"
hash_value = hashlib.md5(b"test").hexdigest()

# A03: Injection
user_input = "malicious_input"
eval(user_input)

query = f"SELECT * FROM users WHERE id = {user_input}"

# A05: Security Misconfiguration
debug = True
ssl_verify = False

# A09: Logging and Monitoring Failures
print(f"User password: {password}")
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(vulnerable_code)
            temp_file = f.name
        
        yield temp_file
        os.unlink(temp_file)
    
    @pytest.fixture
    def secure_code_file(self):
        """Create temporary file with secure code for testing."""
        secure_code = '''
import hashlib
import logging
from cryptography.fernet import Fernet

# Secure implementation
def authenticate_user(username, password_hash):
    """Secure authentication with proper validation."""
    # Use strong cryptography
    secure_hash = hashlib.sha256(password_hash.encode()).hexdigest()
    
    # Proper logging without sensitive data
    logging.info(f"Authentication attempt for user: {username}")
    
    return verify_credentials(username, secure_hash)

def verify_credentials(username, password_hash):
    """Verify user credentials securely."""
    # Use parameterized queries
    query = "SELECT id FROM users WHERE username = ? AND password_hash = ?"
    # Implementation would use proper database binding
    return True

# Secure configuration
DEBUG = False
SSL_VERIFY = True
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(secure_code)
            temp_file = f.name
        
        yield temp_file
        os.unlink(temp_file)
    
    @pytest.mark.asyncio
    async def test_sast_analysis_vulnerable_code(self, security_controls, vulnerable_code_file):
        """Test SAST analysis on vulnerable code."""
        # Run SAST analysis
        result = await security_controls.run_sast_analysis(vulnerable_code_file)
        
        # Validate results
        assert isinstance(result, SASTAnalysisResult)
        assert result.files_analyzed == 1
        assert result.lines_analyzed > 0
        assert len(result.vulnerabilities) > 0
        assert result.execution_time_ms > 0
        
        # Check for specific vulnerabilities
        vulnerability_categories = {v.category for v in result.vulnerabilities}
        expected_categories = {
            OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            OWASPCategory.A03_INJECTION,
            OWASPCategory.A09_LOGGING_MONITORING_FAILURES
        }
        
        # Should detect vulnerabilities in multiple categories
        assert len(vulnerability_categories.intersection(expected_categories)) >= 2
        
        # Validate vulnerability details
        for vuln in result.vulnerabilities:
            assert vuln.id is not None
            assert vuln.severity in VulnerabilitySeverity
            assert vuln.detected_by == TestingMode.SAST
            assert vuln.file_path == vulnerable_code_file
            assert vuln.line_number > 0
            assert vuln.cvss_score >= 0.0
            assert vuln.classification_impact is not None
    
    @pytest.mark.asyncio
    async def test_sast_analysis_secure_code(self, security_controls, secure_code_file):
        """Test SAST analysis on secure code."""
        # Run SAST analysis
        result = await security_controls.run_sast_analysis(secure_code_file)
        
        # Validate results
        assert isinstance(result, SASTAnalysisResult)
        assert result.files_analyzed == 1
        assert result.lines_analyzed > 0
        
        # Should detect fewer or no critical vulnerabilities
        critical_vulns = [v for v in result.vulnerabilities 
                         if v.severity == VulnerabilitySeverity.CRITICAL]
        assert len(critical_vulns) == 0
    
    @pytest.mark.asyncio
    async def test_dast_analysis(self, security_controls):
        """Test DAST analysis functionality."""
        test_endpoint = "https://test.example.com/api"
        
        # Run DAST analysis
        result = await security_controls.run_dast_analysis(test_endpoint)
        
        # Validate results
        assert isinstance(result, DASTAnalysisResult)
        assert result.target_endpoint == test_endpoint
        assert result.requests_sent > 0
        assert result.responses_analyzed > 0
        assert result.execution_time_ms > 0
        
        # Check vulnerability detection
        for vuln in result.vulnerabilities:
            assert vuln.detected_by == TestingMode.DAST
            assert vuln.severity in VulnerabilitySeverity
            assert vuln.cvss_score >= 0.0
    
    @pytest.mark.asyncio
    async def test_dast_custom_payloads(self, security_controls):
        """Test DAST analysis with custom payloads."""
        test_endpoint = "https://test.example.com/api"
        custom_payloads = {
            "sql_injection": ["' UNION SELECT * FROM users --"],
            "xss": ["<script>alert(1)</script>"],
            "command_injection": ["; cat /etc/passwd"]
        }
        
        # Run DAST analysis with custom payloads
        result = await security_controls.run_dast_analysis(
            test_endpoint, 
            test_payloads=custom_payloads
        )
        
        # Validate custom payload testing
        assert result.requests_sent >= len(custom_payloads)
        assert result.execution_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_owasp_compliance_validation(self, security_controls, vulnerable_code_file):
        """Test OWASP Top 10 compliance validation."""
        # Run SAST analysis first
        sast_result = await security_controls.run_sast_analysis(vulnerable_code_file)
        
        # Run DAST analysis
        dast_result = await security_controls.run_dast_analysis("https://test.example.com")
        
        # Validate compliance
        compliance_report = await security_controls.validate_owasp_compliance(
            sast_result, dast_result
        )
        
        # Check compliance report structure
        assert "compliance_status" in compliance_report
        assert "compliance_percentage" in compliance_report
        assert "total_vulnerabilities" in compliance_report
        assert "critical_vulnerabilities" in compliance_report
        assert "high_vulnerabilities" in compliance_report
        assert "category_breakdown" in compliance_report
        assert "recommendations" in compliance_report
        assert "asd_stig_compliance" in compliance_report
        
        # Validate compliance status
        assert compliance_report["compliance_status"] in [
            "COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT"
        ]
        assert 0 <= compliance_report["compliance_percentage"] <= 100
        
        # Validate STIG compliance
        stig_compliance = compliance_report["asd_stig_compliance"]
        assert "stig_compliant" in stig_compliance
        assert "critical_findings" in stig_compliance
        assert "high_findings" in stig_compliance
    
    @pytest.mark.asyncio
    async def test_performance_requirements(self, security_controls, vulnerable_code_file):
        """Test that security controls meet performance requirements (<100ms overhead)."""
        
        # Test SAST performance
        start_time = time.time()
        sast_result = await security_controls.run_sast_analysis(vulnerable_code_file)
        sast_time = (time.time() - start_time) * 1000
        
        # SAST should complete quickly for small files
        assert sast_time < 5000  # 5 seconds for test file
        assert sast_result.execution_time_ms > 0
        
        # Test compliance validation performance
        start_time = time.time()
        compliance_report = await security_controls.validate_owasp_compliance(sast_result)
        compliance_time = (time.time() - start_time) * 1000
        
        # Compliance validation should be very fast
        assert compliance_time < 100  # <100ms requirement
        assert compliance_report["validation_time_ms"] < 100
    
    def test_vulnerability_severity_scoring(self, security_controls):
        """Test CVSS scoring and severity assessment."""
        # Test CVSS score calculation
        critical_score = security_controls._calculate_cvss_score(VulnerabilitySeverity.CRITICAL)
        high_score = security_controls._calculate_cvss_score(VulnerabilitySeverity.HIGH)
        medium_score = security_controls._calculate_cvss_score(VulnerabilitySeverity.MEDIUM)
        low_score = security_controls._calculate_cvss_score(VulnerabilitySeverity.LOW)
        
        # Validate score ordering
        assert critical_score > high_score > medium_score > low_score
        assert critical_score >= 9.0
        assert high_score >= 7.0
        assert medium_score >= 4.0
        assert low_score < 4.0
    
    def test_classification_impact_assessment(self, security_controls):
        """Test classification-aware impact assessment."""
        # Test impact assessment for different severities
        critical_impact = security_controls._assess_classification_impact(VulnerabilitySeverity.CRITICAL)
        low_impact = security_controls._assess_classification_impact(VulnerabilitySeverity.LOW)
        
        # Should reference the classification level
        assert "SECRET" in critical_impact.upper()
        assert "SECRET" in low_impact.upper()
        
        # Critical should indicate higher risk
        assert "High risk" in critical_impact
        assert "Low risk" in low_impact
    
    def test_security_rules_initialization(self, security_controls):
        """Test security rules database initialization."""
        rules = security_controls.security_rules
        
        # Should have rules for all major OWASP categories
        expected_categories = [
            OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            OWASPCategory.A03_INJECTION,
            OWASPCategory.A05_SECURITY_MISCONFIGURATION,
            OWASPCategory.A07_AUTHENTICATION_FAILURES,
            OWASPCategory.A09_LOGGING_MONITORING_FAILURES
        ]
        
        for category in expected_categories:
            assert category in rules
            assert len(rules[category]) > 0
            
            # Validate rule structure
            for rule in rules[category]:
                assert "pattern" in rule
                assert "severity" in rule
                assert "description" in rule
                assert "remediation" in rule
    
    def test_scan_id_generation(self, security_controls):
        """Test unique scan ID generation."""
        scan_id1 = security_controls._generate_scan_id()
        scan_id2 = security_controls._generate_scan_id()
        
        # Should be unique
        assert scan_id1 != scan_id2
        assert scan_id1.startswith("OWASP-")
        assert scan_id2.startswith("OWASP-")
    
    def test_vulnerability_id_generation(self, security_controls):
        """Test unique vulnerability ID generation."""
        vuln_id1 = security_controls._generate_vulnerability_id()
        vuln_id2 = security_controls._generate_vulnerability_id()
        
        # Should be unique and sequential
        assert vuln_id1 != vuln_id2
        assert vuln_id1.startswith("VULN-")
        assert vuln_id2.startswith("VULN-")

class TestOWASPIntegration:
    """Integration tests for OWASP controls with MAESTRO framework."""
    
    @pytest.mark.asyncio
    async def test_maestro_integration(self):
        """Test integration with MAESTRO security framework."""
        # Test with different classification levels
        for classification in ["unclassified", "secret", "top_secret"]:
            controls = OWASPSecurityControls(classification_level=classification)
            assert controls.classification_level == classification
    
    def test_audit_logging_integration(self):
        """Test integration with MAESTRO audit logging."""
        controls = OWASPSecurityControls()
        
        # Should handle missing audit logger gracefully
        assert controls.audit_logger is None or hasattr(controls.audit_logger, 'log_security_event')
    
    def test_crypto_utils_integration(self):
        """Test integration with MAESTRO crypto utilities."""
        controls = OWASPSecurityControls()
        
        # Should handle missing crypto utils gracefully
        assert controls.crypto_utils is None or hasattr(controls.crypto_utils, 'encrypt')

# Performance benchmarks
class TestOWASPPerformance:
    """Performance validation for OWASP security controls."""
    
    @pytest.mark.asyncio
    async def test_sast_performance_benchmark(self):
        """Benchmark SAST analysis performance."""
        controls = OWASPSecurityControls()
        
        # Create test file
        test_code = "print('Hello World')\n" * 1000  # 1000 lines
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_code)
            temp_file = f.name
        
        try:
            # Benchmark SAST analysis
            start_time = time.time()
            result = await controls.run_sast_analysis(temp_file)
            analysis_time = (time.time() - start_time) * 1000
            
            # Performance assertions
            assert analysis_time < 10000  # <10 seconds for 1000 lines
            assert result.lines_analyzed == 1000
            
            print(f"SAST Performance: {analysis_time:.2f}ms for {result.lines_analyzed} lines")
            print(f"Throughput: {result.lines_analyzed / (analysis_time / 1000):.0f} lines/second")
            
        finally:
            os.unlink(temp_file)
    
    @pytest.mark.asyncio 
    async def test_compliance_validation_performance(self):
        """Benchmark compliance validation performance."""
        controls = OWASPSecurityControls()
        
        # Create mock SAST result with many vulnerabilities
        mock_vulnerabilities = []
        for i in range(100):
            vuln = SecurityVulnerability(
                id=f"test-{i}",
                category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                severity=VulnerabilitySeverity.MEDIUM,
                title="Test vulnerability",
                description="Test description",
                file_path="/test/file.py",
                line_number=i,
                code_snippet="test code",
                remediation="Fix it",
                cvss_score=5.0,
                classification_impact="Medium risk",
                detected_by=TestingMode.SAST,
                timestamp=time.time()
            )
            mock_vulnerabilities.append(vuln)
        
        mock_sast_result = SASTAnalysisResult(
            scan_id="test-scan",
            target_path="/test",
            vulnerabilities=mock_vulnerabilities,
            lines_analyzed=1000,
            files_analyzed=10,
            execution_time_ms=500.0,
            coverage_percentage=95.0
        )
        
        # Benchmark compliance validation
        start_time = time.time()
        compliance_report = await controls.validate_owasp_compliance(mock_sast_result)
        validation_time = (time.time() - start_time) * 1000
        
        # Performance assertion - should meet <100ms requirement
        assert validation_time < 100
        assert compliance_report["validation_time_ms"] < 100
        
        print(f"Compliance Validation Performance: {validation_time:.2f}ms for 100 vulnerabilities")

if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "--tb=short"])