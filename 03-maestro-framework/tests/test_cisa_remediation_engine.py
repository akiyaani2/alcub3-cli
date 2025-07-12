#!/usr/bin/env python3
"""
Comprehensive Test Suite for CISA Remediation Engine
Tests all 10 misconfiguration scanners and remediation capabilities
"""

import unittest
import asyncio
import json
import sys
import os
from datetime import datetime
from pathlib import Path

# Add the security framework to Python path
sys.path.append(str(Path(__file__).parent.parent / 'src'))

from cisa_remediation_engine import (
    CISARemediationEngine,
    ScanStatus,
    ThreatLevel,
    ScanResult,
    RemediationResult,
    DefaultConfigScanner,
    PrivilegeSeparationScanner,
    NetworkMonitoringScanner,
    NetworkSegmentationScanner,
    PatchManagementScanner,
    AccessControlScanner,
    MFAScanner,
    ACLScanner,
    CredentialHygieneScanner,
    CodeExecutionScanner
)


class TestCISARemediationEngine(unittest.TestCase):
    """Test the main CISA Remediation Engine"""
    
    def setUp(self):
        """Set up test environment"""
        self.engine = CISARemediationEngine("UNCLASSIFIED")
        self.test_target = "192.168.1.0/24"
        
    async def async_test_comprehensive_scan(self):
        """Test comprehensive scan functionality"""
        # Create test context
        context = {
            'ssh_enabled': True,
            'ssh_default_creds': True,
            'database_enabled': True,
            'database_default_creds': True,
            'default_ports_open': True,
            'default_ssl_cert': True,
            'users_with_admin': 5,
            'total_users': 10,
            'service_accounts_with_admin': True,
            'sudo_logging_enabled': False,
            'shared_admin_accounts': True,
            'ids_enabled': False,
            'netflow_enabled': False,
            'log_retention_days': 30,
            'anomaly_detection_enabled': False,
            'flat_network': True,
            'vlan_implemented': False,
            'dmz_configured': False,
            'unrestricted_internal_access': True,
            'critical_patches_missing': 5,
            'last_patch_days': 60,
            'auto_update_enabled': False,
            'patch_testing_process': False,
            'mfa_enabled': False,
            'mfa_bypass_allowed': True,
            'mfa_for_admins': False,
            'weak_mfa_methods': True,
            'code_signing_enforced': False,
            'script_execution_unrestricted': True,
            'application_whitelisting': False,
            'macro_execution_allowed': True
        }
        
        # Perform scan
        report = await self.engine.scan_target(self.test_target, context=context)
        
        # Validate report structure
        self.assertIsNotNone(report)
        self.assertEqual(report.target, self.test_target)
        self.assertEqual(report.classification_level, "UNCLASSIFIED")
        self.assertIn(report.status, [ScanStatus.REMEDIATION_REQUIRED, ScanStatus.COMPLETED])
        
        # Validate scan results
        self.assertGreater(len(report.scan_results), 0)
        self.assertEqual(report.total_scans, 10)  # All 10 CISA checks
        
        # Check for non-compliant findings
        self.assertGreater(report.non_compliant_count, 0)
        self.assertGreater(report.critical_findings, 0)
        
        # Validate compliance score
        self.assertGreaterEqual(report.overall_compliance_score, 0)
        self.assertLessEqual(report.overall_compliance_score, 100)
        
        # Check patent innovations
        self.assertGreater(len(report.patent_innovations_used), 0)
        
        return report
    
    def test_comprehensive_scan(self):
        """Test wrapper for async comprehensive scan"""
        report = asyncio.run(self.async_test_comprehensive_scan())
        self.assertIsNotNone(report)
    
    async def async_test_remediation(self):
        """Test remediation functionality"""
        # First run a scan
        context = {
            'ssh_default_creds': True,
            'critical_patches_missing': 5,
            'mfa_enabled': False,
            'code_signing_enforced': False
        }
        
        scan_report = await self.engine.scan_target(self.test_target, context=context)
        
        # Perform remediation
        remediated_report = await self.engine.remediate(
            scan_report,
            auto_approve=True
        )
        
        # Validate remediation results
        self.assertGreater(len(remediated_report.remediation_results), 0)
        
        # Check that at least some remediations succeeded
        successful_remediations = [
            r for r in remediated_report.remediation_results if r.success
        ]
        self.assertGreater(len(successful_remediations), 0)
        
        return remediated_report
    
    def test_remediation(self):
        """Test wrapper for async remediation"""
        report = asyncio.run(self.async_test_remediation())
        self.assertIsNotNone(report)
    
    def test_scan_status_tracking(self):
        """Test scan status tracking"""
        scan_id = self.engine._generate_scan_id(self.test_target)
        self.assertIsNotNone(scan_id)
        self.assertEqual(len(scan_id), 16)  # SHA256 truncated
        
        # Test status retrieval
        status = self.engine.get_scan_status(scan_id)
        self.assertIsNone(status)  # Should be None for non-existent scan
    
    def test_report_export(self):
        """Test report export functionality"""
        # Create a mock report
        from dataclasses import dataclass
        
        mock_report = self.engine.export_report(
            type('obj', (object,), {
                'scan_id': 'test123',
                'target': '192.168.1.1',
                'classification_level': 'UNCLASSIFIED',
                'start_time': datetime.utcnow(),
                'end_time': datetime.utcnow(),
                'status': ScanStatus.COMPLETED,
                'overall_compliance_score': 85.5,
                'total_scans': 10,
                'compliant_count': 8,
                'non_compliant_count': 2,
                'critical_findings': 1,
                'high_findings': 1,
                'scan_results': [],
                'remediation_results': []
            })(),
            format='summary'
        )
        
        self.assertIn('CISA Top 10 Misconfiguration Scan Report', mock_report)
        self.assertIn('85.5%', mock_report)
    
    def test_classification_levels(self):
        """Test different classification levels"""
        for level in ["UNCLASSIFIED", "SECRET", "TOP_SECRET"]:
            engine = CISARemediationEngine(level)
            self.assertEqual(engine.classification.level, level)


class TestIndividualScanners(unittest.TestCase):
    """Test individual scanner modules"""
    
    def setUp(self):
        """Set up test environment"""
        self.engine = CISARemediationEngine("UNCLASSIFIED")
    
    async def async_test_default_config_scanner(self):
        """Test default configuration scanner"""
        scanner = DefaultConfigScanner(self.engine)
        
        # Test with default credentials present
        context = {
            'ssh_enabled': True,
            'ssh_default_creds': True,
            'database_enabled': True,
            'database_default_creds': True,
            'default_ports_open': True,
            'default_ssl_cert': True
        }
        
        result = await scanner.scan("192.168.1.1", context)
        
        self.assertEqual(result.misconfiguration_id, "CISA-01")
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.severity, ThreatLevel.CRITICAL)
        self.assertGreater(len(result.findings), 0)
        self.assertGreater(len(result.remediation_steps), 0)
        
        # Test remediation
        remediation = await scanner.remediate(result, auto_approve=True)
        self.assertTrue(remediation.success)
        self.assertGreater(len(remediation.actions_taken), 0)
    
    def test_default_config_scanner(self):
        """Test wrapper for async default config scanner"""
        asyncio.run(self.async_test_default_config_scanner())
    
    async def async_test_privilege_separation_scanner(self):
        """Test privilege separation scanner"""
        scanner = PrivilegeSeparationScanner(self.engine)
        
        # Test with privilege issues
        context = {
            'users_with_admin': 6,
            'total_users': 10,
            'service_accounts_with_admin': True,
            'sudo_logging_enabled': False,
            'shared_admin_accounts': True
        }
        
        result = await scanner.scan("192.168.1.1", context)
        
        self.assertEqual(result.misconfiguration_id, "CISA-02")
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.severity, ThreatLevel.HIGH)
        self.assertGreater(len(result.findings), 0)
    
    def test_privilege_separation_scanner(self):
        """Test wrapper for async privilege separation scanner"""
        asyncio.run(self.async_test_privilege_separation_scanner())
    
    async def async_test_network_monitoring_scanner(self):
        """Test network monitoring scanner"""
        scanner = NetworkMonitoringScanner(self.engine)
        
        # Test with insufficient monitoring
        context = {
            'ids_enabled': False,
            'netflow_enabled': False,
            'log_retention_days': 30,
            'anomaly_detection_enabled': False
        }
        
        result = await scanner.scan("192.168.1.1", context)
        
        self.assertEqual(result.misconfiguration_id, "CISA-03")
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.severity, ThreatLevel.HIGH)
        self.assertEqual(len(result.findings), 4)
    
    def test_network_monitoring_scanner(self):
        """Test wrapper for async network monitoring scanner"""
        asyncio.run(self.async_test_network_monitoring_scanner())
    
    async def async_test_patch_management_scanner(self):
        """Test patch management scanner"""
        scanner = PatchManagementScanner(self.engine)
        
        # Test with missing patches
        context = {
            'critical_patches_missing': 10,
            'last_patch_days': 90,
            'auto_update_enabled': False,
            'patch_testing_process': False
        }
        
        result = await scanner.scan("192.168.1.1", context)
        
        self.assertEqual(result.misconfiguration_id, "CISA-05")
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.severity, ThreatLevel.CRITICAL)
        self.assertGreater(len(result.findings), 0)
    
    def test_patch_management_scanner(self):
        """Test wrapper for async patch management scanner"""
        asyncio.run(self.async_test_patch_management_scanner())
    
    async def async_test_mfa_scanner(self):
        """Test MFA scanner"""
        scanner = MFAScanner(self.engine)
        
        # Test with weak MFA
        context = {
            'mfa_enabled': False,
            'mfa_bypass_allowed': True,
            'mfa_for_admins': False,
            'weak_mfa_methods': True
        }
        
        result = await scanner.scan("192.168.1.1", context)
        
        self.assertEqual(result.misconfiguration_id, "CISA-07")
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.severity, ThreatLevel.HIGH)
        self.assertEqual(len(result.findings), 4)
    
    def test_mfa_scanner(self):
        """Test wrapper for async MFA scanner"""
        asyncio.run(self.async_test_mfa_scanner())
    
    async def async_test_code_execution_scanner(self):
        """Test code execution scanner"""
        scanner = CodeExecutionScanner(self.engine)
        
        # Test with unrestricted execution
        context = {
            'code_signing_enforced': False,
            'script_execution_unrestricted': True,
            'application_whitelisting': False,
            'macro_execution_allowed': True
        }
        
        result = await scanner.scan("192.168.1.1", context)
        
        self.assertEqual(result.misconfiguration_id, "CISA-10")
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.severity, ThreatLevel.CRITICAL)
        self.assertEqual(len(result.findings), 4)
    
    def test_code_execution_scanner(self):
        """Test wrapper for async code execution scanner"""
        asyncio.run(self.async_test_code_execution_scanner())


class TestPerformanceAndCompliance(unittest.TestCase):
    """Test performance targets and compliance validation"""
    
    def setUp(self):
        """Set up test environment"""
        self.engine = CISARemediationEngine("TOP_SECRET")
    
    async def async_test_scan_performance(self):
        """Test scan performance targets"""
        import time
        
        # Simple context for fast scanning
        context = {
            'mfa_enabled': True,
            'ids_enabled': True,
            'patch_testing_process': True,
            'code_signing_enforced': True
        }
        
        start_time = time.time()
        report = await self.engine.scan_target("192.168.1.1", context=context)
        end_time = time.time()
        
        scan_duration = end_time - start_time
        
        # Should complete within reasonable time (30 seconds for all scanners)
        self.assertLess(scan_duration, 30)
        
        # Check individual scanner performance
        for result in report.scan_results:
            # Each scanner should complete within 100ms
            self.assertLess(result.scan_time_ms, 100)
    
    def test_scan_performance(self):
        """Test wrapper for async scan performance"""
        asyncio.run(self.async_test_scan_performance())
    
    def test_maestro_integration(self):
        """Test MAESTRO security framework integration"""
        # Verify MAESTRO client is initialized
        self.assertIsNotNone(self.engine.maestro_client)
        
        # Verify classification-aware operations
        self.assertEqual(self.engine.classification.level, "TOP_SECRET")
    
    def test_patent_features(self):
        """Test patent-defensible features"""
        expected_features = [
            "AI-powered misconfiguration prediction",
            "Classification-aware remediation strategies",
            "Air-gapped scanning capabilities",
            "Real-time threat correlation with MAESTRO",
            "Automated compliance validation"
        ]
        
        for feature in expected_features:
            self.assertIn(feature, self.engine.patent_features)


class TestEdgeCasesAndErrorHandling(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def setUp(self):
        """Set up test environment"""
        self.engine = CISARemediationEngine()
    
    async def async_test_empty_scan(self):
        """Test scan with no findings"""
        # All compliant context
        context = {
            'mfa_enabled': True,
            'mfa_for_admins': True,
            'ids_enabled': True,
            'netflow_enabled': True,
            'log_retention_days': 180,
            'anomaly_detection_enabled': True,
            'vlan_implemented': True,
            'dmz_configured': True,
            'critical_patches_missing': 0,
            'last_patch_days': 7,
            'auto_update_enabled': True,
            'patch_testing_process': True,
            'code_signing_enforced': True,
            'application_whitelisting': True
        }
        
        report = await self.engine.scan_target("192.168.1.1", context=context)
        
        self.assertEqual(report.status, ScanStatus.COMPLETED)
        self.assertEqual(report.non_compliant_count, 0)
        self.assertEqual(report.overall_compliance_score, 100.0)
    
    def test_empty_scan(self):
        """Test wrapper for async empty scan"""
        asyncio.run(self.async_test_empty_scan())
    
    async def async_test_partial_scan(self):
        """Test scanning specific modules only"""
        modules = ['mfa_config', 'patch_management']
        
        report = await self.engine.scan_target(
            "192.168.1.1",
            scan_modules=modules,
            context={'mfa_enabled': False, 'critical_patches_missing': 5}
        )
        
        self.assertEqual(report.total_scans, 2)
        self.assertEqual(len(report.scan_results), 2)
    
    def test_partial_scan(self):
        """Test wrapper for async partial scan"""
        asyncio.run(self.async_test_partial_scan())
    
    def test_invalid_export_format(self):
        """Test invalid export format handling"""
        mock_report = type('obj', (object,), {
            'scan_id': 'test123',
            'target': '192.168.1.1'
        })()
        
        with self.assertRaises(ValueError):
            self.engine.export_report(mock_report, format='invalid')


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)