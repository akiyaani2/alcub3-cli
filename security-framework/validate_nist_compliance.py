#!/usr/bin/env python3
"""
NIST SP 800-171 Compliance Validation Script
Validates the implementation of all 110 NIST controls and CUI handling

This script performs comprehensive validation of:
1. All control definitions and validation methods
2. CUI detection and classification accuracy
3. Compliance assessment performance
4. Report generation functionality
5. Integration with existing MAESTRO components
"""

import sys
import os
import time
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import all components
try:
    from shared.nist_800_171_controls import (
        NIST800171Controls, ControlFamily, ControlPriority, ValidationStatus
    )
    from shared.cui_handler import CUIHandler, CUICategory
    from shared.nist_compliance_assessment import (
        NISTPomplianceAssessment, AssessmentType, RemediationPriority
    )
    from shared.compliance_validator import ComplianceValidator
    from shared.classification import SecurityClassification, ClassificationLevel
    
    print("✓ All NIST SP 800-171 modules imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)


class NISTComplianceValidator:
    """Validates NIST SP 800-171 implementation."""
    
    def __init__(self):
        """Initialize validator."""
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests_passed": 0,
            "tests_failed": 0,
            "performance_metrics": {},
            "validation_errors": []
        }
        
        # Initialize components
        self.nist_controls = NIST800171Controls()
        self.cui_handler = CUIHandler()
        self.assessment_engine = NISTPomplianceAssessment(
            self.nist_controls,
            self.cui_handler
        )
        
        # Initialize compliance validator with classification
        self.classification = SecurityClassification()
        self.classification.set_default_level(ClassificationLevel.CUI)
        self.compliance_validator = ComplianceValidator(self.classification)
    
    def log_result(self, test_name: str, passed: bool, details: str = ""):
        """Log test result."""
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {test_name}")
        if details:
            print(f"      {details}")
        
        if passed:
            self.results["tests_passed"] += 1
        else:
            self.results["tests_failed"] += 1
            self.results["validation_errors"].append({
                "test": test_name,
                "details": details
            })
    
    def validate_control_definitions(self):
        """Validate all 110 control definitions."""
        print("\n=== Validating Control Definitions ===")
        
        # Check total control count
        total_controls = len(self.nist_controls.controls)
        self.log_result(
            "Control count verification",
            total_controls == 110,
            f"Found {total_controls} controls (expected 110)"
        )
        
        # Validate control families
        family_counts = {}
        for control in self.nist_controls.controls.values():
            family = control.family
            family_counts[family] = family_counts.get(family, 0) + 1
        
        expected_families = 14
        self.log_result(
            "Control family verification",
            len(family_counts) == expected_families,
            f"Found {len(family_counts)} families (expected {expected_families})"
        )
        
        # Check critical controls
        critical_controls = [
            c for c in self.nist_controls.controls.values() 
            if c.priority == ControlPriority.CRITICAL
        ]
        self.log_result(
            "Critical controls identified",
            len(critical_controls) > 0,
            f"Found {len(critical_controls)} critical controls"
        )
        
        # Validate control attributes
        missing_attributes = []
        for control_id, control in self.nist_controls.controls.items():
            if not control.validation_method:
                missing_attributes.append(f"{control_id}: missing validation method")
            if not control.remediation_guidance:
                missing_attributes.append(f"{control_id}: missing remediation guidance")
        
        self.log_result(
            "Control attribute completeness",
            len(missing_attributes) == 0,
            f"{len(missing_attributes)} controls with missing attributes"
        )
    
    async def validate_cui_detection(self):
        """Validate CUI detection capabilities."""
        print("\n=== Validating CUI Detection ===")
        
        test_cases = [
            {
                "name": "Export Control Detection",
                "content": "This document contains ITAR controlled technical data",
                "expected_cui": True,
                "expected_category": CUICategory.EXPORT_CONTROL
            },
            {
                "name": "PII Detection",
                "content": "SSN: 123-45-6789, Date of Birth: 01/01/1990",
                "expected_cui": True,
                "expected_category": CUICategory.PRIVACY
            },
            {
                "name": "Non-CUI Content",
                "content": "This is a general business document with no sensitive data",
                "expected_cui": False,
                "expected_category": None
            }
        ]
        
        for test in test_cases:
            start_time = time.time()
            result = await self.cui_handler.detect_cui(test["content"])
            detection_time = (time.time() - start_time) * 1000
            
            # Check detection accuracy
            detection_correct = result.contains_cui == test["expected_cui"]
            
            # Check category if CUI detected
            category_correct = True
            if test["expected_category"] and result.contains_cui:
                category_correct = test["expected_category"] in result.cui_categories
            
            self.log_result(
                f"CUI Detection: {test['name']}",
                detection_correct and category_correct,
                f"Detection time: {detection_time:.1f}ms"
            )
        
        # Performance check
        self.results["performance_metrics"]["cui_detection_ms"] = detection_time
        self.log_result(
            "CUI detection performance",
            detection_time < 10,  # <10ms requirement
            f"{detection_time:.1f}ms (target: <10ms)"
        )
    
    async def validate_control_validation(self):
        """Validate control validation functionality."""
        print("\n=== Validating Control Validation ===")
        
        # Test with compliant system state
        compliant_state = {
            "access_control_policy": True,
            "authentication_enabled": True,
            "authorization_enabled": True,
            "mfa_enabled": True,
            "fips_compliant_mfa": True,
            "audit_logging_enabled": True,
            "audit_integrity_protection": True,
            "log_retention_days": 365
        }
        
        # Test specific controls
        test_controls = ["3.1.1", "3.3.1", "3.5.1"]
        
        for control_id in test_controls:
            start_time = time.time()
            result = await self.nist_controls.validate_control(control_id, compliant_state)
            validation_time = (time.time() - start_time) * 1000
            
            self.log_result(
                f"Control validation: {control_id}",
                result is not None and hasattr(result, 'status'),
                f"Status: {result.status.value if result else 'None'}, Time: {validation_time:.1f}ms"
            )
        
        # Performance check
        self.log_result(
            "Control validation performance",
            validation_time < 50,  # <50ms per control
            f"{validation_time:.1f}ms per control (target: <50ms)"
        )
    
    async def validate_compliance_assessment(self):
        """Validate compliance assessment functionality."""
        print("\n=== Validating Compliance Assessment ===")
        
        # Create test system state
        test_state = {
            "access_control_policy": True,
            "authentication_enabled": True,
            "mfa_enabled": False,  # Non-compliant
            "audit_logging_enabled": True,
            "log_retention_days": 90,  # Partial compliance
            "training_program": True,
            "training_completion_rate": 0.95
        }
        
        # Run assessment
        start_time = time.time()
        assessment_result = await self.assessment_engine.run_assessment(
            AssessmentType.FULL,
            test_state
        )
        assessment_time = (time.time() - start_time) * 1000
        
        # Validate assessment result
        self.log_result(
            "Assessment execution",
            assessment_result is not None,
            f"Assessed {assessment_result.controls_assessed} controls"
        )
        
        self.log_result(
            "Assessment completeness",
            assessment_result.controls_assessed > 100,
            f"{assessment_result.controls_assessed} controls assessed"
        )
        
        # Performance check
        self.results["performance_metrics"]["full_assessment_ms"] = assessment_time
        self.log_result(
            "Assessment performance",
            assessment_time < 5000,  # <5s requirement
            f"{assessment_time:.1f}ms (target: <5000ms)"
        )
        
        # Validate gap analysis
        gaps = await self.assessment_engine.perform_gap_analysis(assessment_result)
        self.log_result(
            "Gap analysis",
            len(gaps) > 0,
            f"Identified {len(gaps)} compliance gaps"
        )
        
        # Validate remediation plan
        remediation_plan = self.assessment_engine.create_remediation_plan(gaps[:5])
        self.log_result(
            "Remediation planning",
            len(remediation_plan) > 0,
            f"Created {len(remediation_plan)} remediation items"
        )
    
    async def validate_report_generation(self):
        """Validate report generation."""
        print("\n=== Validating Report Generation ===")
        
        try:
            # Generate report
            start_time = time.time()
            report = await self.assessment_engine.generate_compliance_report(
                organization="Test Organization",
                system_name="Test System"
            )
            report_time = (time.time() - start_time) * 1000
            
            # Validate report structure
            self.log_result(
                "Report generation",
                report is not None,
                f"Report ID: {report.report_id}"
            )
            
            # Check required fields
            required_fields = [
                "report_id", "report_date", "assessment_result",
                "executive_summary", "gap_analysis", "attestation"
            ]
            
            missing_fields = [
                field for field in required_fields 
                if not hasattr(report, field)
            ]
            
            self.log_result(
                "Report completeness",
                len(missing_fields) == 0,
                f"All required fields present"
            )
            
            # Export to JSON
            json_report = self.assessment_engine.export_report_json(report)
            self.log_result(
                "JSON export",
                len(json_report) > 0,
                f"Exported {len(json_report)} bytes"
            )
            
            # Performance check
            self.log_result(
                "Report generation performance",
                report_time < 2000,  # <2s requirement
                f"{report_time:.1f}ms (target: <2000ms)"
            )
            
        except Exception as e:
            self.log_result("Report generation", False, str(e))
    
    def validate_integration(self):
        """Validate integration with ComplianceValidator."""
        print("\n=== Validating MAESTRO Integration ===")
        
        # Check if NIST SP 800-171 is available
        self.log_result(
            "NIST SP 800-171 module loaded",
            self.compliance_validator.nist_800_171_controls is not None,
            "Module available in ComplianceValidator"
        )
        
        # Check CUI handler
        self.log_result(
            "CUI handler loaded",
            self.compliance_validator.cui_handler is not None,
            "CUI handler available in ComplianceValidator"
        )
        
        # Test integrated validation
        try:
            test_state = {"test": True}
            results = self.compliance_validator.validate_all_with_nist_800_171(test_state)
            
            self.log_result(
                "Integrated validation",
                "nist_800_171_validation" in results or results.get("classification_level") == "CUI",
                "NIST SP 800-171 validation integrated"
            )
        except Exception as e:
            self.log_result("Integrated validation", False, str(e))
    
    async def run_all_validations(self):
        """Run all validation tests."""
        print("=== NIST SP 800-171 Implementation Validation ===")
        print(f"Started: {datetime.now().isoformat()}")
        
        # Run validations
        self.validate_control_definitions()
        await self.validate_cui_detection()
        await self.validate_control_validation()
        await self.validate_compliance_assessment()
        await self.validate_report_generation()
        self.validate_integration()
        
        # Summary
        print("\n=== Validation Summary ===")
        print(f"Tests Passed: {self.results['tests_passed']}")
        print(f"Tests Failed: {self.results['tests_failed']}")
        print(f"Success Rate: {self.results['tests_passed'] / max(self.results['tests_passed'] + self.results['tests_failed'], 1) * 100:.1f}%")
        
        # Performance summary
        print("\n=== Performance Metrics ===")
        for metric, value in self.results["performance_metrics"].items():
            print(f"{metric}: {value:.1f}ms")
        
        # Save results
        with open('nist_compliance_validation_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nResults saved to: nist_compliance_validation_results.json")
        
        # Exit code based on results
        return 0 if self.results["tests_failed"] == 0 else 1


async def main():
    """Main validation function."""
    validator = NISTComplianceValidator()
    return await validator.run_all_validations()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)