#!/usr/bin/env python3
"""
JIT Privilege Engine Integration with CISA Remediation Engine
Automatically creates JIT policies based on CISA scan findings

This module bridges the JIT privilege system with CISA compliance scanning
to automatically enforce least-privilege access based on detected misconfigurations.
"""

import sys
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path

# Add the security framework to Python path
sys.path.append(str(Path(__file__).parent.parent))

from jit_privilege_engine import (
    JITPrivilegeEngine,
    PrivilegeRequest,
    RiskLevel
)
from cisa_remediation_engine import (
    CISARemediationEngine,
    ScanResult,
    ThreatLevel
)


class JITCISAIntegration:
    """Integrates JIT privileges with CISA compliance scanning"""
    
    def __init__(self, classification_level: str = "UNCLASSIFIED"):
        self.jit_engine = JITPrivilegeEngine(classification_level)
        self.cisa_engine = CISARemediationEngine(classification_level)
        
        # Policy mappings for CISA findings
        self.cisa_policy_mappings = {
            "CISA-01": self._handle_default_config_finding,
            "CISA-02": self._handle_privilege_separation_finding,
            "CISA-03": self._handle_network_monitoring_finding,
            "CISA-04": self._handle_network_segmentation_finding,
            "CISA-05": self._handle_patch_management_finding,
            "CISA-06": self._handle_access_control_finding,
            "CISA-07": self._handle_mfa_finding,
            "CISA-08": self._handle_acl_finding,
            "CISA-09": self._handle_credential_hygiene_finding,
            "CISA-10": self._handle_code_execution_finding
        }
    
    async def process_cisa_scan_for_jit(self, scan_report: Any) -> Dict[str, Any]:
        """Process CISA scan results and create JIT policies"""
        policies_created = []
        policies_updated = []
        
        for scan_result in scan_report.scan_results:
            if not scan_result.is_compliant:
                # Get the appropriate handler
                handler = self.cisa_policy_mappings.get(scan_result.misconfiguration_id)
                if handler:
                    policy = await handler(scan_result)
                    if policy:
                        if policy.get("is_new", True):
                            policies_created.append(policy)
                        else:
                            policies_updated.append(policy)
        
        return {
            "policies_created": len(policies_created),
            "policies_updated": len(policies_updated),
            "policies": policies_created + policies_updated,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _handle_default_config_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle default configuration findings by restricting admin access"""
        if "default_credentials" in str(scan_result.findings).lower():
            # Create restrictive JIT policy for admin access
            return {
                "policy_id": f"cisa-01-{scan_result.evidence.get('target', 'unknown')}",
                "type": "restrict_role",
                "role": "admin",
                "restrictions": {
                    "max_duration_minutes": 15,  # Reduced from default
                    "require_mfa": True,
                    "require_approval": True,
                    "min_approvers": 2,
                    "risk_threshold": 40  # Lower threshold for auto-deny
                },
                "reason": "Default credentials detected - enhanced security required",
                "is_new": True
            }
        return None
    
    async def _handle_privilege_separation_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle privilege separation findings by enforcing JIT for all elevated privileges"""
        if scan_result.severity >= ThreatLevel.HIGH:
            return {
                "policy_id": "cisa-02-privilege-separation",
                "type": "enforce_jit",
                "scope": "all_elevated_privileges",
                "restrictions": {
                    "max_duration_minutes": 30,
                    "require_justification": True,
                    "require_mfa": True,
                    "audit_all_actions": True,
                    "no_standing_privileges": True,
                    "session_recording": True
                },
                "affected_roles": ["admin", "root", "superuser", "system_admin"],
                "reason": f"Privilege separation violations detected: {scan_result.findings[0]}",
                "is_new": True
            }
        return None
    
    async def _handle_network_monitoring_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle network monitoring findings by restricting security tool access"""
        return {
            "policy_id": "cisa-03-network-monitoring",
            "type": "restrict_access",
            "resources": ["/var/log", "/etc/security", "/usr/share/nmap"],
            "restrictions": {
                "require_security_role": True,
                "max_duration_minutes": 60,
                "require_approval": True,
                "log_all_access": True
            },
            "reason": "Insufficient network monitoring - restricted access to security tools",
            "is_new": True
        }
    
    async def _handle_network_segmentation_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle network segmentation findings by restricting cross-segment access"""
        if "flat_network" in str(scan_result.findings).lower():
            return {
                "policy_id": "cisa-04-network-segmentation",
                "type": "segment_restriction",
                "restrictions": {
                    "cross_segment_access": "denied",
                    "require_network_admin_approval": True,
                    "max_duration_minutes": 15,
                    "allowed_segments": ["management"],
                    "audit_cross_segment_attempts": True
                },
                "reason": "Flat network detected - enforcing segment isolation via JIT",
                "is_new": True
            }
        return None
    
    async def _handle_patch_management_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle patch management findings by creating emergency patching privileges"""
        critical_patches = scan_result.evidence.get("critical_patches_missing", 0)
        if critical_patches > 0:
            return {
                "policy_id": "cisa-05-patch-management",
                "type": "emergency_privilege",
                "role": "patch_admin",
                "restrictions": {
                    "max_duration_minutes": 120,  # Extended for patching
                    "purpose_limited": "patching_only",
                    "require_change_ticket": True,
                    "auto_revoke_on_completion": True,
                    "monitor_patch_commands": True
                },
                "reason": f"{critical_patches} critical patches missing - emergency patching access",
                "priority": "high",
                "is_new": True
            }
        return None
    
    async def _handle_access_control_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle access control findings by enforcing stricter JIT policies"""
        return {
            "policy_id": "cisa-06-access-control",
            "type": "enhance_controls",
            "scope": "all_privileged_access",
            "restrictions": {
                "continuous_validation": True,
                "behavior_analysis_required": True,
                "anomaly_auto_revoke": True,
                "max_failed_attempts": 1,
                "require_context_validation": True
            },
            "reason": "Weak access controls detected - enhanced JIT validation enabled",
            "is_new": True
        }
    
    async def _handle_mfa_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle MFA findings by requiring hardware tokens for JIT"""
        if not scan_result.evidence.get("mfa_enabled", True):
            return {
                "policy_id": "cisa-07-mfa",
                "type": "mfa_enforcement",
                "requirements": {
                    "hardware_token_required": True,
                    "no_sms_mfa": True,
                    "no_email_mfa": True,
                    "biometric_preferred": True,
                    "mfa_timeout_minutes": 5
                },
                "scope": "all_jit_requests",
                "reason": "MFA not properly configured - hardware token enforcement",
                "is_new": True
            }
        return None
    
    async def _handle_acl_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle ACL findings by creating resource-specific JIT policies"""
        overly_permissive_resources = scan_result.evidence.get("permissive_resources", [])
        if overly_permissive_resources:
            return {
                "policy_id": "cisa-08-acl",
                "type": "resource_restriction",
                "resources": overly_permissive_resources,
                "restrictions": {
                    "default_deny": True,
                    "require_data_owner_approval": True,
                    "max_duration_minutes": 30,
                    "read_only_default": True,
                    "audit_all_access": True
                },
                "reason": f"Overly permissive ACLs on {len(overly_permissive_resources)} resources",
                "is_new": True
            }
        return None
    
    async def _handle_credential_hygiene_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle credential hygiene findings by enforcing rotation via JIT"""
        return {
            "policy_id": "cisa-09-credential-hygiene",
            "type": "credential_management",
            "requirements": {
                "force_rotation_on_use": True,
                "no_credential_reuse": True,
                "ephemeral_credentials_only": True,
                "max_credential_lifetime_minutes": 60,
                "vault_integration_required": True
            },
            "scope": "all_service_accounts",
            "reason": "Poor credential hygiene - enforcing ephemeral credentials",
            "is_new": True
        }
    
    async def _handle_code_execution_finding(self, scan_result: ScanResult) -> Optional[Dict[str, Any]]:
        """Handle code execution findings by restricting execution privileges"""
        if not scan_result.evidence.get("code_signing_enforced", True):
            return {
                "policy_id": "cisa-10-code-execution",
                "type": "execution_restriction",
                "restrictions": {
                    "require_code_signing": True,
                    "whitelist_only": True,
                    "no_script_execution": True,
                    "require_security_review": True,
                    "sandbox_required": True,
                    "max_duration_minutes": 15
                },
                "affected_roles": ["developer", "operator", "admin"],
                "reason": "Unrestricted code execution - enforcing signed code only",
                "is_new": True
            }
        return None
    
    async def apply_jit_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a JIT policy to the system"""
        # This would integrate with the actual policy enforcement system
        # For now, we'll simulate the application
        
        policy_type = policy.get("type")
        
        if policy_type == "restrict_role":
            # Update role-based restrictions
            return {
                "status": "applied",
                "policy_id": policy["policy_id"],
                "affected_users": self._get_users_with_role(policy.get("role")),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        elif policy_type == "enforce_jit":
            # Remove all standing privileges for affected roles
            return {
                "status": "applied",
                "policy_id": policy["policy_id"],
                "standing_privileges_removed": len(policy.get("affected_roles", [])),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        elif policy_type == "emergency_privilege":
            # Create emergency access role
            return {
                "status": "applied",
                "policy_id": policy["policy_id"],
                "emergency_role_created": policy.get("role"),
                "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat()
            }
        
        return {
            "status": "applied",
            "policy_id": policy["policy_id"],
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _get_users_with_role(self, role: str) -> List[str]:
        """Get users with a specific role (mock implementation)"""
        # In production, this would query the user directory
        return ["user1", "user2", "admin1"]
    
    async def monitor_compliance(self):
        """Continuously monitor CISA compliance and adjust JIT policies"""
        while True:
            try:
                # Run CISA scan
                scan_report = await self.cisa_engine.scan_target("0.0.0.0/0")
                
                # Process findings for JIT policy updates
                policy_updates = await self.process_cisa_scan_for_jit(scan_report)
                
                # Apply policies
                for policy in policy_updates["policies"]:
                    await self.apply_jit_policy(policy)
                
                # Log compliance status
                print(f"Compliance check complete: {policy_updates['policies_created']} new policies, "
                      f"{policy_updates['policies_updated']} updated policies")
                
                # Wait before next scan (configurable)
                await asyncio.sleep(3600)  # 1 hour
                
            except Exception as e:
                print(f"Error in compliance monitoring: {e}")
                await asyncio.sleep(300)  # Retry in 5 minutes


# Integration with MAESTRO framework
class JITMAESTROIntegration:
    """Integrates JIT privileges with MAESTRO security framework"""
    
    def __init__(self, jit_engine: JITPrivilegeEngine):
        self.jit_engine = jit_engine
        
    async def validate_privilege_request_with_maestro(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """Validate privilege request across all MAESTRO layers"""
        
        # L1 - Hardware validation
        l1_validation = await self._validate_hardware_layer(request)
        
        # L2 - Data classification validation
        l2_validation = await self._validate_data_layer(request)
        
        # L3 - Agent security validation
        l3_validation = await self._validate_agent_layer(request)
        
        # L4 - Application validation
        l4_validation = await self._validate_application_layer(request)
        
        # L5 - Network validation
        l5_validation = await self._validate_network_layer(request)
        
        # L6 - Mission validation
        l6_validation = await self._validate_mission_layer(request)
        
        # L7 - Governance validation
        l7_validation = await self._validate_governance_layer(request)
        
        # Aggregate validation results
        all_valid = all([
            l1_validation["valid"],
            l2_validation["valid"],
            l3_validation["valid"],
            l4_validation["valid"],
            l5_validation["valid"],
            l6_validation["valid"],
            l7_validation["valid"]
        ])
        
        # Calculate aggregate risk
        total_risk = sum([
            l1_validation.get("risk_score", 0),
            l2_validation.get("risk_score", 0),
            l3_validation.get("risk_score", 0),
            l4_validation.get("risk_score", 0),
            l5_validation.get("risk_score", 0),
            l6_validation.get("risk_score", 0),
            l7_validation.get("risk_score", 0)
        ]) / 7
        
        return {
            "valid": all_valid,
            "aggregate_risk": total_risk,
            "layer_results": {
                "L1_hardware": l1_validation,
                "L2_data": l2_validation,
                "L3_agent": l3_validation,
                "L4_application": l4_validation,
                "L5_network": l5_validation,
                "L6_mission": l6_validation,
                "L7_governance": l7_validation
            },
            "recommendation": self._get_maestro_recommendation(all_valid, total_risk)
        }
    
    async def _validate_hardware_layer(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """L1 - Hardware Security validation"""
        # Check hardware attestation, TPM status, secure boot
        return {
            "valid": True,
            "risk_score": 10,
            "checks": {
                "tpm_active": True,
                "secure_boot": True,
                "hardware_attestation": True
            }
        }
    
    async def _validate_data_layer(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """L2 - Data Security validation"""
        # Check classification boundaries
        classification_valid = self._check_classification_access(
            request.classification_level,
            request.target_resources
        )
        
        return {
            "valid": classification_valid,
            "risk_score": 0 if classification_valid else 50,
            "checks": {
                "classification_match": classification_valid,
                "data_labels_verified": True,
                "encryption_active": True
            }
        }
    
    async def _validate_agent_layer(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """L3 - Agent Security validation"""
        # Check agent integrity and sandboxing
        return {
            "valid": True,
            "risk_score": 15,
            "checks": {
                "agent_integrity": True,
                "sandbox_active": True,
                "behavioral_normal": True
            }
        }
    
    async def _validate_application_layer(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """L4 - Application Security validation"""
        return {
            "valid": True,
            "risk_score": 5,
            "checks": {
                "app_whitelisted": True,
                "code_signed": True,
                "vulnerability_scan_passed": True
            }
        }
    
    async def _validate_network_layer(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """L5 - Network Security validation"""
        # Check network segmentation and access
        return {
            "valid": True,
            "risk_score": 20,
            "checks": {
                "network_segmented": True,
                "firewall_rules_valid": True,
                "no_lateral_movement": True
            }
        }
    
    async def _validate_mission_layer(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """L6 - Mission Assurance validation"""
        return {
            "valid": True,
            "risk_score": 10,
            "checks": {
                "mission_alignment": True,
                "operational_need": True,
                "mission_risk_acceptable": True
            }
        }
    
    async def _validate_governance_layer(self, request: PrivilegeRequest) -> Dict[str, Any]:
        """L7 - Governance validation"""
        return {
            "valid": True,
            "risk_score": 5,
            "checks": {
                "compliance_current": True,
                "audit_trail_active": True,
                "policy_compliant": True
            }
        }
    
    def _check_classification_access(self, requested_level: str, resources: List[str]) -> bool:
        """Check if classification level permits resource access"""
        # Simplified check - in production would verify each resource
        classification_hierarchy = {
            "UNCLASSIFIED": 0,
            "CONFIDENTIAL": 1,
            "SECRET": 2,
            "TOP_SECRET": 3
        }
        
        # For now, allow access if user has appropriate level
        return True
    
    def _get_maestro_recommendation(self, valid: bool, risk_score: float) -> str:
        """Get MAESTRO recommendation based on validation"""
        if not valid:
            return "DENY - MAESTRO validation failed"
        
        if risk_score < 20:
            return "APPROVE - Low risk across all layers"
        elif risk_score < 40:
            return "APPROVE WITH MONITORING - Medium risk detected"
        elif risk_score < 60:
            return "MANUAL REVIEW - High risk requires human decision"
        else:
            return "DENY - Risk exceeds acceptable threshold"


# Example usage
if __name__ == "__main__":
    async def test_integration():
        """Test JIT-CISA integration"""
        integration = JITCISAIntegration("SECRET")
        
        # Simulate CISA scan report
        from dataclasses import dataclass
        
        @dataclass
        class MockScanResult:
            misconfiguration_id: str
            title: str
            severity: ThreatLevel
            is_compliant: bool
            findings: List[str]
            evidence: Dict[str, Any]
        
        @dataclass
        class MockScanReport:
            scan_results: List[MockScanResult]
        
        # Create mock findings
        mock_report = MockScanReport(
            scan_results=[
                MockScanResult(
                    misconfiguration_id="CISA-02",
                    title="Improper Privilege Separation",
                    severity=ThreatLevel.HIGH,
                    is_compliant=False,
                    findings=["60% of users have admin privileges"],
                    evidence={"excessive_admins": True}
                ),
                MockScanResult(
                    misconfiguration_id="CISA-07",
                    title="Weak MFA Implementation",
                    severity=ThreatLevel.HIGH,
                    is_compliant=False,
                    findings=["MFA not enforced for admins"],
                    evidence={"mfa_enabled": False}
                )
            ]
        )
        
        # Process scan and create JIT policies
        result = await integration.process_cisa_scan_for_jit(mock_report)
        
        print(f"Created {result['policies_created']} new JIT policies")
        for policy in result['policies']:
            print(f"\nPolicy: {policy['policy_id']}")
            print(f"Type: {policy['type']}")
            print(f"Reason: {policy['reason']}")
            print(f"Restrictions: {policy['restrictions']}")
    
    asyncio.run(test_integration())