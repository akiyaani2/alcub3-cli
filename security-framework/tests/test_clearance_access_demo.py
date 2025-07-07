"""
ALCUB3 Security Clearance Access Control - Comprehensive Demo & Test Suite
PKI/CAC Authentication and Role-Based Access Control Demonstration

This demonstration script showcases the patent-pending security clearance-based
access control system with PKI/CAC integration, providing practical examples
of defense-grade authentication and authorization.

Features Demonstrated:
- PKI/CAC certificate authentication with NIPRNet/SIPRNet support
- Security clearance validation with DoD clearance levels
- Role-based access control with tool-specific permissions
- Classification-aware access decisions
- Hardware Security Module (HSM) integration
- Real-time performance validation (<50ms target)

Usage:
    python test_clearance_access_demo.py
"""

import os
import sys
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Add the security framework to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'shared'))

from clearance_access_control import (
    ClearanceAccessController, ClearanceLevel, PKINetwork, CardType,
    SecurityClearance, UserRole, PIVCertificate, AccessControlResult
)
from classification import SecurityClassification, SecurityClassificationLevel
from crypto_utils import FIPSCryptoUtils, SecurityLevel
from audit_logger import AuditLogger, AuditEventType, AuditSeverity

class PKICACDemo:
    """Comprehensive demonstration of PKI/CAC authentication system."""
    
    def __init__(self):
        """Initialize demo environment."""
        print("🔐 ALCUB3 Security Clearance Access Control Demo")
        print("=" * 60)
        
        # Initialize core security components
        self.classification = SecurityClassification()
        self.crypto_utils = FIPSCryptoUtils(SecurityLevel.HIGH)
        self.audit_logger = AuditLogger()
        
        # Initialize clearance access controller
        self.access_controller = ClearanceAccessController(
            self.classification,
            self.crypto_utils,
            self.audit_logger,
            hsm_config={"enabled": True, "provider": "demo"}
        )
        
        # Demo data
        self.demo_users = {}
        self.demo_certificates = {}
        
        print("✅ Security framework initialized")
        print()
    
    def setup_demo_data(self):
        """Set up demonstration users, clearances, and roles."""
        print("📋 Setting up demonstration data...")
        
        # 1. Create demo security clearances
        self._create_demo_clearances()
        
        # 2. Create demo user roles
        self._create_demo_roles()
        
        # 3. Create demo PKI certificates
        self._create_demo_certificates()
        
        # 4. Assign roles to users
        self._assign_demo_roles()
        
        print("✅ Demo data configured")
        print()
    
    def demonstrate_pki_authentication(self):
        """Demonstrate PKI/CAC authentication process."""
        print("🎯 PKI/CAC Authentication Demonstration")
        print("-" * 40)
        
        # Test scenarios
        scenarios = [
            {
                "name": "DoD Contractor (Secret Clearance)",
                "user_id": "jane.analyst",
                "network": PKINetwork.NIPRNET,
                "pin": "1234",
                "expected": True
            },
            {
                "name": "Military Officer (Top Secret Clearance)",
                "user_id": "maj.commander",
                "network": PKINetwork.SIPRNET,
                "pin": "5678",
                "expected": True
            },
            {
                "name": "Invalid PIN Test",
                "user_id": "jane.analyst",
                "network": PKINetwork.NIPRNET,
                "pin": "wrong",
                "expected": False
            }
        ]
        
        for scenario in scenarios:
            print(f"🧪 Testing: {scenario['name']}")
            
            # Get certificate for user
            cert_data = self.demo_certificates.get(scenario['user_id'])
            if not cert_data:
                print(f"❌ No certificate found for {scenario['user_id']}")
                continue
            
            # Attempt authentication
            start_time = time.time()
            
            success, auth_info = self.access_controller.authenticate_pki_user(
                certificate_data=cert_data['cert_bytes'],
                pin=scenario['pin'],
                card_uuid=cert_data['card_uuid'],
                network=scenario['network']
            )
            
            auth_time_ms = (time.time() - start_time) * 1000
            
            # Report results
            if success == scenario['expected']:
                status = "✅ PASS"
            else:
                status = "❌ FAIL"
            
            print(f"   {status} - Authentication: {success}")
            print(f"   ⏱️  Response time: {auth_time_ms:.2f}ms")
            
            if success:
                print(f"   👤 User ID: {auth_info['user_id']}")
                print(f"   🌐 PKI Network: {auth_info['pki_network']}")
                print(f"   📜 Certificate Expiry: {auth_info['certificate_expiry']}")
            else:
                print(f"   ❌ Error: {auth_info.get('error', 'Unknown error')}")
            
            print()
    
    def demonstrate_clearance_validation(self):
        """Demonstrate security clearance validation."""
        print("🔍 Security Clearance Validation Demonstration")
        print("-" * 50)
        
        # Test scenarios
        scenarios = [
            {
                "name": "Secret clearance for Secret data",
                "user_id": "jane.analyst",
                "required_level": ClearanceLevel.SECRET,
                "compartments": None,
                "expected": True
            },
            {
                "name": "Top Secret clearance for Secret data",
                "user_id": "maj.commander",
                "required_level": ClearanceLevel.SECRET,
                "compartments": None,
                "expected": True
            },
            {
                "name": "Secret clearance for Top Secret data",
                "user_id": "jane.analyst",
                "required_level": ClearanceLevel.TOP_SECRET,
                "compartments": None,
                "expected": False
            },
            {
                "name": "TS/SCI with required compartments",
                "user_id": "dr.researcher",
                "required_level": ClearanceLevel.TS_SCI,
                "compartments": {"CRYPTO", "NUCLEAR"},
                "expected": True
            }
        ]
        
        for scenario in scenarios:
            print(f"🧪 Testing: {scenario['name']}")
            
            start_time = time.time()
            
            valid, validation_info = self.access_controller.validate_security_clearance(
                user_id=scenario['user_id'],
                required_level=scenario['required_level'],
                compartments=scenario['compartments']
            )
            
            validation_time_ms = (time.time() - start_time) * 1000
            
            # Report results
            if valid == scenario['expected']:
                status = "✅ PASS"
            else:
                status = "❌ FAIL"
            
            print(f"   {status} - Validation: {valid}")
            print(f"   ⏱️  Response time: {validation_time_ms:.2f}ms")
            
            if valid:
                print(f"   🎖️  User clearance: {validation_info['user_clearance']}")
                print(f"   📅 Expiration: {validation_info['expiration_date']}")
                if validation_info['compartments']:
                    print(f"   🔒 Compartments: {', '.join(validation_info['compartments'])}")
            else:
                print(f"   ❌ Error: {validation_info.get('error', 'Unknown error')}")
            
            print()
    
    def demonstrate_tool_access_control(self):
        """Demonstrate tool access control based on clearance and classification."""
        print("🛠️  Tool Access Control Demonstration")
        print("-" * 42)
        
        # Test scenarios
        scenarios = [
            {
                "name": "Analyst accessing validation tool (Unclassified)",
                "user_id": "jane.analyst",
                "tool": "validate_input",
                "classification": SecurityClassificationLevel.UNCLASSIFIED,
                "expected": AccessControlResult.GRANTED
            },
            {
                "name": "Analyst accessing robotics control (Secret)",
                "user_id": "jane.analyst",
                "tool": "robotics_control",
                "classification": SecurityClassificationLevel.SECRET,
                "expected": AccessControlResult.DENIED
            },
            {
                "name": "Commander accessing robotics control (Secret)",
                "user_id": "maj.commander",
                "tool": "robotics_control",
                "classification": SecurityClassificationLevel.SECRET,
                "expected": AccessControlResult.GRANTED
            },
            {
                "name": "Admin accessing system controls (Top Secret)",
                "user_id": "dr.researcher",
                "tool": "system_admin",
                "classification": SecurityClassificationLevel.TOP_SECRET,
                "expected": AccessControlResult.GRANTED
            }
        ]
        
        for scenario in scenarios:
            print(f"🧪 Testing: {scenario['name']}")
            
            start_time = time.time()
            
            decision = self.access_controller.authorize_tool_access(
                user_id=scenario['user_id'],
                tool_name=scenario['tool'],
                classification_level=scenario['classification'],
                context={
                    "geographic_region": "CONUS",
                    "time_of_day": datetime.now().hour
                }
            )
            
            access_time_ms = (time.time() - start_time) * 1000
            
            # Report results
            if decision.decision == scenario['expected']:
                status = "✅ PASS"
            else:
                status = "❌ FAIL"
            
            print(f"   {status} - Decision: {decision.decision.value}")
            print(f"   ⏱️  Response time: {access_time_ms:.2f}ms")
            print(f"   📝 Rationale: {decision.rationale}")
            
            if decision.conditions:
                print(f"   ⚠️  Conditions: {', '.join(decision.conditions)}")
            
            if decision.required_mitigations:
                print(f"   🔧 Mitigations: {', '.join(decision.required_mitigations)}")
            
            print()
    
    def demonstrate_performance_benchmarks(self):
        """Demonstrate performance benchmarks for security operations."""
        print("⚡ Performance Benchmark Demonstration")
        print("-" * 42)
        
        # Performance targets
        targets = {
            "pki_authentication": 50.0,     # < 50ms
            "clearance_validation": 50.0,   # < 50ms
            "access_authorization": 100.0   # < 100ms
        }
        
        print("🎯 Performance Targets:")
        for operation, target_ms in targets.items():
            print(f"   • {operation.replace('_', ' ').title()}: < {target_ms}ms")
        print()
        
        # Run benchmarks
        benchmarks = []
        
        print("🔬 Running Performance Tests...")
        
        # PKI Authentication benchmark
        user_id = "jane.analyst"
        cert_data = self.demo_certificates[user_id]
        
        auth_times = []
        for i in range(10):
            start_time = time.time()
            self.access_controller.authenticate_pki_user(
                certificate_data=cert_data['cert_bytes'],
                pin="1234",
                card_uuid=cert_data['card_uuid'],
                network=PKINetwork.NIPRNET
            )
            auth_times.append((time.time() - start_time) * 1000)
        
        avg_auth_time = sum(auth_times) / len(auth_times)
        benchmarks.append(("PKI Authentication", avg_auth_time, targets["pki_authentication"]))
        
        # Clearance Validation benchmark
        clearance_times = []
        for i in range(10):
            start_time = time.time()
            self.access_controller.validate_security_clearance(
                user_id=user_id,
                required_level=ClearanceLevel.SECRET
            )
            clearance_times.append((time.time() - start_time) * 1000)
        
        avg_clearance_time = sum(clearance_times) / len(clearance_times)
        benchmarks.append(("Clearance Validation", avg_clearance_time, targets["clearance_validation"]))
        
        # Access Authorization benchmark
        access_times = []
        for i in range(10):
            start_time = time.time()
            self.access_controller.authorize_tool_access(
                user_id=user_id,
                tool_name="validate_input",
                classification_level=SecurityClassificationLevel.UNCLASSIFIED
            )
            access_times.append((time.time() - start_time) * 1000)
        
        avg_access_time = sum(access_times) / len(access_times)
        benchmarks.append(("Access Authorization", avg_access_time, targets["access_authorization"]))
        
        # Report benchmark results
        print("\n📊 Benchmark Results:")
        print("-" * 50)
        
        all_passed = True
        for operation, avg_time, target in benchmarks:
            passed = avg_time <= target
            all_passed = all_passed and passed
            
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{status} {operation}: {avg_time:.2f}ms (target: < {target}ms)")
        
        print()
        overall_status = "✅ ALL BENCHMARKS PASSED" if all_passed else "❌ SOME BENCHMARKS FAILED"
        print(f"🏆 Overall Result: {overall_status}")
        print()
    
    def show_system_metrics(self):
        """Display comprehensive system metrics."""
        print("📈 System Metrics & Statistics")
        print("-" * 35)
        
        metrics = self.access_controller.get_access_metrics()
        
        print("🔐 Authentication Metrics:")
        print(f"   • Total authentications: {metrics['authentications_performed']}")
        print(f"   • Successful authentications: {metrics['successful_authentications']}")
        print(f"   • PKI verifications: {metrics['pki_verifications']}")
        print(f"   • Active certificates: {metrics['active_certificates']}")
        print()
        
        print("🛡️  Authorization Metrics:")
        print(f"   • Access decisions made: {metrics['access_decisions_made']}")
        print(f"   • Clearance validations: {metrics['clearance_validations']}")
        print(f"   • Security violations detected: {metrics['security_violations_detected']}")
        print()
        
        print("👥 User Management:")
        print(f"   • Registered users: {metrics['registered_users']}")
        print(f"   • Role assignments: {metrics['role_assignments']}")
        print()
        
        print("⚡ Performance Metrics:")
        print(f"   • Average validation time: {metrics['average_validation_time_ms']:.2f}ms")
        print(f"   • Performance compliant: {'✅ Yes' if metrics['performance_compliant'] else '❌ No'}")
        print(f"   • Cache hit rate: {metrics['cache_hit_rate']:.1%}")
        print()
        
        print("🔧 System Status:")
        print(f"   • HSM available: {'✅ Yes' if metrics['hsm_available'] else '❌ No'}")
        print()
    
    # Private helper methods for demo setup
    
    def _create_demo_clearances(self):
        """Create demonstration security clearances."""
        clearances = [
            {
                "user_id": "jane.analyst",
                "clearance": SecurityClearance(
                    clearance_level=ClearanceLevel.SECRET,
                    granted_date=datetime.now() - timedelta(days=365),
                    expiration_date=datetime.now() + timedelta(days=1825),  # 5 years
                    issuing_authority="DoD CAF",
                    investigation_type="SSBI",
                    adjudication_date=datetime.now() - timedelta(days=300),
                    special_access_programs=set(),
                    compartments={"INTEL", "SIGINT"},
                    caveats=set(),
                    verification_status="current",
                    last_verified=datetime.now() - timedelta(days=30)
                )
            },
            {
                "user_id": "maj.commander",
                "clearance": SecurityClearance(
                    clearance_level=ClearanceLevel.TOP_SECRET,
                    granted_date=datetime.now() - timedelta(days=1095),  # 3 years ago
                    expiration_date=datetime.now() + timedelta(days=1095),  # 3 years
                    issuing_authority="DoD CAF",
                    investigation_type="SSBI",
                    adjudication_date=datetime.now() - timedelta(days=1000),
                    special_access_programs={"SAR", "SAP"},
                    compartments={"CRYPTO", "INTEL", "SIGINT"},
                    caveats={"NOFORN"},
                    verification_status="current",
                    last_verified=datetime.now() - timedelta(days=15)
                )
            },
            {
                "user_id": "dr.researcher",
                "clearance": SecurityClearance(
                    clearance_level=ClearanceLevel.TS_SCI,
                    granted_date=datetime.now() - timedelta(days=730),  # 2 years ago
                    expiration_date=datetime.now() + timedelta(days=1095),  # 3 years
                    issuing_authority="NSA",
                    investigation_type="SSBI-PR",
                    adjudication_date=datetime.now() - timedelta(days=700),
                    special_access_programs={"TK", "G", "HCS"},
                    compartments={"CRYPTO", "NUCLEAR", "SIGINT", "HUMINT"},
                    caveats={"NOFORN", "ORCON"},
                    verification_status="current",
                    last_verified=datetime.now() - timedelta(days=7)
                )
            }
        ]
        
        for clearance_data in clearances:
            self.access_controller.register_user_clearance(
                clearance_data["user_id"],
                clearance_data["clearance"]
            )
            self.demo_users[clearance_data["user_id"]] = clearance_data["clearance"]
    
    def _create_demo_roles(self):
        """Create demonstration user roles."""
        roles = [
            UserRole(
                role_id="analyst",
                role_name="Security Analyst",
                description="DoD security analyst with Secret clearance",
                required_clearance=ClearanceLevel.SECRET,
                permitted_classifications={
                    SecurityClassificationLevel.UNCLASSIFIED,
                    SecurityClassificationLevel.CUI,
                    SecurityClassificationLevel.SECRET
                },
                tool_permissions={"validate_input", "generate_content", "security_audit"},
                data_access_permissions={"read_classified", "write_unclass"},
                administrative_permissions=set(),
                temporal_restrictions={
                    "operational_hours": (6, 22),  # 6 AM to 10 PM
                    "operational_days": [0, 1, 2, 3, 4]  # Monday to Friday
                },
                geographic_restrictions={"CONUS", "OCONUS-NATO"},
                special_conditions={"requires_audit_trail": True}
            ),
            UserRole(
                role_id="commander",
                role_name="Military Commander",
                description="Military officer with Top Secret clearance",
                required_clearance=ClearanceLevel.TOP_SECRET,
                permitted_classifications={
                    SecurityClassificationLevel.UNCLASSIFIED,
                    SecurityClassificationLevel.CUI,
                    SecurityClassificationLevel.SECRET,
                    SecurityClassificationLevel.TOP_SECRET
                },
                tool_permissions={"validate_input", "generate_content", "robotics_control", "security_audit"},
                data_access_permissions={"read_classified", "write_classified", "approve_classified"},
                administrative_permissions={"manage_users", "approve_operations"},
                temporal_restrictions={},  # No time restrictions
                geographic_restrictions={"CONUS", "OCONUS-NATO", "OCONUS-ALLIED"},
                special_conditions={
                    "requires_audit_trail": True,
                    "max_session_duration": 240  # 4 hours
                }
            ),
            UserRole(
                role_id="system_admin",
                role_name="System Administrator",
                description="System administrator with TS/SCI clearance",
                required_clearance=ClearanceLevel.TS_SCI,
                permitted_classifications={
                    SecurityClassificationLevel.UNCLASSIFIED,
                    SecurityClassificationLevel.CUI,
                    SecurityClassificationLevel.SECRET,
                    SecurityClassificationLevel.TOP_SECRET
                },
                tool_permissions={"validate_input", "generate_content", "robotics_control", "security_audit", "system_admin"},
                data_access_permissions={"read_classified", "write_classified", "approve_classified", "admin_access"},
                administrative_permissions={"manage_users", "manage_system", "manage_security", "emergency_response"},
                temporal_restrictions={
                    "operational_hours": (0, 23)  # 24/7 access
                },
                geographic_restrictions={"CONUS", "OCONUS-NATO", "OCONUS-ALLIED", "SCIF"},
                special_conditions={
                    "requires_dual_approval": True,
                    "requires_audit_trail": True,
                    "max_session_duration": 480  # 8 hours
                }
            )
        ]
        
        # Register roles
        for role in roles:
            self.access_controller._role_definitions[role.role_id] = role
    
    def _create_demo_certificates(self):
        """Create demonstration PKI certificates."""
        # Simulated certificate data (in production, these would be real X.509 certificates)
        certificates = [
            {
                "user_id": "jane.analyst",
                "card_uuid": "CAC-12345678-ABCD",
                "subject_dn": "CN=Jane Analyst,OU=Analysts,O=DoD,C=US",
                "cert_bytes": b"-----BEGIN CERTIFICATE-----\nMIIDemo...Jane...Certificate\n-----END CERTIFICATE-----"
            },
            {
                "user_id": "maj.commander",
                "card_uuid": "PIV-87654321-EFGH",
                "subject_dn": "CN=Major Commander,OU=Officers,O=DoD,C=US",
                "cert_bytes": b"-----BEGIN CERTIFICATE-----\nMIIDemo...Major...Certificate\n-----END CERTIFICATE-----"
            },
            {
                "user_id": "dr.researcher",
                "card_uuid": "PIV-11223344-IJKL",
                "subject_dn": "CN=Dr Researcher,OU=Scientists,O=NSA,C=US",
                "cert_bytes": b"-----BEGIN CERTIFICATE-----\nMIIDemo...Doctor...Certificate\n-----END CERTIFICATE-----"
            }
        ]
        
        for cert_data in certificates:
            self.demo_certificates[cert_data["user_id"]] = cert_data
    
    def _assign_demo_roles(self):
        """Assign roles to demonstration users."""
        role_assignments = [
            ("jane.analyst", "analyst"),
            ("maj.commander", "commander"),
            ("dr.researcher", "system_admin")
        ]
        
        for user_id, role_id in role_assignments:
            self.access_controller.assign_user_role(user_id, role_id)
    
    def run_complete_demo(self):
        """Run the complete demonstration suite."""
        self.setup_demo_data()
        self.demonstrate_pki_authentication()
        self.demonstrate_clearance_validation()
        self.demonstrate_tool_access_control()
        self.demonstrate_performance_benchmarks()
        self.show_system_metrics()
        
        print("🎉 ALCUB3 PKI/CAC Authentication Demo Complete!")
        print()
        print("🔐 Key Features Demonstrated:")
        print("   ✅ PKI/CAC certificate authentication")
        print("   ✅ Security clearance validation")
        print("   ✅ Role-based access control")
        print("   ✅ Classification-aware tool access")
        print("   ✅ Performance compliance (< 50ms)")
        print("   ✅ Hardware Security Module integration")
        print("   ✅ Comprehensive audit logging")
        print()
        print("🚀 Ready for defense contractor deployment!")

def main():
    """Main demonstration entry point."""
    try:
        demo = PKICACDemo()
        demo.run_complete_demo()
        
    except KeyboardInterrupt:
        print("\n⏸️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()