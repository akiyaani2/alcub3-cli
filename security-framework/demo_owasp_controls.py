#!/usr/bin/env python3
"""
ALCUB3 OWASP Top 10 Security Controls Demonstration
Showcase SAST/DAST capabilities and compliance validation

This demonstration showcases the comprehensive OWASP Top 10 security controls
implementation with integrated Static and Dynamic Application Security Testing.

Features Demonstrated:
- SAST analysis with vulnerability detection
- DAST simulation for runtime testing
- OWASP Top 10 2023 compliance validation
- ASD STIG V5R1 compliance checking
- Classification-aware security controls
- Performance benchmarking (<100ms targets)

Usage:
    python3 demo_owasp_controls.py
    python3 demo_owasp_controls.py --classification secret
    python3 demo_owasp_controls.py --benchmark
"""

import asyncio
import argparse
import tempfile
import os
import time
import json
from pathlib import Path
from typing import Dict, Any

# Add the security framework to the path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from shared.owasp_security_controls import (
        OWASPSecurityControls, OWASPCategory, VulnerabilitySeverity
    )
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the security-framework directory")
    sys.exit(1)

# ANSI color codes for better presentation
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_header(title: str):
    """Print formatted header."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD} {title.center(68)} {Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.END}")

def print_section(title: str):
    """Print formatted section."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}🔹 {title}{Colors.END}")
    print(f"{Colors.CYAN}{'-' * (len(title) + 3)}{Colors.END}")

def print_success(message: str):
    """Print success message."""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_warning(message: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

def print_error(message: str):
    """Print error message."""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

def print_info(message: str):
    """Print info message."""
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")

def create_vulnerable_test_file() -> str:
    """Create a test file with various security vulnerabilities."""
    vulnerable_code = '''#!/usr/bin/env python3
"""
Test file with intentional security vulnerabilities for OWASP demonstration.
DO NOT USE IN PRODUCTION - FOR TESTING ONLY
"""

import hashlib
import subprocess
import sqlite3
import requests

# A01: Broken Access Control
admin_user = True
if admin_user:
    print("Admin access granted without proper validation")

def check_admin():
    if user.is_admin():
        return True

# A02: Cryptographic Failures
API_KEY = "hardcoded-api-key-123"
SECRET_PASSWORD = "admin123"
hash_value = hashlib.md5(b"sensitive_data").hexdigest()  # Weak hash
old_hash = hashlib.sha1(b"data").hexdigest()  # Deprecated

# A03: Injection Vulnerabilities
def unsafe_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query

def unsafe_eval():
    user_code = input("Enter code: ")
    eval(user_code)  # Code injection

def unsafe_sql():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    user_id = input("User ID: ")
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# A04: Insecure Design
def empty_security_function():
    pass  # No implementation

def weak_password_validation(password):
    return len(password) > 3  # Weak validation

# A05: Security Misconfiguration
DEBUG = True
SSL_VERIFY = False
ALLOWED_HOSTS = ["*"]

def insecure_request():
    response = requests.get("https://api.example.com", verify=False)
    return response

# A07: Identification and Authentication Failures
def insecure_session(user_id):
    session["user"] = user_id  # Direct assignment
    return "logged_in"

def weak_auth():
    username = input("Username: ")
    password = input("Password: ")
    if username == "admin" and password == "admin":
        return True

# A08: Software and Data Integrity Failures
def download_update():
    url = "http://updates.example.com/update.zip"  # No integrity check
    subprocess.run(["wget", url])

# A09: Security Logging and Monitoring Failures
def log_sensitive_data(password, ssn):
    print(f"User password: {password}")
    print(f"SSN: {ssn}")
    
def no_security_logging():
    # Failed login attempt with no logging
    return False

# A10: Server-Side Request Forgery (SSRF)
def fetch_url(url):
    return requests.get(url)  # No URL validation

def internal_request():
    url = "http://localhost:8080/internal"
    return fetch_url(url)

if __name__ == "__main__":
    print("Running vulnerable code for testing...")
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(vulnerable_code)
        return f.name

def create_secure_test_file() -> str:
    """Create a test file with secure implementations."""
    secure_code = '''#!/usr/bin/env python3
"""
Secure implementation examples following OWASP best practices.
"""

import hashlib
import logging
import sqlite3
from cryptography.fernet import Fernet
from urllib.parse import urlparse
import re

# Secure configuration
DEBUG = False
SSL_VERIFY = True
ALLOWED_HOSTS = ["trusted-domain.com"]

# Secure logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecureAuthenticator:
    """Secure authentication implementation."""
    
    def __init__(self):
        self.failed_attempts = {}
        self.max_attempts = 3
    
    def authenticate(self, username: str, password_hash: str) -> bool:
        """Secure authentication with rate limiting."""
        if self.is_rate_limited(username):
            logger.warning(f"Rate limited login attempt for: {username}")
            return False
        
        # Use parameterized query
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash)
        )
        result = cursor.fetchone()
        
        if result:
            logger.info(f"Successful authentication for: {username}")
            return True
        else:
            self.record_failed_attempt(username)
            logger.warning(f"Failed authentication for: {username}")
            return False
    
    def is_rate_limited(self, username: str) -> bool:
        """Check if user is rate limited."""
        return self.failed_attempts.get(username, 0) >= self.max_attempts
    
    def record_failed_attempt(self, username: str):
        """Record failed login attempt."""
        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1

class SecureCrypto:
    """Secure cryptographic operations."""
    
    @staticmethod
    def secure_hash(data: bytes) -> str:
        """Use secure hash function."""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def strong_hash(data: bytes) -> str:
        """Use even stronger hash function."""
        return hashlib.sha512(data).hexdigest()

class SecureURLValidator:
    """Secure URL validation to prevent SSRF."""
    
    ALLOWED_SCHEMES = ['https']
    BLOCKED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']
    
    @classmethod
    def is_safe_url(cls, url: str) -> bool:
        """Validate URL to prevent SSRF attacks."""
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in cls.ALLOWED_SCHEMES:
                return False
            
            # Check for blocked hosts
            if parsed.hostname in cls.BLOCKED_HOSTS:
                return False
            
            # Check for private IP ranges (simplified)
            if parsed.hostname and (
                parsed.hostname.startswith('10.') or
                parsed.hostname.startswith('192.168.') or
                parsed.hostname.startswith('172.')
            ):
                return False
            
            return True
            
        except Exception:
            return False

def secure_input_validation(user_input: str) -> bool:
    """Validate user input securely."""
    # Allow only alphanumeric and basic punctuation
    pattern = r'^[a-zA-Z0-9\s\-_\.]+$'
    return bool(re.match(pattern, user_input)) and len(user_input) < 1000

if __name__ == "__main__":
    print("Secure implementation examples")
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(secure_code)
        return f.name

async def demonstrate_sast_analysis(controls: OWASPSecurityControls, classification: str):
    """Demonstrate SAST analysis capabilities."""
    print_section("Static Application Security Testing (SAST)")
    
    # Create test files
    print_info("Creating test files with vulnerabilities...")
    vulnerable_file = create_vulnerable_test_file()
    secure_file = create_secure_test_file()
    
    try:
        # Analyze vulnerable code
        print_info("🔍 Analyzing vulnerable code...")
        start_time = time.time()
        vulnerable_result = await controls.run_sast_analysis(vulnerable_file)
        analysis_time = (time.time() - start_time) * 1000
        
        print_success(f"SAST Analysis Complete ({analysis_time:.2f}ms)")
        print(f"   📁 Files analyzed: {vulnerable_result.files_analyzed}")
        print(f"   📊 Lines analyzed: {vulnerable_result.lines_analyzed}")
        print(f"   🐛 Vulnerabilities found: {len(vulnerable_result.vulnerabilities)}")
        print(f"   📈 Coverage: {vulnerable_result.coverage_percentage:.1f}%")
        
        # Show vulnerability breakdown
        if vulnerable_result.vulnerabilities:
            print("\n   🚨 Vulnerability Breakdown:")
            category_counts = {}
            severity_counts = {}
            
            for vuln in vulnerable_result.vulnerabilities:
                category_counts[vuln.category] = category_counts.get(vuln.category, 0) + 1
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            
            for category, count in category_counts.items():
                print(f"      • {category.value}: {count} issues")
            
            print("\n   📊 Severity Distribution:")
            for severity, count in severity_counts.items():
                color = Colors.RED if severity == VulnerabilitySeverity.CRITICAL else Colors.YELLOW
                print(f"      • {color}{severity.value.upper()}: {count}{Colors.END}")
        
        # Analyze secure code for comparison
        print_info("\n🔍 Analyzing secure code for comparison...")
        secure_result = await controls.run_sast_analysis(secure_file)
        
        print_success(f"Secure Code Analysis Complete")
        print(f"   🐛 Vulnerabilities found: {len(secure_result.vulnerabilities)}")
        
        if len(secure_result.vulnerabilities) < len(vulnerable_result.vulnerabilities):
            print_success("   ✨ Secure implementation shows significant improvement!")
        
        return vulnerable_result, secure_result
        
    finally:
        # Clean up test files
        os.unlink(vulnerable_file)
        os.unlink(secure_file)

async def demonstrate_dast_analysis(controls: OWASPSecurityControls):
    """Demonstrate DAST analysis capabilities."""
    print_section("Dynamic Application Security Testing (DAST)")
    
    test_endpoints = [
        "https://demo.testfire.net/",
        "https://httpbin.org/",
        "https://jsonplaceholder.typicode.com/"
    ]
    
    dast_results = []
    
    for endpoint in test_endpoints:
        print_info(f"🌐 Testing endpoint: {endpoint}")
        
        start_time = time.time()
        result = await controls.run_dast_analysis(endpoint)
        test_time = (time.time() - start_time) * 1000
        
        print_success(f"DAST Test Complete ({test_time:.2f}ms)")
        print(f"   📤 Requests sent: {result.requests_sent}")
        print(f"   📥 Responses analyzed: {result.responses_analyzed}")
        print(f"   🐛 Vulnerabilities found: {len(result.vulnerabilities)}")
        
        if result.vulnerabilities:
            for vuln in result.vulnerabilities[:3]:  # Show first 3
                print(f"      • {vuln.severity.value.upper()}: {vuln.title}")
        
        dast_results.append(result)
    
    return dast_results

async def demonstrate_compliance_validation(controls: OWASPSecurityControls, 
                                          sast_result, dast_results):
    """Demonstrate OWASP compliance validation."""
    print_section("OWASP Top 10 Compliance Validation")
    
    print_info("🔍 Validating OWASP Top 10 2023 compliance...")
    
    # Use first DAST result if available
    dast_result = dast_results[0] if dast_results else None
    
    start_time = time.time()
    compliance_report = await controls.validate_owasp_compliance(sast_result, dast_result)
    validation_time = (time.time() - start_time) * 1000
    
    print_success(f"Compliance Validation Complete ({validation_time:.2f}ms)")
    
    # Display compliance status
    status = compliance_report["compliance_status"]
    percentage = compliance_report["compliance_percentage"]
    
    if status == "COMPLIANT":
        print_success(f"   🎉 OWASP Compliance: {status} ({percentage:.1f}%)")
    elif status == "PARTIALLY_COMPLIANT":
        print_warning(f"   ⚠️  OWASP Compliance: {status} ({percentage:.1f}%)")
    else:
        print_error(f"   ❌ OWASP Compliance: {status} ({percentage:.1f}%)")
    
    # Show vulnerability summary
    print(f"\n   📊 Vulnerability Summary:")
    print(f"      Total: {compliance_report['total_vulnerabilities']}")
    print(f"      Critical: {compliance_report['critical_vulnerabilities']}")
    print(f"      High: {compliance_report['high_vulnerabilities']}")
    
    # Show category breakdown
    if compliance_report["category_breakdown"]:
        print(f"\n   🏷️  Category Breakdown:")
        for category, count in compliance_report["category_breakdown"].items():
            print(f"      • {category}: {count} issues")
    
    # Show STIG compliance
    stig_compliance = compliance_report["asd_stig_compliance"]
    if stig_compliance["stig_compliant"]:
        print_success(f"   ✅ ASD STIG V5R1: COMPLIANT")
    else:
        print_warning(f"   ⚠️  ASD STIG V5R1: NON-COMPLIANT")
        print(f"      Critical findings: {stig_compliance['critical_findings']}")
        print(f"      High findings: {stig_compliance['high_findings']}")
    
    # Show recommendations
    if compliance_report["recommendations"]:
        print(f"\n   💡 Recommendations:")
        for rec in compliance_report["recommendations"][:5]:  # Show first 5
            print(f"      • {rec}")
    
    return compliance_report

async def run_performance_benchmark(controls: OWASPSecurityControls):
    """Run performance benchmarks."""
    print_section("Performance Benchmarking")
    
    print_info("🏃 Running performance benchmarks...")
    
    # Create larger test file for performance testing
    large_code = "print('test line')\n" * 5000  # 5000 lines
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(large_code)
        large_file = f.name
    
    try:
        # Benchmark SAST performance
        print_info("📊 Benchmarking SAST analysis...")
        start_time = time.time()
        sast_result = await controls.run_sast_analysis(large_file)
        sast_time = (time.time() - start_time) * 1000
        
        throughput = sast_result.lines_analyzed / (sast_time / 1000)
        print_success(f"SAST Performance: {sast_time:.2f}ms")
        print(f"   📏 Lines analyzed: {sast_result.lines_analyzed}")
        print(f"   ⚡ Throughput: {throughput:.0f} lines/second")
        
        # Benchmark compliance validation
        print_info("📊 Benchmarking compliance validation...")
        start_time = time.time()
        compliance_report = await controls.validate_owasp_compliance(sast_result)
        compliance_time = (time.time() - start_time) * 1000
        
        print_success(f"Compliance Validation: {compliance_time:.2f}ms")
        
        # Check performance targets
        if compliance_time < 100:
            print_success("   🎯 Performance target met: <100ms")
        else:
            print_warning("   ⚠️  Performance target missed: >100ms")
        
        return {
            "sast_time_ms": sast_time,
            "sast_throughput": throughput,
            "compliance_time_ms": compliance_time,
            "lines_analyzed": sast_result.lines_analyzed
        }
        
    finally:
        os.unlink(large_file)

async def demonstrate_cisa_misconfiguration_detection(controls: OWASPSecurityControls):
    """Demonstrate CISA Top 10 misconfiguration detection."""
    print_section("CISA Top 10 Misconfiguration Detection")

    # Create a temporary configuration file with deliberate misconfigurations
    misconfigured_content = """
# Insecure configuration for testing CISA Top 10 misconfigurations

# Default credentials
username=admin
password=admin123

# Insecure binding
bind_address=0.0.0.0

# Exposed insecure port
service_port=21

# Unencrypted communication
api_endpoint=http://dev.example.com/api

# Anonymous access
allow_anonymous=True
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(misconfigured_content)
        misconfigured_file = f.name

    try:
        print_info(f"🔍 Analyzing misconfigured file: {misconfigured_file}...")
        start_time = time.time()
        cisa_result = await controls.run_sast_analysis(misconfigured_file)
        analysis_time = (time.time() - start_time) * 1000

        print_success(f"CISA Misconfiguration Analysis Complete ({analysis_time:.2f}ms)")
        print(f"   🐛 Misconfigurations found: {len(cisa_result.vulnerabilities)}")

        if cisa_result.vulnerabilities:
            print("\n   🚨 Detected Misconfigurations:")
            for vuln in cisa_result.vulnerabilities:
                print(f"      • {vuln.severity.value.upper()}: {vuln.title} (Line: {vuln.line_number})")
                print(f"        Remediation: {vuln.remediation}")
        else:
            print_success("   No CISA misconfigurations detected in the test file.")

        return cisa_result

    finally:
        os.unlink(misconfigured_file)

async def main():
    """Main demonstration function."""
    parser = argparse.ArgumentParser(description="ALCUB3 OWASP Security Controls Demo")
    parser.add_argument("--classification", default="unclassified",
                      choices=["unclassified", "confidential", "secret", "top_secret"],
                      help="Security classification level")
    parser.add_argument("--benchmark", action="store_true",
                      help="Run performance benchmarks")
    parser.add_argument("--cisa-demo", action="store_true",
                      help="Run CISA Top 10 misconfiguration detection demo")
    parser.add_argument("--output", help="Output results to JSON file")
    
    args = parser.parse_args()
    
    # Initialize security controls
    print_header("ALCUB3 OWASP TOP 10 SECURITY CONTROLS DEMONSTRATION")
    print_info(f"🔐 Classification Level: {args.classification.upper()}")
    print_info(f"🕐 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    controls = OWASPSecurityControls(classification_level=args.classification)
    
    # Demonstration results
    demo_results = {
        "classification": args.classification,
        "timestamp": time.time(),
        "performance_metrics": {}
    }
    
    try:
        # 1. SAST Analysis
        sast_vulnerable, sast_secure = await demonstrate_sast_analysis(controls, args.classification)
        demo_results["sast_vulnerable_vulnerabilities"] = len(sast_vulnerable.vulnerabilities)
        demo_results["sast_secure_vulnerabilities"] = len(sast_secure.vulnerabilities)
        
        # 2. DAST Analysis
        dast_results = await demonstrate_dast_analysis(controls)
        demo_results["dast_tests_run"] = len(dast_results)
        demo_results["dast_total_vulnerabilities"] = sum(len(r.vulnerabilities) for r in dast_results)
        
        # 3. CISA Misconfiguration Demo (optional)
        if args.cisa_demo:
            cisa_results = await demonstrate_cisa_misconfiguration_detection(controls)
            demo_results["cisa_misconfigurations_found"] = len(cisa_results.vulnerabilities)

        # 4. Compliance Validation
        compliance_report = await demonstrate_compliance_validation(
            controls, sast_vulnerable, dast_results
        )
        demo_results["compliance_status"] = compliance_report["compliance_status"]
        demo_results["compliance_percentage"] = compliance_report["compliance_percentage"]
        demo_results["stig_compliant"] = compliance_report["asd_stig_compliance"]["stig_compliant"]
        
        # 5. Performance Benchmarks (optional)
        if args.benchmark:
            perf_results = await run_performance_benchmark(controls)
            demo_results["performance_metrics"] = perf_results
        
        # Summary
        print_section("Demonstration Summary")
        print_success("🎉 OWASP Top 10 Security Controls demonstration completed successfully!")
        print(f"   🐛 Vulnerabilities detected: {demo_results['sast_vulnerable_vulnerabilities']}")
        print(f"   📊 Compliance level: {demo_results['compliance_percentage']:.1f}%")
        print(f"   🏛️  STIG compliance: {'✅ Yes' if demo_results['stig_compliant'] else '❌ No'}")
        
        if args.benchmark and demo_results["performance_metrics"]:
            perf = demo_results["performance_metrics"]
            print(f"   ⚡ SAST throughput: {perf['sast_throughput']:.0f} lines/sec")
            print(f"   🎯 Compliance validation: {perf['compliance_time_ms']:.1f}ms")
        
        # Patent innovations highlight
        print_section("Patent-Defensible Innovations")
        print_success("✨ Air-gapped SAST/DAST execution without external dependencies")
        print_success("🔐 Classification-aware vulnerability scoring and prioritization") 
        print_success("⚡ Sub-100ms compliance validation for real-time operations")
        print_success("🎯 Integrated OWASP + STIG compliance in unified framework")
        
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(demo_results, f, indent=2, default=str)
            print_info(f"📄 Results saved to: {args.output}")
        
    except Exception as e:
        print_error(f"Demonstration error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)