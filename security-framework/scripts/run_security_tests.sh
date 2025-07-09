#!/bin/bash

# ALCUB3 Security Testing Execution Script
# Comprehensive security validation and automated testing orchestration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SECURITY_FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="${SECURITY_FRAMEWORK_DIR}/tests"
REPORTS_DIR="${SECURITY_FRAMEWORK_DIR}/security_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${REPORTS_DIR}/security_report_${TIMESTAMP}.json"

# Create reports directory if it doesn't exist
mkdir -p "${REPORTS_DIR}"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "$BLUE" "🔍 Checking prerequisites..."
    
    # Check Python version
    if ! python3 --version | grep -E "3\.(8|9|10|11)" > /dev/null; then
        print_status "$RED" "❌ Python 3.8+ required"
        exit 1
    fi
    
    # Check required Python packages
    local required_packages=("pytest" "pytest-asyncio" "asyncio" "pyyaml")
    for package in "${required_packages[@]}"; do
        if ! python3 -c "import ${package}" 2>/dev/null; then
            print_status "$YELLOW" "⚠️  Installing ${package}..."
            pip3 install "${package}"
        fi
    done
    
    print_status "$GREEN" "✅ Prerequisites check passed"
}

# Function to run MAESTRO unit tests
run_maestro_tests() {
    print_status "$BLUE" "🔒 Running MAESTRO Security Framework Tests..."
    
    cd "${SECURITY_FRAMEWORK_DIR}"
    
    if python3 run_tests.py --verbose; then
        print_status "$GREEN" "✅ MAESTRO tests passed"
        return 0
    else
        print_status "$RED" "❌ MAESTRO tests failed"
        return 1
    fi
}

# Function to run automated security tests
run_automated_security_tests() {
    print_status "$BLUE" "🤖 Running Automated Security Tests..."
    
    cd "${SECURITY_FRAMEWORK_DIR}"
    
    # Create temporary test runner
    cat > "${SECURITY_FRAMEWORK_DIR}/temp_security_test_runner.py" << 'EOF'
#!/usr/bin/env python3
import asyncio
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.automated_security_testing import (
    AutomatedSecurityTestingOrchestrator,
    TestPriority,
    TestCategory
)

async def run_all_security_tests():
    """Run all registered security tests."""
    print("🚀 Starting Automated Security Testing Orchestrator...")
    
    orchestrator = AutomatedSecurityTestingOrchestrator()
    orchestrator.start()
    
    # Queue all critical tests
    critical_tests = [
        "vuln_scan_maestro",
        "pen_test_prompt_injection",
        "compliance_fips_validation",
        "container_escape_test",
        "air_gap_validation"
    ]
    
    print("\n📋 Queueing critical security tests...")
    for test_id in critical_tests:
        try:
            orchestrator.queue_test(test_id, TestPriority.CRITICAL)
            print(f"  ✓ Queued: {test_id}")
        except Exception as e:
            print(f"  ✗ Failed to queue {test_id}: {str(e)}")
    
    # Wait for tests to complete
    print("\n⏳ Executing tests (this may take several minutes)...")
    await asyncio.sleep(30)  # Give tests time to run
    
    # Generate report
    report = orchestrator.get_security_report()
    
    # Save report
    report_file = sys.argv[1] if len(sys.argv) > 1 else "security_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    # Print summary
    metrics = report['metrics']
    print("\n📊 Security Test Results Summary:")
    print(f"  • Total Tests Run: {metrics['total_tests_run']}")
    print(f"  • Successful Tests: {metrics['successful_tests']}")
    print(f"  • Failed Tests: {metrics['failed_tests']}")
    print(f"  • Security Score: {metrics['security_score']:.1f}/100")
    print(f"  • Total Vulnerabilities: {metrics['vulnerabilities_found']}")
    print(f"    - Critical: {metrics['critical_vulnerabilities']}")
    print(f"    - High: {metrics['high_vulnerabilities']}")
    print(f"    - Medium: {metrics['medium_vulnerabilities']}")
    print(f"    - Low: {metrics['low_vulnerabilities']}")
    
    # Print recommendations
    if report['recommendations']:
        print("\n🔧 Recommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")
    
    orchestrator.stop()
    
    # Return non-zero if critical vulnerabilities found
    return 1 if metrics['critical_vulnerabilities'] > 0 else 0

if __name__ == "__main__":
    exit_code = asyncio.run(run_all_security_tests())
    sys.exit(exit_code)
EOF
    
    # Run the test runner
    if python3 temp_security_test_runner.py "${REPORT_FILE}"; then
        print_status "$GREEN" "✅ Automated security tests completed"
        rm -f temp_security_test_runner.py
        return 0
    else
        print_status "$RED" "❌ Critical vulnerabilities found"
        rm -f temp_security_test_runner.py
        return 1
    fi
}

# Function to run static analysis
run_static_analysis() {
    print_status "$BLUE" "🔍 Running Static Security Analysis..."
    
    cd "${SECURITY_FRAMEWORK_DIR}"
    
    # Run bandit if available
    if command -v bandit &> /dev/null; then
        print_status "$YELLOW" "  Running Bandit..."
        bandit -r src/ -f json -o "${REPORTS_DIR}/bandit_report_${TIMESTAMP}.json" || true
        bandit -r src/ -f txt || true
    else
        print_status "$YELLOW" "  ⚠️  Bandit not installed, skipping static analysis"
    fi
    
    # Run pylint if available
    if command -v pylint &> /dev/null; then
        print_status "$YELLOW" "  Running Pylint..."
        pylint src/ --output-format=json > "${REPORTS_DIR}/pylint_report_${TIMESTAMP}.json" || true
    fi
}

# Function to run dependency scanning
run_dependency_scan() {
    print_status "$BLUE" "📦 Running Dependency Vulnerability Scan..."
    
    cd "${SECURITY_FRAMEWORK_DIR}"
    
    # Check Python dependencies with safety
    if command -v safety &> /dev/null; then
        print_status "$YELLOW" "  Scanning Python dependencies..."
        safety check --json > "${REPORTS_DIR}/safety_report_${TIMESTAMP}.json" || true
        safety check || true
    else
        print_status "$YELLOW" "  ⚠️  Safety not installed, skipping dependency scan"
    fi
}

# Function to generate executive summary
generate_executive_summary() {
    print_status "$BLUE" "📄 Generating Executive Summary..."
    
    # Create summary script
    cat > "${SECURITY_FRAMEWORK_DIR}/generate_summary.py" << 'EOF'
import json
import sys
from datetime import datetime
from pathlib import Path

def generate_summary(report_file):
    """Generate executive summary from security report."""
    
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    metrics = report.get('metrics', {})
    
    # Generate markdown summary
    summary = f"""# ALCUB3 Security Testing Executive Summary

**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

## Overall Security Posture

- **Security Score**: {metrics.get('security_score', 0):.1f}/100
- **Total Tests Executed**: {metrics.get('total_tests_run', 0)}
- **Test Success Rate**: {(metrics.get('successful_tests', 0) / max(metrics.get('total_tests_run', 1), 1) * 100):.1f}%

## Vulnerability Summary

| Severity | Count | Impact |
|----------|-------|--------|
| Critical | {metrics.get('critical_vulnerabilities', 0)} | Immediate action required |
| High | {metrics.get('high_vulnerabilities', 0)} | Address within 24 hours |
| Medium | {metrics.get('medium_vulnerabilities', 0)} | Address within 1 week |
| Low | {metrics.get('low_vulnerabilities', 0)} | Track for future resolution |

**Total Vulnerabilities**: {metrics.get('vulnerabilities_found', 0)}

## Compliance Status

"""
    
    for standard, compliant in metrics.get('compliance_status', {}).items():
        status = "✅ Compliant" if compliant else "❌ Non-compliant"
        summary += f"- **{standard}**: {status}\n"
    
    summary += "\n## Key Recommendations\n\n"
    
    for rec in report.get('recommendations', []):
        summary += f"- {rec}\n"
    
    summary += "\n## Recent Test Executions\n\n"
    
    for test in report.get('recent_executions', [])[:5]:
        status_icon = "✅" if test['status'] == 'completed' else "❌"
        summary += f"- {status_icon} **{test['test_name']}**: {test.get('vulnerabilities_found', 0)} vulnerabilities\n"
    
    # Save summary
    summary_file = report_file.replace('.json', '_summary.md')
    with open(summary_file, 'w') as f:
        f.write(summary)
    
    print(f"\n{summary}")
    
    return metrics.get('critical_vulnerabilities', 0) == 0

if __name__ == "__main__":
    report_file = sys.argv[1] if len(sys.argv) > 1 else "security_report.json"
    success = generate_summary(report_file)
    sys.exit(0 if success else 1)
EOF
    
    # Generate summary
    python3 generate_summary.py "${REPORT_FILE}"
    rm -f generate_summary.py
}

# Function to run specific test category
run_test_category() {
    local category=$1
    print_status "$BLUE" "🎯 Running ${category} tests..."
    
    cd "${SECURITY_FRAMEWORK_DIR}"
    
    # Map category to test pattern
    case $category in
        "vulnerability")
            pytest tests/test_*vulnerability*.py -v
            ;;
        "penetration")
            pytest tests/test_penetration*.py -v
            ;;
        "compliance")
            pytest tests/test_*compliance*.py tests/test_*owasp*.py -v
            ;;
        "performance")
            pytest tests/test_*performance*.py -v
            ;;
        *)
            print_status "$RED" "Unknown test category: ${category}"
            return 1
            ;;
    esac
}

# Main execution
main() {
    print_status "$BLUE" "🔒 ALCUB3 Security Testing Framework"
    print_status "$BLUE" "===================================="
    
    # Parse command line arguments
    TEST_TYPE="${1:-all}"
    
    # Check prerequisites
    check_prerequisites
    
    # Initialize test results
    TESTS_PASSED=0
    TESTS_FAILED=0
    
    case $TEST_TYPE in
        "all")
            # Run all test suites
            if run_maestro_tests; then
                ((TESTS_PASSED++))
            else
                ((TESTS_FAILED++))
            fi
            
            if run_automated_security_tests; then
                ((TESTS_PASSED++))
            else
                ((TESTS_FAILED++))
            fi
            
            run_static_analysis
            run_dependency_scan
            ;;
        
        "maestro")
            if run_maestro_tests; then
                ((TESTS_PASSED++))
            else
                ((TESTS_FAILED++))
            fi
            ;;
        
        "automated")
            if run_automated_security_tests; then
                ((TESTS_PASSED++))
            else
                ((TESTS_FAILED++))
            fi
            ;;
        
        "static")
            run_static_analysis
            ;;
        
        "dependencies")
            run_dependency_scan
            ;;
        
        "vulnerability"|"penetration"|"compliance"|"performance")
            if run_test_category "$TEST_TYPE"; then
                ((TESTS_PASSED++))
            else
                ((TESTS_FAILED++))
            fi
            ;;
        
        *)
            print_status "$RED" "❌ Unknown test type: ${TEST_TYPE}"
            echo "Usage: $0 [all|maestro|automated|static|dependencies|vulnerability|penetration|compliance|performance]"
            exit 1
            ;;
    esac
    
    # Generate executive summary if we ran automated tests
    if [[ "$TEST_TYPE" == "all" || "$TEST_TYPE" == "automated" ]]; then
        generate_executive_summary
    fi
    
    # Final status
    print_status "$BLUE" "\n===================================="
    print_status "$BLUE" "📊 Final Test Results:"
    print_status "$GREEN" "  ✅ Passed: ${TESTS_PASSED}"
    print_status "$RED" "  ❌ Failed: ${TESTS_FAILED}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        print_status "$GREEN" "\n🎉 All security tests passed!"
        exit 0
    else
        print_status "$RED" "\n⚠️  Some tests failed. Review the reports in: ${REPORTS_DIR}"
        exit 1
    fi
}

# Run main function
main "$@"