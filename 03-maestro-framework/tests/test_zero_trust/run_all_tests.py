#!/usr/bin/env python3
"""
Run all Zero-Trust component tests with coverage reporting
"""

import sys
import subprocess
from pathlib import Path

def run_tests():
    """Run all zero-trust tests with coverage."""
    
    # Test files
    test_files = [
        "test_microsegmentation.py",
        "test_continuous_verification.py",
        "test_identity_access_control.py",
        "test_device_trust_scorer.py",
        "test_policy_engine.py",
        "test_network_gateway.py",
        "test_integration.py"
    ]
    
    # Base directory
    test_dir = Path(__file__).parent
    
    print("Running ALCUB3 Zero-Trust Test Suite")
    print("=" * 50)
    
    # Run pytest with coverage
    cmd = [
        sys.executable, "-m", "pytest",
        "-v",
        "--cov=shared.zero_trust",
        "--cov=shared.zero_trust_integration",
        "--cov=shared.zero_trust_orchestrator",
        "--cov-report=term-missing",
        "--cov-report=html:coverage_report",
        "-x",  # Stop on first failure
        "--tb=short"
    ]
    
    # Add all test files
    for test_file in test_files:
        cmd.append(str(test_dir / test_file))
    
    # Run tests
    result = subprocess.run(cmd, cwd=str(test_dir.parent.parent))
    
    if result.returncode == 0:
        print("\n✅ All tests passed!")
        print("\nCoverage report generated in: coverage_report/index.html")
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)
    
    # Run performance benchmarks
    print("\n" + "=" * 50)
    print("Running Performance Benchmarks")
    print("=" * 50)
    
    benchmark_cmd = [
        sys.executable, "-m", "pytest",
        "-v",
        "-k", "performance",
        "--benchmark-only",
        "--benchmark-autosave"
    ]
    
    # Run benchmarks
    subprocess.run(benchmark_cmd, cwd=str(test_dir))
    
    print("\n✅ Test suite complete!")

if __name__ == "__main__":
    run_tests()