#!/usr/bin/env python3
"""
MAESTRO Security Framework Test Runner
Simple test runner for validating MAESTRO L1-L3 security implementations

Usage:
    python run_tests.py [--verbose] [--test-pattern TEST_PATTERN]
"""

import sys
import os
import unittest
import argparse
from pathlib import Path

# Add the security framework to Python path
security_framework_path = Path(__file__).parent
sys.path.insert(0, str(security_framework_path))

def run_maestro_tests(verbose=False, test_pattern=None):
    """Run MAESTRO security framework tests."""
    
    print("🔒 ALCUB3 MAESTRO Security Framework Test Suite")
    print("=" * 50)
    
    # Discover and run tests
    loader = unittest.TestLoader()
    
    if test_pattern:
        # Run specific test pattern
        suite = loader.loadTestsFromName(test_pattern)
    else:
        # Discover all tests in the tests directory
        test_dir = security_framework_path / "tests"
        suite = loader.discover(str(test_dir), pattern="test_*.py")
    
    # Configure test runner
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        stream=sys.stdout,
        buffer=True
    )
    
    # Run tests
    print(f"Running MAESTRO security tests...")
    print(f"Test discovery path: {test_dir}")
    print("-" * 50)
    
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print("🔒 MAESTRO Test Results Summary")
    print("=" * 50)
    
    if result.wasSuccessful():
        print("✅ All MAESTRO security tests PASSED!")
        print(f"   Tests run: {result.testsRun}")
        print("   Security framework validation: SUCCESSFUL")
        return 0
    else:
        print("❌ MAESTRO security tests FAILED!")
        print(f"   Tests run: {result.testsRun}")
        print(f"   Failures: {len(result.failures)}")
        print(f"   Errors: {len(result.errors)}")
        
        if result.failures:
            print("\n🚫 Test Failures:")
            for test, traceback in result.failures:
                print(f"   - {test}: {traceback.split('AssertionError:')[-1].strip()}")
        
        if result.errors:
            print("\n💥 Test Errors:")
            for test, traceback in result.errors:
                print(f"   - {test}: {traceback.split('Error:')[-1].strip()}")
        
        return 1

def main():
    """Main test runner entry point."""
    parser = argparse.ArgumentParser(
        description="MAESTRO Security Framework Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_tests.py                                    # Run all tests
    python run_tests.py --verbose                          # Run with verbose output
    python run_tests.py --test-pattern test_maestro_integration  # Run specific test module
        """
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose test output"
    )
    
    parser.add_argument(
        "--test-pattern", "-t",
        type=str,
        help="Specific test pattern to run (e.g., test_maestro_integration)"
    )
    
    args = parser.parse_args()
    
    try:
        exit_code = run_maestro_tests(
            verbose=args.verbose,
            test_pattern=args.test_pattern
        )
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Test execution interrupted by user")
        sys.exit(130)
        
    except Exception as e:
        print(f"\n💥 Test runner error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 