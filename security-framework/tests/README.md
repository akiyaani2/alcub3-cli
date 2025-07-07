# MAESTRO Security Framework Tests

This directory contains comprehensive tests for the ALCUB3 MAESTRO security framework, validating L1-L3 security layer implementations and their integration.

## Test Structure

### Integration Tests (`test_maestro_integration.py`)

Comprehensive integration tests that validate:

- **L1 Foundation Security**: Prompt injection detection, adversarial input validation
- **L2 Data Security**: Classification enforcement, data flow control
- **L3 Agent Security**: Agent authorization, access control
- **Cross-Layer Integration**: End-to-end security workflows
- **Performance Requirements**: <100ms L1, <50ms L2, <25ms L3
- **Audit Trail Completeness**: Security event logging
- **Classification Inheritance**: Security level propagation
- **Framework Resilience**: Concurrent operation handling

## Running Tests

### Quick Start

```bash
# Run all MAESTRO security tests
python run_tests.py

# Run with verbose output
python run_tests.py --verbose

# Run specific test module
python run_tests.py --test-pattern test_maestro_integration
```

### From Project Root

```bash
# Run security framework tests from project root
cd security-framework
python run_tests.py
```

## Test Coverage

The test suite validates:

### Security Functionality
- ✅ Prompt injection detection (99.9% effectiveness target)
- ✅ Data classification accuracy
- ✅ Agent authorization controls
- ✅ Cross-layer security integration
- ✅ Audit trail integrity

### Performance Requirements
- ✅ L1 Foundation: <100ms validation time
- ✅ L2 Data: <50ms classification time  
- ✅ L3 Agent: <25ms authorization time
- ✅ Cross-layer: <200ms end-to-end time

### Compliance Validation
- ✅ FIPS 140-2 Level 3+ cryptographic operations
- ✅ STIG ASD V5R1 security controls
- ✅ Classification-aware security inheritance
- ✅ Defense-grade audit trail requirements

## Expected Results

When all tests pass, you should see:

```
🔒 ALCUB3 MAESTRO Security Framework Test Suite
==================================================
Running MAESTRO security tests...
Test discovery path: /path/to/security-framework/tests
--------------------------------------------------
........
----------------------------------------------------------------------
Ran 8 tests in X.XXXs

OK

==================================================
🔒 MAESTRO Test Results Summary
==================================================
✅ All MAESTRO security tests PASSED!
   Tests run: 8
   Security framework validation: SUCCESSFUL
```

## Test Dependencies

The tests require:
- Python 3.8+
- MAESTRO security framework modules
- Standard library modules (unittest, tempfile, threading)

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure you're running from the security-framework directory
2. **Permission Errors**: Tests create temporary directories - ensure write permissions
3. **Performance Failures**: Tests may fail on slower systems - adjust timeouts if needed

### Debug Mode

Run with verbose output to see detailed test execution:

```bash
python run_tests.py --verbose
```

## Adding New Tests

To add new security tests:

1. Create test files with `test_` prefix
2. Inherit from `unittest.TestCase`
3. Follow existing patterns for setup/teardown
4. Include performance and security validations
5. Add comprehensive docstrings

Example test structure:

```python
class TestNewSecurityFeature(unittest.TestCase):
    def setUp(self):
        # Initialize test environment
        pass
    
    def test_security_validation(self):
        # Test security functionality
        pass
    
    def test_performance_requirements(self):
        # Validate performance targets
        pass
    
    def tearDown(self):
        # Clean up test environment
        pass
```

## Security Test Principles

1. **Defense in Depth**: Test multiple security layers
2. **Performance Validation**: Ensure security doesn't impact performance
3. **Compliance Verification**: Validate regulatory requirements
4. **Resilience Testing**: Test under stress conditions
5. **Audit Trail Validation**: Ensure complete security logging 