# ALCUB3 Zero-Trust Architecture Test Suite

This directory contains comprehensive tests for all zero-trust components in the ALCUB3 security framework.

## Test Coverage

### Component Tests

1. **test_microsegmentation.py** - Tests for microsegmentation engine
   - Network segment creation and management
   - Classification-aware packet processing
   - Policy evaluation and enforcement
   - Performance metrics (<5ms packet decisions)
   - Concurrent packet processing

2. **test_continuous_verification.py** - Tests for continuous authentication
   - Session creation and management
   - ML-based risk scoring
   - Behavioral anomaly detection
   - Adaptive authentication requirements
   - Classification-based policies

3. **test_identity_access_control.py** - Tests for ABAC engine
   - Policy creation and evaluation
   - Attribute-based access control
   - Clearance level enforcement
   - Complex condition matching
   - Policy caching (<1ms evaluations)

4. **test_device_trust_scorer.py** - Tests for device trust scoring
   - Device registration with hardware attestation
   - Trust score calculation
   - Compliance checking
   - Behavioral analysis
   - ML-based anomaly detection

5. **test_policy_engine.py** - Tests for policy management
   - Policy creation and versioning
   - Conflict resolution strategies
   - Policy simulation
   - Time-based and classification-aware policies
   - Bulk operations

6. **test_network_gateway.py** - Tests for SDP gateway
   - Micro-tunnel establishment
   - Protocol inspection (HTTP/HTTPS/SSH)
   - Zone-based access control
   - Tunnel rekeying and lifecycle
   - Performance metrics (10Gbps target)

7. **test_integration.py** - Tests for orchestration layer
   - Cross-component integration
   - Security posture management
   - Event correlation and incident response
   - Component health monitoring
   - End-to-end access evaluation

## Running Tests

### Run All Tests
```bash
python run_all_tests.py
```

### Run Individual Test Files
```bash
pytest test_microsegmentation.py -v
pytest test_continuous_verification.py -v
# etc.
```

### Run with Coverage
```bash
pytest --cov=shared.zero_trust --cov-report=html
```

### Run Performance Tests Only
```bash
pytest -k performance -v
```

### Run Specific Test Cases
```bash
pytest test_microsegmentation.py::TestMicrosegmentationEngine::test_packet_processing_allowed -v
```

## Test Requirements

- Python 3.8+
- pytest
- pytest-asyncio
- pytest-cov
- pytest-benchmark
- numpy (for ML tests)
- All MAESTRO framework dependencies

## Performance Targets Validated

- Microsegmentation: <5ms packet decisions ✓
- Identity Access Control: <1ms policy evaluation ✓
- Policy Engine: <1ms evaluation with 100k+ policies ✓
- Network Gateway: <5ms tunnel establishment ✓
- Continuous Verification: <10ms session verification ✓
- Device Trust Scoring: <10ms trust calculation ✓

## Test Patterns

### Async Testing
All components use async/await patterns:
```python
@pytest.mark.asyncio
async def test_async_operation(component):
    result = await component.async_method()
    assert result is not None
```

### Mock Usage
Extensive mocking for external dependencies:
```python
mock_logger = Mock(spec=AuditLogger)
mock_logger.log_event = AsyncMock()
```

### Performance Testing
Built-in performance assertions:
```python
assert stats['avg_decision_time_ms'] < 5.0  # Meet target
```

### Concurrent Testing
Validates concurrent operation handling:
```python
tasks = [component.process(data) for _ in range(100)]
results = await asyncio.gather(*tasks)
```

## Coverage Goals

- Line coverage: >90%
- Branch coverage: >85%
- All critical paths tested
- All error conditions handled
- Performance targets validated

## Integration with CI/CD

These tests are designed to run in CI/CD pipelines:
- Fast execution (<30 seconds total)
- No external dependencies required
- Deterministic results
- Clear failure messages
- Performance regression detection