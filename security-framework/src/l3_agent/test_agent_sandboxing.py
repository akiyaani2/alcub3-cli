"""
Integration Tests for Agent Sandboxing and Integrity Verification System
Task 2.13 - Comprehensive validation of patent-pending sandboxing innovations

This module provides comprehensive testing for the agent sandboxing system,
validating <5ms integrity verification, secure execution environments,
and classification-aware resource management.

Test Coverage:
- Sandbox creation and configuration
- Integrity verification performance (<5ms target)
- Resource monitoring and limits
- State persistence with encryption
- Classification-aware security controls
- Performance validation across all operations
"""

import os
import sys
import time
import unittest
import tempfile
import subprocess
import threading
from unittest.mock import Mock, patch
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from l3_agent.agent_sandboxing import (
    AgentSandboxingSystem, SandboxType, IntegrityCheckType, SandboxState,
    SandboxConfiguration, IntegrityValidationResult, SandboxMetrics,
    SandboxError, IntegrityViolationError
)
from shared.classification import SecurityClassification, ClassificationLevel
from shared.crypto_utils import FIPSCryptoUtils
from shared.audit_logger import AuditLogger

class TestAgentSandboxingSystem(unittest.TestCase):
    """Test suite for Agent Sandboxing System."""
    
    def setUp(self):
        """Set up test environment."""
        # Create mock dependencies
        self.classification_system = Mock(spec=SecurityClassification)
        self.classification_system.default_level = ClassificationLevel.UNCLASSIFIED
        
        self.crypto_utils = Mock(spec=FIPSCryptoUtils)
        self.audit_logger = Mock(spec=AuditLogger)
        
        # Mock crypto operations
        mock_key = Mock()
        mock_key.key_data = b"test_key_data_32_bytes_long_here"
        self.crypto_utils.generate_key.return_value = mock_key
        
        mock_encryption_result = Mock()
        mock_encryption_result.success = True
        mock_encryption_result.data = b"encrypted_test_data"
        self.crypto_utils.encrypt_data.return_value = mock_encryption_result
        
        # Create sandboxing system
        self.sandboxing_system = AgentSandboxingSystem(
            self.classification_system,
            self.crypto_utils,
            self.audit_logger
        )
        
        # Test data
        self.test_agent_id = "test_agent_001"
        self.test_classification = ClassificationLevel.UNCLASSIFIED

    def tearDown(self):
        """Clean up test environment."""
        # Stop background monitoring
        self.sandboxing_system.stop_monitoring()
        
        # Clean up any test files
        try:
            state_path = self.sandboxing_system._state_storage_path
            if state_path.exists():
                for file in state_path.glob("*.state"):
                    file.unlink()
        except:
            pass

    def test_create_sandbox_basic(self):
        """Test basic sandbox creation."""
        start_time = time.time()
        
        # Create sandbox
        sandbox_id = self.sandboxing_system.create_sandbox(
            self.test_agent_id,
            self.test_classification,
            SandboxType.PROCESS
        )
        
        creation_time = (time.time() - start_time) * 1000
        
        # Validate results
        self.assertIsNotNone(sandbox_id)
        self.assertIn(self.test_agent_id, sandbox_id)
        self.assertIn(sandbox_id, self.sandboxing_system._active_sandboxes)
        
        # Validate performance (should be < 100ms)
        self.assertLess(creation_time, 100.0, 
                       f"Sandbox creation took {creation_time:.2f}ms, expected < 100ms")
        
        # Validate sandbox state
        sandbox = self.sandboxing_system._active_sandboxes[sandbox_id]
        self.assertEqual(sandbox.agent_id, self.test_agent_id)
        self.assertEqual(sandbox.state, SandboxState.INITIALIZING)
        self.assertEqual(sandbox.sandbox_type, SandboxType.PROCESS)
        
        # Validate configuration created
        self.assertIn(sandbox_id, self.sandboxing_system._sandbox_configurations)
        config = self.sandboxing_system._sandbox_configurations[sandbox_id]
        self.assertEqual(config.classification_level, self.test_classification)

    def test_create_sandbox_with_custom_config(self):
        """Test sandbox creation with custom configuration."""
        custom_config = {
            "max_cpu_percent": 25.0,
            "max_memory_mb": 128,
            "enable_network": False,
            "integrity_check_interval_seconds": 5
        }
        
        sandbox_id = self.sandboxing_system.create_sandbox(
            self.test_agent_id,
            ClassificationLevel.SECRET,
            SandboxType.CONTAINER,
            custom_config
        )
        
        # Validate custom configuration applied
        config = self.sandboxing_system._sandbox_configurations[sandbox_id]
        self.assertEqual(config.max_cpu_percent, 25.0)
        self.assertEqual(config.max_memory_mb, 128)
        self.assertFalse(config.enable_network)
        self.assertEqual(config.integrity_check_interval_seconds, 5)

    def test_classification_aware_configuration(self):
        """Test that different classification levels get appropriate configurations."""
        test_cases = [
            (ClassificationLevel.UNCLASSIFIED, True, 60),
            (ClassificationLevel.CUI, False, 30),
            (ClassificationLevel.SECRET, False, 15),
            (ClassificationLevel.TOP_SECRET, False, 10)
        ]
        
        for classification, expected_network, expected_interval in test_cases:
            with self.subTest(classification=classification):
                sandbox_id = self.sandboxing_system.create_sandbox(
                    f"agent_{classification.value}",
                    classification,
                    SandboxType.PROCESS
                )
                
                config = self.sandboxing_system._sandbox_configurations[sandbox_id]
                self.assertEqual(config.enable_network, expected_network)
                self.assertEqual(config.integrity_check_interval_seconds, expected_interval)
                
                # Higher classification should have stricter limits
                if classification == ClassificationLevel.TOP_SECRET:
                    self.assertLessEqual(config.max_cpu_percent, 25.0)
                    self.assertLessEqual(config.max_memory_mb, 256)

    def test_integrity_validation_performance(self):
        """Test that integrity validation meets <5ms performance target."""
        # Create sandbox
        sandbox_id = self.sandboxing_system.create_sandbox(
            self.test_agent_id,
            self.test_classification
        )
        
        # Test different integrity check types
        check_types = [
            IntegrityCheckType.MEMORY_CHECKSUM,
            IntegrityCheckType.STATE_VALIDATION,
            IntegrityCheckType.EXECUTION_TRACE,
            IntegrityCheckType.CRYPTO_SIGNATURE
        ]
        
        for check_type in check_types:
            with self.subTest(check_type=check_type):
                start_time = time.time()
                
                result = self.sandboxing_system.validate_integrity(
                    sandbox_id, check_type
                )
                
                validation_time = (time.time() - start_time) * 1000
                
                # Validate performance target (<5ms)
                self.assertLess(validation_time, 5.0,
                               f"Integrity validation took {validation_time:.2f}ms, expected < 5ms")
                
                # Validate result structure
                self.assertIsInstance(result, IntegrityValidationResult)
                self.assertEqual(result.sandbox_id, sandbox_id)
                self.assertEqual(result.check_type, check_type)
                self.assertIsInstance(result.is_valid, bool)
                self.assertGreaterEqual(result.confidence_score, 0.0)
                self.assertLessEqual(result.confidence_score, 1.0)

    def test_integrity_validation_without_process(self):
        """Test integrity validation for sandbox without running process."""
        sandbox_id = self.sandboxing_system.create_sandbox(
            self.test_agent_id,
            self.test_classification
        )
        
        # Test memory checksum (should handle missing process gracefully)
        result = self.sandboxing_system.validate_integrity(
            sandbox_id, IntegrityCheckType.MEMORY_CHECKSUM
        )
        
        self.assertFalse(result.is_valid)
        self.assertIn("No process ID available", result.anomalies_detected)

    def test_state_persistence(self):
        """Test secure state persistence functionality."""
        sandbox_id = self.sandboxing_system.create_sandbox(
            self.test_agent_id,
            ClassificationLevel.SECRET
        )
        
        # Test state persistence
        start_time = time.time()
        success = self.sandboxing_system.persist_sandbox_state(sandbox_id)
        persistence_time = (time.time() - start_time) * 1000
        
        # Validate success and performance
        self.assertTrue(success)
        self.assertLess(persistence_time, 10.0,
                       f"State persistence took {persistence_time:.2f}ms, expected < 10ms")
        
        # Validate state file was created
        state_file = (self.sandboxing_system._state_storage_path / 
                     f"sandbox_{sandbox_id}.state")
        self.assertTrue(state_file.exists())
        
        # Validate encryption was attempted
        self.crypto_utils.encrypt_data.assert_called()

    def test_sandbox_termination(self):
        """Test sandbox termination and cleanup."""
        sandbox_id = self.sandboxing_system.create_sandbox(
            self.test_agent_id,
            self.test_classification
        )
        
        initial_count = self.sandboxing_system._sandboxing_state["active_sandboxes"]
        
        # Terminate sandbox
        success = self.sandboxing_system.terminate_sandbox(
            sandbox_id, "Test termination"
        )
        
        self.assertTrue(success)
        
        # Validate cleanup
        final_count = self.sandboxing_system._sandboxing_state["active_sandboxes"]
        self.assertEqual(final_count, initial_count - 1)
        
        # Validate audit logging
        self.audit_logger.log_security_event.assert_called()

    def test_resource_monitoring(self):
        """Test resource monitoring functionality."""
        sandbox_id = self.sandboxing_system.create_sandbox(
            self.test_agent_id,
            self.test_classification
        )
        
        # Mock a process for metrics gathering
        with patch('psutil.Process') as mock_process_class:
            mock_process = Mock()
            mock_process.cpu_percent.return_value = 15.0
            mock_process.memory_info.return_value = Mock(rss=100 * 1024 * 1024)  # 100MB
            mock_process.connections.return_value = []
            mock_process.open_files.return_value = []
            mock_process.create_time.return_value = time.time() - 60  # 1 minute ago
            mock_process_class.return_value = mock_process
            
            # Set process ID to enable metrics
            self.sandboxing_system._active_sandboxes[sandbox_id].process_id = 12345
            
            # Get metrics
            start_time = time.time()
            metrics = self.sandboxing_system.get_sandbox_metrics(sandbox_id)
            metrics_time = (time.time() - start_time) * 1000
            
            # Validate metrics
            self.assertIsNotNone(metrics)
            self.assertIsInstance(metrics, SandboxMetrics)
            self.assertEqual(metrics.sandbox_id, sandbox_id)
            self.assertEqual(metrics.cpu_percent, 15.0)
            self.assertAlmostEqual(metrics.memory_mb, 100.0, places=1)
            
            # Validate performance (<2ms target)
            self.assertLess(metrics_time, 2.0,
                           f"Metrics collection took {metrics_time:.2f}ms, expected < 2ms")

    def test_error_handling(self):
        """Test error handling for various failure scenarios."""
        # Test invalid sandbox ID
        with self.assertRaises(SandboxingSystemError):
            self.sandboxing_system.validate_integrity("invalid_sandbox_id")
        
        # Test sandbox termination for non-existent sandbox
        result = self.sandboxing_system.terminate_sandbox("invalid_sandbox_id")
        self.assertFalse(result)
        
        # Test metrics for non-existent sandbox
        metrics = self.sandboxing_system.get_sandbox_metrics("invalid_sandbox_id")
        self.assertIsNone(metrics)

    def test_multiple_sandboxes(self):
        """Test managing multiple sandboxes simultaneously."""
        num_sandboxes = 5
        sandbox_ids = []
        
        # Create multiple sandboxes
        for i in range(num_sandboxes):
            sandbox_id = self.sandboxing_system.create_sandbox(
                f"agent_{i}",
                self.test_classification
            )
            sandbox_ids.append(sandbox_id)
        
        # Validate all created
        self.assertEqual(len(self.sandboxing_system._active_sandboxes), num_sandboxes)
        
        # Test integrity validation on all
        for sandbox_id in sandbox_ids:
            result = self.sandboxing_system.validate_integrity(sandbox_id)
            self.assertIsInstance(result, IntegrityValidationResult)
        
        # Terminate all
        for sandbox_id in sandbox_ids:
            success = self.sandboxing_system.terminate_sandbox(sandbox_id)
            self.assertTrue(success)
        
        # Validate cleanup
        final_count = self.sandboxing_system._sandboxing_state["active_sandboxes"]
        self.assertEqual(final_count, 0)

    def test_background_monitoring(self):
        """Test background monitoring threads."""
        # Verify monitoring threads are active
        self.assertTrue(self.sandboxing_system._monitoring_active)
        self.assertTrue(self.sandboxing_system._integrity_monitor_thread.is_alive())
        self.assertTrue(self.sandboxing_system._resource_monitor_thread.is_alive())
        self.assertTrue(self.sandboxing_system._state_persistence_thread.is_alive())

    def test_system_validation(self):
        """Test system validation and metrics."""
        validation_result = self.sandboxing_system.validate()
        
        # Validate structure
        self.assertIn("system", validation_result)
        self.assertIn("status", validation_result)
        self.assertIn("metrics", validation_result)
        self.assertIn("performance_targets", validation_result)
        self.assertIn("innovations", validation_result)
        
        # Validate content
        self.assertEqual(validation_result["system"], "Agent_Sandboxing_System")
        self.assertEqual(validation_result["status"], "operational")
        
        # Validate performance targets
        targets = validation_result["performance_targets"]
        self.assertEqual(targets["integrity_validation_ms"], 5.0)
        self.assertEqual(targets["sandbox_creation_ms"], 100.0)
        self.assertEqual(targets["resource_check_ms"], 2.0)
        self.assertEqual(targets["state_persistence_ms"], 10.0)
        
        # Validate innovations listed
        innovations = validation_result["innovations"]
        expected_innovations = [
            "hardware_enforced_agent_execution_sandboxing",
            "real_time_integrity_verification_sub_5ms",
            "secure_state_persistence_with_crypto_validation",
            "classification_aware_resource_isolation",
            "tamper_evident_execution_monitoring",
            "performance_optimized_sandbox_operations"
        ]
        for innovation in expected_innovations:
            self.assertIn(innovation, innovations)

class TestSandboxConfiguration(unittest.TestCase):
    """Test suite for SandboxConfiguration."""
    
    def test_default_configuration(self):
        """Test default configuration creation."""
        config = SandboxConfiguration(
            sandbox_id="test_sandbox",
            sandbox_type=SandboxType.PROCESS,
            classification_level=ClassificationLevel.UNCLASSIFIED
        )
        
        # Validate defaults
        self.assertIsNotNone(config.allowed_system_calls)
        self.assertIsNotNone(config.denied_system_calls)
        self.assertIn("read", config.allowed_system_calls)
        self.assertIn("write", config.allowed_system_calls)
        self.assertIn("execve", config.denied_system_calls)
        self.assertIn("socket", config.denied_system_calls)

class PerformanceBenchmarkTest(unittest.TestCase):
    """Performance benchmark tests for sandboxing system."""
    
    def setUp(self):
        """Set up benchmark environment."""
        self.classification_system = Mock(spec=SecurityClassification)
        self.classification_system.default_level = ClassificationLevel.UNCLASSIFIED
        self.crypto_utils = Mock(spec=FIPSCryptoUtils)
        self.audit_logger = Mock(spec=AuditLogger)
        
        # Mock crypto operations for performance
        mock_key = Mock()
        mock_key.key_data = b"test_key_data_32_bytes_long_here"
        self.crypto_utils.generate_key.return_value = mock_key
        
        mock_encryption_result = Mock()
        mock_encryption_result.success = True
        mock_encryption_result.data = b"encrypted_test_data"
        self.crypto_utils.encrypt_data.return_value = mock_encryption_result
        
        self.sandboxing_system = AgentSandboxingSystem(
            self.classification_system,
            self.crypto_utils,
            self.audit_logger
        )

    def tearDown(self):
        """Clean up benchmark environment."""
        self.sandboxing_system.stop_monitoring()

    def test_integrity_validation_benchmark(self):
        """Benchmark integrity validation performance."""
        sandbox_id = self.sandboxing_system.create_sandbox(
            "benchmark_agent",
            ClassificationLevel.UNCLASSIFIED
        )
        
        # Warm up
        for _ in range(10):
            self.sandboxing_system.validate_integrity(sandbox_id)
        
        # Benchmark
        num_iterations = 100
        total_time = 0
        
        for _ in range(num_iterations):
            start_time = time.time()
            self.sandboxing_system.validate_integrity(sandbox_id)
            total_time += (time.time() - start_time) * 1000
        
        average_time = total_time / num_iterations
        
        print(f"\nIntegrity validation benchmark:")
        print(f"  Average time: {average_time:.3f}ms")
        print(f"  Target: <5ms")
        print(f"  Performance ratio: {average_time/5.0:.2f}x")
        
        # Validate performance target
        self.assertLess(average_time, 5.0,
                       f"Average integrity validation time {average_time:.3f}ms exceeds 5ms target")

    def test_sandbox_creation_benchmark(self):
        """Benchmark sandbox creation performance."""
        num_iterations = 50
        total_time = 0
        
        for i in range(num_iterations):
            start_time = time.time()
            sandbox_id = self.sandboxing_system.create_sandbox(
                f"benchmark_agent_{i}",
                ClassificationLevel.UNCLASSIFIED
            )
            total_time += (time.time() - start_time) * 1000
            
            # Clean up to avoid memory buildup
            self.sandboxing_system.terminate_sandbox(sandbox_id)
        
        average_time = total_time / num_iterations
        
        print(f"\nSandbox creation benchmark:")
        print(f"  Average time: {average_time:.3f}ms")
        print(f"  Target: <100ms")
        print(f"  Performance ratio: {average_time/100.0:.2f}x")
        
        # Validate performance target
        self.assertLess(average_time, 100.0,
                       f"Average sandbox creation time {average_time:.3f}ms exceeds 100ms target")

if __name__ == "__main__":
    # Run tests with verbose output
    test_suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)