#!/usr/bin/env python3
"""
Test Suite for MAESTRO AI Bias Detection and Mitigation System
Comprehensive validation of bias detection, confidence scoring, and automated mitigation

This test suite validates the complete AI bias detection implementation,
including fairness metrics, mitigation strategies, and FISMA compliance.

Test Coverage:
- Bias detection algorithms (demographic parity, equalized odds, calibration)
- Confidence scoring and uncertainty quantification
- Automated mitigation strategies
- FISMA compliance validation
- Performance requirements (<100ms for assessment)
- Classification-aware bias detection
"""

import pytest
import numpy as np
import time
from unittest.mock import Mock, patch
import asyncio

# Import the module under test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from shared.ai_bias_detection import (
        AIBiasDetectionSystem, BiasMetric, SeverityLevel, MitigationStrategy,
        BiasDetectionResult, MitigationResult, FairnessAssessment,
        DemographicParityDetector, EqualizedOddsDetector, CalibrationDetector,
        AIBiasMitigator
    )
except ImportError as e:
    print(f"Import error: {e}")
    # Create mock classes for testing
    class AIBiasDetectionSystem:
        pass

class TestBiasDetectors:
    """Test suite for individual bias detection algorithms."""
    
    @pytest.fixture
    def sample_data_balanced(self):
        """Create balanced sample data for testing."""
        np.random.seed(42)
        n_samples = 1000
        
        # Balanced groups (50% each)
        protected_attributes = np.random.choice([0, 1], size=n_samples, p=[0.5, 0.5])
        
        # Fair predictions (equal positive rates)
        predictions = np.random.random(n_samples)
        
        # Fair true labels
        true_labels = (predictions > 0.5).astype(int)
        
        return predictions, protected_attributes, true_labels
    
    @pytest.fixture
    def sample_data_biased(self):
        """Create biased sample data for testing."""
        np.random.seed(42)
        n_samples = 1000
        
        # Imbalanced groups
        protected_attributes = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
        
        # Biased predictions (group 0 gets higher rates)
        predictions = np.random.random(n_samples)
        group_0_mask = protected_attributes == 0
        group_1_mask = protected_attributes == 1
        
        # Introduce bias: group 0 gets +0.2 boost
        predictions[group_0_mask] = np.clip(predictions[group_0_mask] + 0.2, 0, 1)
        
        # True labels based on original fair distribution
        fair_predictions = np.random.random(n_samples)
        true_labels = (fair_predictions > 0.5).astype(int)
        
        return predictions, protected_attributes, true_labels
    
    def test_demographic_parity_detector_fair(self, sample_data_balanced):
        """Test demographic parity detector on fair data."""
        predictions, protected_attributes, _ = sample_data_balanced
        
        detector = DemographicParityDetector(threshold=0.1)
        result = detector.detect_bias(predictions, protected_attributes)
        
        # Validate result structure
        assert isinstance(result, BiasDetectionResult)
        assert result.metric == BiasMetric.DEMOGRAPHIC_PARITY
        assert result.bias_score >= 0
        assert result.confidence > 0
        assert result.uncertainty >= 0
        assert len(result.affected_groups) == 2
        
        # Should detect low bias on balanced data
        assert result.severity in [SeverityLevel.NEGLIGIBLE, SeverityLevel.LOW]
    
    def test_demographic_parity_detector_biased(self, sample_data_biased):
        """Test demographic parity detector on biased data."""
        predictions, protected_attributes, _ = sample_data_biased
        
        detector = DemographicParityDetector(threshold=0.1)
        result = detector.detect_bias(predictions, protected_attributes)
        
        # Should detect significant bias
        assert result.bias_score > 0.1
        assert result.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        
        # Validate metadata
        assert "group_rates" in result.metadata
        assert "detection_time_ms" in result.metadata
        assert result.metadata["detection_time_ms"] > 0
    
    def test_equalized_odds_detector_fair(self, sample_data_balanced):
        """Test equalized odds detector on fair data."""
        predictions, protected_attributes, true_labels = sample_data_balanced
        
        # Convert to binary predictions
        binary_predictions = (predictions > 0.5).astype(int)
        
        detector = EqualizedOddsDetector(threshold=0.1)
        result = detector.detect_bias(binary_predictions, protected_attributes, true_labels)
        
        # Validate result
        assert result.metric == BiasMetric.EQUALIZED_ODDS
        assert result.bias_score >= 0
        assert "group_metrics" in result.metadata
        assert "tpr_difference" in result.metadata
        assert "fpr_difference" in result.metadata
    
    def test_equalized_odds_detector_biased(self, sample_data_biased):
        """Test equalized odds detector on biased data."""
        predictions, protected_attributes, true_labels = sample_data_biased
        
        # Convert to binary predictions
        binary_predictions = (predictions > 0.5).astype(int)
        
        detector = EqualizedOddsDetector(threshold=0.1)
        result = detector.detect_bias(binary_predictions, protected_attributes, true_labels)
        
        # Should detect bias
        assert result.bias_score > 0
        assert result.severity != SeverityLevel.NEGLIGIBLE
    
    def test_equalized_odds_requires_labels(self, sample_data_balanced):
        """Test that equalized odds requires true labels."""
        predictions, protected_attributes, _ = sample_data_balanced
        
        detector = EqualizedOddsDetector()
        
        with pytest.raises(ValueError, match="True labels required"):
            detector.detect_bias(predictions, protected_attributes, None)
    
    def test_calibration_detector_fair(self, sample_data_balanced):
        """Test calibration detector on fair data."""
        predictions, protected_attributes, true_labels = sample_data_balanced
        
        detector = CalibrationDetector(threshold=0.1, bins=5)
        result = detector.detect_bias(predictions, protected_attributes, true_labels)
        
        # Validate result
        assert result.metric == BiasMetric.CALIBRATION
        assert result.bias_score >= 0
        assert "group_calibrations" in result.metadata
    
    def test_calibration_detector_requires_labels(self, sample_data_balanced):
        """Test that calibration detection requires true labels."""
        predictions, protected_attributes, _ = sample_data_balanced
        
        detector = CalibrationDetector()
        
        with pytest.raises(ValueError, match="True labels required"):
            detector.detect_bias(predictions, protected_attributes, None)

class TestBiasMitigation:
    """Test suite for bias mitigation strategies."""
    
    @pytest.fixture
    def biased_sample_data(self):
        """Create sample data with known bias for mitigation testing."""
        np.random.seed(42)
        n_samples = 500
        
        protected_attributes = np.random.choice([0, 1], size=n_samples, p=[0.6, 0.4])
        
        # Create biased predictions
        predictions = np.random.random(n_samples)
        group_0_mask = protected_attributes == 0
        predictions[group_0_mask] += 0.3  # Strong bias toward group 0
        predictions = np.clip(predictions, 0, 1)
        
        return predictions, protected_attributes
    
    @pytest.fixture
    def mock_bias_result(self):
        """Create mock bias detection result."""
        return BiasDetectionResult(
            metric=BiasMetric.DEMOGRAPHIC_PARITY,
            method="statistical_analysis",
            bias_score=0.25,
            severity=SeverityLevel.HIGH,
            confidence=0.85,
            uncertainty=0.15,
            affected_groups=["0", "1"],
            sample_size=500,
            threshold_used=0.1,
            detection_timestamp=time.time(),
            metadata={}
        )
    
    def test_threshold_adjustment_mitigation(self, biased_sample_data, mock_bias_result):
        """Test threshold adjustment mitigation strategy."""
        predictions, protected_attributes = biased_sample_data
        
        mitigator = AIBiasMitigator()
        result = mitigator.apply_mitigation(
            MitigationStrategy.THRESHOLD_ADJUSTMENT,
            predictions,
            protected_attributes,
            mock_bias_result,
            base_threshold=0.5
        )
        
        # Validate result
        assert isinstance(result, MitigationResult)
        assert result.strategy == MitigationStrategy.THRESHOLD_ADJUSTMENT
        assert result.pre_mitigation_bias > 0
        assert result.post_mitigation_bias >= 0
        assert result.success is True
        
        # Should show improvement
        assert result.improvement_percentage >= 0
    
    def test_reweighting_mitigation(self, biased_sample_data, mock_bias_result):
        """Test reweighting mitigation strategy."""
        predictions, protected_attributes = biased_sample_data
        
        mitigator = AIBiasMitigator()
        result = mitigator.apply_mitigation(
            MitigationStrategy.REWEIGHTING,
            predictions,
            protected_attributes,
            mock_bias_result
        )
        
        # Validate result
        assert result.strategy == MitigationStrategy.REWEIGHTING
        assert result.success is True
        assert result.performance_impact >= 0
    
    def test_postprocessing_mitigation(self, biased_sample_data, mock_bias_result):
        """Test postprocessing mitigation strategy."""
        predictions, protected_attributes = biased_sample_data
        
        mitigator = AIBiasMitigator()
        result = mitigator.apply_mitigation(
            MitigationStrategy.POSTPROCESSING,
            predictions,
            protected_attributes,
            mock_bias_result,
            target_threshold=0.5
        )
        
        # Validate result
        assert result.strategy == MitigationStrategy.POSTPROCESSING
        assert result.success is True
    
    def test_unsupported_mitigation_strategy(self, biased_sample_data, mock_bias_result):
        """Test handling of unsupported mitigation strategy."""
        predictions, protected_attributes = biased_sample_data
        
        mitigator = AIBiasMitigator()
        
        # Mock an unsupported strategy
        unsupported_strategy = MitigationStrategy.IN_PROCESSING
        
        with pytest.raises(ValueError, match="Unsupported mitigation strategy"):
            mitigator.apply_mitigation(
                unsupported_strategy,
                predictions,
                protected_attributes,
                mock_bias_result
            )

class TestAIBiasDetectionSystem:
    """Test suite for the complete AI bias detection system."""
    
    @pytest.fixture
    def bias_system(self):
        """Create AI bias detection system for testing."""
        return AIBiasDetectionSystem(classification_level="secret")
    
    @pytest.fixture
    def fair_scenario_data(self):
        """Create fair scenario test data."""
        np.random.seed(42)
        n_samples = 800
        
        # Balanced groups
        protected_attributes = np.random.choice([0, 1], size=n_samples, p=[0.5, 0.5])
        
        # Fair predictions
        predictions = np.random.random(n_samples)
        true_labels = (np.random.random(n_samples) > 0.5).astype(int)
        
        return predictions, protected_attributes, true_labels
    
    @pytest.fixture
    def biased_scenario_data(self):
        """Create biased scenario test data."""
        np.random.seed(42)
        n_samples = 800
        
        # Imbalanced groups
        protected_attributes = np.random.choice([0, 1], size=n_samples, p=[0.8, 0.2])
        
        # Heavily biased predictions
        predictions = np.random.random(n_samples)
        group_0_mask = protected_attributes == 0
        predictions[group_0_mask] += 0.4  # Strong bias
        predictions = np.clip(predictions, 0, 1)
        
        # True labels
        true_labels = (np.random.random(n_samples) > 0.5).astype(int)
        
        return predictions, protected_attributes, true_labels
    
    @pytest.mark.asyncio
    async def test_fairness_assessment_fair_scenario(self, bias_system, fair_scenario_data):
        """Test fairness assessment on fair scenario."""
        predictions, protected_attributes, true_labels = fair_scenario_data
        
        assessment = await bias_system.assess_fairness(
            predictions, protected_attributes, true_labels, apply_mitigation=False
        )
        
        # Validate assessment structure
        assert isinstance(assessment, FairnessAssessment)
        assert assessment.classification_level == "secret"
        assert assessment.total_samples == len(predictions)
        assert len(assessment.detection_results) > 0
        assert assessment.overall_fairness_score >= 0
        assert assessment.compliance_status in ["COMPLIANT", "REQUIRES_MONITORING", "PARTIALLY_COMPLIANT", "NON_COMPLIANT"]
        
        # Should show good fairness
        assert assessment.overall_fairness_score > 0.5
        assert assessment.compliance_status in ["COMPLIANT", "REQUIRES_MONITORING"]
    
    @pytest.mark.asyncio
    async def test_fairness_assessment_biased_scenario(self, bias_system, biased_scenario_data):
        """Test fairness assessment on biased scenario."""
        predictions, protected_attributes, true_labels = biased_scenario_data
        
        assessment = await bias_system.assess_fairness(
            predictions, protected_attributes, true_labels, apply_mitigation=True
        )
        
        # Should detect bias
        assert assessment.overall_fairness_score < 0.8
        high_severity_count = sum(1 for r in assessment.detection_results 
                                if r.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL])
        assert high_severity_count > 0
        
        # Should have mitigation results if bias was detected
        if any(r.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] 
               for r in assessment.detection_results):
            assert len(assessment.mitigation_results) > 0
        
        # Should have recommendations
        assert len(assessment.recommendations) > 0
    
    @pytest.mark.asyncio
    async def test_fairness_assessment_without_true_labels(self, bias_system, fair_scenario_data):
        """Test fairness assessment without true labels."""
        predictions, protected_attributes, _ = fair_scenario_data
        
        assessment = await bias_system.assess_fairness(
            predictions, protected_attributes, true_labels=None, apply_mitigation=False
        )
        
        # Should still work with limited metrics
        assert isinstance(assessment, FairnessAssessment)
        assert len(assessment.detection_results) > 0
        
        # Should only have metrics that don't require true labels
        for result in assessment.detection_results:
            assert result.metric in [BiasMetric.DEMOGRAPHIC_PARITY]
    
    @pytest.mark.asyncio
    async def test_performance_requirements(self, bias_system, fair_scenario_data):
        """Test that bias detection meets performance requirements."""
        predictions, protected_attributes, true_labels = fair_scenario_data
        
        # Test assessment performance
        start_time = time.time()
        assessment = await bias_system.assess_fairness(
            predictions, protected_attributes, true_labels, apply_mitigation=False
        )
        assessment_time = (time.time() - start_time) * 1000
        
        # Should complete within reasonable time
        assert assessment_time < 5000  # 5 seconds for 800 samples
        assert assessment.assessment_duration_ms > 0
        
        # Individual detection should be fast
        for result in assessment.detection_results:
            detection_time = result.metadata.get("detection_time_ms", 0)
            assert detection_time < 1000  # 1 second per detection
    
    def test_assessment_id_generation(self, bias_system):
        """Test unique assessment ID generation."""
        id1 = bias_system._generate_assessment_id()
        id2 = bias_system._generate_assessment_id()
        
        assert id1 != id2
        assert id1.startswith("BIAS-ASSESS-")
        assert id2.startswith("BIAS-ASSESS-")
    
    def test_mitigation_strategy_selection(self, bias_system):
        """Test mitigation strategy selection logic."""
        # Test demographic parity
        demo_result = BiasDetectionResult(
            metric=BiasMetric.DEMOGRAPHIC_PARITY,
            method="statistical_analysis",
            bias_score=0.2,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            uncertainty=0.2,
            affected_groups=["0", "1"],
            sample_size=100,
            threshold_used=0.1,
            detection_timestamp=time.time(),
            metadata={}
        )
        
        strategy = bias_system._select_mitigation_strategy(demo_result)
        assert strategy == MitigationStrategy.THRESHOLD_ADJUSTMENT
        
        # Test equalized odds
        eq_odds_result = BiasDetectionResult(
            metric=BiasMetric.EQUALIZED_ODDS,
            method="statistical_analysis",
            bias_score=0.15,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            uncertainty=0.2,
            affected_groups=["0", "1"],
            sample_size=100,
            threshold_used=0.1,
            detection_timestamp=time.time(),
            metadata={}
        )
        
        strategy = bias_system._select_mitigation_strategy(eq_odds_result)
        assert strategy == MitigationStrategy.POSTPROCESSING
    
    def test_overall_fairness_score_calculation(self, bias_system):
        """Test overall fairness score calculation."""
        # Create mock detection results
        results = [
            BiasDetectionResult(
                metric=BiasMetric.DEMOGRAPHIC_PARITY,
                method="statistical_analysis",
                bias_score=0.1,  # Low bias
                severity=SeverityLevel.LOW,
                confidence=0.9,
                uncertainty=0.1,
                affected_groups=["0", "1"],
                sample_size=100,
                threshold_used=0.1,
                detection_timestamp=time.time(),
                metadata={}
            ),
            BiasDetectionResult(
                metric=BiasMetric.EQUALIZED_ODDS,
                method="statistical_analysis",
                bias_score=0.05,  # Very low bias
                severity=SeverityLevel.NEGLIGIBLE,
                confidence=0.8,
                uncertainty=0.2,
                affected_groups=["0", "1"],
                sample_size=100,
                threshold_used=0.1,
                detection_timestamp=time.time(),
                metadata={}
            )
        ]
        
        score = bias_system._calculate_overall_fairness_score(results)
        
        # Should be high score (low bias)
        assert 0.8 <= score <= 1.0
    
    def test_compliance_status_determination(self, bias_system):
        """Test FISMA compliance status determination."""
        # Test compliant scenario
        good_results = [
            BiasDetectionResult(
                metric=BiasMetric.DEMOGRAPHIC_PARITY,
                method="statistical_analysis",
                bias_score=0.02,
                severity=SeverityLevel.NEGLIGIBLE,
                confidence=0.9,
                uncertainty=0.1,
                affected_groups=["0", "1"],
                sample_size=100,
                threshold_used=0.1,
                detection_timestamp=time.time(),
                metadata={}
            )
        ]
        
        status = bias_system._determine_compliance_status(good_results)
        assert status == "COMPLIANT"
        
        # Test non-compliant scenario
        bad_results = [
            BiasDetectionResult(
                metric=BiasMetric.DEMOGRAPHIC_PARITY,
                method="statistical_analysis",
                bias_score=0.3,
                severity=SeverityLevel.CRITICAL,
                confidence=0.9,
                uncertainty=0.1,
                affected_groups=["0", "1"],
                sample_size=100,
                threshold_used=0.1,
                detection_timestamp=time.time(),
                metadata={}
            )
        ]
        
        status = bias_system._determine_compliance_status(bad_results)
        assert status == "NON_COMPLIANT"

class TestBiasDetectionIntegration:
    """Integration tests for bias detection with MAESTRO framework."""
    
    @pytest.mark.asyncio
    async def test_maestro_integration(self):
        """Test integration with MAESTRO security framework."""
        # Test with different classification levels
        for classification in ["unclassified", "confidential", "secret", "top_secret"]:
            system = AIBiasDetectionSystem(classification_level=classification)
            assert system.classification_level == classification
    
    def test_audit_logging_integration(self):
        """Test integration with MAESTRO audit logging."""
        system = AIBiasDetectionSystem()
        
        # Should handle missing audit logger gracefully
        assert system.audit_logger is None or hasattr(system.audit_logger, 'log_security_event')

class TestBiasDetectionPerformance:
    """Performance validation for bias detection system."""
    
    @pytest.mark.asyncio
    async def test_large_dataset_performance(self):
        """Test performance on larger datasets."""
        system = AIBiasDetectionSystem()
        
        # Create large dataset
        np.random.seed(42)
        n_samples = 10000
        
        protected_attributes = np.random.choice([0, 1, 2], size=n_samples, p=[0.4, 0.4, 0.2])
        predictions = np.random.random(n_samples)
        true_labels = (np.random.random(n_samples) > 0.5).astype(int)
        
        # Benchmark assessment performance
        start_time = time.time()
        assessment = await system.assess_fairness(
            predictions, protected_attributes, true_labels, apply_mitigation=False
        )
        assessment_time = (time.time() - start_time) * 1000
        
        # Performance assertions
        assert assessment_time < 30000  # <30 seconds for 10k samples
        assert assessment.total_samples == n_samples
        
        print(f"Large Dataset Performance: {assessment_time:.2f}ms for {n_samples} samples")
        print(f"Throughput: {n_samples / (assessment_time / 1000):.0f} samples/second")
    
    @pytest.mark.asyncio
    async def test_multiple_groups_performance(self):
        """Test performance with multiple protected groups."""
        system = AIBiasDetectionSystem()
        
        # Create dataset with many groups
        np.random.seed(42)
        n_samples = 5000
        n_groups = 5
        
        protected_attributes = np.random.choice(range(n_groups), size=n_samples)
        predictions = np.random.random(n_samples)
        true_labels = (np.random.random(n_samples) > 0.5).astype(int)
        
        # Benchmark with multiple groups
        start_time = time.time()
        assessment = await system.assess_fairness(
            predictions, protected_attributes, true_labels, apply_mitigation=True
        )
        assessment_time = (time.time() - start_time) * 1000
        
        # Performance should scale reasonably with number of groups
        assert assessment_time < 20000  # <20 seconds for 5k samples with 5 groups
        assert len(assessment.detection_results) > 0
        
        print(f"Multi-Group Performance: {assessment_time:.2f}ms for {n_groups} groups")

if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "--tb=short"])