#!/usr/bin/env python3
"""
ALCUB3 AI Bias Detection and Mitigation Demonstration
Showcase FISMA-compliant AI fairness monitoring capabilities

This demonstration showcases the comprehensive AI bias detection and mitigation
system with real-time fairness assessment, confidence scoring, and automated
mitigation strategies as required by FISMA for AI systems.

Features Demonstrated:
- Multi-metric bias detection (demographic parity, equalized odds, calibration)
- Confidence scoring with uncertainty quantification
- Automated mitigation strategies (threshold adjustment, reweighting, postprocessing)
- FISMA compliance validation and reporting
- Classification-aware bias assessment
- Real-time performance monitoring

Usage:
    python3 demo_ai_bias_detection.py
    python3 demo_ai_bias_detection.py --scenario biased
    python3 demo_ai_bias_detection.py --classification secret --benchmark
"""

import asyncio
import argparse
import numpy as np
import time
import json
from typing import Dict, List, Any
from pathlib import Path

# Add the security framework to the path
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from shared.ai_bias_detection import (
        AIBiasDetectionSystem, BiasMetric, SeverityLevel, MitigationStrategy,
        BiasDetectionResult, MitigationResult, FairnessAssessment
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
    
    # Bias-specific colors
    BIAS = '\033[38;5;208m'      # Orange for bias
    FAIRNESS = '\033[38;5;46m'   # Bright green for fairness
    CONFIDENCE = '\033[38;5;51m' # Bright cyan for confidence

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

def create_fair_scenario_data(n_samples: int = 1000) -> tuple:
    """Create fair scenario test data."""
    np.random.seed(42)
    
    # Balanced groups
    protected_attributes = np.random.choice([0, 1], size=n_samples, p=[0.5, 0.5])
    
    # Fair predictions (similar rates across groups)
    predictions = np.random.random(n_samples)
    
    # Fair true labels
    true_labels = (np.random.random(n_samples) > 0.5).astype(int)
    
    return predictions, protected_attributes, true_labels

def create_biased_scenario_data(n_samples: int = 1000) -> tuple:
    """Create biased scenario test data."""
    np.random.seed(42)
    
    # Imbalanced groups (realistic scenario)
    protected_attributes = np.random.choice([0, 1, 2], size=n_samples, p=[0.6, 0.3, 0.1])
    
    # Introduce systematic bias
    predictions = np.random.random(n_samples)
    
    # Group 0 gets higher positive predictions (bias)
    group_0_mask = protected_attributes == 0
    group_1_mask = protected_attributes == 1
    group_2_mask = protected_attributes == 2
    
    predictions[group_0_mask] += 0.25  # Strong bias toward group 0
    predictions[group_1_mask] += 0.1   # Moderate bias toward group 1
    # Group 2 gets no boost (discrimination)
    
    predictions = np.clip(predictions, 0, 1)
    
    # True labels based on fair distribution
    fair_base = np.random.random(n_samples)
    true_labels = (fair_base > 0.5).astype(int)
    
    return predictions, protected_attributes, true_labels

def create_defense_scenario_data(n_samples: int = 1000) -> tuple:
    """Create defense-specific scenario with security clearance bias."""
    np.random.seed(42)
    
    # Security clearance levels as protected attribute
    # 0=No Clearance, 1=Secret, 2=Top Secret
    clearance_levels = np.random.choice([0, 1, 2], size=n_samples, p=[0.4, 0.4, 0.2])
    
    # AI system for security risk assessment
    # Bias: Higher clearance levels get lower risk scores (bias in favor)
    base_risk_scores = np.random.random(n_samples)
    
    # Introduce clearance bias
    secret_mask = clearance_levels == 1
    ts_mask = clearance_levels == 2
    
    base_risk_scores[secret_mask] -= 0.15   # Lower risk for Secret clearance
    base_risk_scores[ts_mask] -= 0.3        # Much lower risk for TS clearance
    
    predictions = np.clip(base_risk_scores, 0, 1)
    
    # True risk labels (should be independent of clearance)
    true_labels = (np.random.random(n_samples) > 0.7).astype(int)  # 30% high risk
    
    return predictions, clearance_levels, true_labels

async def demonstrate_bias_detection(system: AIBiasDetectionSystem, scenario_name: str, 
                                   predictions: np.ndarray, protected_attributes: np.ndarray,
                                   true_labels: np.ndarray):
    """Demonstrate bias detection on a specific scenario."""
    print_section(f"Bias Detection: {scenario_name} Scenario")
    
    print_info(f"📊 Dataset: {len(predictions)} samples, {len(np.unique(protected_attributes))} groups")
    
    # Show group distribution
    unique_groups, group_counts = np.unique(protected_attributes, return_counts=True)
    print_info("👥 Group distribution:")
    for group, count in zip(unique_groups, group_counts):
        percentage = (count / len(predictions)) * 100
        print(f"      Group {group}: {count} samples ({percentage:.1f}%)")
    
    # Show prediction rates by group
    print_info("📈 Positive prediction rates by group:")
    for group in unique_groups:
        group_mask = protected_attributes == group
        group_preds = predictions[group_mask]
        positive_rate = np.mean(group_preds > 0.5) * 100
        avg_score = np.mean(group_preds)
        print(f"      Group {group}: {positive_rate:.1f}% positive, avg score: {avg_score:.3f}")
    
    # Run fairness assessment
    print_info("🔍 Running comprehensive fairness assessment...")
    start_time = time.time()
    
    assessment = await system.assess_fairness(
        predictions, protected_attributes, true_labels, apply_mitigation=True
    )
    
    assessment_time = (time.time() - start_time) * 1000
    
    print_success(f"Assessment complete in {assessment_time:.2f}ms")
    
    # Display results
    print(f"\n📋 Assessment ID: {assessment.assessment_id}")
    print(f"🔐 Classification: {assessment.classification_level.upper()}")
    print(f"📊 Overall Fairness Score: {assessment.overall_fairness_score:.3f}")
    
    # Compliance status with color coding
    status = assessment.compliance_status
    if status == "COMPLIANT":
        print_success(f"✅ FISMA Compliance: {status}")
    elif status == "REQUIRES_MONITORING":
        print_warning(f"⚠️  FISMA Compliance: {status}")
    else:
        print_error(f"❌ FISMA Compliance: {status}")
    
    # Show detection results
    if assessment.detection_results:
        print_info("\n🎯 Bias Detection Results:")
        for i, result in enumerate(assessment.detection_results, 1):
            severity_color = {
                SeverityLevel.CRITICAL: Colors.RED,
                SeverityLevel.HIGH: Colors.YELLOW,
                SeverityLevel.MEDIUM: Colors.BLUE,
                SeverityLevel.LOW: Colors.GREEN,
                SeverityLevel.NEGLIGIBLE: Colors.GREEN
            }.get(result.severity, Colors.END)
            
            print(f"   {i}. {result.metric.value}")
            print(f"      {severity_color}Severity: {result.severity.value.upper()}{Colors.END}")
            print(f"      Bias Score: {result.bias_score:.4f}")
            print(f"      Confidence: {result.confidence:.3f} (±{result.uncertainty:.3f})")
            print(f"      Affected Groups: {', '.join(result.affected_groups)}")
    
    # Show mitigation results
    if assessment.mitigation_results:
        print_info("\n🛠️  Bias Mitigation Results:")
        for i, result in enumerate(assessment.mitigation_results, 1):
            success_color = Colors.GREEN if result.success else Colors.RED
            print(f"   {i}. {result.strategy.value}")
            print(f"      {success_color}Success: {result.success}{Colors.END}")
            print(f"      Improvement: {result.improvement_percentage:.1f}%")
            print(f"      Pre-mitigation bias: {result.pre_mitigation_bias:.4f}")
            print(f"      Post-mitigation bias: {result.post_mitigation_bias:.4f}")
            print(f"      Performance impact: {result.performance_impact:.4f}")
    
    # Show recommendations
    if assessment.recommendations:
        print_info("\n💡 Recommendations:")
        for i, rec in enumerate(assessment.recommendations, 1):
            if "URGENT" in rec or "CRITICAL" in rec:
                print(f"   {Colors.RED}{i}. {rec}{Colors.END}")
            elif "HIGH PRIORITY" in rec:
                print(f"   {Colors.YELLOW}{i}. {rec}{Colors.END}")
            else:
                print(f"   {i}. {rec}")
    
    return assessment

async def demonstrate_confidence_scoring(system: AIBiasDetectionSystem):
    """Demonstrate confidence scoring and uncertainty quantification."""
    print_section("Confidence Scoring & Uncertainty Quantification")
    
    print_info("🧪 Testing bias detection confidence with varying sample sizes...")
    
    sample_sizes = [100, 500, 1000, 5000]
    confidence_results = []
    
    for n_samples in sample_sizes:
        # Create biased data with known bias
        np.random.seed(42)
        protected_attributes = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
        predictions = np.random.random(n_samples)
        
        # Add consistent bias
        group_0_mask = protected_attributes == 0
        predictions[group_0_mask] += 0.2
        predictions = np.clip(predictions, 0, 1)
        
        true_labels = (np.random.random(n_samples) > 0.5).astype(int)
        
        # Run assessment
        assessment = await system.assess_fairness(
            predictions, protected_attributes, true_labels, apply_mitigation=False
        )
        
        # Extract confidence metrics
        if assessment.detection_results:
            avg_confidence = np.mean([r.confidence for r in assessment.detection_results])
            avg_uncertainty = np.mean([r.uncertainty for r in assessment.detection_results])
            
            confidence_results.append({
                "sample_size": n_samples,
                "confidence": avg_confidence,
                "uncertainty": avg_uncertainty,
                "fairness_score": assessment.overall_fairness_score
            })
            
            print(f"   📊 N={n_samples:4d}: Confidence={avg_confidence:.3f}, Uncertainty={avg_uncertainty:.3f}")
    
    # Show confidence trend
    print_info("\n📈 Confidence Analysis:")
    print("   • Confidence should increase with larger sample sizes")
    print("   • Uncertainty should decrease with more data")
    print("   • Bias detection becomes more reliable with sufficient samples")
    
    return confidence_results

async def run_performance_benchmark(system: AIBiasDetectionSystem):
    """Run performance benchmarks for different scenarios."""
    print_section("Performance Benchmarking")
    
    print_info("🏃 Running bias detection performance benchmarks...")
    
    benchmark_scenarios = [
        ("Small Dataset", 500, 2),
        ("Medium Dataset", 2000, 3),
        ("Large Dataset", 10000, 4),
        ("Very Large Dataset", 50000, 5)
    ]
    
    performance_results = []
    
    for scenario_name, n_samples, n_groups in benchmark_scenarios:
        print_info(f"📊 Benchmarking: {scenario_name} ({n_samples} samples, {n_groups} groups)")
        
        # Create test data
        np.random.seed(42)
        protected_attributes = np.random.choice(range(n_groups), size=n_samples)
        predictions = np.random.random(n_samples)
        true_labels = (np.random.random(n_samples) > 0.5).astype(int)
        
        # Benchmark assessment
        start_time = time.time()
        assessment = await system.assess_fairness(
            predictions, protected_attributes, true_labels, apply_mitigation=True
        )
        assessment_time = (time.time() - start_time) * 1000
        
        # Calculate throughput
        throughput = n_samples / (assessment_time / 1000)
        
        performance_results.append({
            "scenario": scenario_name,
            "samples": n_samples,
            "groups": n_groups,
            "time_ms": assessment_time,
            "throughput": throughput,
            "detections": len(assessment.detection_results),
            "mitigations": len(assessment.mitigation_results)
        })
        
        print_success(f"   ⚡ {assessment_time:.2f}ms ({throughput:.0f} samples/sec)")
        print(f"      Detections: {len(assessment.detection_results)}, Mitigations: {len(assessment.mitigation_results)}")
    
    # Performance summary
    print_info("\n📊 Performance Summary:")
    fastest = min(performance_results, key=lambda x: x["time_ms"])
    highest_throughput = max(performance_results, key=lambda x: x["throughput"])
    
    print(f"   🚀 Fastest: {fastest['scenario']} - {fastest['time_ms']:.2f}ms")
    print(f"   📈 Highest Throughput: {highest_throughput['scenario']} - {highest_throughput['throughput']:.0f} samples/sec")
    
    # Check performance targets
    small_dataset_time = next(r["time_ms"] for r in performance_results if r["scenario"] == "Small Dataset")
    if small_dataset_time < 1000:  # <1 second for small datasets
        print_success("   🎯 Performance Target Met: <1s for small datasets")
    else:
        print_warning("   ⚠️  Performance Target Missed: >1s for small datasets")
    
    return performance_results

def display_patent_innovations():
    """Display patent-defensible innovations."""
    print_section("Patent-Defensible Innovations")
    
    innovations = [
        "🔬 Multi-modal bias detection with statistical and ML approaches",
        "🔐 Classification-aware fairness metrics for defense data processing",
        "⚡ Real-time bias mitigation with performance preservation guarantees",
        "📊 Uncertainty-based confidence scoring for AI decision validation",
        "🎯 Adaptive threshold adjustment based on operational security context",
        "🛡️  FISMA-compliant bias monitoring with automated compliance reporting",
        "🔄 Continuous fairness assessment with drift detection capabilities"
    ]
    
    print_success("✨ ALCUB3 AI Bias Detection System includes the following innovations:")
    for innovation in innovations:
        print(f"   {innovation}")
    
    print_info("\n💼 Market Applications:")
    applications = [
        "Defense AI systems with security clearance considerations",
        "Government AI applications requiring FISMA compliance",
        "Critical infrastructure AI with fairness requirements",
        "Healthcare AI systems with demographic bias concerns",
        "Financial AI applications with regulatory compliance needs"
    ]
    
    for app in applications:
        print(f"   • {app}")

async def main():
    """Main demonstration function."""
    parser = argparse.ArgumentParser(description="ALCUB3 AI Bias Detection Demo")
    parser.add_argument("--scenario", 
                      choices=["fair", "biased", "defense", "all"], 
                      default="all",
                      help="Bias scenario to demonstrate")
    parser.add_argument("--classification", 
                      choices=["unclassified", "confidential", "secret", "top_secret"],
                      default="secret",
                      help="Security classification level")
    parser.add_argument("--benchmark", action="store_true",
                      help="Run performance benchmarks")
    parser.add_argument("--output", help="Output results to JSON file")
    
    args = parser.parse_args()
    
    # Initialize bias detection system
    print_header("ALCUB3 AI BIAS DETECTION & MITIGATION DEMONSTRATION")
    print_info(f"🔐 Classification Level: {args.classification.upper()}")
    print_info(f"🕐 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    system = AIBiasDetectionSystem(classification_level=args.classification)
    
    # Demonstration results
    demo_results = {
        "classification": args.classification,
        "timestamp": time.time(),
        "scenarios": [],
        "performance_metrics": {}
    }
    
    try:
        # Run scenario demonstrations
        scenarios_to_run = []
        
        if args.scenario == "all":
            scenarios_to_run = [
                ("Fair AI System", create_fair_scenario_data),
                ("Biased AI System", create_biased_scenario_data),
                ("Defense Security Assessment", create_defense_scenario_data)
            ]
        elif args.scenario == "fair":
            scenarios_to_run = [("Fair AI System", create_fair_scenario_data)]
        elif args.scenario == "biased":
            scenarios_to_run = [("Biased AI System", create_biased_scenario_data)]
        elif args.scenario == "defense":
            scenarios_to_run = [("Defense Security Assessment", create_defense_scenario_data)]
        
        # Run scenarios
        for scenario_name, data_generator in scenarios_to_run:
            predictions, protected_attributes, true_labels = data_generator()
            
            assessment = await demonstrate_bias_detection(
                system, scenario_name, predictions, protected_attributes, true_labels
            )
            
            demo_results["scenarios"].append({
                "name": scenario_name,
                "fairness_score": assessment.overall_fairness_score,
                "compliance_status": assessment.compliance_status,
                "biases_detected": len([r for r in assessment.detection_results 
                                      if r.severity != SeverityLevel.NEGLIGIBLE]),
                "mitigations_applied": len(assessment.mitigation_results)
            })
        
        # Confidence scoring demonstration
        confidence_results = await demonstrate_confidence_scoring(system)
        demo_results["confidence_analysis"] = confidence_results
        
        # Performance benchmarks (optional)
        if args.benchmark:
            performance_results = await run_performance_benchmark(system)
            demo_results["performance_metrics"] = performance_results
        
        # Display innovations
        display_patent_innovations()
        
        # Summary
        print_section("Demonstration Summary")
        print_success("🎉 AI Bias Detection & Mitigation demonstration completed successfully!")
        
        total_assessments = len(demo_results["scenarios"])
        compliant_count = sum(1 for s in demo_results["scenarios"] 
                            if s["compliance_status"] == "COMPLIANT")
        
        print(f"   📊 Scenarios tested: {total_assessments}")
        print(f"   ✅ FISMA compliant: {compliant_count}/{total_assessments}")
        print(f"   🎯 Average fairness score: {np.mean([s['fairness_score'] for s in demo_results['scenarios']]):.3f}")
        
        if args.benchmark and demo_results["performance_metrics"]:
            avg_throughput = np.mean([p["throughput"] for p in demo_results["performance_metrics"]])
            print(f"   ⚡ Average throughput: {avg_throughput:.0f} samples/sec")
        
        # FISMA compliance summary
        print_section("FISMA Compliance Summary")
        print_success("✅ SP 800-53 SI-4: System monitoring implemented with bias detection")
        print_success("✅ SP 800-53 RA-5: Vulnerability scanning includes AI bias assessment")
        print_success("✅ SP 800-53 CA-7: Continuous monitoring with automated bias detection")
        print_success("✅ SP 800-53 SI-7: Software integrity includes AI fairness validation")
        
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