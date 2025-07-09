#!/usr/bin/env python3
"""
ALCUB3 Task Completion Handler Demo
===================================

This script demonstrates how to use the task completion handler
for various scenarios.
"""

import asyncio
import sys
import os
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.task_completion_handler import (
    TaskCompletionHandler,
    TaskContext,
    TaskType,
    ExecutionMode,
    ClassificationLevel
)


async def demo_feature_completion():
    """Demo: Handling a feature task completion."""
    print("=" * 60)
    print("DEMO 1: Feature Task Completion")
    print("=" * 60)
    
    # Create handler
    handler = TaskCompletionHandler()
    
    # Create task context for a new feature
    task_context = TaskContext(
        task_id="DEMO-001",
        task_type=TaskType.FEATURE,
        title="Add AI-powered threat detection",
        description="Implement ML-based anomaly detection for real-time threat identification",
        classification_level=ClassificationLevel.UNCLASSIFIED,
        changed_files=[
            "security-framework/src/ai_threat_detector.py",
            "security-framework/src/ml_models.py",
            "packages/core/src/api/threat_api.ts"
        ],
        author="demo_user"
    )
    
    # Run full validation
    print("\nRunning full validation for feature task...")
    report = await handler.handle_task_completion(
        task_context=task_context,
        execution_mode=ExecutionMode.FULL
    )
    
    # Display results
    print(f"\n✅ Task Completion Report:")
    print(f"   Security Score: {report.security_results.get('summary', {}).get('score', 0)}/100")
    print(f"   Patent Innovations Found: {len(report.patent_findings)}")
    print(f"   Documentation Generated: {len(report.documentation_generated)} files")
    print(f"   Issues Found: {len(report.issues_found)}")
    print(f"   Production Ready: {report.compliance_status.get('production_ready')}")
    
    if report.recommendations:
        print("\n📋 Recommendations:")
        for rec in report.recommendations:
            print(f"   - {rec}")
    
    return report


async def demo_security_patch():
    """Demo: Handling a security patch task."""
    print("\n" + "=" * 60)
    print("DEMO 2: Security Patch Task")
    print("=" * 60)
    
    handler = TaskCompletionHandler()
    
    task_context = TaskContext(
        task_id="DEMO-002",
        task_type=TaskType.SECURITY_PATCH,
        title="Fix authentication bypass vulnerability",
        description="Patch critical auth bypass in JWT validation",
        classification_level=ClassificationLevel.SECRET,
        changed_files=[
            "packages/core/src/auth/jwt_validator.ts",
            "packages/core/src/auth/session_manager.ts"
        ],
        author="security_team"
    )
    
    # Run security-focused validation
    print("\nRunning security-only validation for patch...")
    report = await handler.handle_task_completion(
        task_context=task_context,
        execution_mode=ExecutionMode.SECURITY_ONLY
    )
    
    print(f"\n🔒 Security Patch Report:")
    print(f"   Security Score: {report.security_results.get('summary', {}).get('score', 0)}/100")
    print(f"   Critical Findings: {len([i for i in report.issues_found if i['severity'] == 'critical'])}")
    print(f"   Audit Block: {report.audit_block_hash[:16]}...")
    
    return report


async def demo_quick_validation():
    """Demo: Quick validation for rapid feedback."""
    print("\n" + "=" * 60)
    print("DEMO 3: Quick Validation (CI/CD)")
    print("=" * 60)
    
    handler = TaskCompletionHandler()
    
    task_context = TaskContext(
        task_id="DEMO-003",
        task_type=TaskType.BUG_FIX,
        title="Fix null pointer in robotics adapter",
        description="Handle edge case in Boston Dynamics adapter",
        classification_level=ClassificationLevel.UNCLASSIFIED,
        changed_files=[
            "universal-robotics/adapters/spot-adapter/spot-security-adapter.ts"
        ],
        commit_hash="abc123def456",
        branch_name="fix/robotics-npe",
        author="developer"
    )
    
    # Run quick validation
    print("\nRunning quick validation...")
    start_time = datetime.now()
    
    report = await handler.handle_task_completion(
        task_context=task_context,
        execution_mode=ExecutionMode.QUICK
    )
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    print(f"\n⚡ Quick Validation Report:")
    print(f"   Completed in: {elapsed:.2f} seconds")
    print(f"   Security Score: {report.security_results.get('summary', {}).get('score', 0)}/100")
    print(f"   Ready to merge: {report.compliance_status.get('production_ready')}")
    
    return report


async def demo_patent_analysis():
    """Demo: Patent-focused analysis."""
    print("\n" + "=" * 60)
    print("DEMO 4: Patent Innovation Analysis")
    print("=" * 60)
    
    handler = TaskCompletionHandler()
    
    task_context = TaskContext(
        task_id="DEMO-004",
        task_type=TaskType.FEATURE,
        title="Implement quantum-resistant encryption for air-gap transfers",
        description="Novel post-quantum cryptography for secure offline data exchange",
        classification_level=ClassificationLevel.UNCLASSIFIED,
        changed_files=[
            "security-framework/src/quantum_crypto.py",
            "security-framework/src/air_gap_quantum_protocol.py"
        ],
        author="research_team"
    )
    
    # Run patent-only analysis
    print("\nRunning patent innovation analysis...")
    report = await handler.handle_task_completion(
        task_context=task_context,
        execution_mode=ExecutionMode.PATENT_ONLY
    )
    
    print(f"\n💡 Patent Analysis Report:")
    print(f"   Innovations Found: {len(report.patent_findings)}")
    
    if report.patent_findings:
        print("\n   Top Innovations:")
        for patent in report.patent_findings[:3]:
            print(f"   - {patent['title']}")
            print(f"     Score: {patent['patentability_score']}/5")
            print(f"     Type: {patent['innovation_type']}")
    
    return report


async def demo_custom_config():
    """Demo: Using custom configuration."""
    print("\n" + "=" * 60)
    print("DEMO 5: Custom Configuration")
    print("=" * 60)
    
    # Create custom config
    custom_config = Path("demo_config.yml")
    with open(custom_config, 'w') as f:
        f.write("""
execution_mode: full
parallel_execution: true
max_workers: 2

security_tests:
  red_team: false  # Skip heavy red team for demo
  fuzzing: true
  chaos: false
  adversarial: true

patent_analysis:
  enabled: true
  prior_art_search: false  # Skip for speed
  claim_generation: true

documentation:
  technical_guide: true
  security_report: true
  compliance: false
  patent_draft: true

thresholds:
  security_score_minimum: 90  # Stricter threshold
  patent_score_minimum: 4     # Higher bar for patents
""")
    
    # Create handler with custom config
    handler = TaskCompletionHandler(config_path=custom_config)
    
    task_context = TaskContext(
        task_id="DEMO-005",
        task_type=TaskType.FEATURE,
        title="Add custom security validation",
        description="Implement custom validation with strict thresholds",
        classification_level=ClassificationLevel.UNCLASSIFIED,
        changed_files=["security-framework/src/custom_validator.py"],
        author="demo_user"
    )
    
    print("\nRunning with custom configuration...")
    report = await handler.handle_task_completion(task_context)
    
    print(f"\n⚙️  Custom Config Report:")
    print(f"   Security Threshold: 90 (vs default 85)")
    print(f"   Security Score: {report.security_results.get('summary', {}).get('score', 0)}/100")
    print(f"   Meets Custom Threshold: {report.security_results.get('summary', {}).get('score', 0) >= 90}")
    
    # Clean up
    custom_config.unlink()
    
    return report


async def main():
    """Run all demos."""
    print("🚀 ALCUB3 Task Completion Handler Demo")
    print("=====================================\n")
    
    demos = [
        ("Feature Completion", demo_feature_completion),
        ("Security Patch", demo_security_patch),
        ("Quick Validation", demo_quick_validation),
        ("Patent Analysis", demo_patent_analysis),
        ("Custom Config", demo_custom_config)
    ]
    
    results = []
    for name, demo_func in demos:
        try:
            report = await demo_func()
            results.append((name, "Success", report))
        except Exception as e:
            print(f"\n❌ {name} demo failed: {str(e)}")
            results.append((name, "Failed", str(e)))
    
    # Summary
    print("\n" + "=" * 60)
    print("DEMO SUMMARY")
    print("=" * 60)
    
    for name, status, _ in results:
        emoji = "✅" if status == "Success" else "❌"
        print(f"{emoji} {name}: {status}")
    
    print("\n✨ Demo complete!")
    print("\nTo use in your workflow:")
    print("1. Install git hooks: ./security-framework/hooks/install-hooks.sh")
    print("2. Configure settings: .alcub3/config/task-completion.yml")
    print("3. Use GitHub Actions: .github/workflows/task-completion-security.yml")


if __name__ == "__main__":
    # Note: This is a demo script. In production, the handler would be
    # triggered automatically by git hooks, CI/CD, or API calls.
    print("Note: This is a demo. Some features are simulated for demonstration.")
    print("In production, actual security tests and patent analysis would run.\n")
    
    asyncio.run(main())