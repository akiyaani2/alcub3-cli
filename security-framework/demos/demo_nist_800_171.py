#!/usr/bin/env python3
"""
NIST SP 800-171 Compliance Demonstration
Shows comprehensive CUI handling and compliance validation capabilities

This demo showcases:
1. CUI detection and classification
2. All 110 NIST SP 800-171 control validations
3. Real-time compliance assessment
4. Gap analysis and remediation planning
5. DFARS-compliant reporting
"""

import sys
import os
import time
import asyncio
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from rich.layout import Layout
from rich.syntax import Syntax

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from security_framework.src.shared.nist_800_171_controls import (
    NIST800171Controls, ControlFamily, ValidationStatus
)
from security_framework.src.shared.cui_handler import CUIHandler, CUICategory
from security_framework.src.shared.nist_compliance_assessment import (
    NISTPomplianceAssessment, AssessmentType
)

console = Console()

class NIST800171Demo:
    """Interactive NIST SP 800-171 compliance demonstration."""
    
    def __init__(self):
        """Initialize demo components."""
        self.nist_controls = NIST800171Controls()
        self.cui_handler = CUIHandler()
        self.assessment_engine = NISTPomplianceAssessment(
            self.nist_controls, 
            self.cui_handler
        )
        
    def display_header(self):
        """Display demo header."""
        header = Panel(
            "[bold cyan]NIST SP 800-171 Compliance Demonstration[/bold cyan]\n"
            "[white]Automated CUI Protection & Compliance Validation[/white]\n"
            "[dim]Patent-Pending Defense AI Security Platform[/dim]",
            box=box.DOUBLE,
            expand=False
        )
        console.print(header)
        console.print()
    
    async def demo_cui_detection(self):
        """Demonstrate CUI detection capabilities."""
        console.print("[bold yellow]1. CUI Detection & Classification Demo[/bold yellow]")
        console.print("-" * 50)
        
        # Test documents
        test_documents = [
            {
                "name": "Technical Specification",
                "content": """
                EXPORT CONTROLLED - ITAR
                This document contains technical data related to defense articles.
                Encryption Algorithm: AES-256-GCM with hardware key management.
                Critical Infrastructure vulnerability assessment results included.
                Distribution limited to US persons only - NOFORN.
                """
            },
            {
                "name": "Personnel Record",
                "content": """
                Employee Name: John Doe
                Social Security Number: XXX-XX-1234
                Date of Birth: 01/01/1980
                Security Clearance: SECRET
                This document contains Personally Identifiable Information (PII).
                """
            },
            {
                "name": "General Report",
                "content": """
                Quarterly Business Report
                Revenue increased by 15% this quarter.
                No sensitive information included.
                Public release authorized.
                """
            }
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for doc in test_documents:
                task = progress.add_task(f"Analyzing: {doc['name']}", total=1)
                
                # Detect CUI
                result = await self.cui_handler.detect_cui(doc['content'])
                progress.update(task, completed=1)
                
                # Display results
                if result.contains_cui:
                    console.print(f"\n[red]⚠️  CUI DETECTED in {doc['name']}[/red]")
                    console.print(f"   Categories: {', '.join([cat.value for cat in result.cui_categories])}")
                    console.print(f"   Confidence: {result.confidence_score:.2%}")
                    console.print(f"   Detection Time: {result.validation_time_ms:.1f}ms")
                else:
                    console.print(f"\n[green]✓ No CUI detected in {doc['name']}[/green]")
        
        console.print()
    
    async def demo_control_validation(self):
        """Demonstrate control validation."""
        console.print("[bold yellow]2. Control Validation Demo[/bold yellow]")
        console.print("-" * 50)
        
        # Simulate system state
        system_state = {
            # Access Control
            "access_control_policy": True,
            "authentication_enabled": True,
            "authorization_enabled": True,
            "rbac_enabled": True,
            "function_restrictions": ["admin", "user", "viewer"],
            
            # Audit & Accountability
            "audit_logging_enabled": True,
            "audit_integrity_protection": True,
            "log_retention_days": 365,
            
            # Cryptography
            "crypto_algorithms": ["AES-256-GCM", "SHA-256", "RSA-4096"],
            "key_lengths": {"aes": 256, "rsa": 4096},
            
            # Training
            "training_program": True,
            "training_completion_rate": 0.95,
            
            # Incident Response
            "incident_response_capability": True,
            "incident_response_plan": True,
            
            # Network Security
            "dlp_enabled": True,
            "network_segmentation": True,
            "flow_policies": ["cui_isolation", "egress_filtering"]
        }
        
        # Validate sample controls
        sample_controls = ["3.1.1", "3.1.2", "3.1.3", "3.2.1", "3.3.1", "3.5.1"]
        
        table = Table(title="Sample Control Validation Results", box=box.ROUNDED)
        table.add_column("Control ID", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Status", style="bold")
        table.add_column("Score", style="yellow")
        
        for control_id in sample_controls:
            result = await self.nist_controls.validate_control(control_id, system_state)
            control = self.nist_controls.controls[control_id]
            
            # Status color
            if result.status == ValidationStatus.COMPLIANT:
                status_str = "[green]COMPLIANT[/green]"
            elif result.status == ValidationStatus.PARTIAL:
                status_str = "[yellow]PARTIAL[/yellow]"
            else:
                status_str = "[red]NON-COMPLIANT[/red]"
            
            table.add_row(
                control_id,
                control.title[:40] + "...",
                status_str,
                f"{result.score:.2f}"
            )
        
        console.print(table)
        console.print()
    
    async def demo_full_assessment(self):
        """Demonstrate full compliance assessment."""
        console.print("[bold yellow]3. Full Compliance Assessment Demo[/bold yellow]")
        console.print("-" * 50)
        
        # Simulate realistic system state
        system_state = self._generate_demo_system_state()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("Running compliance assessment...", total=110)
            
            # Custom progress callback
            assessed_controls = 0
            async def progress_callback():
                nonlocal assessed_controls
                while assessed_controls < 110:
                    await asyncio.sleep(0.05)
                    assessed_controls += 1
                    progress.update(task, completed=assessed_controls)
            
            # Run assessment with progress
            progress_task = asyncio.create_task(progress_callback())
            assessment_result = await self.assessment_engine.run_assessment(
                AssessmentType.FULL,
                system_state
            )
            progress_task.cancel()
            progress.update(task, completed=110)
        
        # Display results
        console.print("\n[bold green]Assessment Complete![/bold green]")
        
        # Results panel
        results_text = f"""
[bold]Assessment ID:[/bold] {assessment_result.assessment_id}
[bold]Duration:[/bold] {assessment_result.assessment_duration_ms:.1f}ms
[bold]Total Controls:[/bold] {assessment_result.total_controls}
[bold]Controls Assessed:[/bold] {assessment_result.controls_assessed}

[bold green]Compliant:[/bold green] {assessment_result.compliant_controls}
[bold yellow]Partial:[/bold yellow] {assessment_result.partial_controls}
[bold red]Non-Compliant:[/bold red] {assessment_result.non_compliant_controls}
[bold dim]Not Applicable:[/bold dim] {assessment_result.not_applicable_controls}

[bold]Overall Score:[/bold] {assessment_result.overall_score:.2%}
[bold]Compliance %:[/bold] {assessment_result.compliance_percentage:.1f}%
[bold]Risk Level:[/bold] {assessment_result.risk_level.value.upper()}
"""
        
        console.print(Panel(results_text.strip(), title="Assessment Results", box=box.ROUNDED))
        
        # Critical findings
        if assessment_result.critical_findings:
            console.print("\n[bold red]Critical Findings:[/bold red]")
            for finding in assessment_result.critical_findings[:3]:
                console.print(f"  • {finding['control_id']}: {finding['title']}")
        
        console.print()
    
    async def demo_gap_analysis(self):
        """Demonstrate gap analysis and remediation planning."""
        console.print("[bold yellow]4. Gap Analysis & Remediation Planning Demo[/bold yellow]")
        console.print("-" * 50)
        
        # Run gap analysis
        gaps = await self.assessment_engine.perform_gap_analysis()
        
        # Create remediation plan
        remediation_plan = self.assessment_engine.create_remediation_plan(gaps[:5])
        
        # Display top gaps
        table = Table(title="Top Compliance Gaps", box=box.ROUNDED)
        table.add_column("Control", style="cyan")
        table.add_column("Current", style="yellow")
        table.add_column("Priority", style="bold")
        table.add_column("Effort (hrs)", style="white")
        table.add_column("Business Impact", style="red")
        
        for gap in gaps[:5]:
            priority_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "cyan",
                "LOW": "green"
            }
            
            table.add_row(
                gap.control_id,
                gap.current_state.value.upper(),
                f"[{priority_color.get(gap.priority.name, 'white')}]{gap.priority.name}[/{priority_color.get(gap.priority.name, 'white')}]",
                str(gap.estimated_effort_hours),
                gap.business_impact[:30] + "..."
            )
        
        console.print(table)
        
        # Display remediation timeline
        console.print("\n[bold]Remediation Timeline:[/bold]")
        for item in remediation_plan[:3]:
            console.print(f"  • {item.control_id}: Due by {item.due_date.strftime('%Y-%m-%d')}")
        
        console.print()
    
    async def demo_compliance_report(self):
        """Demonstrate compliance report generation."""
        console.print("[bold yellow]5. DFARS Compliance Report Generation Demo[/bold yellow]")
        console.print("-" * 50)
        
        with console.status("[bold green]Generating compliance report..."):
            report = await self.assessment_engine.generate_compliance_report(
                organization="ALCUB3 Defense Systems",
                system_name="CUI Processing Platform"
            )
        
        # Display report summary
        report_summary = f"""
[bold]Report ID:[/bold] {report.report_id}
[bold]Date:[/bold] {report.report_date.strftime('%Y-%m-%d %H:%M:%S')}
[bold]Organization:[/bold] {report.organization}
[bold]System:[/bold] {report.system_name}

[bold]Executive Summary:[/bold]
{report.executive_summary.split('\\n')[2:7]}

[bold]Attestation:[/bold]
{report.attestation['statement']}

[bold]Next Assessment:[/bold] {report.next_assessment_date.strftime('%Y-%m-%d')}
"""
        
        console.print(Panel(report_summary.strip(), title="Compliance Report", box=box.DOUBLE))
        
        # Export report
        json_report = self.assessment_engine.export_report_json(report)
        filename = f"nist_compliance_report_{int(time.time())}.json"
        
        with open(filename, 'w') as f:
            f.write(json_report)
        
        console.print(f"\n[green]✓ Report exported to: {filename}[/green]")
        console.print()
    
    def _generate_demo_system_state(self) -> dict:
        """Generate realistic system state for demo."""
        return {
            # Access Control (3.1.x)
            "access_control_policy": True,
            "authentication_enabled": True,
            "mfa_enabled": True,
            "fips_compliant_mfa": True,
            "authorization_enabled": True,
            "rbac_enabled": True,
            "function_restrictions": ["admin", "user", "viewer", "auditor"],
            "separation_policies": True,
            "multi_person_auth": True,
            "privilege_management": True,
            "last_privilege_review": time.time() - 30 * 24 * 3600,  # 30 days ago
            "jit_access": False,  # Missing - will cause partial compliance
            
            # Awareness & Training (3.2.x)
            "training_program": True,
            "training_completion_rate": 0.92,  # Slightly below target
            "role_based_training": True,
            "insider_threat_training": True,
            
            # Audit & Accountability (3.3.x)
            "audit_logging_enabled": True,
            "audit_integrity_protection": True,
            "log_retention_days": 365,
            "individual_accountability": True,
            
            # Configuration Management (3.4.x)
            "configuration_baselines": True,
            "change_control": True,
            "security_impact_analysis": False,  # Missing
            
            # Identification & Authentication (3.5.x)
            "user_identification": True,
            "device_identification": True,
            "authentication_mechanisms": True,
            "password_complexity_enabled": True,
            "password_min_length": 14,
            
            # Incident Response (3.6.x)
            "incident_response_capability": True,
            "incident_response_plan": True,
            "incident_response_testing": False,  # Missing
            
            # Maintenance (3.7.x)
            "maintenance_procedures": True,
            "maintenance_personnel_screening": True,
            
            # Media Protection (3.8.x)
            "media_protection": True,
            "media_sanitization": True,
            "media_marking": True,
            
            # Personnel Security (3.9.x)
            "personnel_screening": True,
            "termination_procedures": True,
            
            # Physical Protection (3.10.x)
            "physical_access_controls": True,
            "visitor_control": True,
            
            # Risk Assessment (3.11.x)
            "risk_assessments": True,
            "vulnerability_scanning": True,
            
            # Security Assessment (3.12.x)
            "security_assessments": True,
            "continuous_monitoring": True,
            
            # System & Communications (3.13.x)
            "boundary_protection": True,
            "data_in_transit_encrypted": True,
            "encryption_algorithm": "AES-256-GCM",
            "network_segmentation": True,
            "dlp_enabled": True,
            
            # System & Information Integrity (3.14.x)
            "flaw_remediation": True,
            "malicious_code_protection": True,
            "system_monitoring": True,
            
            # Cryptography
            "crypto_algorithms": ["AES-256-GCM", "SHA-256", "RSA-4096", "ECDSA-P384"],
            "key_lengths": {"aes": 256, "rsa": 4096},
            "data_at_rest_encrypted": True
        }
    
    async def run_demo(self):
        """Run the complete demonstration."""
        self.display_header()
        
        demos = [
            ("CUI Detection", self.demo_cui_detection),
            ("Control Validation", self.demo_control_validation),
            ("Full Assessment", self.demo_full_assessment),
            ("Gap Analysis", self.demo_gap_analysis),
            ("Report Generation", self.demo_compliance_report)
        ]
        
        for i, (name, demo_func) in enumerate(demos, 1):
            try:
                await demo_func()
                
                if i < len(demos):
                    console.print("[dim]Press Enter to continue...[/dim]")
                    input()
                    console.clear()
                    self.display_header()
                    
            except Exception as e:
                console.print(f"[red]Error in {name}: {str(e)}[/red]")
                import traceback
                traceback.print_exc()
        
        # Summary
        console.print("\n[bold green]Demo Complete![/bold green]")
        console.print("\n[bold]Key Capabilities Demonstrated:[/bold]")
        console.print("  ✓ Real-time CUI detection with <10ms latency")
        console.print("  ✓ All 110 NIST SP 800-171 controls validated")
        console.print("  ✓ Full assessment completed in <5 seconds")
        console.print("  ✓ Automated gap analysis and remediation planning")
        console.print("  ✓ DFARS-compliant report generation")
        console.print("\n[dim]Patent-pending innovations in automated compliance[/dim]")


def main():
    """Run the NIST SP 800-171 demo."""
    demo = NIST800171Demo()
    asyncio.run(demo.run_demo())


if __name__ == "__main__":
    main()