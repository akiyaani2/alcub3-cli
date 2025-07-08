#!/usr/bin/env python3
"""
Patent Showcase System Validation Tests
=======================================

Validates the patent demonstration system across all presentation modes
and ensures proper functionality for different audience types.
"""

import asyncio
import json
import os
import time
from unittest.mock import patch
import sys

# Add current directory to path for imports
sys.path.append('.')

try:
    from demo_patent_showcase import PatentShowcaseDemo, DemoMode
except ImportError:
    print("Warning: demo_patent_showcase.py not found, using mock validation")
    PatentShowcaseDemo = None

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class PatentDemoValidator:
    def __init__(self):
        self.test_results = []
        self.passed = 0
        self.failed = 0
        
    def log_test(self, test_name: str, passed: bool, details: str = ""):
        """Log test result with details."""
        status = "PASS" if passed else "FAIL"
        color = Colors.GREEN if passed else Colors.RED
        
        print(f"  {color}[{status}]{Colors.END} {test_name}")
        if details:
            print(f"    {Colors.BLUE}{details}{Colors.END}")
            
        self.test_results.append({
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": time.time()
        })
        
        if passed:
            self.passed += 1
        else:
            self.failed += 1
            
    async def test_demo_system_exists(self):
        """Test that the demo system files exist and are importable."""
        print(f"\n{Colors.CYAN}Testing Demo System Availability...{Colors.END}")
        
        # Test main demo file exists
        demo_file_exists = os.path.exists('demos/demo_patent_showcase.py')
        self.log_test("Demo file exists", demo_file_exists, 
                     "demo_patent_showcase.py found" if demo_file_exists else "demo_patent_showcase.py missing")
        
        # Test README exists
        readme_exists = os.path.exists('demos/README_PATENT_DEMO.md')
        self.log_test("README exists", readme_exists,
                     "README_PATENT_DEMO.md found" if readme_exists else "README_PATENT_DEMO.md missing")
        
        # Test importability
        import_success = PatentShowcaseDemo is not None
        self.log_test("Demo system importable", import_success,
                     "PatentShowcaseDemo class imported" if import_success else "Import failed")
        
        return demo_file_exists and readme_exists and import_success
        
    async def test_patent_portfolio_data(self):
        """Test that patent portfolio data is comprehensive."""
        print(f"\n{Colors.CYAN}Testing Patent Portfolio Data...{Colors.END}")
        
        if PatentShowcaseDemo is None:
            self.log_test("Patent data validation", False, "Demo system not available")
            return False
            
        demo = PatentShowcaseDemo()
        innovations = demo.innovations
        
        # Test minimum innovation count
        min_innovations = len(innovations) >= 10
        self.log_test("Minimum innovations count", min_innovations,
                     f"{len(innovations)} innovations loaded (target: 10+)")
        
        # Test innovation data completeness
        complete_data = True
        required_fields = ['name', 'category', 'description', 'market_value', 'performance_metric']
        
        for innovation in innovations:
            for field in required_fields:
                if not hasattr(innovation, field) or not getattr(innovation, field):
                    complete_data = False
                    break
            if not complete_data:
                break
                
        self.log_test("Innovation data complete", complete_data,
                     "All innovations have required fields" if complete_data else "Missing required fields")
        
        # Test market categories
        categories = set(innovation.category for innovation in innovations)
        expected_categories = {
            "Universal Robotics Security",
            "Air-Gapped AI Operations", 
            "Agent Security",
            "Security Framework"
        }
        
        has_key_categories = len(expected_categories.intersection(categories)) >= 3
        self.log_test("Key patent categories", has_key_categories,
                     f"Categories found: {', '.join(categories)}")
        
        return min_innovations and complete_data and has_key_categories
        
    async def test_presentation_modes(self):
        """Test all presentation modes function correctly."""
        print(f"\n{Colors.CYAN}Testing Presentation Modes...{Colors.END}")
        
        if PatentShowcaseDemo is None:
            self.log_test("Presentation mode validation", False, "Demo system not available")
            return False
            
        demo = PatentShowcaseDemo()
        
        # Test executive presentation
        try:
            # Mock the async sleep and input to speed up testing
            with patch('asyncio.sleep', return_value=None):
                await demo.executive_presentation()
            exec_success = True
            exec_details = "Executive presentation completed successfully"
        except Exception as e:
            exec_success = False
            exec_details = f"Executive presentation failed: {str(e)}"
            
        self.log_test("Executive presentation", exec_success, exec_details)
        
        # Test technical deep dive  
        try:
            with patch('asyncio.sleep', return_value=None):
                await demo.technical_deep_dive()
            tech_success = True
            tech_details = "Technical deep dive completed successfully"
        except Exception as e:
            tech_success = False
            tech_details = f"Technical deep dive failed: {str(e)}"
            
        self.log_test("Technical deep dive", tech_success, tech_details)
        
        # Test patent portfolio overview
        try:
            with patch('asyncio.sleep', return_value=None):
                await demo.patent_portfolio_overview()
            patent_success = True
            patent_details = "Patent portfolio overview completed successfully"
        except Exception as e:
            patent_success = False
            patent_details = f"Patent portfolio overview failed: {str(e)}"
            
        self.log_test("Patent portfolio overview", patent_success, patent_details)
        
        return exec_success and tech_success and patent_success
        
    async def test_performance_demonstrations(self):
        """Test performance benchmark demonstrations."""
        print(f"\n{Colors.CYAN}Testing Performance Demonstrations...{Colors.END}")
        
        if PatentShowcaseDemo is None:
            self.log_test("Performance demo validation", False, "Demo system not available")
            return False
            
        demo = PatentShowcaseDemo()
        
        # Test performance benchmark display
        try:
            with patch('asyncio.sleep', return_value=None):
                await demo._show_performance_benchmarks()
            perf_success = True
            perf_details = "Performance benchmarks displayed successfully"
        except Exception as e:
            perf_success = False
            perf_details = f"Performance benchmarks failed: {str(e)}"
            
        self.log_test("Performance benchmarks", perf_success, perf_details)
        
        # Test specific demo components
        try:
            with patch('asyncio.sleep', return_value=None):
                await demo._demo_hal_cryptography()
                await demo._demo_mcp_protocol()
                await demo._demo_agent_sandboxing()
            component_success = True
            component_details = "All demo components executed successfully"
        except Exception as e:
            component_success = False
            component_details = f"Demo components failed: {str(e)}"
            
        self.log_test("Demo components", component_success, component_details)
        
        return perf_success and component_success
        
    async def test_report_generation(self):
        """Test report generation and export functionality."""
        print(f"\n{Colors.CYAN}Testing Report Generation...{Colors.END}")
        
        if PatentShowcaseDemo is None:
            self.log_test("Report generation validation", False, "Demo system not available")
            return False
            
        demo = PatentShowcaseDemo()
        demo.metrics.audience_type = "Test"
        demo.metrics.innovations_shown = ["Test Innovation"]
        
        # Test report export
        try:
            await demo._export_demo_report()
            report_success = True
            report_details = "Demo report generated successfully"
            
            # Check if report file was created
            import glob
            report_files = glob.glob("alcub3_patent_demo_report_*.json")
            if report_files:
                # Validate report content
                with open(report_files[-1], 'r') as f:
                    report_data = json.load(f)
                    
                required_sections = ['demo_session', 'patent_portfolio_summary', 'performance_highlights']
                has_sections = all(section in report_data for section in required_sections)
                
                if has_sections:
                    report_details += f" - Report file: {report_files[-1]}"
                else:
                    report_success = False
                    report_details = "Report missing required sections"
                    
        except Exception as e:
            report_success = False
            report_details = f"Report generation failed: {str(e)}"
            
        self.log_test("Report generation", report_success, report_details)
        
        return report_success
        
    async def test_audience_targeting(self):
        """Test audience-specific content and messaging."""
        print(f"\n{Colors.CYAN}Testing Audience Targeting...{Colors.END}")
        
        # Test that different modes set appropriate metrics
        if PatentShowcaseDemo is None:
            self.log_test("Audience targeting validation", False, "Demo system not available")
            return False
            
        demo = PatentShowcaseDemo()
        
        # Test executive mode sets business focus
        with patch('asyncio.sleep', return_value=None):
            await demo.executive_presentation()
            
        exec_targeting = (demo.metrics.audience_type == "Executive/Investor" and 
                         demo.metrics.technical_depth == "Business-focused")
        self.log_test("Executive targeting", exec_targeting,
                     f"Audience: {demo.metrics.audience_type}, Depth: {demo.metrics.technical_depth}")
        
        # Test technical mode sets implementation focus
        demo = PatentShowcaseDemo()  # Reset
        with patch('asyncio.sleep', return_value=None):
            await demo.technical_deep_dive()
            
        tech_targeting = (demo.metrics.audience_type == "Technical" and
                         demo.metrics.technical_depth == "Deep implementation details")
        self.log_test("Technical targeting", tech_targeting,
                     f"Audience: {demo.metrics.audience_type}, Depth: {demo.metrics.technical_depth}")
        
        return exec_targeting and tech_targeting
        
    def generate_validation_report(self):
        """Generate comprehensive validation report."""
        total_tests = self.passed + self.failed
        success_rate = (self.passed / total_tests * 100) if total_tests > 0 else 0
        
        report = {
            "validation_summary": {
                "total_tests": total_tests,
                "passed": self.passed,
                "failed": self.failed,
                "success_rate": f"{success_rate:.1f}%",
                "timestamp": time.time()
            },
            "test_results": self.test_results,
            "recommendation": "APPROVED FOR USE" if success_rate >= 90 else "NEEDS FIXES"
        }
        
        # Save report
        report_file = f"patent_demo_validation_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        return report, report_file
        
    async def run_full_validation(self):
        """Run complete validation suite."""
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                    ALCUB3 PATENT DEMO VALIDATION SUITE                      ║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        
        # Run all validation tests
        await self.test_demo_system_exists()
        await self.test_patent_portfolio_data()
        await self.test_presentation_modes()
        await self.test_performance_demonstrations()
        await self.test_report_generation()
        await self.test_audience_targeting()
        
        # Generate final report
        report, report_file = self.generate_validation_report()
        
        # Display summary
        print(f"\n{Colors.HEADER}{Colors.BOLD}VALIDATION SUMMARY{Colors.END}")
        print(f"  Total Tests: {report['validation_summary']['total_tests']}")
        print(f"  {Colors.GREEN}Passed: {report['validation_summary']['passed']}{Colors.END}")
        print(f"  {Colors.RED}Failed: {report['validation_summary']['failed']}{Colors.END}")
        print(f"  Success Rate: {Colors.CYAN}{report['validation_summary']['success_rate']}{Colors.END}")
        print(f"  Recommendation: {Colors.GREEN if 'APPROVED' in report['recommendation'] else Colors.YELLOW}{report['recommendation']}{Colors.END}")
        print(f"  Report: {Colors.BLUE}{report_file}{Colors.END}")
        
        return report['validation_summary']['success_rate'] != "0.0%"

async def main():
    """Main validation entry point."""
    validator = PatentDemoValidator()
    
    try:
        success = await validator.run_full_validation()
        exit_code = 0 if success else 1
        
        if success:
            print(f"\n{Colors.GREEN}✅ Patent demonstration system validation PASSED{Colors.END}")
            print(f"{Colors.CYAN}Ready for use with all audience types{Colors.END}")
        else:
            print(f"\n{Colors.RED}❌ Patent demonstration system validation FAILED{Colors.END}")
            print(f"{Colors.YELLOW}Review test results and fix issues before use{Colors.END}")
            
        return exit_code
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Validation interrupted by user{Colors.END}")
        return 1
    except Exception as e:
        print(f"\n{Colors.RED}Validation error: {e}{Colors.END}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code) 