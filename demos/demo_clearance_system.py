#!/usr/bin/env python3
"""
ALCUB3 PKI/CAC Access Control System - Interactive Demo
Self-contained demonstration for stakeholder presentations

This demo simulates a complete PKI/CAC authentication and clearance system
without requiring actual smart cards or DoD infrastructure. Perfect for
client demonstrations, investor meetings, or technical reviews.

Usage:
    python3 demo_clearance_system.py
    
Features:
- Interactive menu-driven interface
- Realistic authentication scenarios
- Performance benchmarking
- Visual security status display
- Export demo results to report
"""

import os
import sys
import time
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from enum import Enum

# Add some visual flair for presentations
try:
    import colorama
    from colorama import Fore, Style, Back
    colorama.init()
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback for environments without colorama
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""

def colored_print(text: str, color: str = "", style: str = "", end: str = "\n"):
    """Print colored text if colors are available."""
    if COLORS_AVAILABLE:
        print(f"{style}{color}{text}{Style.RESET_ALL}", end=end)
    else:
        print(text, end=end)

def print_header(title: str):
    """Print a formatted header."""
    colored_print("=" * 70, Fore.CYAN, Style.BRIGHT)
    colored_print(f" {title.center(68)} ", Fore.WHITE, Style.BRIGHT, end='')
    print()
    colored_print("=" * 70, Fore.CYAN, Style.BRIGHT)

def print_section(title: str):
    """Print a formatted section header."""
    print("\n") # Add a newline before the section title
    colored_print(f"🔹 {title}", Fore.YELLOW, Style.BRIGHT)
    colored_print("-" * (len(title) + 3), Fore.YELLOW)

def print_success(message: str):
    """Print a success message."""
    colored_print(f"✅ {message}", Fore.GREEN, Style.BRIGHT)

def print_warning(message: str):
    """Print a warning message."""
    colored_print(f"⚠️  {message}", Fore.YELLOW, Style.BRIGHT)

def print_error(message: str):
    """Print an error message."""
    colored_print(f"❌ {message}", Fore.RED, Style.BRIGHT)

def print_info(message: str):
    """Print an info message."""
    colored_print(f"ℹ️  {message}", Fore.BLUE)

# Demo Data Classes
class ClearanceLevel(Enum):
    NONE = "none"
    PUBLIC_TRUST = "public_trust"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"
    TS_SCI = "ts_sci"

class PKINetwork(Enum):
    NIPRNET = "niprnet"
    SIPRNET = "siprnet"
    JWICS = "jwics"

class AccessResult(Enum):
    GRANTED = "granted"
    DENIED = "denied"
    PENDING = "pending"

@dataclass
class DemoUser:
    user_id: str
    name: str
    clearance_level: ClearanceLevel
    card_uuid: str
    pki_network: PKINetwork
    role: str
    compartments: List[str]
    last_auth: datetime = None

@dataclass
class DemoMetrics:
    total_authentications: int = 0
    successful_authentications: int = 0
    clearance_validations: int = 0
    access_decisions: int = 0
    avg_auth_time_ms: float = 0.0
    avg_validation_time_ms: float = 0.0
    system_uptime_hours: float = 0.0

class ALCUB3Demo:
    """Interactive demonstration of ALCUB3 PKI/CAC access control system."""
    
    def __init__(self):
        """Initialize the demo environment."""
        self.start_time = datetime.now()
        self.metrics = DemoMetrics()
        self.demo_users = self._create_demo_users()
        self.current_user = None
        self.demo_log = []

        # Check for colorama dependency
        if not COLORS_AVAILABLE:
            print_warning("Colorama not found. Demo will run without colors. Install with: pip install colorama")
        
    def _create_demo_users(self) -> Dict[str, DemoUser]:
        """Create realistic demo user accounts."""
        users = {
            "jane.analyst": DemoUser(
                user_id="jane.analyst",
                name="Jane Analyst",
                clearance_level=ClearanceLevel.SECRET,
                card_uuid="CAC-12345678-ABCD",
                pki_network=PKINetwork.NIPRNET,
                role="Security Analyst",
                compartments=["INTEL", "SIGINT"]
            ),
            "maj.commander": DemoUser(
                user_id="maj.commander", 
                name="Major John Commander",
                clearance_level=ClearanceLevel.TOP_SECRET,
                card_uuid="PIV-87654321-EFGH",
                pki_network=PKINetwork.SIPRNET,
                role="Military Commander",
                compartments=["CRYPTO", "INTEL", "SIGINT"]
            ),
            "dr.researcher": DemoUser(
                user_id="dr.researcher",
                name="Dr. Sarah Researcher", 
                clearance_level=ClearanceLevel.TS_SCI,
                card_uuid="PIV-11223344-IJKL",
                pki_network=PKINetwork.JWICS,
                role="Research Scientist",
                compartments=["CRYPTO", "NUCLEAR", "SIGINT", "HUMINT"]
            ),
            "contractor.basic": DemoUser(
                user_id="contractor.basic",
                name="Bob Contractor",
                clearance_level=ClearanceLevel.PUBLIC_TRUST,
                card_uuid="CAC-55667788-MNOP",
                pki_network=PKINetwork.NIPRNET,
                role="Support Contractor",
                compartments=[]
            )
        }
        return users
    
    def run_interactive_demo(self):
        """Run the interactive demonstration."""
        self._show_welcome()
        
        while True:
            self._show_main_menu()
            choice = input("\n" + Fore.CYAN + "Select option (1-8): " + Style.RESET_ALL).strip()
            
            if choice == "1":
                self._demo_pki_authentication()
            elif choice == "2":
                self._demo_clearance_validation()
            elif choice == "3":
                self._demo_access_control()
            elif choice == "4":
                self._demo_performance_benchmark()
            elif choice == "5":
                self._show_system_status()
            elif choice == "6":
                self._show_security_metrics()
            elif choice == "7":
                self._export_demo_report()
            elif choice == "8":
                self._show_exit_summary()
                break
            else:
                print_error("Invalid option. Please select 1-8.")
            
            input("\n" + Fore.GRAY + "Press Enter to continue..." + Style.RESET_ALL)

    def run_scripted_demo(self, script_file: str):
        """Run the demo using a predefined script of commands."""
        self._show_welcome()
        
        try:
            with open(script_file, 'r') as f:
                commands = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except FileNotFoundError:
            print_error(f"Script file not found: {script_file}")
            return

        print_info(f"Running scripted demo from {script_file}...")
        for i, command in enumerate(commands):
            command = command.split('#')[0].strip() # Remove comments and strip whitespace
            if not command: # Skip empty lines after stripping
                continue
            print_info(f"--- Executing command {i+1}/{len(commands)}: {command} ---")
            time.sleep(1) # Pause for readability
            
            if command == "1":
                # For authentication, we need to select a user. Assume first user for scripted.
                self._authenticate_user(list(self.demo_users.values())[0])
            elif command == "2":
                self._demo_clearance_validation()
            elif command == "3":
                self._demo_access_control()
            elif command == "4":
                self._demo_performance_benchmark()
            elif command == "5":
                self._show_system_status()
            elif command == "6":
                self._show_security_metrics()
            elif command == "7":
                self._export_demo_report()
            elif command == "8":
                self._show_exit_summary()
                break # Exit after summary in scripted mode
            else:
                print_error(f"Unknown command in script: {command}")
                
        print_info("\nScripted demo finished.")
        self._show_exit_summary() # Ensure summary is shown at the end of scripted demo
    
    def _show_welcome(self):
        """Display welcome screen."""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        print_header("ALCUB3 PKI/CAC ACCESS CONTROL SYSTEM DEMO")
        colored_print("\n🛡️  DEFENSE-GRADE AI INTEGRATION PLATFORM", Fore.GREEN, Style.BRIGHT)
        colored_print("   Patent-Pending Security Clearance Authentication", Fore.WHITE)
        
        print_section("Demo Environment Initialized")
        print_success(f"Demo started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print_success(f"Demo users loaded: {len(self.demo_users)}")
        print_success("PKI/CAC simulation ready")
        print_success("Security framework active")
        
        print_info("\nThis demonstration showcases:")
        print("   • PKI/CAC smart card authentication")
        print("   • DoD security clearance validation")
        print("   • Role-based access control")
        print("   • Real-time performance monitoring")
        print("   • Defense-grade compliance validation")
    
    def _show_main_menu(self):
        """Display the main demo menu."""
        print("\n")
        print_header("DEMO MENU")
        
        colored_print("1. 🔐 PKI/CAC Authentication Demo", Fore.CYAN)
        colored_print("2. 🎖️  Security Clearance Validation", Fore.CYAN)
        colored_print("3. 🛠️  Access Control Demonstration", Fore.CYAN)
        colored_print("4. ⚡ Performance Benchmarking", Fore.CYAN)
        colored_print("5. 📊 System Status Dashboard", Fore.CYAN)
        colored_print("6. 📈 Security Metrics Report", Fore.CYAN)
        colored_print("7. 📄 Export Demo Report", Fore.CYAN)
        colored_print("8. 🚪 Exit Demo", Fore.RED)
    
    def _demo_pki_authentication(self):
        """Demonstrate PKI/CAC authentication process."""
        print_section("PKI/CAC Authentication Demonstration")
        
        print_info("Available demo users:")
        for i, (user_id, user) in enumerate(self.demo_users.items(), 1):
            network_color = Fore.GREEN if user.pki_network == PKINetwork.NIPRNET else Fore.YELLOW
            print(f"   {i}. {user.name} ({user_id})")
            colored_print(f"      Card: {user.card_uuid} | Network: {user.pki_network.value}", network_color)
        
        try:
            choice = int(input(f"\nSelect user (1-{len(self.demo_users)}): ")) - 1
            user_list = list(self.demo_users.values())
            
            if 0 <= choice < len(user_list):
                selected_user = user_list[choice]
                self._authenticate_user(selected_user)
            else:
                print_error("Invalid selection")
        except ValueError:
            print_error("Please enter a valid number")
    
    def _authenticate_user(self, user: DemoUser):
        """Simulate PKI/CAC authentication for a user."""
        print(f"\n🔄 Authenticating {user.name}...")
        
        # Simulate authentication steps with realistic timing
        steps = [
            ("Reading smart card", 0.1),
            ("Validating certificate chain", 0.3),
            ("Checking revocation status", 0.2),
            ("Verifying PIN", 0.1),
            ("Extracting user identity", 0.1)
        ]
        
        total_time = 0
        for step, duration in steps:
            print(f"   • {step}...", end="", flush=True)
            time.sleep(duration)
            total_time += duration * 1000  # Convert to ms
            print_success(f" {duration*1000:.0f}ms")
        
        # Simulate authentication result
        auth_success = random.random() > 0.1  # 90% success rate
        
        if auth_success:
            print_success(f"\n✅ Authentication successful for {user.name}")
            print_info(f"   User ID: {user.user_id}")
            print_info(f"   PKI Network: {user.pki_network.value}")
            print_info(f"   Card UUID: {user.card_uuid}")
            print_info(f"   Total time: {total_time:.0f}ms")
            
            user.last_auth = datetime.now()
            self.current_user = user
            self.metrics.total_authentications += 1
            self.metrics.successful_authentications += 1
            
            # Update average time
            if self.metrics.avg_auth_time_ms == 0:
                self.metrics.avg_auth_time_ms = total_time
            else:
                self.metrics.avg_auth_time_ms = (self.metrics.avg_auth_time_ms + total_time) / 2
                
            self._log_demo_event("PKI_AUTHENTICATION", f"Successful auth for {user.user_id}", total_time)
        else:
            print_error(f"\n❌ Authentication failed for {user.name}")
            print_warning("   Possible causes: expired certificate, invalid PIN, revoked card")
            self.metrics.total_authentications += 1
            self._log_demo_event("PKI_AUTHENTICATION", f"Failed auth for {user.user_id}", total_time)
    
    def _demo_clearance_validation(self):
        """Demonstrate security clearance validation."""
        print_section("Security Clearance Validation")
        
        if not self.current_user:
            print_warning("No authenticated user. Running authentication first...")
            self._authenticate_user(list(self.demo_users.values())[0])
        
        user = self.current_user
        print_info(f"Validating clearance for: {user.name}")
        
        # Demonstrate different clearance scenarios
        scenarios = [
            ("Access UNCLASSIFIED data", ClearanceLevel.NONE, True),
            ("Access SECRET intelligence", ClearanceLevel.SECRET, user.clearance_level.value in ["secret", "top_secret", "ts_sci"]),
            ("Access TOP SECRET operations", ClearanceLevel.TOP_SECRET, user.clearance_level.value in ["top_secret", "ts_sci"]),
            ("Access TS/SCI compartments", ClearanceLevel.TS_SCI, user.clearance_level.value == "ts_sci")
        ]
        
        print_info("\nTesting clearance scenarios:")
        
        for scenario, required_level, should_pass in scenarios:
            print(f"\n   🧪 {scenario}")
            print(f"      Required: {required_level.value.upper()}")
            print(f"      User has: {user.clearance_level.value.upper()}")
            
            # Simulate validation time
            start_time = time.time()
            time.sleep(0.02)  # 20ms simulation
            validation_time = (time.time() - start_time) * 1000
            
            if should_pass:
                print_success(f"      ✅ GRANTED ({validation_time:.0f}ms)")
            else:
                print_error(f"      ❌ DENIED ({validation_time:.0f}ms)")
            
            self.metrics.clearance_validations += 1
            
            # Update average validation time
            if self.metrics.avg_validation_time_ms == 0:
                self.metrics.avg_validation_time_ms = validation_time
            else:
                self.metrics.avg_validation_time_ms = (self.metrics.avg_validation_time_ms + validation_time) / 2
        
        # Show compartment access
        if user.compartments:
            print_info(f"\n🔒 Available compartments: {', '.join(user.compartments)}")
        
        self._log_demo_event("CLEARANCE_VALIDATION", f"Validated {len(scenarios)} scenarios", 
                           self.metrics.avg_validation_time_ms)
    
    def _demo_access_control(self):
        """Demonstrate role-based access control."""
        print_section("Role-Based Access Control")
        
        if not self.current_user:
            print_warning("No authenticated user. Please authenticate first.")
            return
        
        user = self.current_user
        print_info(f"Testing tool access for: {user.name} ({user.role})")
        
        # Define tools with different access requirements
        tools = [
            ("validate_input", "Input Validation", ClearanceLevel.NONE, "unclassified"),
            ("generate_content", "Content Generation", ClearanceLevel.PUBLIC_TRUST, "cui"), 
            ("robotics_control", "Robotics Control", ClearanceLevel.SECRET, "secret"),
            ("security_audit", "Security Audit", ClearanceLevel.SECRET, "secret"),
            ("system_admin", "System Administration", ClearanceLevel.TOP_SECRET, "top_secret")
        ]
        
        print_info("\nTesting tool access permissions:")
        
        for tool_id, tool_name, required_clearance, data_classification in tools:
            print(f"\n   🛠️  {tool_name}")
            print(f"      Classification: {data_classification.upper()}")
            print(f"      Required clearance: {required_clearance.value.upper()}")
            
            # Simulate access decision
            start_time = time.time()
            time.sleep(0.03)  # 30ms simulation
            decision_time = (time.time() - start_time) * 1000
            
            # Determine access based on clearance hierarchy
            clearance_hierarchy = {
                "none": 0, "public_trust": 1, "confidential": 2, 
                "secret": 3, "top_secret": 4, "ts_sci": 5
            }
            
            user_level = clearance_hierarchy.get(user.clearance_level.value, 0)
            required_level = clearance_hierarchy.get(required_clearance.value, 0)
            
            if user_level >= required_level:
                print_success(f"      ✅ ACCESS GRANTED ({decision_time:.0f}ms)")
                print_info(f"         Authorized via role: {user.role}")
            else:
                print_error(f"      ❌ ACCESS DENIED ({decision_time:.0f}ms)")
                print_warning(f"         Insufficient clearance level")
            
            self.metrics.access_decisions += 1
        
        self._log_demo_event("ACCESS_CONTROL", f"Tested {len(tools)} tools", 30.0)
    
    def _demo_performance_benchmark(self):
        """Demonstrate system performance benchmarking."""
        print_section("Performance Benchmarking")
        
        benchmarks = [
            ("PKI Authentication", 1000, 50),
            ("Clearance Validation", 5000, 50),
            ("Access Authorization", 2000, 100),
            ("Concurrent Operations", 10000, 200)
        ]
        
        print_info("Running performance benchmarks...")
        
        results = {}
        for benchmark_name, iterations, target_ms in benchmarks:
            print(f"\n   🏃 {benchmark_name}")
            print(f"      Iterations: {iterations:,}")
            print(f"      Target: <{target_ms}ms average")
            
            # Simulate benchmark
            start_time = time.time()
            
            # Realistic performance simulation
            base_time = target_ms * 0.6  # Perform better than target
            variation = target_ms * 0.2  # Add some realistic variation
            
            total_time = 0
            for i in range(iterations):
                op_time = base_time + random.uniform(-variation, variation)
                total_time += max(op_time, 1)  # Minimum 1ms
                
                if i % (iterations // 10) == 0:  # Show progress
                    progress = (i / iterations) * 100
                    print(f"      Progress: {progress:.0f}%", end="\r", flush=True)
            
            avg_time = total_time / iterations
            benchmark_duration = time.time() - start_time
            
            print(f"      Progress: 100%")
            
            if avg_time <= target_ms:
                print_success(f"      ✅ PASSED: {avg_time:.2f}ms average")
            else:
                print_error(f"      ❌ FAILED: {avg_time:.2f}ms average")
            
            print_info(f"      Benchmark completed in {benchmark_duration:.2f}s")
            
            results[benchmark_name] = {
                "avg_time_ms": avg_time,
                "target_ms": target_ms,
                "iterations": iterations,
                "passed": avg_time <= target_ms
            }
        
        # Summary
        passed_tests = sum(1 for r in results.values() if r["passed"])
        total_tests = len(results)
        
        print_info(f"\n📊 Benchmark Summary:")
        print_success(f"   Tests passed: {passed_tests}/{total_tests}")
        
        if passed_tests == total_tests:
            print_success("   🎉 ALL PERFORMANCE TARGETS MET!")
        else:
            print_warning("   ⚠️  Some performance targets missed")
        
        self._log_demo_event("PERFORMANCE_BENCHMARK", f"Completed {total_tests} benchmarks", 0)
    
    def _show_system_status(self):
        """Display current system status dashboard."""
        print_section("System Status Dashboard")
        
        uptime = datetime.now() - self.start_time
        uptime_str = f"{uptime.total_seconds() / 3600:.1f} hours"
        
        # System status
        print_info("🖥️  System Information:")
        print_success(f"   Status: OPERATIONAL")
        print_success(f"   Uptime: {uptime_str}")
        print_success(f"   Demo version: 1.0.0")
        print_success(f"   Framework: MAESTRO L1-L3")
        
        # Authentication status
        print_info("\n🔐 Authentication Status:")
        if self.current_user:
            print_success(f"   Current user: {self.current_user.name}")
            print_success(f"   Clearance: {self.current_user.clearance_level.value.upper()}")
            print_success(f"   Last auth: {self.current_user.last_auth.strftime('%H:%M:%S') if self.current_user.last_auth else 'Never'}")
        else:
            print_warning("   No user currently authenticated")
        
        # Security features status
        print_info("\n🛡️  Security Features:")
        features = [
            ("PKI/CAC Authentication", "ACTIVE"),
            ("Security Clearance Validation", "ACTIVE"),
            ("Role-Based Access Control", "ACTIVE"),
            ("Hardware Security Module", "SIMULATED"),
            ("Audit Logging", "ACTIVE"),
            ("Performance Monitoring", "ACTIVE")
        ]
        
        for feature, status in features:
            if status == "ACTIVE":
                print_success(f"   {feature}: {status}")
            else:
                print_warning(f"   {feature}: {status}")
    
    def _show_security_metrics(self):
        """Display security metrics and statistics."""
        print_section("Security Metrics Report")
        
        # Update metrics
        self.metrics.system_uptime_hours = (datetime.now() - self.start_time).total_seconds() / 3600
        
        print_info("📊 Authentication Metrics:")
        print(f"   Total authentications: {self.metrics.total_authentications}")
        print(f"   Successful authentications: {self.metrics.successful_authentications}")
        success_rate = (self.metrics.successful_authentications / max(self.metrics.total_authentications, 1)) * 100
        print(f"   Success rate: {success_rate:.1f}%")
        print(f"   Average auth time: {self.metrics.avg_auth_time_ms:.1f}ms")
        
        print_info("\n🎖️  Authorization Metrics:")
        print(f"   Clearance validations: {self.metrics.clearance_validations}")
        print(f"   Access decisions: {self.metrics.access_decisions}")
        print(f"   Average validation time: {self.metrics.avg_validation_time_ms:.1f}ms")
        
        print_info("\n⚡ Performance Status:")
        auth_compliant = self.metrics.avg_auth_time_ms < 50
        validation_compliant = self.metrics.avg_validation_time_ms < 50
        
        if auth_compliant:
            print_success(f"   Authentication performance: COMPLIANT (<50ms)")
        else:
            print_warning(f"   Authentication performance: NON-COMPLIANT (>{self.metrics.avg_auth_time_ms:.1f}ms)")
        
        if validation_compliant:
            print_success(f"   Validation performance: COMPLIANT (<50ms)")
        else:
            print_warning(f"   Validation performance: NON-COMPLIANT (>{self.metrics.avg_validation_time_ms:.1f}ms)")
        
        print_info(f"\n🕐 System Uptime: {self.metrics.system_uptime_hours:.2f} hours")
    
    def _export_demo_report(self):
        """Export demo results to a report file."""
        print_section("Export Demo Report")
        
        report = {
            "demo_info": {
                "title": "ALCUB3 PKI/CAC Access Control System Demo",
                "date": datetime.now().isoformat(),
                "duration_hours": (datetime.now() - self.start_time).total_seconds() / 3600,
                "version": "1.0.0"
            },
            "metrics": asdict(self.metrics),
            "demo_users": {uid: asdict(user) for uid, user in self.demo_users.items()},
            "current_user": asdict(self.current_user) if self.current_user else None,
            "demo_log": self.demo_log
        }
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(os.path.dirname(__file__), f"alcub3_demo_report_{timestamp}.json")
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            print_success(f"Demo report exported to: {filename}")
            print_info(f"Report size: {os.path.getsize(filename)} bytes")
            print_info("Report includes:")
            print("   • Complete demo metrics")
            print("   • User authentication history")
            print("   • Performance benchmarks")
            print("   • Security event log")
            
        except Exception as e:
            print_error(f"Failed to export report: {e}")
    
    def _log_demo_event(self, event_type: str, description: str, duration_ms: float):
        """Log demo events for reporting."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "description": description,
            "duration_ms": duration_ms,
            "user": self.current_user.user_id if self.current_user else None
        }
        self.demo_log.append(event)
    
    def _show_exit_summary(self):
        """Display demo completion summary."""
        print_section("Demo Session Summary")
        
        duration = datetime.now() - self.start_time
        duration_str = f"{duration.total_seconds() / 60:.1f} minutes"
        
        print_success(f"Demo completed successfully!")
        print_info(f"Session duration: {duration_str}")
        print_info(f"Events logged: {len(self.demo_log)}")
        
        if self.metrics.total_authentications > 0:
            print_info(f"Authentications performed: {self.metrics.total_authentications}")
            print_info(f"Success rate: {(self.metrics.successful_authentications/self.metrics.total_authentications)*100:.1f}%")
        
        print_info("\n🎯 Demo Features Showcased:")
        print("   ✅ PKI/CAC smart card authentication")
        print("   ✅ DoD security clearance validation")
        print("   ✅ Role-based access control")
        print("   ✅ Real-time performance monitoring")
        print("   ✅ Security metrics and reporting")
        
        print_info("\n🚀 ALCUB3 Ready for:")
        print("   • Defense contractor demonstrations")
        print("   • Phase 3 Universal Robotics Security")
        print("   • Production deployment")
        print("   • Patent application filing")
        
        colored_print("\nThank you for exploring ALCUB3!", Fore.GREEN, Style.BRIGHT)

import argparse

def main():
    """Main demo entry point."""
    parser = argparse.ArgumentParser(description="ALCUB3 PKI/CAC Access Control System Demo")
    parser.add_argument("--scripted", type=str, help="Path to a file containing a list of commands to execute.")
    args = parser.parse_args()

    try:
        demo = ALCUB3Demo()
        if args.scripted:
            demo.run_scripted_demo(args.scripted)
        else:
            demo.run_interactive_demo()
    except KeyboardInterrupt:
        colored_print("\n\n⏸️  Demo interrupted by user", Fore.YELLOW, Style.BRIGHT)
        colored_print("Thank you for exploring ALCUB3!", Fore.GREEN)
    except Exception as e:
        colored_print(f"\n❌ Demo error: {e}", Fore.RED, Style.BRIGHT)

if __name__ == "__main__":
    main()