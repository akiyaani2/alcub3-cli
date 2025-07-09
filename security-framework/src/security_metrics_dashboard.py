#!/usr/bin/env python3
"""
ALCUB3 Security Metrics Dashboard
Real-time security posture visualization and executive reporting.

This module provides:
- Real-time security metrics visualization
- Executive dashboard for security posture
- Trend analysis and historical tracking
- Compliance status monitoring
- Vulnerability tracking and reporting
"""

import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.figure import Figure
import numpy as np
import pandas as pd
from pathlib import Path

# Add security framework to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from automated_security_testing import SecurityMetrics, AutomatedSecurityTestingOrchestrator

class SecurityMetricsDashboard:
    """Interactive security metrics dashboard for ALCUB3."""
    
    def __init__(self, data_dir: str = "security_reports"):
        """Initialize the security metrics dashboard."""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.metrics_history: List[SecurityMetrics] = []
        self.current_metrics: Optional[SecurityMetrics] = None
        
    def load_metrics_history(self, days: int = 30) -> List[SecurityMetrics]:
        """Load historical metrics from saved reports."""
        metrics_list = []
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Load all JSON reports from data directory
        for report_file in self.data_dir.glob("security_report_*.json"):
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                    
                # Extract metrics from report
                if 'metrics' in data and 'last_assessment' in data['metrics']:
                    metrics_data = data['metrics']
                    # Convert ISO string to datetime
                    metrics_data['last_assessment'] = datetime.fromisoformat(
                        metrics_data['last_assessment'].replace('Z', '+00:00')
                    )
                    
                    # Only include recent metrics
                    if metrics_data['last_assessment'] >= cutoff_date:
                        metrics_list.append(metrics_data)
            except Exception as e:
                print(f"Error loading {report_file}: {e}")
        
        # Sort by date
        metrics_list.sort(key=lambda x: x['last_assessment'])
        self.metrics_history = metrics_list
        
        return metrics_list
    
    def generate_executive_dashboard(self, output_file: str = "security_dashboard.png"):
        """Generate comprehensive executive security dashboard."""
        # Create figure with subplots
        fig = plt.figure(figsize=(20, 12))
        fig.suptitle('ALCUB3 Security Metrics Dashboard', fontsize=20, fontweight='bold')
        
        # Load current metrics from orchestrator
        orchestrator = AutomatedSecurityTestingOrchestrator()
        current_report = orchestrator.get_security_report()
        self.current_metrics = current_report['metrics']
        
        # Load historical data
        self.load_metrics_history()
        
        # Create grid for subplots
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # 1. Security Score Gauge (Top Left)
        ax1 = fig.add_subplot(gs[0, 0])
        self._create_security_score_gauge(ax1, self.current_metrics['security_score'])
        
        # 2. Vulnerability Breakdown (Top Center)
        ax2 = fig.add_subplot(gs[0, 1])
        self._create_vulnerability_breakdown(ax2, self.current_metrics)
        
        # 3. Test Success Rate (Top Right)
        ax3 = fig.add_subplot(gs[0, 2])
        self._create_test_success_gauge(ax3, self.current_metrics)
        
        # 4. Security Score Trend (Middle Left-Center)
        ax4 = fig.add_subplot(gs[1, :2])
        self._create_security_score_trend(ax4)
        
        # 5. Compliance Status (Middle Right)
        ax5 = fig.add_subplot(gs[1, 2])
        self._create_compliance_status(ax5, self.current_metrics)
        
        # 6. Vulnerability Trend (Bottom Left)
        ax6 = fig.add_subplot(gs[2, 0])
        self._create_vulnerability_trend(ax6)
        
        # 7. Test Execution History (Bottom Center)
        ax7 = fig.add_subplot(gs[2, 1])
        self._create_test_execution_history(ax7)
        
        # 8. Key Metrics Summary (Bottom Right)
        ax8 = fig.add_subplot(gs[2, 2])
        self._create_metrics_summary(ax8, self.current_metrics)
        
        # Add timestamp
        fig.text(0.99, 0.01, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", 
                ha='right', va='bottom', fontsize=10, alpha=0.7)
        
        # Save dashboard
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Dashboard saved to: {output_file}")
        
        return output_file
    
    def _create_security_score_gauge(self, ax, score: float):
        """Create security score gauge chart."""
        # Create semi-circular gauge
        theta = np.linspace(0, np.pi, 100)
        radius_outer = 1
        radius_inner = 0.7
        
        # Define color zones
        colors = ['#ff4444', '#ff8800', '#ffbb00', '#88dd00', '#00aa00']
        boundaries = [0, 40, 60, 70, 85, 100]
        
        # Draw colored segments
        for i in range(len(boundaries)-1):
            mask = (score/100 * np.pi >= theta) & (theta >= boundaries[i]/100 * np.pi)
            if np.any(mask):
                ax.fill_between(theta[mask], radius_inner, radius_outer, 
                              color=colors[i], alpha=0.3)
        
        # Draw gauge outline
        ax.plot(theta, [radius_outer]*len(theta), 'k-', linewidth=2)
        ax.plot(theta, [radius_inner]*len(theta), 'k-', linewidth=2)
        ax.plot([0, 0], [radius_inner, radius_outer], 'k-', linewidth=2)
        ax.plot([np.pi, np.pi], [radius_inner, radius_outer], 'k-', linewidth=2)
        
        # Add needle
        needle_angle = score/100 * np.pi
        ax.plot([0, np.cos(needle_angle)*0.9], [0, np.sin(needle_angle)*0.9], 
               'k-', linewidth=4)
        ax.plot(0, 0, 'ko', markersize=10)
        
        # Add score text
        ax.text(0, -0.3, f"{score:.1f}", fontsize=36, fontweight='bold', 
               ha='center', va='center')
        ax.text(0, -0.5, "Security Score", fontsize=14, ha='center', va='center')
        
        # Set limits and remove axes
        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-0.6, 1.2)
        ax.set_aspect('equal')
        ax.axis('off')
    
    def _create_vulnerability_breakdown(self, ax, metrics: Dict[str, Any]):
        """Create vulnerability breakdown pie chart."""
        severities = ['Critical', 'High', 'Medium', 'Low']
        counts = [
            metrics['critical_vulnerabilities'],
            metrics['high_vulnerabilities'],
            metrics['medium_vulnerabilities'],
            metrics['low_vulnerabilities']
        ]
        colors = ['#ff4444', '#ff8800', '#ffbb00', '#88dd00']
        
        # Filter out zero values
        non_zero_data = [(s, c, col) for s, c, col in zip(severities, counts, colors) if c > 0]
        
        if non_zero_data:
            labels, sizes, colors_filtered = zip(*non_zero_data)
            
            wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors_filtered,
                                             autopct='%1.0f%%', startangle=90,
                                             textprops={'fontsize': 12})
            
            # Add total in center
            total_vulns = sum(counts)
            ax.text(0, 0, f"{total_vulns}\nTotal", fontsize=16, fontweight='bold',
                   ha='center', va='center')
        else:
            ax.text(0.5, 0.5, "No Vulnerabilities\nDetected", fontsize=16,
                   ha='center', va='center', transform=ax.transAxes,
                   bbox=dict(boxstyle="round,pad=0.3", facecolor='lightgreen'))
        
        ax.set_title("Vulnerability Breakdown", fontsize=14, fontweight='bold')
    
    def _create_test_success_gauge(self, ax, metrics: Dict[str, Any]):
        """Create test success rate gauge."""
        total_tests = metrics['total_tests_run']
        successful_tests = metrics['successful_tests']
        
        if total_tests > 0:
            success_rate = (successful_tests / total_tests) * 100
        else:
            success_rate = 100
        
        # Create simple circular progress
        theta = np.linspace(0, 2*np.pi, 100)
        radius = 0.8
        
        # Background circle
        ax.plot(radius * np.cos(theta), radius * np.sin(theta), 
               color='lightgray', linewidth=20, solid_capstyle='round')
        
        # Progress arc
        progress_theta = np.linspace(-np.pi/2, -np.pi/2 + (success_rate/100 * 2*np.pi), 100)
        color = '#00aa00' if success_rate >= 90 else '#ff8800' if success_rate >= 70 else '#ff4444'
        ax.plot(radius * np.cos(progress_theta), radius * np.sin(progress_theta), 
               color=color, linewidth=20, solid_capstyle='round')
        
        # Add text
        ax.text(0, 0, f"{success_rate:.0f}%", fontsize=28, fontweight='bold',
               ha='center', va='center')
        ax.text(0, -0.3, f"{successful_tests}/{total_tests}", fontsize=12,
               ha='center', va='center')
        ax.text(0, -1.2, "Test Success Rate", fontsize=14, fontweight='bold',
               ha='center', va='center')
        
        ax.set_xlim(-1.5, 1.5)
        ax.set_ylim(-1.5, 1.5)
        ax.set_aspect('equal')
        ax.axis('off')
    
    def _create_security_score_trend(self, ax):
        """Create security score trend line chart."""
        if not self.metrics_history:
            ax.text(0.5, 0.5, "Insufficient Historical Data", fontsize=14,
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title("Security Score Trend", fontsize=14, fontweight='bold')
            return
        
        # Extract dates and scores
        dates = [m['last_assessment'] for m in self.metrics_history]
        scores = [m['security_score'] for m in self.metrics_history]
        
        # Plot trend line
        ax.plot(dates, scores, 'b-', linewidth=2, marker='o', markersize=6)
        
        # Add threshold lines
        ax.axhline(y=90, color='green', linestyle='--', alpha=0.5, label='Excellent')
        ax.axhline(y=70, color='orange', linestyle='--', alpha=0.5, label='Acceptable')
        ax.axhline(y=50, color='red', linestyle='--', alpha=0.5, label='Critical')
        
        # Format x-axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
        ax.xaxis.set_major_locator(mdates.DayLocator(interval=7))
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)
        
        # Labels and styling
        ax.set_xlabel("Date", fontsize=12)
        ax.set_ylabel("Security Score", fontsize=12)
        ax.set_title("Security Score Trend (30 Days)", fontsize=14, fontweight='bold')
        ax.set_ylim(0, 105)
        ax.grid(True, alpha=0.3)
        ax.legend(loc='lower right')
    
    def _create_compliance_status(self, ax, metrics: Dict[str, Any]):
        """Create compliance status indicators."""
        compliance = metrics.get('compliance_status', {})
        
        standards = list(compliance.keys())
        y_positions = np.arange(len(standards))
        
        # Create horizontal bar chart
        colors = ['green' if compliance[std] else 'red' for std in standards]
        bars = ax.barh(y_positions, [1]*len(standards), color=colors, alpha=0.7)
        
        # Add status text
        for i, (std, compliant) in enumerate(compliance.items()):
            status = "✓ Compliant" if compliant else "✗ Non-Compliant"
            ax.text(0.5, i, status, ha='center', va='center', 
                   fontweight='bold', color='white')
        
        # Styling
        ax.set_yticks(y_positions)
        ax.set_yticklabels(standards)
        ax.set_xlim(0, 1)
        ax.set_xticks([])
        ax.set_title("Compliance Status", fontsize=14, fontweight='bold')
        
        # Add border
        for spine in ax.spines.values():
            spine.set_visible(True)
            spine.set_linewidth(1)
    
    def _create_vulnerability_trend(self, ax):
        """Create vulnerability count trend chart."""
        if not self.metrics_history:
            ax.text(0.5, 0.5, "Insufficient Historical Data", fontsize=14,
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title("Vulnerability Trend", fontsize=14, fontweight='bold')
            return
        
        # Extract data
        dates = [m['last_assessment'] for m in self.metrics_history]
        critical = [m['critical_vulnerabilities'] for m in self.metrics_history]
        high = [m['high_vulnerabilities'] for m in self.metrics_history]
        medium = [m['medium_vulnerabilities'] for m in self.metrics_history]
        low = [m['low_vulnerabilities'] for m in self.metrics_history]
        
        # Create stacked area chart
        ax.fill_between(dates, 0, critical, color='#ff4444', alpha=0.8, label='Critical')
        ax.fill_between(dates, critical, np.array(critical)+np.array(high), 
                       color='#ff8800', alpha=0.8, label='High')
        ax.fill_between(dates, np.array(critical)+np.array(high), 
                       np.array(critical)+np.array(high)+np.array(medium), 
                       color='#ffbb00', alpha=0.8, label='Medium')
        ax.fill_between(dates, np.array(critical)+np.array(high)+np.array(medium), 
                       np.array(critical)+np.array(high)+np.array(medium)+np.array(low), 
                       color='#88dd00', alpha=0.8, label='Low')
        
        # Styling
        ax.set_xlabel("Date", fontsize=12)
        ax.set_ylabel("Vulnerability Count", fontsize=12)
        ax.set_title("Vulnerability Trend", fontsize=14, fontweight='bold')
        ax.legend(loc='upper right')
        ax.grid(True, alpha=0.3)
        
        # Format x-axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)
    
    def _create_test_execution_history(self, ax):
        """Create test execution history chart."""
        if not self.metrics_history:
            ax.text(0.5, 0.5, "Insufficient Historical Data", fontsize=14,
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title("Test Execution History", fontsize=14, fontweight='bold')
            return
        
        # Extract data
        dates = [m['last_assessment'] for m in self.metrics_history]
        total_tests = [m['total_tests_run'] for m in self.metrics_history]
        successful = [m['successful_tests'] for m in self.metrics_history]
        failed = [m['failed_tests'] for m in self.metrics_history]
        
        # Create bar chart
        width = 0.35
        x = np.arange(len(dates))
        
        bars1 = ax.bar(x - width/2, successful, width, label='Successful', color='green', alpha=0.8)
        bars2 = ax.bar(x + width/2, failed, width, label='Failed', color='red', alpha=0.8)
        
        # Styling
        ax.set_xlabel("Test Run", fontsize=12)
        ax.set_ylabel("Test Count", fontsize=12)
        ax.set_title("Test Execution History", fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels([d.strftime('%m/%d') for d in dates][-10:], rotation=45)
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
    
    def _create_metrics_summary(self, ax, metrics: Dict[str, Any]):
        """Create key metrics summary table."""
        ax.axis('off')
        
        # Prepare summary data
        summary_data = [
            ["Metric", "Value", "Status"],
            ["Security Score", f"{metrics['security_score']:.1f}/100", 
             "🟢" if metrics['security_score'] >= 80 else "🟡" if metrics['security_score'] >= 60 else "🔴"],
            ["Total Vulnerabilities", str(metrics['vulnerabilities_found']),
             "🟢" if metrics['vulnerabilities_found'] == 0 else "🟡" if metrics['vulnerabilities_found'] < 10 else "🔴"],
            ["Critical Issues", str(metrics['critical_vulnerabilities']),
             "🟢" if metrics['critical_vulnerabilities'] == 0 else "🔴"],
            ["Test Success Rate", f"{(metrics['successful_tests']/max(metrics['total_tests_run'], 1)*100):.0f}%",
             "🟢" if metrics['successful_tests']/max(metrics['total_tests_run'], 1) >= 0.9 else "🟡"],
            ["Avg Test Duration", f"{metrics['average_test_duration']:.1f}s",
             "🟢" if metrics['average_test_duration'] < 300 else "🟡"],
            ["Last Assessment", metrics['last_assessment'].strftime('%Y-%m-%d %H:%M'), "ℹ️"]
        ]
        
        # Create table
        table = ax.table(cellText=summary_data[1:], colLabels=summary_data[0],
                        cellLoc='center', loc='center',
                        colWidths=[0.4, 0.4, 0.2])
        
        # Style table
        table.auto_set_font_size(False)
        table.set_fontsize(11)
        table.scale(1, 2)
        
        # Color header
        for i in range(3):
            table[(0, i)].set_facecolor('#4a86e8')
            table[(0, i)].set_text_props(weight='bold', color='white')
        
        ax.set_title("Key Metrics Summary", fontsize=14, fontweight='bold', pad=20)
    
    def generate_html_report(self, output_file: str = "security_report.html"):
        """Generate interactive HTML security report."""
        # Load current metrics
        orchestrator = AutomatedSecurityTestingOrchestrator()
        current_report = orchestrator.get_security_report()
        metrics = current_report['metrics']
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ALCUB3 Security Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4a86e8;
            padding-bottom: 10px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .metric-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }}
        .metric-label {{
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }}
        .status-good {{ color: #28a745; }}
        .status-warning {{ color: #ffc107; }}
        .status-danger {{ color: #dc3545; }}
        .vulnerability-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .vulnerability-table th, .vulnerability-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        .vulnerability-table th {{
            background-color: #4a86e8;
            color: white;
        }}
        .vulnerability-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .recommendation {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }}
        .timestamp {{
            text-align: right;
            color: #999;
            font-size: 12px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>ALCUB3 Security Assessment Report</h1>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value {self._get_status_class(metrics['security_score'], 80, 60)}">
                    {metrics['security_score']:.1f}
                </div>
                <div class="metric-label">Security Score</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-value {self._get_status_class(100-metrics['vulnerabilities_found'], 100, 90)}">
                    {metrics['vulnerabilities_found']}
                </div>
                <div class="metric-label">Total Vulnerabilities</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-value {self._get_status_class(100-metrics['critical_vulnerabilities']*10, 100, 90)}">
                    {metrics['critical_vulnerabilities']}
                </div>
                <div class="metric-label">Critical Issues</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-value">
                    {metrics['total_tests_run']}
                </div>
                <div class="metric-label">Tests Executed</div>
            </div>
        </div>
        
        <h2>Vulnerability Breakdown</h2>
        <table class="vulnerability-table">
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Impact</th>
                <th>Action Required</th>
            </tr>
            <tr>
                <td style="color: #dc3545; font-weight: bold;">Critical</td>
                <td>{metrics['critical_vulnerabilities']}</td>
                <td>System compromise possible</td>
                <td>Immediate remediation required</td>
            </tr>
            <tr>
                <td style="color: #fd7e14; font-weight: bold;">High</td>
                <td>{metrics['high_vulnerabilities']}</td>
                <td>Significant security risk</td>
                <td>Address within 24 hours</td>
            </tr>
            <tr>
                <td style="color: #ffc107; font-weight: bold;">Medium</td>
                <td>{metrics['medium_vulnerabilities']}</td>
                <td>Moderate security risk</td>
                <td>Address within 1 week</td>
            </tr>
            <tr>
                <td style="color: #28a745; font-weight: bold;">Low</td>
                <td>{metrics['low_vulnerabilities']}</td>
                <td>Minor security weakness</td>
                <td>Track for future resolution</td>
            </tr>
        </table>
        
        <h2>Compliance Status</h2>
        <table class="vulnerability-table">
            <tr>
                <th>Standard</th>
                <th>Status</th>
            </tr>
"""
        
        for standard, compliant in metrics.get('compliance_status', {}).items():
            status = "✅ Compliant" if compliant else "❌ Non-Compliant"
            html_content += f"""
            <tr>
                <td>{standard}</td>
                <td>{status}</td>
            </tr>
"""
        
        html_content += f"""
        </table>
        
        <h2>Recommendations</h2>
"""
        
        for rec in current_report.get('recommendations', []):
            html_content += f"""
        <div class="recommendation">
            {rec}
        </div>
"""
        
        html_content += f"""
        <div class="timestamp">
            Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"HTML report saved to: {output_file}")
        return output_file
    
    def _get_status_class(self, value: float, good_threshold: float, warning_threshold: float) -> str:
        """Get CSS class based on value and thresholds."""
        if value >= good_threshold:
            return "status-good"
        elif value >= warning_threshold:
            return "status-warning"
        else:
            return "status-danger"


def main():
    """Example usage of the security metrics dashboard."""
    dashboard = SecurityMetricsDashboard()
    
    # Generate visual dashboard
    dashboard.generate_executive_dashboard("security_dashboard.png")
    
    # Generate HTML report
    dashboard.generate_html_report("security_report.html")
    
    print("Security dashboard and report generated successfully!")


if __name__ == "__main__":
    main()