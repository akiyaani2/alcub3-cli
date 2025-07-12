import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2024 ALCUB3 Systems
 * SPDX-License-Identifier: Apache-2.0
 *
 * ALCUB3 Configuration Drift Dashboard - Task 4.3.6
 *
 * Real-time dashboard for configuration drift monitoring with live updates,
 * metrics visualization, and MAESTRO-compliant reporting.
 */
import { useState, useEffect, useMemo } from 'react';
import { Box, Text, Newline } from 'ink';
import { Colors } from '../colors.js';
// Mock data generators for development
const generateMockMetrics = () => ({
    system_status: Math.random() > 0.8 ? 'warning' : 'healthy',
    uptime_hours: 24.5 + Math.random() * 100,
    total_baselines: 15 + Math.floor(Math.random() * 10),
    active_monitoring: 8 + Math.floor(Math.random() * 5),
    total_detections: 342 + Math.floor(Math.random() * 50),
    alerts_generated: 28 + Math.floor(Math.random() * 10),
    critical_alerts: Math.floor(Math.random() * 5),
    remediations_completed: 22 + Math.floor(Math.random() * 8),
    success_rate: 0.85 + Math.random() * 0.15,
    average_detection_time_ms: 120 + Math.random() * 100,
    false_positive_rate: Math.random() * 0.1,
    last_updated: new Date().toISOString()
});
const generateMockAlerts = () => {
    const severities = ['critical', 'high', 'medium', 'low', 'info'];
    const systems = ['web-server-01', 'db-server-02', 'app-server-03', 'security-gateway'];
    const statuses = ['active', 'acknowledged', 'resolved'];
    return Array.from({ length: 5 }, (_, i) => ({
        alert_id: `alert_${String(i + 1).padStart(3, '0')}`,
        timestamp: Date.now() - (i * 3600000) - Math.random() * 3600000,
        severity: severities[Math.floor(Math.random() * severities.length)],
        title: `Configuration Drift Alert #${i + 1}`,
        description: `Drift detected in ${systems[Math.floor(Math.random() * systems.length)]}`,
        source_system: systems[Math.floor(Math.random() * systems.length)],
        status: statuses[Math.floor(Math.random() * statuses.length)],
        drift_events_count: 1 + Math.floor(Math.random() * 5)
    }));
};
const generateMockBaselines = () => {
    const types = ['full_system', 'security_configuration', 'application_configuration'];
    const classifications = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET'];
    const systems = ['web-cluster', 'database-cluster', 'security-cluster'];
    return Array.from({ length: 8 }, (_, i) => ({
        baseline_id: `baseline_${String(i + 1).padStart(3, '0')}`,
        baseline_type: types[i % types.length],
        classification_level: classifications[i % classifications.length],
        target_systems: [systems[i % systems.length]],
        status: Math.random() > 0.9 ? 'error' : 'active',
        last_scan: Date.now() - Math.random() * 86400000,
        drift_score: Math.random() * 10,
        monitoring_enabled: Math.random() > 0.2
    }));
};
// Main dashboard component
const DriftDashboard = ({ refreshInterval = 5000, userClearance = 'UNCLASSIFIED' }) => {
    // Dashboard state
    const [metrics, setMetrics] = useState(generateMockMetrics());
    const [alerts, setAlerts] = useState(generateMockAlerts());
    const [baselines, setBaselines] = useState(generateMockBaselines());
    const [_remediations, _setRemediations] = useState([]);
    const [lastUpdate, setLastUpdate] = useState(new Date());
    const [isConnected, _setIsConnected] = useState(true);
    const [selectedView, _setSelectedView] = useState('overview');
    // Auto-refresh data
    useEffect(() => {
        const interval = setInterval(() => {
            if (isConnected) {
                setMetrics(generateMockMetrics());
                setAlerts(generateMockAlerts());
                setBaselines(generateMockBaselines());
                setLastUpdate(new Date());
            }
        }, refreshInterval);
        return () => clearInterval(interval);
    }, [refreshInterval, isConnected]);
    // Computed values
    const statusColor = useMemo(() => {
        switch (metrics.system_status) {
            case 'healthy': return Colors.AccentGreen;
            case 'warning': return Colors.AccentYellow;
            case 'critical': return Colors.AccentRed;
            case 'offline': return Colors.Gray;
            default: return Colors.Foreground;
        }
    }, [metrics.system_status]);
    const activeAlerts = useMemo(() => alerts.filter(alert => alert.status === 'active'), [alerts]);
    const criticalAlerts = useMemo(() => alerts.filter(alert => alert.severity === 'critical'), [alerts]);
    const formatUptime = (hours) => {
        const days = Math.floor(hours / 24);
        const remainingHours = Math.floor(hours % 24);
        const minutes = Math.floor((hours % 1) * 60);
        return `${days}d ${remainingHours}h ${minutes}m`;
    };
    const formatTimestamp = (timestamp) => {
        const date = new Date(timestamp);
        return date.toLocaleString();
    };
    const getClassificationColor = (level) => {
        switch (level) {
            case 'UNCLASSIFIED': return Colors.AccentGreen;
            case 'CONFIDENTIAL': return Colors.AccentYellow;
            case 'SECRET': return Colors.AccentRed;
            case 'TOP_SECRET': return Colors.AccentPurple;
            default: return Colors.Foreground;
        }
    };
    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'critical': return Colors.AccentRed;
            case 'high': return Colors.AccentYellow;
            case 'medium': return Colors.AccentYellow;
            case 'low': return Colors.AccentCyan;
            case 'info': return Colors.AccentBlue;
            default: return Colors.Foreground;
        }
    };
    // Header component
    const DashboardHeader = () => (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [_jsxs(Box, { justifyContent: "space-between", children: [_jsx(Text, { bold: true, color: Colors.AccentBlue, children: "\uD83D\uDEE1\uFE0F  ALCUB3 Configuration Drift Detection Dashboard" }), _jsx(Text, { color: statusColor, bold: true, children: metrics.system_status.toUpperCase() })] }), _jsxs(Box, { justifyContent: "space-between", children: [_jsxs(Text, { color: Colors.Gray, children: ["Classification: ", _jsx(Text, { color: getClassificationColor(userClearance), children: userClearance })] }), _jsxs(Text, { color: Colors.Gray, children: ["Last Update: ", lastUpdate.toLocaleTimeString()] })] }), _jsx(Box, { children: _jsxs(Text, { color: Colors.Gray, children: ["Connection: ", _jsx(Text, { color: isConnected ? Colors.AccentGreen : Colors.AccentRed, children: isConnected ? '🟢 Connected' : '🔴 Disconnected' })] }) })] }));
    // Metrics overview component
    const MetricsOverview = () => (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [_jsx(Text, { bold: true, color: Colors.AccentCyan, children: "\uD83D\uDCCA System Metrics" }), _jsx(Newline, {}), _jsxs(Box, { flexDirection: "row", justifyContent: "space-between", children: [_jsxs(Box, { flexDirection: "column", width: "50%", children: [_jsxs(Text, { children: ["\uD83D\uDD50 Uptime: ", _jsx(Text, { bold: true, children: formatUptime(metrics.uptime_hours) })] }), _jsxs(Text, { children: ["\uD83D\uDCCB Total Baselines: ", _jsx(Text, { bold: true, color: Colors.AccentCyan, children: metrics.total_baselines })] }), _jsxs(Text, { children: ["\uD83D\uDC41\uFE0F  Active Monitoring: ", _jsx(Text, { bold: true, color: Colors.AccentGreen, children: metrics.active_monitoring })] }), _jsxs(Text, { children: ["\uD83D\uDD0D Total Detections: ", _jsx(Text, { bold: true, children: metrics.total_detections })] }), _jsxs(Text, { children: ["\u26A0\uFE0F  Alerts Generated: ", _jsx(Text, { bold: true, color: Colors.AccentYellow, children: metrics.alerts_generated })] })] }), _jsxs(Box, { flexDirection: "column", width: "50%", children: [_jsxs(Text, { children: ["\uD83D\uDEA8 Critical Alerts: ", _jsx(Text, { bold: true, color: Colors.AccentRed, children: metrics.critical_alerts })] }), _jsxs(Text, { children: ["\u2705 Remediations: ", _jsx(Text, { bold: true, color: Colors.AccentGreen, children: metrics.remediations_completed })] }), _jsxs(Text, { children: ["\uD83D\uDCC8 Success Rate: ", _jsxs(Text, { bold: true, color: Colors.AccentGreen, children: [(metrics.success_rate * 100).toFixed(1), "%"] })] }), _jsxs(Text, { children: ["\u23F1\uFE0F  Avg Detection: ", _jsxs(Text, { bold: true, children: [metrics.average_detection_time_ms.toFixed(1), "ms"] })] }), _jsxs(Text, { children: ["\u274C False Positive: ", _jsxs(Text, { bold: true, children: [(metrics.false_positive_rate * 100).toFixed(1), "%"] })] })] })] })] }));
    // Recent alerts component
    const RecentAlerts = () => (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [_jsx(Text, { bold: true, color: Colors.AccentCyan, children: "\uD83D\uDEA8 Recent Alerts" }), _jsx(Newline, {}), activeAlerts.length === 0 ? (_jsx(Text, { color: Colors.AccentGreen, children: "\u2705 No active alerts" })) : (activeAlerts.slice(0, 5).map((alert) => (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [_jsxs(Box, { justifyContent: "space-between", children: [_jsxs(Text, { children: [_jsx(Text, { color: getSeverityColor(alert.severity), bold: true, children: alert.severity.toUpperCase() }), ' ', _jsx(Text, { bold: true, children: alert.title })] }), _jsx(Text, { color: Colors.Gray, children: formatTimestamp(alert.timestamp) })] }), _jsx(Box, { children: _jsxs(Text, { color: Colors.Gray, children: ["\uD83D\uDCCD ", alert.source_system, " | \uD83D\uDD04 ", alert.drift_events_count, " events | \uD83D\uDCCA ", _jsx(Text, { color: Colors.AccentCyan, children: alert.status })] }) }), _jsx(Text, { color: Colors.Gray, wrap: "wrap", children: alert.description })] }, alert.alert_id))))] }));
    // Baseline status component
    const BaselineStatus = () => (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [_jsx(Text, { bold: true, color: Colors.AccentCyan, children: "\uD83D\uDCCB Baseline Status" }), _jsx(Newline, {}), baselines.slice(0, 6).map((baseline) => (_jsxs(Box, { justifyContent: "space-between", marginBottom: 1, children: [_jsxs(Box, { flexDirection: "column", width: "60%", children: [_jsxs(Text, { children: [_jsx(Text, { bold: true, children: baseline.baseline_id }), ' ', _jsxs(Text, { color: getClassificationColor(baseline.classification_level), children: ["[", baseline.classification_level, "]"] })] }), _jsxs(Text, { color: Colors.Gray, children: [baseline.baseline_type, " | ", baseline.target_systems.join(', ')] })] }), _jsxs(Box, { flexDirection: "column", width: "40%", children: [_jsxs(Text, { children: ["Status: ", _jsx(Text, { color: baseline.status === 'active' ? Colors.AccentGreen : Colors.AccentRed, children: baseline.status })] }), _jsxs(Text, { children: ["Drift: ", _jsx(Text, { color: baseline.drift_score > 5 ? Colors.AccentYellow : Colors.AccentGreen, children: baseline.drift_score.toFixed(1) }), ' ', "Monitor: ", _jsx(Text, { color: baseline.monitoring_enabled ? Colors.AccentGreen : Colors.Gray, children: baseline.monitoring_enabled ? '🟢' : '⚫' })] })] })] }, baseline.baseline_id)))] }));
    // Navigation component
    const Navigation = () => (_jsxs(Box, { justifyContent: "space-around", marginBottom: 1, borderStyle: "single", borderColor: Colors.Gray, children: [_jsx(Text, { color: selectedView === 'overview' ? Colors.AccentBlue : Colors.Gray, children: "[1] Overview" }), _jsx(Text, { color: selectedView === 'alerts' ? Colors.AccentBlue : Colors.Gray, children: "[2] Alerts" }), _jsx(Text, { color: selectedView === 'baselines' ? Colors.AccentBlue : Colors.Gray, children: "[3] Baselines" }), _jsx(Text, { color: selectedView === 'remediations' ? Colors.AccentBlue : Colors.Gray, children: "[4] Remediation" })] }));
    // Statistics bar component
    const StatisticsBar = () => (_jsxs(Box, { justifyContent: "space-between", borderStyle: "single", borderColor: Colors.Gray, paddingX: 1, children: [_jsxs(Text, { children: ["\uD83D\uDCCA Baselines: ", _jsxs(Text, { bold: true, color: Colors.AccentCyan, children: [metrics.active_monitoring, "/", metrics.total_baselines] })] }), _jsxs(Text, { children: ["\uD83D\uDEA8 Active Alerts: ", _jsx(Text, { bold: true, color: Colors.AccentYellow, children: activeAlerts.length })] }), _jsxs(Text, { children: ["\uD83D\uDD34 Critical: ", _jsx(Text, { bold: true, color: Colors.AccentRed, children: criticalAlerts.length })] }), _jsxs(Text, { children: ["\u2705 Success Rate: ", _jsxs(Text, { bold: true, color: Colors.AccentGreen, children: [(metrics.success_rate * 100).toFixed(0), "%"] })] })] }));
    return (_jsxs(Box, { flexDirection: "column", padding: 1, children: [_jsx(DashboardHeader, {}), _jsx(Navigation, {}), _jsx(StatisticsBar, {}), _jsx(Newline, {}), _jsx(MetricsOverview, {}), _jsx(RecentAlerts, {}), _jsx(BaselineStatus, {}), _jsx(Box, { borderStyle: "single", borderColor: Colors.Gray, padding: 1, marginTop: 1, children: _jsx(Text, { color: Colors.Gray, children: "\uD83D\uDCA1 Commands: [R]efresh | [Q]uit | [1-4] Navigation | [H]elp | Connected to ALCUB3 Configuration Drift Detection System v1.0.0" }) })] }));
};
export { DriftDashboard };
//# sourceMappingURL=DriftDashboard.js.map