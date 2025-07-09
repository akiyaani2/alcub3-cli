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

import React, { useState, useEffect, useMemo } from 'react';
import { Box, Text, Newline } from 'ink';
import { Colors } from '../colors.js';

// Dashboard data interfaces
interface DriftMetrics {
  system_status: 'healthy' | 'warning' | 'critical' | 'offline';
  uptime_hours: number;
  total_baselines: number;
  active_monitoring: number;
  total_detections: number;
  alerts_generated: number;
  critical_alerts: number;
  remediations_completed: number;
  success_rate: number;
  average_detection_time_ms: number;
  false_positive_rate: number;
  last_updated: string;
}

interface AlertSummary {
  alert_id: string;
  timestamp: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  source_system: string;
  status: 'active' | 'acknowledged' | 'resolved';
  drift_events_count: number;
}

interface BaselineStatus {
  baseline_id: string;
  baseline_type: string;
  classification_level: string;
  target_systems: string[];
  status: 'active' | 'inactive' | 'error';
  last_scan: number;
  drift_score: number;
  monitoring_enabled: boolean;
}

interface RemediationStatus {
  plan_id: string;
  baseline_id: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'requires_approval';
  progress_percentage: number;
  estimated_completion: number;
  safety_level: 'safe' | 'cautious' | 'risky' | 'dangerous';
}

// Mock data generators for development
const generateMockMetrics = (): DriftMetrics => ({
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

const generateMockAlerts = (): AlertSummary[] => {
  const severities: AlertSummary['severity'][] = ['critical', 'high', 'medium', 'low', 'info'];
  const systems = ['web-server-01', 'db-server-02', 'app-server-03', 'security-gateway'];
  const statuses: AlertSummary['status'][] = ['active', 'acknowledged', 'resolved'];
  
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

const generateMockBaselines = (): BaselineStatus[] => {
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

// Component props
interface DriftDashboardProps {
  refreshInterval?: number;
  userClearance?: string;
}

// Main dashboard component
const DriftDashboard: React.FC<DriftDashboardProps> = ({
  refreshInterval = 5000,
  userClearance = 'UNCLASSIFIED'
}) => {
  
  // Dashboard state
  const [metrics, setMetrics] = useState<DriftMetrics>(generateMockMetrics());
  const [alerts, setAlerts] = useState<AlertSummary[]>(generateMockAlerts());
  const [baselines, setBaselines] = useState<BaselineStatus[]>(generateMockBaselines());
  const [_remediations, _setRemediations] = useState<RemediationStatus[]>([]);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [isConnected, _setIsConnected] = useState(true);
  const [selectedView, _setSelectedView] = useState<'overview' | 'alerts' | 'baselines' | 'remediations'>('overview');

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

  const activeAlerts = useMemo(() => 
    alerts.filter(alert => alert.status === 'active'), [alerts]);

  const criticalAlerts = useMemo(() => 
    alerts.filter(alert => alert.severity === 'critical'), [alerts]);

  const formatUptime = (hours: number): string => {
    const days = Math.floor(hours / 24);
    const remainingHours = Math.floor(hours % 24);
    const minutes = Math.floor((hours % 1) * 60);
    return `${days}d ${remainingHours}h ${minutes}m`;
  };

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const getClassificationColor = (level: string): string => {
    switch (level) {
      case 'UNCLASSIFIED': return Colors.AccentGreen;
      case 'CONFIDENTIAL': return Colors.AccentYellow;
      case 'SECRET': return Colors.AccentRed;
      case 'TOP_SECRET': return Colors.AccentPurple;
      default: return Colors.Foreground;
    }
  };

  const getSeverityColor = (severity: string): string => {
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
  const DashboardHeader: React.FC = () => (
    <Box flexDirection="column" marginBottom={1}>
      <Box justifyContent="space-between">
        <Text bold color={Colors.AccentBlue}>
          🛡️  ALCUB3 Configuration Drift Detection Dashboard
        </Text>
        <Text color={statusColor} bold>
          {metrics.system_status.toUpperCase()}
        </Text>
      </Box>
      <Box justifyContent="space-between">
        <Text color={Colors.Gray}>
          Classification: <Text color={getClassificationColor(userClearance)}>{userClearance}</Text>
        </Text>
        <Text color={Colors.Gray}>
          Last Update: {lastUpdate.toLocaleTimeString()}
        </Text>
      </Box>
      <Box>
        <Text color={Colors.Gray}>
          Connection: <Text color={isConnected ? Colors.AccentGreen : Colors.AccentRed}>
            {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
          </Text>
        </Text>
      </Box>
    </Box>
  );

  // Metrics overview component
  const MetricsOverview: React.FC = () => (
    <Box flexDirection="column" marginBottom={1}>
      <Text bold color={Colors.AccentCyan}>📊 System Metrics</Text>
      <Newline />
      
      <Box flexDirection="row" justifyContent="space-between">
        <Box flexDirection="column" width="50%">
          <Text>🕐 Uptime: <Text bold>{formatUptime(metrics.uptime_hours)}</Text></Text>
          <Text>📋 Total Baselines: <Text bold color={Colors.AccentCyan}>{metrics.total_baselines}</Text></Text>
          <Text>👁️  Active Monitoring: <Text bold color={Colors.AccentGreen}>{metrics.active_monitoring}</Text></Text>
          <Text>🔍 Total Detections: <Text bold>{metrics.total_detections}</Text></Text>
          <Text>⚠️  Alerts Generated: <Text bold color={Colors.AccentYellow}>{metrics.alerts_generated}</Text></Text>
        </Box>
        
        <Box flexDirection="column" width="50%">
          <Text>🚨 Critical Alerts: <Text bold color={Colors.AccentRed}>{metrics.critical_alerts}</Text></Text>
          <Text>✅ Remediations: <Text bold color={Colors.AccentGreen}>{metrics.remediations_completed}</Text></Text>
          <Text>📈 Success Rate: <Text bold color={Colors.AccentGreen}>{(metrics.success_rate * 100).toFixed(1)}%</Text></Text>
          <Text>⏱️  Avg Detection: <Text bold>{metrics.average_detection_time_ms.toFixed(1)}ms</Text></Text>
          <Text>❌ False Positive: <Text bold>{(metrics.false_positive_rate * 100).toFixed(1)}%</Text></Text>
        </Box>
      </Box>
    </Box>
  );

  // Recent alerts component
  const RecentAlerts: React.FC = () => (
    <Box flexDirection="column" marginBottom={1}>
      <Text bold color={Colors.AccentCyan}>🚨 Recent Alerts</Text>
      <Newline />
      
      {activeAlerts.length === 0 ? (
        <Text color={Colors.AccentGreen}>✅ No active alerts</Text>
      ) : (
        activeAlerts.slice(0, 5).map((alert) => (
          <Box key={alert.alert_id} flexDirection="column" marginBottom={1}>
            <Box justifyContent="space-between">
              <Text>
                <Text color={getSeverityColor(alert.severity)} bold>
                  {alert.severity.toUpperCase()}
                </Text>
                {' '}
                <Text bold>{alert.title}</Text>
              </Text>
              <Text color={Colors.Gray}>
                {formatTimestamp(alert.timestamp)}
              </Text>
            </Box>
            <Box>
              <Text color={Colors.Gray}>
                📍 {alert.source_system} | 🔄 {alert.drift_events_count} events | 
                📊 <Text color={Colors.AccentCyan}>{alert.status}</Text>
              </Text>
            </Box>
            <Text color={Colors.Gray} wrap="wrap">
              {alert.description}
            </Text>
          </Box>
        ))
      )}
    </Box>
  );

  // Baseline status component
  const BaselineStatus: React.FC = () => (
    <Box flexDirection="column" marginBottom={1}>
      <Text bold color={Colors.AccentCyan}>📋 Baseline Status</Text>
      <Newline />
      
      {baselines.slice(0, 6).map((baseline) => (
        <Box key={baseline.baseline_id} justifyContent="space-between" marginBottom={1}>
          <Box flexDirection="column" width="60%">
            <Text>
              <Text bold>{baseline.baseline_id}</Text>
              {' '}
              <Text color={getClassificationColor(baseline.classification_level)}>
                [{baseline.classification_level}]
              </Text>
            </Text>
            <Text color={Colors.Gray}>
              {baseline.baseline_type} | {baseline.target_systems.join(', ')}
            </Text>
          </Box>
          
          <Box flexDirection="column" width="40%">
            <Text>
              Status: <Text color={baseline.status === 'active' ? Colors.AccentGreen : Colors.AccentRed}>
                {baseline.status}
              </Text>
            </Text>
            <Text>
              Drift: <Text color={baseline.drift_score > 5 ? Colors.AccentYellow : Colors.AccentGreen}>
                {baseline.drift_score.toFixed(1)}
              </Text>
              {' '}
              Monitor: <Text color={baseline.monitoring_enabled ? Colors.AccentGreen : Colors.Gray}>
                {baseline.monitoring_enabled ? '🟢' : '⚫'}
              </Text>
            </Text>
          </Box>
        </Box>
      ))}
    </Box>
  );

  // Navigation component
  const Navigation: React.FC = () => (
    <Box justifyContent="space-around" marginBottom={1} borderStyle="single" borderColor={Colors.Gray}>
      <Text color={selectedView === 'overview' ? Colors.AccentBlue : Colors.Gray}>
        [1] Overview
      </Text>
      <Text color={selectedView === 'alerts' ? Colors.AccentBlue : Colors.Gray}>
        [2] Alerts
      </Text>
      <Text color={selectedView === 'baselines' ? Colors.AccentBlue : Colors.Gray}>
        [3] Baselines
      </Text>
      <Text color={selectedView === 'remediations' ? Colors.AccentBlue : Colors.Gray}>
        [4] Remediation
      </Text>
    </Box>
  );

  // Statistics bar component
  const StatisticsBar: React.FC = () => (
    <Box justifyContent="space-between" borderStyle="single" borderColor={Colors.Gray} paddingX={1}>
      <Text>
        📊 Baselines: <Text bold color={Colors.AccentCyan}>{metrics.active_monitoring}/{metrics.total_baselines}</Text>
      </Text>
      <Text>
        🚨 Active Alerts: <Text bold color={Colors.AccentYellow}>{activeAlerts.length}</Text>
      </Text>
      <Text>
        🔴 Critical: <Text bold color={Colors.AccentRed}>{criticalAlerts.length}</Text>
      </Text>
      <Text>
        ✅ Success Rate: <Text bold color={Colors.AccentGreen}>{(metrics.success_rate * 100).toFixed(0)}%</Text>
      </Text>
    </Box>
  );

  return (
    <Box flexDirection="column" padding={1}>
      <DashboardHeader />
      <Navigation />
      <StatisticsBar />
      <Newline />
      <MetricsOverview />
      <RecentAlerts />
      <BaselineStatus />
      
      <Box borderStyle="single" borderColor={Colors.Gray} padding={1} marginTop={1}>
        <Text color={Colors.Gray}>
          💡 Commands: [R]efresh | [Q]uit | [1-4] Navigation | [H]elp
          | Connected to ALCUB3 Configuration Drift Detection System v1.0.0
        </Text>
      </Box>
    </Box>
  );
};

export { DriftDashboard }; 