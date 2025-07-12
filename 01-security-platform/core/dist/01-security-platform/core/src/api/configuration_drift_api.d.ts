/**
 * Copyright 2024 ALCUB3 Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { Router } from 'express';
import { Server } from 'socket.io';
export interface BaselineCreateRequest {
    target_systems: string[];
    baseline_type: string;
    scopes: string[];
    metadata?: Record<string, any>;
}
export interface BaselineSnapshot {
    baseline_id: string;
    baseline_type: string;
    classification_level: string;
    creation_timestamp: number;
    created_by: string;
    target_systems: string[];
    configuration_items: ConfigurationItem[];
    integrity_hash: string;
    cryptographic_signature: string;
    version: string;
    status: string;
    metadata?: Record<string, any>;
}
export interface ConfigurationItem {
    path: string;
    value: any;
    data_type: string;
    last_modified: number;
    checksum: string;
    classification_level: string;
    scope: string;
    metadata?: Record<string, any>;
}
export interface DriftDetectionRequest {
    baseline_id: string;
    current_config?: Record<string, any>;
    detection_method?: string;
    sensitivity_level?: string;
}
export interface DriftDetectionResult {
    detection_id: string;
    analysis_timestamp: number;
    baseline_id: string;
    drift_events: DriftEvent[];
    overall_drift_score: number;
    total_changes: number;
    critical_changes: number;
    anomaly_detected: boolean;
    risk_level: string;
    recommendations: string[];
    confidence_interval: [number, number];
    classification_level: string;
}
export interface DriftEvent {
    event_id: string;
    timestamp: number;
    configuration_path: string;
    change_type: string;
    baseline_value: any;
    current_value: any;
    drift_score: number;
    severity: string;
    anomaly_type: string;
    confidence: number;
    metadata?: Record<string, any>;
}
export interface MonitoringConfiguration {
    baseline_id: string;
    target_systems: string[];
    monitoring_interval_seconds: number;
    alert_thresholds: Record<string, number>;
    notification_channels: string[];
    escalation_rules: Record<string, any>;
    classification_level: string;
    auto_remediation_enabled: boolean;
    monitoring_scopes: string[];
}
export interface RemediationPlan {
    plan_id: string;
    baseline_id: string;
    target_system: string;
    drift_events: DriftEvent[];
    remediation_steps: RemediationStep[];
    estimated_duration_minutes: number;
    safety_level: string;
    approval_required: string;
    risk_assessment: Record<string, any>;
    classification_level: string;
    created_timestamp: number;
    created_by: string;
}
export interface RemediationStep {
    step_id: string;
    action: string;
    target_path: string;
    current_value: any;
    target_value: any;
    execution_order: number;
    estimated_duration_seconds: number;
    safety_checks: string[];
    rollback_data: Record<string, any>;
    dependencies: string[];
    metadata?: Record<string, any>;
}
export interface RemediationResult {
    result_id: string;
    plan_id: string;
    execution_timestamp: number;
    status: string;
    steps_completed: number;
    steps_failed: number;
    execution_time_seconds: number;
    success_rate: number;
    verification_results: Record<string, boolean>;
    rollback_performed: boolean;
    error_messages: string[];
    metadata?: Record<string, any>;
}
export declare class ConfigurationDriftAPI {
    private activeProcesses;
    private pendingDetections;
    private activeMonitoring;
    private io;
    private pythonPath;
    constructor();
    /**
     * Set Socket.IO server for real-time updates
     */
    setSocketIO(io: Server): void;
    /**
     * Create Express router with configuration drift endpoints
     */
    createRouter(): Router;
    /**
     * Handle baseline creation
     */
    private handleCreateBaseline;
    /**
     * Handle drift detection
     */
    private handleDetectDrift;
    /**
     * Handle monitoring setup
     */
    private handleStartMonitoring;
    /**
     * Handle remediation plan creation
     */
    private handleCreateRemediationPlan;
    /**
     * Handle remediation execution
     */
    private handleExecuteRemediation;
    /**
     * Handle get statistics
     */
    private handleGetStatistics;
    /**
     * Handle list baselines
     */
    private handleListBaselines;
    /**
     * Handle get baseline
     */
    private handleGetBaseline;
    /**
     * Handle delete baseline
     */
    private handleDeleteBaseline;
    /**
     * Handle validate baseline
     */
    private handleValidateBaseline;
    /**
     * Handle get detection result
     */
    private handleGetDetectionResult;
    /**
     * Handle predict drift
     */
    private handlePredictDrift;
    /**
     * Handle get monitoring status
     */
    private handleGetMonitoringStatus;
    /**
     * Handle update monitoring
     */
    private handleUpdateMonitoring;
    /**
     * Handle stop monitoring
     */
    private handleStopMonitoring;
    /**
     * Handle get remediation plan
     */
    private handleGetRemediationPlan;
    /**
     * Handle approve remediation
     */
    private handleApproveRemediation;
    /**
     * Handle get pending approvals
     */
    private handleGetPendingApprovals;
    /**
     * Handle get drift report
     */
    private handleGetDriftReport;
    /**
     * Handle get remediation report
     */
    private handleGetRemediationReport;
    private validateBaselineRequest;
    private createBaseline;
    private processDetection;
    private startMonitoring;
    private createRemediationPlan;
    private executeRemediation;
    private getStatistics;
    private listBaselines;
    private getBaseline;
    private deleteBaseline;
    private validateBaseline;
    private getDetectionResult;
    private predictDrift;
    private getMonitoringStatus;
    private updateMonitoring;
    private stopMonitoring;
    private getRemediationPlan;
    private approveRemediation;
    private getPendingApprovals;
    private getDriftReport;
    private getRemediationReport;
    /**
     * Call Python method with error handling
     */
    private callPythonMethod;
    /**
     * Setup WebSocket handlers
     */
    private setupSocketHandlers;
    /**
     * Cleanup resources
     */
    cleanup(): void;
}
export declare const configurationDriftAPI: ConfigurationDriftAPI;
