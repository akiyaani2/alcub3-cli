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

import { Router, Request, Response, NextFunction } from 'express';
import { Server, Socket } from 'socket.io';
import { ChildProcess, spawn } from 'child_process';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';

// Import types and utilities
import { SecurityClassification } from '../security/classification.js';
import { logger } from '../telemetry/logger.js';

// Configuration Drift types
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

export class ConfigurationDriftAPI {
  private activeProcesses: Map<string, ChildProcess> = new Map();
  private pendingDetections: Map<string, DriftDetectionRequest> = new Map();
  private activeMonitoring: Map<string, any> = new Map();
  private io: Server | null = null;
  private pythonPath: string;

  constructor() {
    // Configure Python path
    this.pythonPath = process.env.PYTHON_PATH || 'python3';
  }

  /**
   * Set Socket.IO server for real-time updates
   */
  public setSocketIO(io: Server): void {
    this.io = io;
    this.setupSocketHandlers();
  }

  /**
   * Create Express router with configuration drift endpoints
   */
  public createRouter(): Router {
    const router = Router();

    // Baseline management endpoints
    router.post('/baselines', this.handleCreateBaseline.bind(this));
    router.get('/baselines', this.handleListBaselines.bind(this));
    router.get('/baselines/:baseline_id', this.handleGetBaseline.bind(this));
    router.delete('/baselines/:baseline_id', this.handleDeleteBaseline.bind(this));
    router.post('/baselines/:baseline_id/validate', this.handleValidateBaseline.bind(this));

    // Drift detection endpoints
    router.post('/detect', this.handleDetectDrift.bind(this));
    router.get('/detect/:detection_id', this.handleGetDetectionResult.bind(this));
    router.post('/predict', this.handlePredictDrift.bind(this));

    // Monitoring endpoints
    router.post('/monitor', this.handleStartMonitoring.bind(this));
    router.get('/monitor', this.handleGetMonitoringStatus.bind(this));
    router.put('/monitor/:baseline_id', this.handleUpdateMonitoring.bind(this));
    router.delete('/monitor/:baseline_id', this.handleStopMonitoring.bind(this));

    // Remediation endpoints
    router.post('/remediate', this.handleCreateRemediationPlan.bind(this));
    router.get('/remediate/:plan_id', this.handleGetRemediationPlan.bind(this));
    router.post('/remediate/:plan_id/execute', this.handleExecuteRemediation.bind(this));
    router.post('/remediate/:plan_id/approve', this.handleApproveRemediation.bind(this));
    router.get('/remediate/pending/approvals', this.handleGetPendingApprovals.bind(this));

    // Statistics and reporting
    router.get('/statistics', this.handleGetStatistics.bind(this));
    router.get('/reports/drift', this.handleGetDriftReport.bind(this));
    router.get('/reports/remediation', this.handleGetRemediationReport.bind(this));

    return router;
  }

  /**
   * Handle baseline creation
   */
  private async handleCreateBaseline(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const request: BaselineCreateRequest = {
        target_systems: req.body.target_systems || ['localhost'],
        baseline_type: req.body.baseline_type || 'full_system',
        scopes: req.body.scopes || ['filesystem', 'services', 'security', 'maestro'],
        metadata: req.body.metadata || {}
      };

      // Validate request
      const validation = this.validateBaselineRequest(request);
      if (!validation.valid) {
        res.status(400).json({ error: validation.error });
        return;
      }

      // Create baseline via Python engine
      const result = await this.createBaseline(request, user);

      // Send real-time update if connected
      if (this.io) {
        const userRoom = `user:${user.id}`;
        this.io.to(userRoom).emit('baseline-created', result);
      }

      res.status(201).json(result);

    } catch (error) {
      logger.error('Error creating baseline:', error);
      next(error);
    }
  }

  /**
   * Handle drift detection
   */
  private async handleDetectDrift(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const request: DriftDetectionRequest = {
        baseline_id: req.body.baseline_id,
        current_config: req.body.current_config || {},
        detection_method: req.body.detection_method || 'hybrid',
        sensitivity_level: req.body.sensitivity_level || 'medium'
      };

      // Validate request
      if (!request.baseline_id) {
        res.status(400).json({ error: 'baseline_id is required' });
        return;
      }

      // Generate detection ID
      const detectionId = uuidv4();

      // Store pending detection
      this.pendingDetections.set(detectionId, request);

      // Process detection via Python engine
      const result = await this.processDetection(detectionId, request, user);

      // Send real-time update if connected
      if (this.io) {
        const userRoom = `user:${user.id}`;
        this.io.to(userRoom).emit('drift-detected', result);
      }

      res.status(result.anomaly_detected ? 200 : 202).json(result);

    } catch (error) {
      logger.error('Error detecting drift:', error);
      next(error);
    }
  }

  /**
   * Handle monitoring setup
   */
  private async handleStartMonitoring(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const config: MonitoringConfiguration = {
        baseline_id: req.body.baseline_id,
        target_systems: req.body.target_systems || ['localhost'],
        monitoring_interval_seconds: req.body.monitoring_interval_seconds || 300,
        alert_thresholds: req.body.alert_thresholds || { critical: 8.0, high: 6.0, medium: 4.0 },
        notification_channels: req.body.notification_channels || ['email', 'dashboard'],
        escalation_rules: req.body.escalation_rules || {},
        classification_level: req.body.classification_level || 'UNCLASSIFIED',
        auto_remediation_enabled: req.body.auto_remediation_enabled || false,
        monitoring_scopes: req.body.monitoring_scopes || ['filesystem', 'services', 'security']
      };

      // Validate configuration
      if (!config.baseline_id) {
        res.status(400).json({ error: 'baseline_id is required' });
        return;
      }

      // Start monitoring via Python engine
      const result = await this.startMonitoring(config, user);

      // Track active monitoring
      this.activeMonitoring.set(config.baseline_id, {
        config,
        started_by: user.id,
        started_at: Date.now()
      });

      // Send real-time update if connected
      if (this.io) {
        const userRoom = `user:${user.id}`;
        this.io.to(userRoom).emit('monitoring-started', result);
      }

      res.status(200).json(result);

    } catch (error) {
      logger.error('Error starting monitoring:', error);
      next(error);
    }
  }

  /**
   * Handle remediation plan creation
   */
  private async handleCreateRemediationPlan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const request = {
        baseline_id: req.body.baseline_id,
        drift_events: req.body.drift_events || [],
        target_system: req.body.target_system || 'localhost',
        auto_approve: req.body.auto_approve || false
      };

      // Validate request
      if (!request.baseline_id || !request.drift_events.length) {
        res.status(400).json({ error: 'baseline_id and drift_events are required' });
        return;
      }

      // Create remediation plan via Python engine
      const result = await this.createRemediationPlan(request, user);

      // Send real-time update if connected
      if (this.io) {
        const userRoom = `user:${user.id}`;
        this.io.to(userRoom).emit('remediation-plan-created', result);
      }

      res.status(201).json(result);

    } catch (error) {
      logger.error('Error creating remediation plan:', error);
      next(error);
    }
  }

  /**
   * Handle remediation execution
   */
  private async handleExecuteRemediation(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { plan_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const request = {
        plan_id,
        force_execute: req.body.force_execute || false,
        approval_override: req.body.approval_override || false
      };

      // Execute remediation via Python engine
      const result = await this.executeRemediation(request, user);

      // Send real-time update if connected
      if (this.io) {
        const userRoom = `user:${user.id}`;
        this.io.to(userRoom).emit('remediation-executed', result);
      }

      res.status(200).json(result);

    } catch (error) {
      logger.error('Error executing remediation:', error);
      next(error);
    }
  }

  /**
   * Handle get statistics
   */
  private async handleGetStatistics(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user?.roles?.includes('security_admin')) {
        res.status(403).json({ error: 'Security admin access required' });
        return;
      }

      const timeRange = req.query.time_range as string || '24h';
      const stats = await this.getStatistics(timeRange);
      
      res.json(stats);

    } catch (error) {
      logger.error('Error getting statistics:', error);
      next(error);
    }
  }

  /**
   * Handle list baselines
   */
  private async handleListBaselines(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const filters = {
        classification_level: req.query.classification_level as string,
        baseline_type: req.query.baseline_type as string,
        status: req.query.status as string
      };

      const baselines = await this.listBaselines(filters, user);
      
      res.json({
        baselines,
        total: baselines.length
      });

    } catch (error) {
      logger.error('Error listing baselines:', error);
      next(error);
    }
  }

  /**
   * Handle get baseline
   */
  private async handleGetBaseline(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { baseline_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const baseline = await this.getBaseline(baseline_id, user);
      
      if (!baseline) {
        res.status(404).json({ error: 'Baseline not found' });
        return;
      }

      res.json(baseline);

    } catch (error) {
      logger.error('Error getting baseline:', error);
      next(error);
    }
  }

  /**
   * Handle delete baseline
   */
  private async handleDeleteBaseline(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { baseline_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      if (!user.roles?.includes('security_admin')) {
        res.status(403).json({ error: 'Security admin access required' });
        return;
      }

      const result = await this.deleteBaseline(baseline_id, user);
      
      res.json(result);

    } catch (error) {
      logger.error('Error deleting baseline:', error);
      next(error);
    }
  }

  /**
   * Handle validate baseline
   */
  private async handleValidateBaseline(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { baseline_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const validation = await this.validateBaseline(baseline_id, user);
      
      res.json(validation);

    } catch (error) {
      logger.error('Error validating baseline:', error);
      next(error);
    }
  }

  /**
   * Handle get detection result
   */
  private async handleGetDetectionResult(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { detection_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const result = await this.getDetectionResult(detection_id, user);
      
      if (!result) {
        res.status(404).json({ error: 'Detection result not found' });
        return;
      }

      res.json(result);

    } catch (error) {
      logger.error('Error getting detection result:', error);
      next(error);
    }
  }

  /**
   * Handle predict drift
   */
  private async handlePredictDrift(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const request = {
        baseline_id: req.body.baseline_id,
        prediction_horizon_hours: req.body.prediction_horizon_hours || 24,
        historical_data: req.body.historical_data || []
      };

      const prediction = await this.predictDrift(request, user);
      
      res.json(prediction);

    } catch (error) {
      logger.error('Error predicting drift:', error);
      next(error);
    }
  }

  /**
   * Handle get monitoring status
   */
  private async handleGetMonitoringStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const status = await this.getMonitoringStatus(user);
      
      res.json(status);

    } catch (error) {
      logger.error('Error getting monitoring status:', error);
      next(error);
    }
  }

  /**
   * Handle update monitoring
   */
  private async handleUpdateMonitoring(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { baseline_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const updates = req.body;
      const result = await this.updateMonitoring(baseline_id, updates, user);
      
      res.json(result);

    } catch (error) {
      logger.error('Error updating monitoring:', error);
      next(error);
    }
  }

  /**
   * Handle stop monitoring
   */
  private async handleStopMonitoring(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { baseline_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const result = await this.stopMonitoring(baseline_id, user);
      
      // Remove from active monitoring
      this.activeMonitoring.delete(baseline_id);

      res.json(result);

    } catch (error) {
      logger.error('Error stopping monitoring:', error);
      next(error);
    }
  }

  /**
   * Handle get remediation plan
   */
  private async handleGetRemediationPlan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { plan_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const plan = await this.getRemediationPlan(plan_id, user);
      
      if (!plan) {
        res.status(404).json({ error: 'Remediation plan not found' });
        return;
      }

      res.json(plan);

    } catch (error) {
      logger.error('Error getting remediation plan:', error);
      next(error);
    }
  }

  /**
   * Handle approve remediation
   */
  private async handleApproveRemediation(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { plan_id } = req.params;
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      if (!user.roles?.some((r: string) => ['supervisor', 'security_team', 'ciso'].includes(r))) {
        res.status(403).json({ error: 'Approval authority required' });
        return;
      }

      const approval = {
        plan_id,
        approver: user.id,
        approved: req.body.approved,
        comments: req.body.comments
      };

      const result = await this.approveRemediation(approval, user);
      
      res.json(result);

    } catch (error) {
      logger.error('Error approving remediation:', error);
      next(error);
    }
  }

  /**
   * Handle get pending approvals
   */
  private async handleGetPendingApprovals(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.roles?.some((r: string) => ['supervisor', 'security_team', 'ciso'].includes(r))) {
        res.status(403).json({ error: 'Approval authority required' });
        return;
      }

      const approvals = await this.getPendingApprovals(user);
      
      res.json({
        approvals,
        total: approvals.length
      });

    } catch (error) {
      logger.error('Error getting pending approvals:', error);
      next(error);
    }
  }

  /**
   * Handle get drift report
   */
  private async handleGetDriftReport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const params = {
        baseline_id: req.query.baseline_id as string,
        time_range: req.query.time_range as string || '24h',
        format: req.query.format as string || 'json'
      };

      const report = await this.getDriftReport(params, user);
      
      if (params.format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="drift_report.csv"');
      }

      res.json(report);

    } catch (error) {
      logger.error('Error getting drift report:', error);
      next(error);
    }
  }

  /**
   * Handle get remediation report
   */
  private async handleGetRemediationReport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const params = {
        time_range: req.query.time_range as string || '24h',
        status: req.query.status as string,
        format: req.query.format as string || 'json'
      };

      const report = await this.getRemediationReport(params, user);
      
      if (params.format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="remediation_report.csv"');
      }

      res.json(report);

    } catch (error) {
      logger.error('Error getting remediation report:', error);
      next(error);
    }
  }

  // Validation methods
  private validateBaselineRequest(request: BaselineCreateRequest): { valid: boolean; error?: string } {
    if (!request.target_systems || request.target_systems.length === 0) {
      return { valid: false, error: 'At least one target system is required' };
    }

    if (!request.baseline_type) {
      return { valid: false, error: 'Baseline type is required' };
    }

    if (!request.scopes || request.scopes.length === 0) {
      return { valid: false, error: 'At least one scope is required' };
    }

    return { valid: true };
  }

  // Python integration methods
  private async createBaseline(request: BaselineCreateRequest, user: any): Promise<BaselineSnapshot> {
    return this.callPythonMethod('create_baseline', {
      target_systems: request.target_systems,
      baseline_type: request.baseline_type,
      scopes: request.scopes,
      created_by: user.id,
      metadata: request.metadata
    });
  }

  private async processDetection(detectionId: string, request: DriftDetectionRequest, user: any): Promise<DriftDetectionResult> {
    return this.callPythonMethod('detect_drift', {
      detection_id: detectionId,
      baseline_id: request.baseline_id,
      current_config: request.current_config,
      detection_method: request.detection_method,
      sensitivity_level: request.sensitivity_level,
      user_id: user.id
    });
  }

  private async startMonitoring(config: MonitoringConfiguration, user: any): Promise<any> {
    return this.callPythonMethod('start_monitoring', {
      ...config,
      started_by: user.id
    });
  }

  private async createRemediationPlan(request: any, user: any): Promise<RemediationPlan> {
    return this.callPythonMethod('create_remediation_plan', {
      ...request,
      created_by: user.id
    });
  }

  private async executeRemediation(request: any, user: any): Promise<RemediationResult> {
    return this.callPythonMethod('execute_remediation', {
      ...request,
      executed_by: user.id
    });
  }

  private async getStatistics(timeRange: string): Promise<any> {
    return this.callPythonMethod('get_statistics', {
      time_range: timeRange
    });
  }

  private async listBaselines(filters: any, user: any): Promise<BaselineSnapshot[]> {
    return this.callPythonMethod('list_baselines', {
      ...filters,
      user_id: user.id
    });
  }

  private async getBaseline(baselineId: string, user: any): Promise<BaselineSnapshot | null> {
    return this.callPythonMethod('get_baseline', {
      baseline_id: baselineId,
      user_id: user.id
    });
  }

  private async deleteBaseline(baselineId: string, user: any): Promise<any> {
    return this.callPythonMethod('delete_baseline', {
      baseline_id: baselineId,
      deleted_by: user.id
    });
  }

  private async validateBaseline(baselineId: string, user: any): Promise<any> {
    return this.callPythonMethod('validate_baseline', {
      baseline_id: baselineId,
      user_id: user.id
    });
  }

  private async getDetectionResult(detectionId: string, user: any): Promise<DriftDetectionResult | null> {
    return this.callPythonMethod('get_detection_result', {
      detection_id: detectionId,
      user_id: user.id
    });
  }

  private async predictDrift(request: any, user: any): Promise<any> {
    return this.callPythonMethod('predict_drift', {
      ...request,
      user_id: user.id
    });
  }

  private async getMonitoringStatus(user: any): Promise<any> {
    return this.callPythonMethod('get_monitoring_status', {
      user_id: user.id
    });
  }

  private async updateMonitoring(baselineId: string, updates: any, user: any): Promise<any> {
    return this.callPythonMethod('update_monitoring', {
      baseline_id: baselineId,
      ...updates,
      updated_by: user.id
    });
  }

  private async stopMonitoring(baselineId: string, user: any): Promise<any> {
    return this.callPythonMethod('stop_monitoring', {
      baseline_id: baselineId,
      stopped_by: user.id
    });
  }

  private async getRemediationPlan(planId: string, user: any): Promise<RemediationPlan | null> {
    return this.callPythonMethod('get_remediation_plan', {
      plan_id: planId,
      user_id: user.id
    });
  }

  private async approveRemediation(approval: any, user: any): Promise<any> {
    return this.callPythonMethod('approve_remediation', approval);
  }

  private async getPendingApprovals(user: any): Promise<any[]> {
    return this.callPythonMethod('get_pending_approvals', {
      user_id: user.id
    });
  }

  private async getDriftReport(params: any, user: any): Promise<any> {
    return this.callPythonMethod('get_drift_report', {
      ...params,
      user_id: user.id
    });
  }

  private async getRemediationReport(params: any, user: any): Promise<any> {
    return this.callPythonMethod('get_remediation_report', {
      ...params,
      user_id: user.id
    });
  }

  /**
   * Call Python method with error handling
   */
  private async callPythonMethod(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(
        process.cwd(),
        'security-framework',
        'src',
        'configuration_drift_integration.py'
      );

      const pythonArgs = [
        scriptPath,
        method,
        '--params', JSON.stringify(params)
      ];

      const pythonProcess = spawn(this.pythonPath, pythonArgs);
      const processId = `${method}_${Date.now()}`;
      this.activeProcesses.set(processId, pythonProcess);

      let output = '';
      let errorOutput = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.stderr.on('data', (data: Buffer) => {
        errorOutput += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        this.activeProcesses.delete(processId);

        if (code !== 0) {
          logger.error(`Configuration drift process exited with code ${code}: ${errorOutput}`);
          reject(new Error(`Process failed: ${errorOutput}`));
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result);
        } catch (error) {
          logger.error('Failed to parse configuration drift response:', output);
          reject(new Error('Invalid response from configuration drift engine'));
        }
      });

      pythonProcess.on('error', (error: Error) => {
        this.activeProcesses.delete(processId);
        logger.error('Failed to start configuration drift process:', error);
        reject(error);
      });
    });
  }

  /**
   * Setup WebSocket handlers
   */
  private setupSocketHandlers(): void {
    if (!this.io) return;

    const driftNamespace = this.io.of('/drift');

    driftNamespace.on('connection', (socket: Socket) => {
      logger.info(`Configuration drift WebSocket client connected: ${socket.id}`);

      // Handle user room subscription
      socket.on('subscribe-user', (userId: string) => {
        const userRoom = `user:${userId}`;
        socket.join(userRoom);
        logger.info(`Socket ${socket.id} joined room ${userRoom}`);
      });

      // Handle baseline monitoring subscription
      socket.on('monitor-baseline', (baselineId: string) => {
        const baselineRoom = `baseline:${baselineId}`;
        socket.join(baselineRoom);
        
        // Start sending periodic updates
        const interval = setInterval(async () => {
          try {
            const status = await this.getBaseline(baselineId, { id: 'system' });
            if (status) {
              socket.emit('baseline-update', status);
            } else {
              clearInterval(interval);
            }
          } catch (error) {
            clearInterval(interval);
          }
        }, 10000); // Every 10 seconds

        socket.on('disconnect', () => {
          clearInterval(interval);
        });
      });

      // Handle drift detection monitoring
      socket.on('monitor-detection', (detectionId: string) => {
        const detectionRoom = `detection:${detectionId}`;
        socket.join(detectionRoom);
      });

      // Handle remediation monitoring
      socket.on('monitor-remediation', (planId: string) => {
        const remediationRoom = `remediation:${planId}`;
        socket.join(remediationRoom);
      });

      socket.on('disconnect', () => {
        logger.info(`Configuration drift WebSocket client disconnected: ${socket.id}`);
      });
    });
  }

  /**
   * Cleanup resources
   */
  public cleanup(): void {
    // Kill any active processes
    for (const [id, process] of this.activeProcesses) {
      process.kill();
      logger.info(`Killed configuration drift process: ${id}`);
    }
    this.activeProcesses.clear();
    this.pendingDetections.clear();
    this.activeMonitoring.clear();
  }
}

// Export a singleton instance
export const configurationDriftAPI = new ConfigurationDriftAPI();