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
import { spawn } from 'child_process';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
// Using console as logger for now
const logger = console;
export class ConfigurationDriftAPI {
    activeProcesses = new Map();
    pendingDetections = new Map();
    activeMonitoring = new Map();
    io = null;
    pythonPath;
    constructor() {
        // Configure Python path
        this.pythonPath = process.env.PYTHON_PATH || 'python3';
    }
    /**
     * Set Socket.IO server for real-time updates
     */
    setSocketIO(io) {
        this.io = io;
        this.setupSocketHandlers();
    }
    /**
     * Create Express router with configuration drift endpoints
     */
    createRouter() {
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
    async handleCreateBaseline(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const request = {
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
        }
        catch (error) {
            logger.error('Error creating baseline:', error);
            next(error);
        }
    }
    /**
     * Handle drift detection
     */
    async handleDetectDrift(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const request = {
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
        }
        catch (error) {
            logger.error('Error detecting drift:', error);
            next(error);
        }
    }
    /**
     * Handle monitoring setup
     */
    async handleStartMonitoring(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const config = {
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
        }
        catch (error) {
            logger.error('Error starting monitoring:', error);
            next(error);
        }
    }
    /**
     * Handle remediation plan creation
     */
    async handleCreateRemediationPlan(req, res, next) {
        try {
            const { user } = req;
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
        }
        catch (error) {
            logger.error('Error creating remediation plan:', error);
            next(error);
        }
    }
    /**
     * Handle remediation execution
     */
    async handleExecuteRemediation(req, res, next) {
        try {
            const { plan_id } = req.params;
            const { user } = req;
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
        }
        catch (error) {
            logger.error('Error executing remediation:', error);
            next(error);
        }
    }
    /**
     * Handle get statistics
     */
    async handleGetStatistics(req, res, next) {
        try {
            const { user } = req;
            if (!user?.roles?.includes('security_admin')) {
                res.status(403).json({ error: 'Security admin access required' });
                return;
            }
            const timeRange = req.query.time_range || '24h';
            const stats = await this.getStatistics(timeRange);
            res.json(stats);
        }
        catch (error) {
            logger.error('Error getting statistics:', error);
            next(error);
        }
    }
    /**
     * Handle list baselines
     */
    async handleListBaselines(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const filters = {
                classification_level: req.query.classification_level,
                baseline_type: req.query.baseline_type,
                status: req.query.status
            };
            const baselines = await this.listBaselines(filters, user);
            res.json({
                baselines,
                total: baselines.length
            });
        }
        catch (error) {
            logger.error('Error listing baselines:', error);
            next(error);
        }
    }
    /**
     * Handle get baseline
     */
    async handleGetBaseline(req, res, next) {
        try {
            const { baseline_id } = req.params;
            const { user } = req;
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
        }
        catch (error) {
            logger.error('Error getting baseline:', error);
            next(error);
        }
    }
    /**
     * Handle delete baseline
     */
    async handleDeleteBaseline(req, res, next) {
        try {
            const { baseline_id } = req.params;
            const { user } = req;
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
        }
        catch (error) {
            logger.error('Error deleting baseline:', error);
            next(error);
        }
    }
    /**
     * Handle validate baseline
     */
    async handleValidateBaseline(req, res, next) {
        try {
            const { baseline_id } = req.params;
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const validation = await this.validateBaseline(baseline_id, user);
            res.json(validation);
        }
        catch (error) {
            logger.error('Error validating baseline:', error);
            next(error);
        }
    }
    /**
     * Handle get detection result
     */
    async handleGetDetectionResult(req, res, next) {
        try {
            const { detection_id } = req.params;
            const { user } = req;
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
        }
        catch (error) {
            logger.error('Error getting detection result:', error);
            next(error);
        }
    }
    /**
     * Handle predict drift
     */
    async handlePredictDrift(req, res, next) {
        try {
            const { user } = req;
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
        }
        catch (error) {
            logger.error('Error predicting drift:', error);
            next(error);
        }
    }
    /**
     * Handle get monitoring status
     */
    async handleGetMonitoringStatus(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const status = await this.getMonitoringStatus(user);
            res.json(status);
        }
        catch (error) {
            logger.error('Error getting monitoring status:', error);
            next(error);
        }
    }
    /**
     * Handle update monitoring
     */
    async handleUpdateMonitoring(req, res, next) {
        try {
            const { baseline_id } = req.params;
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const updates = req.body;
            const result = await this.updateMonitoring(baseline_id, updates, user);
            res.json(result);
        }
        catch (error) {
            logger.error('Error updating monitoring:', error);
            next(error);
        }
    }
    /**
     * Handle stop monitoring
     */
    async handleStopMonitoring(req, res, next) {
        try {
            const { baseline_id } = req.params;
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const result = await this.stopMonitoring(baseline_id, user);
            // Remove from active monitoring
            this.activeMonitoring.delete(baseline_id);
            res.json(result);
        }
        catch (error) {
            logger.error('Error stopping monitoring:', error);
            next(error);
        }
    }
    /**
     * Handle get remediation plan
     */
    async handleGetRemediationPlan(req, res, next) {
        try {
            const { plan_id } = req.params;
            const { user } = req;
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
        }
        catch (error) {
            logger.error('Error getting remediation plan:', error);
            next(error);
        }
    }
    /**
     * Handle approve remediation
     */
    async handleApproveRemediation(req, res, next) {
        try {
            const { plan_id } = req.params;
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            if (!user.roles?.some((r) => ['supervisor', 'security_team', 'ciso'].includes(r))) {
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
        }
        catch (error) {
            logger.error('Error approving remediation:', error);
            next(error);
        }
    }
    /**
     * Handle get pending approvals
     */
    async handleGetPendingApprovals(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.roles?.some((r) => ['supervisor', 'security_team', 'ciso'].includes(r))) {
                res.status(403).json({ error: 'Approval authority required' });
                return;
            }
            const approvals = await this.getPendingApprovals(user);
            res.json({
                approvals,
                total: approvals.length
            });
        }
        catch (error) {
            logger.error('Error getting pending approvals:', error);
            next(error);
        }
    }
    /**
     * Handle get drift report
     */
    async handleGetDriftReport(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const params = {
                baseline_id: req.query.baseline_id,
                time_range: req.query.time_range || '24h',
                format: req.query.format || 'json'
            };
            const report = await this.getDriftReport(params, user);
            if (params.format === 'csv') {
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', 'attachment; filename="drift_report.csv"');
            }
            res.json(report);
        }
        catch (error) {
            logger.error('Error getting drift report:', error);
            next(error);
        }
    }
    /**
     * Handle get remediation report
     */
    async handleGetRemediationReport(req, res, next) {
        try {
            const { user } = req;
            if (!user || !user.id) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }
            const params = {
                time_range: req.query.time_range || '24h',
                status: req.query.status,
                format: req.query.format || 'json'
            };
            const report = await this.getRemediationReport(params, user);
            if (params.format === 'csv') {
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', 'attachment; filename="remediation_report.csv"');
            }
            res.json(report);
        }
        catch (error) {
            logger.error('Error getting remediation report:', error);
            next(error);
        }
    }
    // Validation methods
    validateBaselineRequest(request) {
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
    async createBaseline(request, user) {
        return this.callPythonMethod('create_baseline', {
            target_systems: request.target_systems,
            baseline_type: request.baseline_type,
            scopes: request.scopes,
            created_by: user.id,
            metadata: request.metadata
        });
    }
    async processDetection(detectionId, request, user) {
        return this.callPythonMethod('detect_drift', {
            detection_id: detectionId,
            baseline_id: request.baseline_id,
            current_config: request.current_config,
            detection_method: request.detection_method,
            sensitivity_level: request.sensitivity_level,
            user_id: user.id
        });
    }
    async startMonitoring(config, user) {
        return this.callPythonMethod('start_monitoring', {
            ...config,
            started_by: user.id
        });
    }
    async createRemediationPlan(request, user) {
        return this.callPythonMethod('create_remediation_plan', {
            ...request,
            created_by: user.id
        });
    }
    async executeRemediation(request, user) {
        return this.callPythonMethod('execute_remediation', {
            ...request,
            executed_by: user.id
        });
    }
    async getStatistics(timeRange) {
        return this.callPythonMethod('get_statistics', {
            time_range: timeRange
        });
    }
    async listBaselines(filters, user) {
        return this.callPythonMethod('list_baselines', {
            ...filters,
            user_id: user.id
        });
    }
    async getBaseline(baselineId, user) {
        return this.callPythonMethod('get_baseline', {
            baseline_id: baselineId,
            user_id: user.id
        });
    }
    async deleteBaseline(baselineId, user) {
        return this.callPythonMethod('delete_baseline', {
            baseline_id: baselineId,
            deleted_by: user.id
        });
    }
    async validateBaseline(baselineId, user) {
        return this.callPythonMethod('validate_baseline', {
            baseline_id: baselineId,
            user_id: user.id
        });
    }
    async getDetectionResult(detectionId, user) {
        return this.callPythonMethod('get_detection_result', {
            detection_id: detectionId,
            user_id: user.id
        });
    }
    async predictDrift(request, user) {
        return this.callPythonMethod('predict_drift', {
            ...request,
            user_id: user.id
        });
    }
    async getMonitoringStatus(user) {
        return this.callPythonMethod('get_monitoring_status', {
            user_id: user.id
        });
    }
    async updateMonitoring(baselineId, updates, user) {
        return this.callPythonMethod('update_monitoring', {
            baseline_id: baselineId,
            ...updates,
            updated_by: user.id
        });
    }
    async stopMonitoring(baselineId, user) {
        return this.callPythonMethod('stop_monitoring', {
            baseline_id: baselineId,
            stopped_by: user.id
        });
    }
    async getRemediationPlan(planId, user) {
        return this.callPythonMethod('get_remediation_plan', {
            plan_id: planId,
            user_id: user.id
        });
    }
    async approveRemediation(approval, user) {
        return this.callPythonMethod('approve_remediation', approval);
    }
    async getPendingApprovals(user) {
        return this.callPythonMethod('get_pending_approvals', {
            user_id: user.id
        });
    }
    async getDriftReport(params, user) {
        return this.callPythonMethod('get_drift_report', {
            ...params,
            user_id: user.id
        });
    }
    async getRemediationReport(params, user) {
        return this.callPythonMethod('get_remediation_report', {
            ...params,
            user_id: user.id
        });
    }
    /**
     * Call Python method with error handling
     */
    async callPythonMethod(method, params) {
        return new Promise((resolve, reject) => {
            const scriptPath = path.join(process.cwd(), 'security-framework', 'src', 'configuration_drift_integration.py');
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
            pythonProcess.stdout.on('data', (data) => {
                output += data.toString();
            });
            pythonProcess.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });
            pythonProcess.on('close', (code) => {
                this.activeProcesses.delete(processId);
                if (code !== 0) {
                    logger.error(`Configuration drift process exited with code ${code}: ${errorOutput}`);
                    reject(new Error(`Process failed: ${errorOutput}`));
                    return;
                }
                try {
                    const result = JSON.parse(output);
                    resolve(result);
                }
                catch (error) {
                    logger.error('Failed to parse configuration drift response:', output);
                    reject(new Error('Invalid response from configuration drift engine'));
                }
            });
            pythonProcess.on('error', (error) => {
                this.activeProcesses.delete(processId);
                logger.error('Failed to start configuration drift process:', error);
                reject(error);
            });
        });
    }
    /**
     * Setup WebSocket handlers
     */
    setupSocketHandlers() {
        if (!this.io)
            return;
        const driftNamespace = this.io.of('/drift');
        driftNamespace.on('connection', (socket) => {
            logger.info(`Configuration drift WebSocket client connected: ${socket.id}`);
            // Handle user room subscription
            socket.on('subscribe-user', (userId) => {
                const userRoom = `user:${userId}`;
                socket.join(userRoom);
                logger.info(`Socket ${socket.id} joined room ${userRoom}`);
            });
            // Handle baseline monitoring subscription
            socket.on('monitor-baseline', (baselineId) => {
                const baselineRoom = `baseline:${baselineId}`;
                socket.join(baselineRoom);
                // Start sending periodic updates
                const interval = setInterval(async () => {
                    try {
                        const status = await this.getBaseline(baselineId, { id: 'system' });
                        if (status) {
                            socket.emit('baseline-update', status);
                        }
                        else {
                            clearInterval(interval);
                        }
                    }
                    catch (error) {
                        clearInterval(interval);
                    }
                }, 10000); // Every 10 seconds
                socket.on('disconnect', () => {
                    clearInterval(interval);
                });
            });
            // Handle drift detection monitoring
            socket.on('monitor-detection', (detectionId) => {
                const detectionRoom = `detection:${detectionId}`;
                socket.join(detectionRoom);
            });
            // Handle remediation monitoring
            socket.on('monitor-remediation', (planId) => {
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
    cleanup() {
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
//# sourceMappingURL=configuration_drift_api.js.map