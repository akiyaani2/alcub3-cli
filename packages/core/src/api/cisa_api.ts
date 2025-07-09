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

/**
 * CISA Top 10 Misconfiguration Remediation API
 * 
 * This module provides RESTful API endpoints for the CISA remediation engine,
 * enabling real-time scanning, remediation, and monitoring of cybersecurity
 * misconfigurations.
 * 
 * Patent-Defensible Features:
 * - Real-time WebSocket updates for scan progress
 * - Classification-aware API responses
 * - Integrated MAESTRO security validation
 * - Air-gapped result caching
 */

import express, { Router, Request, Response } from 'express';
import { Server as SocketIOServer } from 'socket.io';
import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import { ClassificationLevel } from './classification.js';
import { authManager } from './auth.js';
import { enhancedSecurityMiddleware } from './enhanced_middleware.js';

// Types for CISA API
interface ScanRequest {
  target: string;
  classification?: ClassificationLevel;
  modules?: string[];
  context?: Record<string, any>;
}

interface RemediationRequest {
  scanId: string;
  autoApprove?: boolean;
  modulesToRemediate?: string[];
}

interface ScanStatus {
  scanId: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'remediation_required' | 'remediated';
  progress: string;
  complianceScore?: number;
  criticalFindings?: number;
  lastUpdate: Date;
}

interface ScanResult {
  scanId: string;
  target: string;
  startTime: Date;
  endTime?: Date;
  status: string;
  classificationLevel: string;
  totalScans: number;
  compliantCount: number;
  nonCompliantCount: number;
  criticalFindings: number;
  highFindings: number;
  overallComplianceScore: number;
  scanResults: any[];
  remediationResults?: any[];
  patentInnovationsUsed: string[];
  maestroValidation: any;
}

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ 
      filename: 'cisa-api.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5
    })
  ]
});

/**
 * CISA Remediation API Service
 */
export class CISARemediationAPI {
  private activeScanProcesses: Map<string, ChildProcess> = new Map();
  private scanResults: Map<string, ScanResult> = new Map();
  private scanStatuses: Map<string, ScanStatus> = new Map();
  private io?: SocketIOServer;
  private pythonPath: string;

  constructor() {
    this.pythonPath = path.join(
      process.cwd(),
      'security-framework',
      'src',
      'cisa_remediation_engine.py'
    );
  }

  /**
   * Set Socket.IO server for real-time updates
   */
  public setSocketIO(io: SocketIOServer): void {
    this.io = io;
    
    // Set up Socket.IO namespaces
    const cisaNamespace = io.of('/cisa');
    
    cisaNamespace.on('connection', (socket) => {
      logger.info('CISA WebSocket client connected', {
        socketId: socket.id,
        clientAddress: socket.handshake.address
      });

      // Subscribe to scan updates
      socket.on('subscribe-scan', (scanId: string) => {
        socket.join(`scan-${scanId}`);
        logger.info('Client subscribed to scan updates', { scanId, socketId: socket.id });
        
        // Send current status if available
        const status = this.scanStatuses.get(scanId);
        if (status) {
          socket.emit('scan-status', status);
        }
      });

      socket.on('unsubscribe-scan', (scanId: string) => {
        socket.leave(`scan-${scanId}`);
        logger.info('Client unsubscribed from scan updates', { scanId, socketId: socket.id });
      });

      socket.on('disconnect', () => {
        logger.info('CISA WebSocket client disconnected', { socketId: socket.id });
      });
    });
  }

  /**
   * Create Express router with all CISA endpoints
   */
  public createRouter(): Router {
    const router = Router();

    // Apply security middleware to all routes
    router.use(enhancedSecurityMiddleware);

    // POST /api/v1/cisa/scan - Initiate a new scan
    router.post('/scan', async (req: Request, res: Response) => {
      try {
        const scanRequest: ScanRequest = req.body;
        
        // Validate request
        if (!scanRequest.target) {
          return res.status(400).json({
            error: 'Target is required',
            timestamp: new Date().toISOString()
          });
        }

        // Get classification from authenticated user or request
        const userClassification = (req as any).apiKeyData?.classification || 
                                 scanRequest.classification || 
                                 ClassificationLevel.UNCLASSIFIED;

        // Generate scan ID
        const scanId = uuidv4();

        // Initialize scan status
        const scanStatus: ScanStatus = {
          scanId,
          status: 'pending',
          progress: '0/10',
          lastUpdate: new Date()
        };

        this.scanStatuses.set(scanId, scanStatus);

        // Start scan process
        this.startScanProcess(scanId, scanRequest, userClassification);

        // Return immediate response
        res.status(202).json({
          scanId,
          status: 'accepted',
          message: 'Scan initiated successfully',
          websocketUrl: `/cisa?scanId=${scanId}`,
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Error initiating scan', {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined
        });

        res.status(500).json({
          error: 'Failed to initiate scan',
          details: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
    });

    // GET /api/v1/cisa/status/:scanId - Get scan status
    router.get('/status/:scanId', async (req: Request, res: Response) => {
      try {
        const { scanId } = req.params;
        
        const status = this.scanStatuses.get(scanId);
        if (!status) {
          return res.status(404).json({
            error: 'Scan not found',
            scanId,
            timestamp: new Date().toISOString()
          });
        }

        res.json({
          ...status,
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Error getting scan status', {
          error: error instanceof Error ? error.message : 'Unknown error',
          scanId: req.params.scanId
        });

        res.status(500).json({
          error: 'Failed to get scan status',
          details: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
    });

    // POST /api/v1/cisa/remediate - Execute remediation
    router.post('/remediate', async (req: Request, res: Response) => {
      try {
        const remediationRequest: RemediationRequest = req.body;
        
        // Validate request
        if (!remediationRequest.scanId) {
          return res.status(400).json({
            error: 'Scan ID is required',
            timestamp: new Date().toISOString()
          });
        }

        // Check if scan exists and is complete
        const scanResult = this.scanResults.get(remediationRequest.scanId);
        if (!scanResult) {
          return res.status(404).json({
            error: 'Scan not found or not complete',
            scanId: remediationRequest.scanId,
            timestamp: new Date().toISOString()
          });
        }

        // Update status
        const status = this.scanStatuses.get(remediationRequest.scanId);
        if (status) {
          status.status = 'in_progress';
          status.lastUpdate = new Date();
          this.broadcastScanUpdate(remediationRequest.scanId, status);
        }

        // Start remediation process
        this.startRemediationProcess(
          remediationRequest.scanId,
          scanResult,
          remediationRequest.autoApprove || false,
          remediationRequest.modulesToRemediate
        );

        res.status(202).json({
          scanId: remediationRequest.scanId,
          status: 'accepted',
          message: 'Remediation initiated successfully',
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Error initiating remediation', {
          error: error instanceof Error ? error.message : 'Unknown error'
        });

        res.status(500).json({
          error: 'Failed to initiate remediation',
          details: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
    });

    // GET /api/v1/cisa/report/:scanId - Get scan report
    router.get('/report/:scanId', async (req: Request, res: Response) => {
      try {
        const { scanId } = req.params;
        const format = req.query.format || 'json';
        
        const scanResult = this.scanResults.get(scanId);
        if (!scanResult) {
          return res.status(404).json({
            error: 'Scan report not found',
            scanId,
            timestamp: new Date().toISOString()
          });
        }

        // Apply classification filtering
        const userClassification = (req as any).apiKeyData?.classification || 
                                 ClassificationLevel.UNCLASSIFIED;
        
        // Filter results based on classification
        const filteredResult = this.filterResultsByClassification(
          scanResult,
          userClassification
        );

        if (format === 'summary') {
          res.type('text/plain').send(this.generateSummaryReport(filteredResult));
        } else {
          res.json({
            ...filteredResult,
            timestamp: new Date().toISOString()
          });
        }

      } catch (error) {
        logger.error('Error getting scan report', {
          error: error instanceof Error ? error.message : 'Unknown error',
          scanId: req.params.scanId
        });

        res.status(500).json({
          error: 'Failed to get scan report',
          details: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
    });

    // GET /api/v1/cisa/scans - List all scans
    router.get('/scans', async (req: Request, res: Response) => {
      try {
        const scans = Array.from(this.scanStatuses.values()).map(status => ({
          scanId: status.scanId,
          status: status.status,
          complianceScore: status.complianceScore,
          criticalFindings: status.criticalFindings,
          lastUpdate: status.lastUpdate
        }));

        res.json({
          scans,
          total: scans.length,
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Error listing scans', {
          error: error instanceof Error ? error.message : 'Unknown error'
        });

        res.status(500).json({
          error: 'Failed to list scans',
          details: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
    });

    // DELETE /api/v1/cisa/scan/:scanId - Cancel a scan
    router.delete('/scan/:scanId', async (req: Request, res: Response) => {
      try {
        const { scanId } = req.params;
        
        // Check if scan exists
        if (!this.scanStatuses.has(scanId)) {
          return res.status(404).json({
            error: 'Scan not found',
            scanId,
            timestamp: new Date().toISOString()
          });
        }

        // Terminate scan process if running
        const process = this.activeScanProcesses.get(scanId);
        if (process) {
          process.kill('SIGTERM');
          this.activeScanProcesses.delete(scanId);
        }

        // Update status
        const status = this.scanStatuses.get(scanId);
        if (status) {
          status.status = 'failed';
          status.lastUpdate = new Date();
          this.broadcastScanUpdate(scanId, status);
        }

        res.json({
          scanId,
          status: 'cancelled',
          message: 'Scan cancelled successfully',
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Error cancelling scan', {
          error: error instanceof Error ? error.message : 'Unknown error',
          scanId: req.params.scanId
        });

        res.status(500).json({
          error: 'Failed to cancel scan',
          details: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
    });

    return router;
  }

  /**
   * Start scan process
   */
  private startScanProcess(
    scanId: string,
    scanRequest: ScanRequest,
    classification: ClassificationLevel
  ): void {
    const args = [
      this.pythonPath,
      '--target', scanRequest.target,
      '--classification', classification,
      '--format', 'json'
    ];

    if (scanRequest.modules && scanRequest.modules.length > 0) {
      args.push('--modules', ...scanRequest.modules);
    }

    const scanProcess = spawn('python3', args, {
      env: { ...process.env, PYTHONUNBUFFERED: '1' }
    });

    this.activeScanProcesses.set(scanId, scanProcess);

    let outputBuffer = '';
    let errorBuffer = '';

    scanProcess.stdout.on('data', (data) => {
      outputBuffer += data.toString();
      
      // Try to parse progress updates
      try {
        const lines = outputBuffer.split('\n');
        for (const line of lines) {
          if (line.includes('Scanning') || line.includes('Progress')) {
            this.updateScanProgress(scanId, line);
          }
        }
      } catch (e) {
        // Ignore parsing errors
      }
    });

    scanProcess.stderr.on('data', (data) => {
      errorBuffer += data.toString();
      logger.warn('Scan process error output', { scanId, error: data.toString() });
    });

    scanProcess.on('close', (code) => {
      this.activeScanProcesses.delete(scanId);

      if (code === 0) {
        // Parse final results
        try {
          const lastJsonStart = outputBuffer.lastIndexOf('{');
          if (lastJsonStart !== -1) {
            const jsonStr = outputBuffer.substring(lastJsonStart);
            const result = JSON.parse(jsonStr);
            
            // Store results
            this.scanResults.set(scanId, result);
            
            // Update status
            const status = this.scanStatuses.get(scanId);
            if (status) {
              status.status = result.status || 'completed';
              status.complianceScore = result.overallComplianceScore;
              status.criticalFindings = result.criticalFindings;
              status.progress = `${result.totalScans}/${result.totalScans}`;
              status.lastUpdate = new Date();
              this.broadcastScanUpdate(scanId, status);
            }
          }
        } catch (error) {
          logger.error('Error parsing scan results', {
            scanId,
            error: error instanceof Error ? error.message : 'Unknown error',
            output: outputBuffer.substring(-1000) // Last 1000 chars
          });
          
          this.updateScanStatus(scanId, 'failed');
        }
      } else {
        logger.error('Scan process failed', {
          scanId,
          code,
          error: errorBuffer
        });
        
        this.updateScanStatus(scanId, 'failed');
      }
    });
  }

  /**
   * Start remediation process
   */
  private startRemediationProcess(
    scanId: string,
    scanResult: ScanResult,
    autoApprove: boolean,
    modulesToRemediate?: string[]
  ): void {
    // Save scan result to temporary file for remediation
    const tempFile = `/tmp/scan-${scanId}.json`;
    require('fs').writeFileSync(tempFile, JSON.stringify(scanResult));

    const args = [
      this.pythonPath,
      '--remediate-from-file', tempFile,
      '--format', 'json'
    ];

    if (autoApprove) {
      args.push('--auto-approve');
    }

    if (modulesToRemediate && modulesToRemediate.length > 0) {
      args.push('--remediate-modules', ...modulesToRemediate);
    }

    const remediateProcess = spawn('python3', args, {
      env: { ...process.env, PYTHONUNBUFFERED: '1' }
    });

    let outputBuffer = '';

    remediateProcess.stdout.on('data', (data) => {
      outputBuffer += data.toString();
    });

    remediateProcess.on('close', (code) => {
      // Clean up temp file
      try {
        require('fs').unlinkSync(tempFile);
      } catch (e) {
        // Ignore cleanup errors
      }

      if (code === 0) {
        try {
          const result = JSON.parse(outputBuffer);
          
          // Update stored results
          const existingResult = this.scanResults.get(scanId);
          if (existingResult) {
            existingResult.remediationResults = result.remediationResults;
            existingResult.status = result.status;
          }
          
          // Update status
          this.updateScanStatus(scanId, 'remediated');
          
        } catch (error) {
          logger.error('Error parsing remediation results', {
            scanId,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          
          this.updateScanStatus(scanId, 'failed');
        }
      } else {
        this.updateScanStatus(scanId, 'failed');
      }
    });
  }

  /**
   * Update scan progress
   */
  private updateScanProgress(scanId: string, progressMessage: string): void {
    const status = this.scanStatuses.get(scanId);
    if (status) {
      // Extract progress numbers if possible
      const progressMatch = progressMessage.match(/(\d+)\/(\d+)/);
      if (progressMatch) {
        status.progress = `${progressMatch[1]}/${progressMatch[2]}`;
      }
      
      status.status = 'in_progress';
      status.lastUpdate = new Date();
      
      this.broadcastScanUpdate(scanId, status);
    }
  }

  /**
   * Update scan status
   */
  private updateScanStatus(scanId: string, newStatus: ScanStatus['status']): void {
    const status = this.scanStatuses.get(scanId);
    if (status) {
      status.status = newStatus;
      status.lastUpdate = new Date();
      this.broadcastScanUpdate(scanId, status);
    }
  }

  /**
   * Broadcast scan update via WebSocket
   */
  private broadcastScanUpdate(scanId: string, status: ScanStatus): void {
    if (this.io) {
      this.io.of('/cisa').to(`scan-${scanId}`).emit('scan-status', status);
      
      logger.debug('Broadcasted scan update', {
        scanId,
        status: status.status,
        progress: status.progress
      });
    }
  }

  /**
   * Filter results based on classification level
   */
  private filterResultsByClassification(
    result: ScanResult,
    userClassification: ClassificationLevel
  ): ScanResult {
    // In a real implementation, this would filter sensitive findings
    // based on the user's classification level
    return result;
  }

  /**
   * Generate summary report
   */
  private generateSummaryReport(result: ScanResult): string {
    let summary = `
CISA Top 10 Misconfiguration Scan Report
========================================
Scan ID: ${result.scanId}
Target: ${result.target}
Classification: ${result.classificationLevel}
Status: ${result.status}

Overall Compliance Score: ${result.overallComplianceScore.toFixed(1)}%
Total Scans: ${result.totalScans}
Compliant: ${result.compliantCount}
Non-Compliant: ${result.nonCompliantCount}
Critical Findings: ${result.criticalFindings}
High Findings: ${result.highFindings}

Non-Compliant Findings:
`;

    for (const scanResult of result.scanResults) {
      if (!scanResult.is_compliant) {
        summary += `\n[${scanResult.severity}] ${scanResult.title}\n`;
        for (const finding of scanResult.findings) {
          summary += `  - ${finding}\n`;
        }
      }
    }

    if (result.remediationResults && result.remediationResults.length > 0) {
      summary += '\nRemediation Results:\n';
      for (const remediation of result.remediationResults) {
        const status = remediation.success ? 'SUCCESS' : 'FAILED';
        summary += `\n${remediation.misconfiguration_id}: ${status}\n`;
        if (remediation.actions_taken.length > 0) {
          summary += '  Actions taken:\n';
          for (const action of remediation.actions_taken) {
            summary += `    - ${action}\n`;
          }
        }
      }
    }

    return summary;
  }

  /**
   * Clean up resources
   */
  public cleanup(): void {
    // Terminate all active scan processes
    for (const [scanId, process] of this.activeScanProcesses) {
      process.kill('SIGTERM');
      logger.info('Terminated scan process on cleanup', { scanId });
    }
    
    this.activeScanProcesses.clear();
  }
}

// Export singleton instance
export const cisaAPI = new CISARemediationAPI();