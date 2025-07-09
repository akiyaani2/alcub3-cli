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

// JIT types
export interface PrivilegeRequest {
  userId: string;
  requestedRole: string;
  requestedPermissions?: string[];
  duration: number; // minutes
  justification: string;
  classification?: string;
  targetResources?: string[];
  sourceIp?: string;
  mfaVerified?: boolean;
}

export interface PrivilegeResponse {
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'revoked';
  requestId?: string;
  sessionId?: string;
  sessionToken?: string;
  expiresAt?: string;
  approversNotified?: string[];
  reason?: string;
  message?: string;
}

export interface SessionStatus {
  sessionId: string;
  userId: string;
  isActive: boolean;
  grantedRole: string;
  expiresAt: string;
  timeRemaining: number;
  riskScore: number;
  monitoringData?: Record<string, any>;
}

export interface ApprovalResponse {
  approvalId: string;
  approver: string;
  approved: boolean;
  comments?: string;
}

export interface JITStatistics {
  totalRequests: number;
  autoApproved: number;
  manuallyApproved: number;
  denied: number;
  revoked: number;
  activeSessions: number;
  approvalRate: number;
  autoApprovalRate: number;
  revocationRate: number;
}

export class JITPrivilegeAPI {
  private activeProcesses: Map<string, ChildProcess> = new Map();
  private pendingRequests: Map<string, PrivilegeRequest> = new Map();
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
   * Create Express router with JIT endpoints
   */
  public createRouter(): Router {
    const router = Router();

    // Request privilege escalation
    router.post('/request', this.handlePrivilegeRequest.bind(this));

    // Get request/session status
    router.get('/status/:id', this.handleStatusRequest.bind(this));

    // Process approval response
    router.post('/approve', this.handleApprovalResponse.bind(this));

    // Get active sessions
    router.get('/sessions', this.handleGetSessions.bind(this));

    // Revoke a session
    router.delete('/session/:sessionId', this.handleRevokeSession.bind(this));

    // Get system statistics
    router.get('/stats', this.handleGetStatistics.bind(this));

    // Get pending approvals
    router.get('/approvals/pending', this.handleGetPendingApprovals.bind(this));

    return router;
  }

  /**
   * Handle privilege escalation request
   */
  private async handlePrivilegeRequest(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any; // User from auth middleware
      
      if (!user || !user.id) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const request: PrivilegeRequest = {
        userId: user.id,
        requestedRole: req.body.role,
        requestedPermissions: req.body.permissions || [],
        duration: req.body.duration || 15,
        justification: req.body.justification,
        classification: req.body.classification || user.classification || 'UNCLASSIFIED',
        targetResources: req.body.resources || [],
        sourceIp: req.ip,
        mfaVerified: req.body.mfaVerified || false
      };

      // Validate request
      const validation = this.validateRequest(request);
      if (!validation.valid) {
        res.status(400).json({ error: validation.error });
        return;
      }

      // Generate request ID
      const requestId = uuidv4();

      // Store pending request
      this.pendingRequests.set(requestId, request);

      // Process request via Python engine
      const result = await this.processPrivilegeRequest(requestId, request, user);

      // Send real-time update if connected
      if (this.io) {
        const userRoom = `user:${user.id}`;
        this.io.to(userRoom).emit('privilege-request-status', result);
      }

      res.status(result.status === 'denied' ? 403 : 202).json(result);

    } catch (error) {
      logger.error('Error processing privilege request:', error);
      next(error);
    }
  }

  /**
   * Handle status request for session or approval
   */
  private async handleStatusRequest(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { user } = req as any;

      if (!user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      // Try to get session status first
      const sessionStatus = await this.getSessionStatus(id);
      if (sessionStatus) {
        // Verify user owns the session
        if (sessionStatus.userId !== user.id && !user.roles?.includes('security_admin')) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }
        res.json(sessionStatus);
        return;
      }

      // Try to get approval status
      const approvalStatus = await this.getApprovalStatus(id);
      if (approvalStatus) {
        res.json(approvalStatus);
        return;
      }

      res.status(404).json({ error: 'Request or session not found' });

    } catch (error) {
      logger.error('Error getting status:', error);
      next(error);
    }
  }

  /**
   * Handle approval response
   */
  private async handleApprovalResponse(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user || !user.roles?.some((r: string) => ['supervisor', 'security_team', 'ciso'].includes(r))) {
        res.status(403).json({ error: 'Approval authority required' });
        return;
      }

      const response: ApprovalResponse = {
        approvalId: req.body.approvalId,
        approver: user.id,
        approved: req.body.approved,
        comments: req.body.comments
      };

      const result = await this.processApprovalResponse(response);

      // Notify requester via WebSocket
      if (this.io && result.userId) {
        const userRoom = `user:${result.userId}`;
        this.io.to(userRoom).emit('approval-processed', result);
      }

      res.json(result);

    } catch (error) {
      logger.error('Error processing approval:', error);
      next(error);
    }
  }

  /**
   * Handle get active sessions
   */
  private async handleGetSessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { user } = req as any;
      
      if (!user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      // Regular users can only see their own sessions
      const userId = user.roles?.includes('security_admin') ? req.query.userId as string : user.id;
      
      const sessions = await this.getActiveSessions(userId);
      
      res.json({
        sessions,
        total: sessions.length
      });

    } catch (error) {
      logger.error('Error getting sessions:', error);
      next(error);
    }
  }

  /**
   * Handle session revocation
   */
  private async handleRevokeSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { sessionId } = req.params;
      const { user } = req as any;
      const { reason } = req.body;

      if (!user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      // Get session to verify ownership
      const session = await this.getSessionStatus(sessionId);
      if (!session) {
        res.status(404).json({ error: 'Session not found' });
        return;
      }

      // Check authorization
      if (session.userId !== user.id && !user.roles?.includes('security_admin')) {
        res.status(403).json({ error: 'Not authorized to revoke this session' });
        return;
      }

      const result = await this.revokeSession(sessionId, reason || 'Manual revocation');

      // Notify user via WebSocket
      if (this.io) {
        const userRoom = `user:${session.userId}`;
        this.io.to(userRoom).emit('session-revoked', {
          sessionId,
          reason: result.reason
        });
      }

      res.json(result);

    } catch (error) {
      logger.error('Error revoking session:', error);
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

      const stats = await this.getStatistics();
      res.json(stats);

    } catch (error) {
      logger.error('Error getting statistics:', error);
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

      const approvals = await this.getPendingApprovals(user.id);
      
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
   * Validate privilege request
   */
  private validateRequest(request: PrivilegeRequest): { valid: boolean; error?: string } {
    if (!request.requestedRole) {
      return { valid: false, error: 'Role is required' };
    }

    if (!request.justification || request.justification.length < 10) {
      return { valid: false, error: 'Justification must be at least 10 characters' };
    }

    if (request.duration < 5 || request.duration > 480) {
      return { valid: false, error: 'Duration must be between 5 and 480 minutes' };
    }

    const validClassifications = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
    if (request.classification && !validClassifications.includes(request.classification)) {
      return { valid: false, error: 'Invalid classification level' };
    }

    return { valid: true };
  }

  /**
   * Process privilege request via Python engine
   */
  private async processPrivilegeRequest(
    requestId: string,
    request: PrivilegeRequest,
    user: any
  ): Promise<PrivilegeResponse> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(
        process.cwd(),
        'security-framework',
        'src',
        'jit_privilege_engine.py'
      );

      const pythonArgs = [
        scriptPath,
        'request',
        '--request-id', requestId,
        '--user-id', request.userId,
        '--role', request.requestedRole,
        '--duration', request.duration.toString(),
        '--justification', request.justification,
        '--classification', request.classification || 'UNCLASSIFIED'
      ];

      if (request.targetResources?.length) {
        pythonArgs.push('--resources', ...request.targetResources);
      }

      if (request.requestedPermissions?.length) {
        pythonArgs.push('--permissions', ...request.requestedPermissions);
      }

      // Add context
      const context = {
        current_classification: user.classification || 'UNCLASSIFIED',
        failed_auth_count: user.failedAuthCount || 0,
        source_ip: request.sourceIp,
        mfa_verified: request.mfaVerified
      };

      pythonArgs.push('--context', JSON.stringify(context));

      const pythonProcess = spawn(this.pythonPath, pythonArgs);
      this.activeProcesses.set(requestId, pythonProcess);

      let output = '';
      let errorOutput = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.stderr.on('data', (data: Buffer) => {
        errorOutput += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        this.activeProcesses.delete(requestId);

        if (code !== 0) {
          logger.error(`JIT process exited with code ${code}: ${errorOutput}`);
          reject(new Error(`Process failed: ${errorOutput}`));
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result);
        } catch (error) {
          logger.error('Failed to parse JIT response:', output);
          reject(new Error('Invalid response from JIT engine'));
        }
      });

      pythonProcess.on('error', (error: Error) => {
        this.activeProcesses.delete(requestId);
        logger.error('Failed to start JIT process:', error);
        reject(error);
      });
    });
  }

  /**
   * Get session status
   */
  private async getSessionStatus(sessionId: string): Promise<SessionStatus | null> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(
        process.cwd(),
        'security-framework',
        'src',
        'jit_privilege_engine.py'
      );

      const pythonArgs = [
        scriptPath,
        'status',
        '--session-id', sessionId
      ];

      const pythonProcess = spawn(this.pythonPath, pythonArgs);

      let output = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        if (code !== 0) {
          resolve(null);
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result);
        } catch (error) {
          resolve(null);
        }
      });

      pythonProcess.on('error', () => {
        resolve(null);
      });
    });
  }

  /**
   * Get approval status
   */
  private async getApprovalStatus(approvalId: string): Promise<any> {
    // Implementation would query the approval system
    // For now, return null
    return null;
  }

  /**
   * Process approval response
   */
  private async processApprovalResponse(response: ApprovalResponse): Promise<any> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(
        process.cwd(),
        'security-framework',
        'src',
        'jit_privilege_engine.py'
      );

      const pythonArgs = [
        scriptPath,
        'approve',
        '--approval-id', response.approvalId,
        '--approver', response.approver,
        '--approved', response.approved.toString()
      ];

      if (response.comments) {
        pythonArgs.push('--comments', response.comments);
      }

      const pythonProcess = spawn(this.pythonPath, pythonArgs);

      let output = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        if (code !== 0) {
          reject(new Error('Failed to process approval'));
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result);
        } catch (error) {
          reject(new Error('Invalid response'));
        }
      });
    });
  }

  /**
   * Get active sessions
   */
  private async getActiveSessions(userId?: string): Promise<SessionStatus[]> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(
        process.cwd(),
        'security-framework',
        'src',
        'jit_privilege_engine.py'
      );

      const pythonArgs = [scriptPath, 'sessions'];
      
      if (userId) {
        pythonArgs.push('--user-id', userId);
      }

      const pythonProcess = spawn(this.pythonPath, pythonArgs);

      let output = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        if (code !== 0) {
          resolve([]);
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result.sessions || []);
        } catch (error) {
          resolve([]);
        }
      });
    });
  }

  /**
   * Revoke a session
   */
  private async revokeSession(sessionId: string, reason: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(
        process.cwd(),
        'security-framework',
        'src',
        'jit_privilege_engine.py'
      );

      const pythonArgs = [
        scriptPath,
        'revoke',
        '--session-id', sessionId,
        '--reason', reason
      ];

      const pythonProcess = spawn(this.pythonPath, pythonArgs);

      let output = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        if (code !== 0) {
          reject(new Error('Failed to revoke session'));
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result);
        } catch (error) {
          reject(new Error('Invalid response'));
        }
      });
    });
  }

  /**
   * Get JIT statistics
   */
  private async getStatistics(): Promise<JITStatistics> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(
        process.cwd(),
        'security-framework',
        'src',
        'jit_privilege_engine.py'
      );

      const pythonArgs = [scriptPath, 'stats'];

      const pythonProcess = spawn(this.pythonPath, pythonArgs);

      let output = '';

      pythonProcess.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      pythonProcess.on('close', (code: number) => {
        if (code !== 0) {
          reject(new Error('Failed to get statistics'));
          return;
        }

        try {
          const result = JSON.parse(output);
          resolve(result);
        } catch (error) {
          reject(new Error('Invalid response'));
        }
      });
    });
  }

  /**
   * Get pending approvals for a user
   */
  private async getPendingApprovals(approverId: string): Promise<any[]> {
    // Implementation would query the approval system
    // For now, return empty array
    return [];
  }

  /**
   * Setup WebSocket handlers
   */
  private setupSocketHandlers(): void {
    if (!this.io) return;

    const jitNamespace = this.io.of('/jit');

    jitNamespace.on('connection', (socket: Socket) => {
      logger.info(`JIT WebSocket client connected: ${socket.id}`);

      // Handle user room subscription
      socket.on('subscribe-user', (userId: string) => {
        const userRoom = `user:${userId}`;
        socket.join(userRoom);
        logger.info(`Socket ${socket.id} joined room ${userRoom}`);
      });

      // Handle session monitoring subscription
      socket.on('monitor-session', (sessionId: string) => {
        const sessionRoom = `session:${sessionId}`;
        socket.join(sessionRoom);
        
        // Start sending periodic updates
        const interval = setInterval(async () => {
          const status = await this.getSessionStatus(sessionId);
          if (status) {
            socket.emit('session-update', status);
          } else {
            clearInterval(interval);
          }
        }, 5000); // Every 5 seconds

        socket.on('disconnect', () => {
          clearInterval(interval);
        });
      });

      // Handle approval monitoring
      socket.on('monitor-approvals', (approverId: string) => {
        const approvalRoom = `approver:${approverId}`;
        socket.join(approvalRoom);
      });

      socket.on('disconnect', () => {
        logger.info(`JIT WebSocket client disconnected: ${socket.id}`);
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
      logger.info(`Killed JIT process: ${id}`);
    }
    this.activeProcesses.clear();
    this.pendingRequests.clear();
  }
}

// Export a singleton instance
export const jitAPI = new JITPrivilegeAPI();