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
export interface PrivilegeRequest {
    userId: string;
    requestedRole: string;
    requestedPermissions?: string[];
    duration: number;
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
export declare class JITPrivilegeAPI {
    private activeProcesses;
    private pendingRequests;
    private io;
    private pythonPath;
    constructor();
    /**
     * Set Socket.IO server for real-time updates
     */
    setSocketIO(io: Server): void;
    /**
     * Create Express router with JIT endpoints
     */
    createRouter(): Router;
    /**
     * Handle privilege escalation request
     */
    private handlePrivilegeRequest;
    /**
     * Handle status request for session or approval
     */
    private handleStatusRequest;
    /**
     * Handle approval response
     */
    private handleApprovalResponse;
    /**
     * Handle get active sessions
     */
    private handleGetSessions;
    /**
     * Handle session revocation
     */
    private handleRevokeSession;
    /**
     * Handle get statistics
     */
    private handleGetStatistics;
    /**
     * Handle get pending approvals
     */
    private handleGetPendingApprovals;
    /**
     * Validate privilege request
     */
    private validateRequest;
    /**
     * Process privilege request via Python engine
     */
    private processPrivilegeRequest;
    /**
     * Get session status
     */
    private getSessionStatus;
    /**
     * Get approval status
     */
    private getApprovalStatus;
    /**
     * Process approval response
     */
    private processApprovalResponse;
    /**
     * Get active sessions
     */
    private getActiveSessions;
    /**
     * Revoke a session
     */
    private revokeSession;
    /**
     * Get JIT statistics
     */
    private getStatistics;
    /**
     * Get pending approvals for a user
     */
    private getPendingApprovals;
    /**
     * Setup WebSocket handlers
     */
    private setupSocketHandlers;
    /**
     * Cleanup resources
     */
    cleanup(): void;
}
export declare const jitAPI: JITPrivilegeAPI;
