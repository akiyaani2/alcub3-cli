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
import { Router } from 'express';
import { Server as SocketIOServer } from 'socket.io';
/**
 * CISA Remediation API Service
 */
export declare class CISARemediationAPI {
    private activeScanProcesses;
    private scanResults;
    private scanStatuses;
    private io?;
    private pythonPath;
    constructor();
    /**
     * Set Socket.IO server for real-time updates
     */
    setSocketIO(io: SocketIOServer): void;
    /**
     * Create Express router with all CISA endpoints
     */
    createRouter(): Router;
    /**
     * Start scan process
     */
    private startScanProcess;
    /**
     * Start remediation process
     */
    private startRemediationProcess;
    /**
     * Update scan progress
     */
    private updateScanProgress;
    /**
     * Update scan status
     */
    private updateScanStatus;
    /**
     * Broadcast scan update via WebSocket
     */
    private broadcastScanUpdate;
    /**
     * Filter results based on classification level
     */
    private filterResultsByClassification;
    /**
     * Generate summary report
     */
    private generateSummaryReport;
    /**
     * Clean up resources
     */
    cleanup(): void;
}
export declare const cisaAPI: CISARemediationAPI;
