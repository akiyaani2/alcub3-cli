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
 * Enhanced API Middleware - Addressing Agent 3 Critical Feedback
 *
 * This module implements high-performance middleware that addresses all critical
 * Agent 3 feedback recommendations:
 *
 * 1. Performance: Uses persistent MAESTRO service instead of spawning processes
 * 2. Authentication: Integrates with MAESTRO crypto utilities
 * 3. Logging: Comprehensive structured logging with security events
 * 4. Input Validation: Expanded validation with JSON Schema
 * 5. Error Handling: Specific error types and proper HTTP response mapping
 *
 * Performance Targets:
 * - <100ms total middleware overhead
 * - Persistent service communication
 * - Async operations with connection pooling
 */
import { Request, Response, NextFunction } from 'express';
interface SecurityValidationRequest {
    text: string;
    classification: string;
    context?: Record<string, any>;
}
interface SecurityValidationResponse {
    is_valid: boolean;
    threat_level: string;
    violations: string[];
    validation_time_ms: number;
    classification_level: string;
    audit_event_id?: string;
}
declare class MAESTROServiceClient {
    private client;
    private serviceUrl;
    private isServiceAvailable;
    constructor(serviceUrl?: string);
    private checkServiceHealth;
    validateSecurity(request: SecurityValidationRequest): Promise<SecurityValidationResponse>;
    getServiceStatus(): Promise<any>;
}
declare const maestroClient: MAESTROServiceClient;
/**
 * Enhanced authentication middleware with MAESTRO integration
 */
export declare const enhancedAuthenticationMiddleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
/**
 * Enhanced input validation middleware with JSON Schema
 */
export declare const inputValidationMiddleware: (req: Request, res: Response, next: NextFunction) => void;
/**
 * Enhanced security middleware with persistent MAESTRO service
 */
export declare const enhancedSecurityMiddleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
/**
 * Performance monitoring middleware
 */
export declare const performanceMonitoringMiddleware: (req: Request, res: Response, next: NextFunction) => void;
/**
 * Combined enhanced middleware stack
 */
export declare const enhancedMiddlewareStack: ((req: Request, res: Response, next: NextFunction) => void)[];
export { maestroClient };
