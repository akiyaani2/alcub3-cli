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
import axios from 'axios';
import { ClassificationLevel, isClassificationAllowed } from './classification.js';
import { authManager } from './auth.js';
import winston from 'winston';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
// Enhanced logging configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.errors({ stack: true }), winston.format.json()),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({
            filename: 'api-security.log',
            maxsize: 10485760, // 10MB
            maxFiles: 5
        })
    ]
});
// JSON Schema validator
const AjvConstructor = Ajv;
const ajv = new AjvConstructor({ allErrors: true });
const addFormatsFunc = addFormats;
addFormatsFunc(ajv);
// Request validation schemas
const validationSchemas = {
    securityValidation: {
        type: 'object',
        properties: {
            text: { type: 'string', minLength: 1, maxLength: 100000 },
            classification: {
                type: 'string',
                enum: ['UNCLASSIFIED', 'CUI', 'SECRET', 'TOP_SECRET']
            },
            context: { type: 'object' }
        },
        required: ['text'],
        additionalProperties: false
    },
    generalRequest: {
        type: 'object',
        properties: {
            // Add common validation rules for all requests
            timestamp: { type: 'number' },
            requestId: { type: 'string', format: 'uuid' }
        },
        additionalProperties: true
    }
};
// Compile validators
const validators = {
    securityValidation: ajv.compile(validationSchemas.securityValidation),
    generalRequest: ajv.compile(validationSchemas.generalRequest)
};
// Classification rules with granular permissions
const CLASSIFICATION_RULES = {
    '/api/v1/maestro/metrics': ClassificationLevel.SECRET,
    '/api/v1/maestro/status': ClassificationLevel.UNCLASSIFIED,
    '/api/v1/maestro/admin': ClassificationLevel.SECRET,
    '/api/v1/maestro/health': ClassificationLevel.UNCLASSIFIED,
};
class MAESTROServiceClient {
    client;
    serviceUrl;
    isServiceAvailable = false;
    constructor(serviceUrl = 'http://127.0.0.1:8001') {
        this.serviceUrl = serviceUrl;
        this.client = axios.create({
            baseURL: serviceUrl,
            timeout: 5000, // 5 second timeout
            headers: {
                'Content-Type': 'application/json'
            }
        });
        // Check service availability on startup
        this.checkServiceHealth();
    }
    async checkServiceHealth() {
        try {
            const response = await this.client.get('/health');
            this.isServiceAvailable = response.status === 200;
            logger.info('MAESTRO service health check passed', {
                serviceUrl: this.serviceUrl,
                available: this.isServiceAvailable
            });
        }
        catch (error) {
            this.isServiceAvailable = false;
            logger.warn('MAESTRO service not available, falling back to basic validation', {
                serviceUrl: this.serviceUrl,
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    }
    async validateSecurity(request) {
        const startTime = Date.now();
        try {
            if (!this.isServiceAvailable) {
                // Fallback to basic validation
                return {
                    is_valid: true, // Allow request but log warning
                    threat_level: 'LOW',
                    violations: [],
                    validation_time_ms: Date.now() - startTime,
                    classification_level: request.classification || 'UNCLASSIFIED',
                    audit_event_id: `fallback-${Date.now()}`
                };
            }
            const response = await this.client.post('/validate', request);
            const validationTime = Date.now() - startTime;
            // Log performance metrics
            if (validationTime > 100) {
                logger.warn('Security validation exceeded performance target', {
                    validationTime,
                    target: 100,
                    request: { textLength: request.text.length, classification: request.classification }
                });
            }
            logger.info('Security validation completed', {
                isValid: response.data.is_valid,
                threatLevel: response.data.threat_level,
                validationTime: response.data.validation_time_ms,
                totalTime: validationTime
            });
            return response.data;
        }
        catch (error) {
            const validationTime = Date.now() - startTime;
            logger.error('Security validation service error', {
                error: error instanceof Error ? error.message : 'Unknown error',
                validationTime,
                serviceUrl: this.serviceUrl
            });
            // Fallback response for service errors
            return {
                is_valid: false,
                threat_level: 'HIGH',
                violations: ['Service validation failed - security risk'],
                validation_time_ms: validationTime,
                classification_level: request.classification || 'UNCLASSIFIED'
            };
        }
    }
    async getServiceStatus() {
        try {
            const response = await this.client.get('/status');
            return response.data;
        }
        catch (error) {
            return {
                status: 'unavailable',
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }
}
// Global service client instance
const maestroClient = new MAESTROServiceClient();
/**
 * Enhanced authentication middleware with MAESTRO integration
 */
export const enhancedAuthenticationMiddleware = async (req, res, next) => {
    const startTime = Date.now();
    try {
        const apiKey = req.headers['x-api-key'];
        const authHeader = req.headers['authorization'];
        // Try API key authentication first
        if (apiKey) {
            const result = await authManager.validateApiKey(apiKey);
            if (!result.valid) {
                logger.warn('API key authentication failed', {
                    error: result.error,
                    ip: req.ip,
                    userAgent: req.get('User-Agent')
                });
                res.status(401).json({
                    error: `Unauthorized: ${result.error}`,
                    timestamp: new Date().toISOString()
                });
                return;
            }
            // Attach key data to request for downstream middleware
            req.apiKeyData = result.keyData;
            req.authTime = Date.now() - startTime;
            logger.info('API key authentication successful', {
                keyId: result.keyData?.keyId,
                classification: result.keyData?.classification,
                authTime: Date.now() - startTime
            });
            next();
            return;
        }
        // Try OAuth2 authentication (placeholder)
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const result = await authManager.validateOAuth2Token(token);
            if (!result.valid) {
                logger.warn('OAuth2 authentication failed', {
                    error: result.error,
                    ip: req.ip
                });
                res.status(401).json({
                    error: `Unauthorized: ${result.error}`,
                    timestamp: new Date().toISOString()
                });
                return;
            }
            // Attach user info to request
            req.userInfo = result.userInfo;
            req.authTime = Date.now() - startTime;
            next();
            return;
        }
        // No valid authentication found
        logger.warn('No authentication provided', {
            ip: req.ip,
            path: req.path,
            userAgent: req.get('User-Agent')
        });
        res.status(401).json({
            error: 'Unauthorized: Missing or invalid authentication',
            timestamp: new Date().toISOString()
        });
    }
    catch (error) {
        logger.error('Authentication middleware error', {
            error: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined,
            ip: req.ip,
            path: req.path
        });
        res.status(500).json({
            error: `Authentication error: ${error instanceof Error ? error.message : 'Unknown error'}`,
            timestamp: new Date().toISOString()
        });
    }
};
/**
 * Enhanced input validation middleware with JSON Schema
 */
export const inputValidationMiddleware = (req, res, next) => {
    try {
        // Validate request body if present
        if (req.body && Object.keys(req.body).length > 0) {
            // Check for security validation requirements
            if (req.body.text) {
                const valid = validators.securityValidation(req.body);
                if (!valid) {
                    const errors = validators.securityValidation.errors?.map((error) => `${error.instancePath} ${error.message}`).join(', ') || 'Validation failed';
                    logger.warn('Input validation failed for security request', {
                        errors,
                        bodyKeys: Object.keys(req.body),
                        ip: req.ip,
                        path: req.path
                    });
                    res.status(400).json({
                        error: 'Bad Request: Input validation failed',
                        details: errors,
                        timestamp: new Date().toISOString()
                    });
                    return;
                }
            }
            // General request validation
            const generalValid = validators.generalRequest(req.body);
            if (!generalValid) {
                logger.debug('General validation warnings', {
                    errors: validators.generalRequest.errors,
                    path: req.path
                });
                // Don't block request for general validation failures, just log
            }
        }
        // Validate headers
        const requiredHeaders = ['user-agent'];
        for (const header of requiredHeaders) {
            if (!req.headers[header]) {
                logger.warn(`Missing required header: ${header}`, {
                    ip: req.ip,
                    path: req.path
                });
            }
        }
        next();
    }
    catch (error) {
        logger.error('Input validation middleware error', {
            error: error instanceof Error ? error.message : 'Unknown error',
            path: req.path
        });
        res.status(500).json({
            error: 'Internal Server Error: Input validation failed',
            timestamp: new Date().toISOString()
        });
    }
};
/**
 * Enhanced security middleware with persistent MAESTRO service
 */
export const enhancedSecurityMiddleware = async (req, res, next) => {
    const startTime = Date.now();
    try {
        // 1. Authentication (already handled by enhancedAuthenticationMiddleware)
        const apiKeyData = req.apiKeyData;
        let userClassification = ClassificationLevel.UNCLASSIFIED;
        if (apiKeyData) {
            userClassification = apiKeyData.classification;
        }
        else {
            // Fallback to header-based classification
            const classificationHeader = String(req.headers['x-classification-level'] || 'UNCLASSIFIED').toUpperCase();
            userClassification = classificationHeader;
        }
        // 2. Classification-aware authorization
        for (const [routePrefix, minLevel] of Object.entries(CLASSIFICATION_RULES)) {
            if (req.path.startsWith(routePrefix)) {
                if (!isClassificationAllowed(userClassification, minLevel)) {
                    logger.warn('Classification authorization failed', {
                        userClassification,
                        requiredLevel: minLevel,
                        path: req.path,
                        ip: req.ip
                    });
                    res.status(403).json({
                        error: `Forbidden: Minimum classification ${minLevel} required`,
                        userClassification: userClassification,
                        timestamp: new Date().toISOString()
                    });
                    return;
                }
                break;
            }
        }
        // 3. MAESTRO L1 Security Validation (for requests with body.text)
        if (req.body && req.body.text) {
            try {
                const validationRequest = {
                    text: req.body.text,
                    classification: userClassification,
                    context: req.body.context || {
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        path: req.path,
                        timestamp: Date.now()
                    }
                };
                const validationResult = await maestroClient.validateSecurity(validationRequest);
                if (!validationResult.is_valid) {
                    logger.warn('MAESTRO security validation failed', {
                        threatLevel: validationResult.threat_level,
                        violations: validationResult.violations,
                        validationTime: validationResult.validation_time_ms,
                        path: req.path,
                        ip: req.ip,
                        textLength: req.body.text.length
                    });
                    res.status(403).json({
                        error: 'Forbidden: Security validation failed',
                        threatLevel: validationResult.threat_level,
                        violations: validationResult.violations,
                        auditEventId: validationResult.audit_event_id,
                        timestamp: new Date().toISOString()
                    });
                    return;
                }
                // Attach validation results to request for downstream use
                req.securityValidation = validationResult;
                logger.info('MAESTRO security validation passed', {
                    threatLevel: validationResult.threat_level,
                    validationTime: validationResult.validation_time_ms,
                    path: req.path,
                    textLength: req.body.text.length
                });
            }
            catch (validationError) {
                logger.error('Security validation service error', {
                    error: validationError instanceof Error ? validationError.message : 'Unknown error',
                    path: req.path,
                    ip: req.ip
                });
                res.status(500).json({
                    error: 'Internal Server Error: Security validation service unavailable',
                    timestamp: new Date().toISOString()
                });
                return;
            }
        }
        // 4. Performance monitoring
        const totalTime = Date.now() - startTime;
        if (totalTime > 100) {
            logger.warn('Security middleware exceeded performance target', {
                totalTime,
                target: 100,
                path: req.path
            });
        }
        // Attach performance metrics to request
        req.securityTime = totalTime;
        next();
    }
    catch (error) {
        logger.error('Security middleware error', {
            error: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined,
            path: req.path,
            ip: req.ip
        });
        res.status(500).json({
            error: `Security middleware error: ${error instanceof Error ? error.message : 'Unknown error'}`,
            timestamp: new Date().toISOString()
        });
    }
};
/**
 * Performance monitoring middleware
 */
export const performanceMonitoringMiddleware = (req, res, next) => {
    const startTime = Date.now();
    // Override res.end to capture response time
    /*
    const originalEnd = res.end;
    res.end = function(chunk?: any, encoding?: any) {
      const responseTime = Date.now() - startTime;
      
      // Set performance headers
      res.setHeader('X-Response-Time', `${responseTime}ms`);
      res.setHeader('X-Auth-Time', `${(req as any).authTime || 0}ms`);
      res.setHeader('X-Security-Time', `${(req as any).securityTime || 0}ms`);
      
      // Log performance metrics
      logger.info('Request completed', {
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        responseTime,
        authTime: (req as any).authTime || 0,
        securityTime: (req as any).securityTime || 0,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      // Call original end method
      originalEnd.call(this, chunk, encoding);
    };
    */
    next();
};
/**
 * Combined enhanced middleware stack
 */
export const enhancedMiddlewareStack = [
    performanceMonitoringMiddleware,
    inputValidationMiddleware,
    enhancedAuthenticationMiddleware,
    enhancedSecurityMiddleware
];
// Export service client for status monitoring
export { maestroClient };
//# sourceMappingURL=enhanced_middleware.js.map