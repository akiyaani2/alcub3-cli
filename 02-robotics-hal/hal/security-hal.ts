/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// universal-robotics/hal/security-hal.ts

import { EventEmitter } from 'events';

/**
 * ALCUB3 Universal Robotics Security HAL
 * Patent-Pending Universal Security Interface for Robotics Platforms
 * 
 * This module implements a Hardware Abstraction Layer (HAL) that provides
 * a unified security interface for applying MAESTRO L1-L3 security controls
 * to any robotics platform (Boston Dynamics, ROS2, DJI, etc.).
 * 
 * Key Innovations:
 * - Universal security interface abstraction for heterogeneous robot fleets
 * - Real-time security state synchronization across platforms
 * - Classification-aware robotics command validation
 * - Cross-platform emergency stop and safety override systems
 * 
 * Patent Claims:
 * - Method for universal security control of heterogeneous robotics platforms
 * - Real-time security state correlation across multiple robot types
 * - Classification-aware robotics command authorization system
 * - Universal emergency response coordination for robot fleets
 */

// Core Security HAL Types
export enum RoboticsSecurityLevel {
    UNCLASSIFIED = "UNCLASSIFIED",
    CUI = "CONTROLLED_UNCLASSIFIED_INFORMATION", 
    SECRET = "SECRET",
    TOP_SECRET = "TOP_SECRET"
}

export enum PlatformType {
    BOSTON_DYNAMICS = "boston_dynamics",
    ROS2 = "ros2",
    DJI_DRONE = "dji_drone",
    GENERIC = "generic"
}

export enum SecurityState {
    SECURE = "secure",
    DEGRADED = "degraded",
    COMPROMISED = "compromised",
    EMERGENCY_STOP = "emergency_stop",
    UNKNOWN = "unknown"
}

export enum CommandType {
    MOVEMENT = "movement",
    SENSOR_ACCESS = "sensor_access",
    DATA_COLLECTION = "data_collection",
    COMMUNICATION = "communication",
    SYSTEM_CONTROL = "system_control",
    EMERGENCY_STOP = "emergency_stop"
}

export enum RiskLevel {
    LOW = "low",
    MEDIUM = "medium", 
    HIGH = "high",
    CRITICAL = "critical"
}

export interface RobotPlatformIdentity {
    platformId: string;
    platformType: PlatformType;
    hardwareVersion: string;
    softwareVersion: string;
    securityCapabilities: SecurityCapability[];
    classificationLevel: RoboticsSecurityLevel;
    lastSecurityValidation: Date;
}

export interface SecurityCapability {
    capabilityId: string;
    capabilityType: string;
    supportedClassifications: RoboticsSecurityLevel[];
    performanceMetrics: {
        latencyMs: number;
        throughputOpsPerSec: number;
        reliabilityPercent: number;
    };
    complianceStandards: string[];
}

export interface RoboticsCommand {
    commandId: string;
    commandType: CommandType;
    targetPlatformId: string;
    payload: any;
    classificationLevel: RoboticsSecurityLevel;
    requiredClearance: RoboticsSecurityLevel;
    timestamp: Date;
    userId: string;
    signature?: string;
}

export interface SecurityValidationResult {
    isValid: boolean;
    validationTime: Date;
    securityChecks: SecurityCheck[];
    overallRisk: RiskLevel;
    recommendations: string[];
    auditTrail: string[];
}

export interface SecurityCheck {
    checkId: string;
    checkType: string;
    passed: boolean;
    riskLevel: RiskLevel;
    details: string;
    mitigations: string[];
}

export interface EmergencyResponse {
    responseId: string;
    triggerReason: string;
    affectedPlatforms: string[];
    responseActions: EmergencyAction[];
    executionTime: Date;
    success: boolean;
}

export interface EmergencyAction {
    actionType: "stop" | "isolate" | "secure" | "notify";
    targetPlatform: string;
    executedAt: Date;
    success: boolean;
    details: string;
}

export interface SecurityContext {
    platformId: string;
    operatorId: string;
    sessionId: string;
    timestamp: Date;
    classification: RoboticsSecurityLevel;
}

// Simplified audit logger interface for HAL use
export interface SecurityAuditLogger {
    logSecurityEvent(
        eventType: string,
        message: string,
        classificationLevel: RoboticsSecurityLevel,
        metadata?: any
    ): void;
}

/**
 * Universal Security Hardware Abstraction Layer
 * 
 * Provides a unified security interface for all robotics platforms,
 * enabling consistent application of MAESTRO security controls
 * regardless of the underlying robot hardware/software.
 */
export class UniversalSecurityHAL extends EventEmitter {
    private registeredPlatforms: Map<string, RobotPlatformIdentity>;
    private securityStates: Map<string, SecurityState>;
    private platformAdapters: Map<PlatformType, RoboticsSecurityAdapter>;
    private auditLogger: SecurityAuditLogger;
    private emergencyStopActive: boolean;
    
    // Performance monitoring
    private performanceMetrics: {
        commandValidations: number;
        securityChecks: number;
        emergencyResponses: number;
        averageLatencyMs: number;
    };
    
    constructor(auditLogger: SecurityAuditLogger) {
        super();
        
        this.auditLogger = auditLogger;
        this.registeredPlatforms = new Map();
        this.securityStates = new Map();
        this.platformAdapters = new Map();
        this.emergencyStopActive = false;
        
        this.performanceMetrics = {
            commandValidations: 0,
            securityChecks: 0,
            emergencyResponses: 0,
            averageLatencyMs: 0
        };
        
        // Initialize security monitoring
        this.initializeSecurityMonitoring();
    }
    
    /**
     * Register a robotics platform with the Security HAL
     * Establishes secure communication and validates platform capabilities
     */
    async registerPlatform(identity: RobotPlatformIdentity, adapter: RoboticsSecurityAdapter): Promise<boolean> {
        const startTime = Date.now();
        
        try {
            // Validate platform security capabilities
            const validationResult = await this.validatePlatformSecurity(identity);
            if (!validationResult.isValid) {
                this.auditLogger.logSecurityEvent(
                    'platform_registration_failed',
                    `Platform ${identity.platformId} failed security validation`,
                    identity.classificationLevel,
                    { validationResult }
                );
                return false;
            }
            
            // Register platform and adapter
            this.registeredPlatforms.set(identity.platformId, identity);
            this.platformAdapters.set(identity.platformType, adapter);
            this.securityStates.set(identity.platformId, SecurityState.SECURE);
            
            // Initialize platform security
            await adapter.initializeSecurity(identity);
            
            // Log successful registration
            this.auditLogger.logSecurityEvent(
                'platform_registered',
                `Platform ${identity.platformId} successfully registered`,
                identity.classificationLevel,
                { 
                    platformType: identity.platformType,
                    capabilities: identity.securityCapabilities.length,
                    registrationTime: Date.now() - startTime
                }
            );
            
            this.emit('platformRegistered', identity);
            return true;
            
        } catch (error: any) {
            this.auditLogger.logSecurityEvent(
                'platform_registration_error',
                `Platform registration failed: ${error.message}`,
                identity.classificationLevel,
                { error: error.message, platformId: identity.platformId }
            );
            return false;
        }
    }
    
    /**
     * Validate and execute a robotics command with security controls
     * Applies MAESTRO L1-L3 security validation before command execution
     */
    async executeSecureCommand(command: RoboticsCommand): Promise<SecurityValidationResult> {
        const startTime = Date.now();
        this.performanceMetrics.commandValidations++;
        
        try {
            // Emergency stop check
            if (this.emergencyStopActive && command.commandType !== CommandType.EMERGENCY_STOP) {
                return {
                    isValid: false,
                    validationTime: new Date(),
                    securityChecks: [{
                        checkId: 'emergency_stop_active',
                        checkType: 'emergency_override',
                        passed: false,
                        riskLevel: RiskLevel.CRITICAL,
                        details: 'Emergency stop is active - command rejected',
                        mitigations: ['Clear emergency stop condition', 'Verify system safety']
                    }],
                    overallRisk: RiskLevel.CRITICAL,
                    recommendations: ['Emergency stop must be cleared before normal operations'],
                    auditTrail: [`Command ${command.commandId} rejected due to emergency stop`]
                };
            }
            
            // Platform validation
            const platform = this.registeredPlatforms.get(command.targetPlatformId);
            if (!platform) {
                throw new Error(`Platform ${command.targetPlatformId} not registered`);
            }
            
            // Security validation pipeline
            const validationResult = await this.validateCommandSecurity(command, platform);
            
            if (validationResult.isValid) {
                // Execute command through platform adapter
                const adapter = this.platformAdapters.get(platform.platformType);
                if (adapter) {
                    await adapter.executeCommand(command);
                    
                    // Update security state
                    this.updatePlatformSecurityState(command.targetPlatformId, SecurityState.SECURE);
                }
            }
            
            // Performance tracking
            const executionTime = Date.now() - startTime;
            this.updatePerformanceMetrics(executionTime);
            
            // Audit logging
            this.auditLogger.logSecurityEvent(
                'command_executed',
                `Command ${command.commandId} executed with validation result: ${validationResult.isValid}`,
                command.classificationLevel,
                {
                    commandType: command.commandType,
                    platformId: command.targetPlatformId,
                    executionTimeMs: executionTime,
                    overallRisk: validationResult.overallRisk
                }
            );
            
            return validationResult;
            
        } catch (error: any) {
            this.auditLogger.logSecurityEvent(
                'command_execution_error',
                `Command execution failed: ${error.message}`,
                command.classificationLevel,
                { error: error.message, commandId: command.commandId }
            );
            
            return {
                isValid: false,
                validationTime: new Date(),
                securityChecks: [],
                overallRisk: RiskLevel.HIGH,
                recommendations: ['Review command parameters and platform status'],
                auditTrail: [`Command execution failed: ${error.message}`]
            };
        }
    }
    
    /**
     * Emergency stop all registered platforms
     * Implements immediate safety override across all robot types
     */
    async emergencyStopAll(reason: string, userId: string): Promise<EmergencyResponse> {
        const responseId = `emergency_${Date.now()}`;
        const startTime = new Date();
        const actions: EmergencyAction[] = [];
        
        try {
            this.emergencyStopActive = true;
            this.performanceMetrics.emergencyResponses++;
            
            // Execute emergency stop on all platforms
            for (const [platformId, platform] of this.registeredPlatforms) {
                try {
                    const adapter = this.platformAdapters.get(platform.platformType);
                    if (adapter) {
                        await adapter.emergencyStop(platformId, reason);
                        
                        actions.push({
                            actionType: "stop",
                            targetPlatform: platformId,
                            executedAt: new Date(),
                            success: true,
                            details: `Emergency stop executed successfully`
                        });
                        
                        // Update security state
                        this.securityStates.set(platformId, SecurityState.EMERGENCY_STOP);
                    }
                } catch (error: any) {
                    actions.push({
                        actionType: "stop",
                        targetPlatform: platformId,
                        executedAt: new Date(),
                        success: false,
                        details: `Emergency stop failed: ${error.message}`
                    });
                }
            }
            
            const response: EmergencyResponse = {
                responseId,
                triggerReason: reason,
                affectedPlatforms: Array.from(this.registeredPlatforms.keys()),
                responseActions: actions,
                executionTime: startTime,
                success: actions.every(action => action.success)
            };
            
            // Critical audit logging
            this.auditLogger.logSecurityEvent(
                'emergency_stop_executed',
                `Emergency stop executed by ${userId}: ${reason}`,
                RoboticsSecurityLevel.SECRET, // Always log emergency stops as SECRET
                {
                    responseId,
                    affectedPlatforms: response.affectedPlatforms.length,
                    successfulStops: actions.filter(a => a.success).length,
                    failedStops: actions.filter(a => !a.success).length
                }
            );
            
            this.emit('emergencyStop', response);
            return response;
            
        } catch (error: any) {
            this.auditLogger.logSecurityEvent(
                'emergency_stop_error',
                `Emergency stop execution failed: ${error.message}`,
                RoboticsSecurityLevel.SECRET,
                { error: error.message, responseId }
            );
            
            throw error;
        }
    }
    
    /**
     * Clear emergency stop condition and resume normal operations
     */
    async clearEmergencyStop(userId: string, justification: string): Promise<boolean> {
        try {
            // Validate all platforms are in safe state
            for (const [platformId, platform] of this.registeredPlatforms) {
                const adapter = this.platformAdapters.get(platform.platformType);
                if (adapter) {
                    const safetyStatus = await adapter.validateSafetyState(platformId);
                    if (!safetyStatus.isSafe) {
                        this.auditLogger.logSecurityEvent(
                            'emergency_clear_denied',
                            `Emergency stop clear denied - platform ${platformId} not safe`,
                            platform.classificationLevel,
                            { safetyStatus, justification }
                        );
                        return false;
                    }
                }
            }
            
            // Clear emergency stop
            this.emergencyStopActive = false;
            
            // Reset platform states to secure
            for (const platformId of this.registeredPlatforms.keys()) {
                this.securityStates.set(platformId, SecurityState.SECURE);
            }
            
            this.auditLogger.logSecurityEvent(
                'emergency_stop_cleared',
                `Emergency stop cleared by ${userId}: ${justification}`,
                RoboticsSecurityLevel.SECRET,
                { justification, platformCount: this.registeredPlatforms.size }
            );
            
            this.emit('emergencyStopCleared');
            return true;
            
        } catch (error: any) {
            this.auditLogger.logSecurityEvent(
                'emergency_clear_error',
                `Emergency stop clear failed: ${error.message}`,
                RoboticsSecurityLevel.SECRET,
                { error: error.message, userId }
            );
            return false;
        }
    }
    
    /**
     * Get comprehensive security status for all platforms
     */
    getSecurityStatus(): {
        overallStatus: SecurityState;
        platformStatuses: Map<string, SecurityState>;
        emergencyStopActive: boolean;
        performanceMetrics: any;
        registeredPlatforms: number;
    } {
        // Determine overall security status
        let overallStatus = SecurityState.SECURE;
        
        if (this.emergencyStopActive) {
            overallStatus = SecurityState.EMERGENCY_STOP;
        } else {
            const states = Array.from(this.securityStates.values());
            if (states.includes(SecurityState.COMPROMISED)) {
                overallStatus = SecurityState.COMPROMISED;
            } else if (states.includes(SecurityState.DEGRADED)) {
                overallStatus = SecurityState.DEGRADED;
            }
        }
        
        return {
            overallStatus,
            platformStatuses: new Map(this.securityStates),
            emergencyStopActive: this.emergencyStopActive,
            performanceMetrics: { ...this.performanceMetrics },
            registeredPlatforms: this.registeredPlatforms.size
        };
    }
    
    // Private implementation methods
    
    private async validatePlatformSecurity(identity: RobotPlatformIdentity): Promise<SecurityValidationResult> {
        const checks: SecurityCheck[] = [];
        
        // Validate security capabilities
        checks.push({
            checkId: 'capabilities_validation',
            checkType: 'platform_capabilities',
            passed: identity.securityCapabilities.length > 0,
            riskLevel: identity.securityCapabilities.length > 0 ? RiskLevel.LOW : RiskLevel.HIGH,
            details: `Platform has ${identity.securityCapabilities.length} security capabilities`,
            mitigations: identity.securityCapabilities.length === 0 ? ['Add security capabilities'] : []
        });
        
        // Validate classification level
        const classificationValid = Object.values(RoboticsSecurityLevel).includes(identity.classificationLevel);
        checks.push({
            checkId: 'classification_validation',
            checkType: 'classification_level',
            passed: classificationValid,
            riskLevel: classificationValid ? RiskLevel.LOW : RiskLevel.CRITICAL,
            details: `Classification level: ${identity.classificationLevel}`,
            mitigations: !classificationValid ? ['Set valid classification level'] : []
        });
        
        const overallValid = checks.every(check => check.passed);
        const maxRisk = checks.reduce((max, check) => 
            this.getRiskPriority(check.riskLevel) > this.getRiskPriority(max) ? check.riskLevel : max, 
            RiskLevel.LOW
        );
        
        return {
            isValid: overallValid,
            validationTime: new Date(),
            securityChecks: checks,
            overallRisk: maxRisk,
            recommendations: checks.flatMap(check => check.mitigations),
            auditTrail: [`Platform ${identity.platformId} security validation completed`]
        };
    }
    
    private async validateCommandSecurity(command: RoboticsCommand, platform: RobotPlatformIdentity): Promise<SecurityValidationResult> {
        const checks: SecurityCheck[] = [];
        this.performanceMetrics.securityChecks++;
        
        // Classification level validation
        const classificationCheck = this.validateClassificationAccess(
            command.classificationLevel, 
            command.requiredClearance
        );
        checks.push(classificationCheck);
        
        // Platform capability validation
        const capabilityCheck = this.validatePlatformCapability(command, platform);
        checks.push(capabilityCheck);
        
        // Command type validation
        const commandTypeCheck = this.validateCommandType(command);
        checks.push(commandTypeCheck);
        
        const overallValid = checks.every(check => check.passed);
        const maxRisk = checks.reduce((max, check) => 
            this.getRiskPriority(check.riskLevel) > this.getRiskPriority(max) ? check.riskLevel : max, 
            RiskLevel.LOW
        );
        
        return {
            isValid: overallValid,
            validationTime: new Date(),
            securityChecks: checks,
            overallRisk: maxRisk,
            recommendations: checks.flatMap(check => check.mitigations),
            auditTrail: [`Command ${command.commandId} security validation completed`]
        };
    }
    
    private validateClassificationAccess(commandLevel: RoboticsSecurityLevel, requiredClearance: RoboticsSecurityLevel): SecurityCheck {
        const levelHierarchy = {
            [RoboticsSecurityLevel.UNCLASSIFIED]: 0,
            [RoboticsSecurityLevel.CUI]: 1,
            [RoboticsSecurityLevel.SECRET]: 2,
            [RoboticsSecurityLevel.TOP_SECRET]: 3
        };
        
        const commandLevelNum = levelHierarchy[commandLevel];
        const requiredLevelNum = levelHierarchy[requiredClearance];
        const passed = requiredLevelNum >= commandLevelNum;
        
        return {
            checkId: 'classification_access',
            checkType: 'access_control',
            passed,
            riskLevel: passed ? RiskLevel.LOW : RiskLevel.HIGH,
            details: `Command level: ${commandLevel}, Required clearance: ${requiredClearance}`,
            mitigations: !passed ? ['Obtain appropriate security clearance', 'Reduce command classification level'] : []
        };
    }
    
    private validatePlatformCapability(command: RoboticsCommand, platform: RobotPlatformIdentity): SecurityCheck {
        const hasCapability = platform.securityCapabilities.some(cap => 
            cap.supportedClassifications.includes(command.classificationLevel)
        );
        
        return {
            checkId: 'platform_capability',
            checkType: 'capability_validation',
            passed: hasCapability,
            riskLevel: hasCapability ? RiskLevel.LOW : RiskLevel.MEDIUM,
            details: `Platform supports ${command.classificationLevel}: ${hasCapability}`,
            mitigations: !hasCapability ? ['Upgrade platform security capabilities', 'Use different platform'] : []
        };
    }
    
    private validateCommandType(command: RoboticsCommand): SecurityCheck {
        const validTypes = Object.values(CommandType);
        const passed = validTypes.includes(command.commandType);
        
        return {
            checkId: 'command_type',
            checkType: 'command_validation',
            passed,
            riskLevel: passed ? RiskLevel.LOW : RiskLevel.MEDIUM,
            details: `Command type: ${command.commandType}`,
            mitigations: !passed ? ['Use valid command type', 'Review command structure'] : []
        };
    }
    
    private getRiskPriority(risk: RiskLevel): number {
        const priorities = {
            [RiskLevel.LOW]: 0,
            [RiskLevel.MEDIUM]: 1,
            [RiskLevel.HIGH]: 2,
            [RiskLevel.CRITICAL]: 3
        };
        return priorities[risk];
    }
    
    private updatePlatformSecurityState(platformId: string, state: SecurityState): void {
        this.securityStates.set(platformId, state);
        this.emit('securityStateChanged', { platformId, state });
    }
    
    private updatePerformanceMetrics(executionTimeMs: number): void {
        // Update rolling average
        const currentAvg = this.performanceMetrics.averageLatencyMs;
        const totalCommands = this.performanceMetrics.commandValidations;
        
        this.performanceMetrics.averageLatencyMs = 
            ((currentAvg * (totalCommands - 1)) + executionTimeMs) / totalCommands;
    }
    
    private initializeSecurityMonitoring(): void {
        // Set up periodic security health checks
        setInterval((): void => {
            this.performSecurityHealthCheck().catch(console.error);
        }, 30000); // Every 30 seconds
    }
    
    private async performSecurityHealthCheck(): Promise<void> {
        for (const [platformId, platform] of this.registeredPlatforms) {
            try {
                const adapter = this.platformAdapters.get(platform.platformType);
                if (adapter) {
                    const healthStatus = await adapter.getSecurityHealth(platformId);
                    
                    if (!healthStatus.isHealthy) {
                        this.updatePlatformSecurityState(platformId, SecurityState.DEGRADED);
                        
                        this.auditLogger.logSecurityEvent(
                            'security_health_degraded',
                            `Platform ${platformId} security health degraded`,
                            platform.classificationLevel,
                            { healthStatus }
                        );
                    }
                }
            } catch (error) {
                this.updatePlatformSecurityState(platformId, SecurityState.UNKNOWN);
            }
        }
    }
}

/**
 * Abstract base class for platform-specific security adapters
 * Each robotics platform (Spot, ROS2, DJI) implements this interface
 */
export abstract class RoboticsSecurityAdapter {
    abstract initializeSecurity(identity: RobotPlatformIdentity): Promise<void>;
    abstract executeCommand(command: RoboticsCommand): Promise<void>;
    abstract emergencyStop(platformId: string, reason: string): Promise<void>;
    abstract validateSafetyState(platformId: string): Promise<{ isSafe: boolean; details: string }>;
    abstract getSecurityHealth(platformId: string): Promise<{ isHealthy: boolean; details: string }>;
} 