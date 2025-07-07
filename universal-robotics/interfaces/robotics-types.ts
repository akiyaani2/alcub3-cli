/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// universal-robotics/interfaces/robotics-types.ts

/**
 * Universal Robotics Type Definitions
 * 
 * This module defines the core types and interfaces for the Universal Robotics
 * Security Framework, providing a unified type system across all supported
 * robotics platforms.
 */

/**
 * Supported robotics platforms
 */
export enum RoboticsPlatform {
  SPOT = 'spot',
  ROS2 = 'ros2',
  DJI = 'dji',
  GENERIC = 'generic'
}

/**
 * Security classification levels for robotics operations
 */
export enum SecurityClassification {
  UNCLASSIFIED = 'UNCLASSIFIED',
  CUI = 'CUI',
  SECRET = 'SECRET',
  TOP_SECRET = 'TOP_SECRET'
}

/**
 * Command execution status
 */
export enum CommandStatus {
  PENDING = 'pending',
  EXECUTING = 'executing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
  SECURITY_VIOLATION = 'security_violation'
}

/**
 * Emergency response types
 */
export enum EmergencyType {
  IMMEDIATE_STOP = 'immediate_stop',
  SAFE_LANDING = 'safe_landing',
  RETURN_TO_BASE = 'return_to_base',
  HOLD_POSITION = 'hold_position',
  EMERGENCY_SHUTDOWN = 'emergency_shutdown'
}

/**
 * Telemetry data types
 */
export enum TelemetryType {
  POSITION = 'position',
  VELOCITY = 'velocity',
  ORIENTATION = 'orientation',
  SENSOR_DATA = 'sensor_data',
  BATTERY_STATUS = 'battery_status',
  SYSTEM_STATUS = 'system_status',
  CAMERA_FEED = 'camera_feed',
  LIDAR_DATA = 'lidar_data'
}

/**
 * 3D position coordinates
 */
export interface Position3D {
  x: number;
  y: number;
  z: number;
  timestamp: number;
  accuracy?: number;
}

/**
 * Geographic coordinates
 */
export interface GeoPosition {
  latitude: number;
  longitude: number;
  altitude: number;
  timestamp: number;
  accuracy?: number;
}

/**
 * 3D velocity vector
 */
export interface Velocity3D {
  vx: number;
  vy: number;
  vz: number;
  timestamp: number;
}

/**
 * 3D orientation (quaternion)
 */
export interface Orientation3D {
  w: number;
  x: number;
  y: number;
  z: number;
  timestamp: number;
}

/**
 * Euler angles representation
 */
export interface EulerAngles {
  roll: number;
  pitch: number;
  yaw: number;
  timestamp: number;
}

/**
 * Battery status information
 */
export interface BatteryStatus {
  percentage: number;
  voltage: number;
  current: number;
  temperature: number;
  timeRemaining?: number;
  isCharging: boolean;
  timestamp: number;
}

/**
 * System health status
 */
export interface SystemStatus {
  overall: 'healthy' | 'warning' | 'critical' | 'offline';
  subsystems: Record<string, {
    status: 'healthy' | 'warning' | 'critical' | 'offline';
    message?: string;
  }>;
  timestamp: number;
}

/**
 * Universal robotics command structure
 */
export interface RoboticsCommand {
  id: string;
  platform: RoboticsPlatform;
  command: string;
  parameters: Record<string, any>;
  classification: SecurityClassification;
  priority: number;
  timeout?: number;
  requiredCapabilities?: string[];
  safetyConstraints?: SafetyConstraints;
  metadata?: Record<string, any>;
}

/**
 * Safety constraints for robotics operations
 */
export interface SafetyConstraints {
  maxVelocity?: Velocity3D;
  maxAcceleration?: number;
  operatingArea?: GeoBoundary;
  minBatteryLevel?: number;
  requiredSensors?: string[];
  weatherLimitations?: WeatherConstraints;
  timeConstraints?: TimeConstraints;
}

/**
 * Geographic boundary definition
 */
export interface GeoBoundary {
  type: 'circle' | 'polygon' | 'rectangle';
  center?: GeoPosition;
  radius?: number;
  vertices?: GeoPosition[];
  minAltitude?: number;
  maxAltitude?: number;
}

/**
 * Weather constraints
 */
export interface WeatherConstraints {
  maxWindSpeed?: number;
  maxPrecipitation?: number;
  minVisibility?: number;
  temperatureRange?: {
    min: number;
    max: number;
  };
}

/**
 * Time-based constraints
 */
export interface TimeConstraints {
  startTime?: Date;
  endTime?: Date;
  maxDuration?: number;
  allowedTimeWindows?: Array<{
    start: string; // HH:MM format
    end: string;   // HH:MM format
  }>;
}

/**
 * Command execution result
 */
export interface CommandResult {
  commandId: string;
  platform: RoboticsPlatform;
  status: CommandStatus;
  result?: any;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  executionTime: number;
  securityValidation: SecurityValidationResult;
  timestamp: number;
}

/**
 * Security validation result
 */
export interface SecurityValidationResult {
  passed: boolean;
  classification: SecurityClassification;
  validationTime: number;
  checks: Array<{
    name: string;
    passed: boolean;
    message?: string;
  }>;
  signature?: string;
}

/**
 * Telemetry data structure
 */
export interface TelemetryData {
  id: string;
  platform: RoboticsPlatform;
  robotId: string;
  type: TelemetryType;
  data: any;
  classification: SecurityClassification;
  encrypted: boolean;
  integrity: {
    checksum: string;
    algorithm: string;
  };
  timestamp: number;
}

/**
 * Platform capabilities
 */
export interface PlatformCapabilities {
  platform: RoboticsPlatform;
  version: string;
  supportedCommands: string[];
  sensors: SensorCapability[];
  actuators: ActuatorCapability[];
  communicationProtocols: string[];
  securityFeatures: SecurityFeature[];
  limitations: PlatformLimitations;
}

/**
 * Sensor capability definition
 */
export interface SensorCapability {
  type: string;
  model: string;
  accuracy: number;
  range: number;
  frequency: number;
  dataTypes: TelemetryType[];
}

/**
 * Actuator capability definition
 */
export interface ActuatorCapability {
  type: string;
  model: string;
  maxForce?: number;
  maxSpeed?: number;
  precision: number;
  supportedCommands: string[];
}

/**
 * Security feature definition
 */
export interface SecurityFeature {
  name: string;
  type: 'encryption' | 'authentication' | 'authorization' | 'audit' | 'emergency';
  level: SecurityClassification;
  enabled: boolean;
  configuration?: Record<string, any>;
}

/**
 * Platform limitations
 */
export interface PlatformLimitations {
  maxOperatingTime?: number;
  maxRange?: number;
  maxPayload?: number;
  environmentalLimits?: WeatherConstraints;
  connectivityRequirements?: string[];
}

/**
 * Emergency response configuration
 */
export interface EmergencyConfig {
  type: EmergencyType;
  triggerConditions: EmergencyTrigger[];
  responseActions: EmergencyAction[];
  notificationTargets: string[];
  timeoutSeconds: number;
}

/**
 * Emergency trigger condition
 */
export interface EmergencyTrigger {
  type: 'manual' | 'automatic' | 'sensor' | 'communication_loss' | 'security_breach';
  condition: string;
  threshold?: number;
  duration?: number;
}

/**
 * Emergency response action
 */
export interface EmergencyAction {
  type: EmergencyType;
  parameters?: Record<string, any>;
  priority: number;
  timeout: number;
}

/**
 * Platform connection configuration
 */
export interface PlatformConfig {
  platform: RoboticsPlatform;
  robotId: string;
  connectionType: 'direct' | 'network' | 'cloud' | 'serial';
  connectionParams: Record<string, any>;
  securityConfig: {
    classification: SecurityClassification;
    encryptionEnabled: boolean;
    authenticationMethod: string;
    certificatePath?: string;
  };
  capabilities: PlatformCapabilities;
  emergencyConfig: EmergencyConfig;
}

/**
 * Multi-robot coordination task
 */
export interface CoordinationTask {
  id: string;
  name: string;
  description: string;
  participants: string[]; // Robot IDs
  commands: RoboticsCommand[];
  constraints: CoordinationConstraints;
  classification: SecurityClassification;
  status: 'planned' | 'executing' | 'completed' | 'failed' | 'cancelled';
  startTime?: Date;
  endTime?: Date;
}

/**
 * Coordination constraints
 */
export interface CoordinationConstraints {
  minDistance?: number;
  maxDistance?: number;
  synchronization?: 'strict' | 'loose' | 'none';
  communicationRequired?: boolean;
  fallbackBehavior?: string;
}

/**
 * Mission plan structure
 */
export interface MissionPlan {
  id: string;
  name: string;
  description: string;
  classification: SecurityClassification;
  participants: string[];
  waypoints: MissionWaypoint[];
  tasks: CoordinationTask[];
  safetyProtocols: SafetyProtocol[];
  contingencyPlans: ContingencyPlan[];
  estimatedDuration: number;
  requiredApprovals: string[];
}

/**
 * Mission waypoint
 */
export interface MissionWaypoint {
  id: string;
  position: GeoPosition;
  actions: string[];
  constraints: SafetyConstraints;
  dwellTime?: number;
  requiredSensors?: string[];
}

/**
 * Safety protocol definition
 */
export interface SafetyProtocol {
  id: string;
  name: string;
  triggers: EmergencyTrigger[];
  actions: EmergencyAction[];
  priority: number;
  autoExecute: boolean;
}

/**
 * Contingency plan
 */
export interface ContingencyPlan {
  id: string;
  scenario: string;
  triggers: string[];
  actions: string[];
  fallbackMission?: string;
  approvalRequired: boolean;
}

/**
 * Real-time status update
 */
export interface StatusUpdate {
  robotId: string;
  platform: RoboticsPlatform;
  position: GeoPosition;
  velocity: Velocity3D;
  orientation: Orientation3D;
  battery: BatteryStatus;
  system: SystemStatus;
  activeCommands: string[];
  lastUpdate: number;
}

/**
 * Security audit log entry
 */
export interface SecurityAuditLog {
  id: string;
  timestamp: number;
  robotId: string;
  platform: RoboticsPlatform;
  event: string;
  classification: SecurityClassification;
  user?: string;
  command?: RoboticsCommand;
  result: 'success' | 'failure' | 'violation';
  details: Record<string, any>;
  signature: string;
} 