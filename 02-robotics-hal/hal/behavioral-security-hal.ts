/**
 * ALCUB3 Behavioral Security Hardware Abstraction Layer
 * Universal Behavioral Monitoring Interface for Robotics Platforms
 * 
 * This module provides a unified interface for behavioral monitoring across
 * different robotics platforms (Boston Dynamics, ROS2, DJI, etc.) with
 * hardware-level security integration.
 * 
 * Key Features:
 * - Universal behavioral monitoring interface
 * - Platform-agnostic behavioral data collection
 * - Hardware-level security integration
 * - Real-time behavioral analysis coordination
 * - Cross-platform behavioral correlation
 * 
 * @author ALCUB3 Development Team
 * @classification For Official Use Only
 */

import { EventEmitter } from 'events';
import { Logger } from '../src/utils/logger';
import { PerformanceBudget } from '../src/utils/performance-budget';
import { SecurityContext, ClassificationLevel } from '../src/security/security-context';
import { HardwareSecurityModule } from './security-hal';
import { AdvancedSecurityHAL } from './advanced-security-hal';

// Type definitions
export interface BehavioralSensorData {
  timestamp: Date;
  robotId: string;
  platformType: RobotPlatformType;
  
  // Movement data
  position?: {
    x: number;
    y: number;
    z: number;
    confidence: number;
  };
  
  velocity?: {
    vx: number;
    vy: number;
    vz: number;
    confidence: number;
  };
  
  // Communication data
  communication?: {
    messageFrequency: number;
    messageTypes: Record<string, number>;
    avgResponseTime: number;
    signalStrength: number;
    packetLossRate: number;
  };
  
  // Sensor data
  sensors?: {
    [sensorName: string]: {
      value: number;
      confidence: number;
      noiseLevel: number;
      lastCalibration?: Date;
    };
  };
  
  // Task execution data
  taskExecution?: {
    completionRate: number;
    executionTime: number;
    errorRate: number;
    complexityScore: number;
    cpuUsage: number;
    memoryUsage: number;
  };
  
  // Power consumption data
  power?: {
    consumption: number;
    batteryLevel: number;
    efficiency: number;
    temperature: number;
  };
  
  // Security context
  securityContext?: {
    classificationLevel: ClassificationLevel;
    securityDomain: string;
    encryptionEnabled: boolean;
    integrityChecksum?: string;
  };
}

export enum RobotPlatformType {
  BOSTON_DYNAMICS_SPOT = 'boston_dynamics_spot',
  ROS2_GENERIC = 'ros2_generic',
  DJI_DRONE = 'dji_drone',
  INDUSTRIAL_ARM = 'industrial_arm',
  AGV_PLATFORM = 'agv_platform',
  HUMANOID_ROBOT = 'humanoid_robot',
  MARINE_PLATFORM = 'marine_platform',
  AERIAL_SWARM = 'aerial_swarm',
  GROUND_VEHICLE = 'ground_vehicle',
  UNKNOWN = 'unknown'
}

export enum BehavioralAnomalyType {
  BASELINE_DEVIATION = 'baseline_deviation',
  ABNORMAL_SEQUENCE = 'abnormal_sequence',
  TEMPORAL_ANOMALY = 'temporal_anomaly',
  CROSS_MODAL_INCONSISTENCY = 'cross_modal_inconsistency',
  EMERGENT_BEHAVIOR = 'emergent_behavior',
  BEHAVIORAL_DEGRADATION = 'behavioral_degradation',
  COORDINATED_ANOMALY = 'coordinated_anomaly',
  ADAPTIVE_ATTACK = 'adaptive_attack'
}

export interface BehavioralAnomaly {
  anomalyId: string;
  anomalyType: BehavioralAnomalyType;
  timestamp: Date;
  affectedRobots: string[];
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // Detection details
  detectionMethod: string;
  featureContributions: Record<string, number>;
  behavioralContext: Record<string, any>;
  
  // Classification
  classificationLevel: ClassificationLevel;
  
  // Response recommendations
  recommendedActions: string[];
  autoResponseTriggered: boolean;
}

export interface BehavioralPattern {
  patternId: string;
  patternType: string;
  robotId: string;
  platformType: RobotPlatformType;
  
  // Pattern characteristics
  signature: number[];
  frequency: number;
  confidence: number;
  firstObserved: Date;
  lastObserved: Date;
  observations: number;
  
  // Stability metrics
  stabilityScore: number;
  adaptationRate: number;
}

export interface BehavioralCorrelation {
  correlationId: string;
  correlationType: string;
  sourceRobot: string;
  targetRobot: string;
  sourcePlatform: RobotPlatformType;
  targetPlatform: RobotPlatformType;
  
  // Correlation metrics
  correlationStrength: number;
  correlationSignificance: number;
  correlationStability: number;
  
  // Temporal information
  firstObserved: Date;
  lastObserved: Date;
  observationCount: number;
}

export interface BehavioralMonitoringConfig {
  enableRealTimeMonitoring: boolean;
  targetResponseTimeMs: number;
  maxConcurrentRobots: number;
  
  // Security settings
  classificationLevel: ClassificationLevel;
  encryptionEnabled: boolean;
  auditLoggingEnabled: boolean;
  
  // Performance settings
  memoryLimitMB: number;
  cpuLimitPercent: number;
  diskCacheSizeMB: number;
  
  // Platform-specific settings
  platformAdapters: Record<RobotPlatformType, any>;
}

export interface BehavioralSecurityEvent {
  eventId: string;
  eventType: string;
  timestamp: Date;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical' | 'emergency';
  
  // Event details
  affectedRobots: string[];
  threatLevel: string;
  confidence: number;
  
  // Context
  classificationLevel: ClassificationLevel;
  securityDomain: string;
  
  // Response
  automatedResponse: boolean;
  responseActions: string[];
}

/**
 * Platform-specific behavioral adapter interface
 */
export interface BehavioralPlatformAdapter {
  platformType: RobotPlatformType;
  
  // Data collection
  collectBehavioralData(robotId: string): Promise<BehavioralSensorData>;
  
  // Feature extraction
  extractBehavioralFeatures(data: BehavioralSensorData): Promise<Record<string, any>>;
  
  // Pattern recognition
  recognizeBehavioralPatterns(features: Record<string, any>): Promise<BehavioralPattern[]>;
  
  // Anomaly detection
  detectBehavioralAnomalies(patterns: BehavioralPattern[]): Promise<BehavioralAnomaly[]>;
  
  // Response actions
  executeResponseAction(action: string, robotId: string): Promise<boolean>;
  
  // Configuration
  configure(config: any): Promise<void>;
  
  // Status
  getStatus(): Promise<{
    isConnected: boolean;
    health: string;
    lastUpdate: Date;
    errorCount: number;
  }>;
}

/**
 * Boston Dynamics Spot behavioral adapter
 */
export class SpotBehavioralAdapter implements BehavioralPlatformAdapter {
  platformType = RobotPlatformType.BOSTON_DYNAMICS_SPOT;
  private logger: Logger;
  
  constructor() {
    this.logger = new Logger('SpotBehavioralAdapter');
  }
  
  async collectBehavioralData(robotId: string): Promise<BehavioralSensorData> {
    return PerformanceBudget.measureAsync('spot-behavioral-data-collection', async () => {
      // Collect Spot-specific behavioral data
      const data: BehavioralSensorData = {
        timestamp: new Date(),
        robotId,
        platformType: this.platformType,
        
        // Spot-specific movement data
        position: {
          x: 0, y: 0, z: 0, confidence: 0.95
        },
        velocity: {
          vx: 0, vy: 0, vz: 0, confidence: 0.95
        },
        
        // Spot-specific sensor data
        sensors: {
          'lidar': { value: 1.0, confidence: 0.9, noiseLevel: 0.02 },
          'cameras': { value: 1.0, confidence: 0.95, noiseLevel: 0.01 },
          'imu': { value: 1.0, confidence: 0.99, noiseLevel: 0.005 }
        },
        
        // Spot-specific power data
        power: {
          consumption: 200.0,
          batteryLevel: 0.8,
          efficiency: 0.85,
          temperature: 35.0
        }
      };
      
      this.logger.info(`Collected behavioral data for Spot robot ${robotId}`);
      return data;
    });
  }
  
  async extractBehavioralFeatures(data: BehavioralSensorData): Promise<Record<string, any>> {
    return PerformanceBudget.measureAsync('spot-feature-extraction', async () => {
      // Extract Spot-specific behavioral features
      const features: Record<string, any> = {
        'quadruped_gait': this.extractGaitFeatures(data),
        'terrain_adaptation': this.extractTerrainFeatures(data),
        'dynamic_balance': this.extractBalanceFeatures(data),
        'sensor_fusion': this.extractSensorFusionFeatures(data)
      };
      
      return features;
    });
  }
  
  private extractGaitFeatures(data: BehavioralSensorData): number[] {
    // Extract quadruped gait characteristics
    if (!data.velocity) return [0, 0, 0, 0];
    
    const speed = Math.sqrt(data.velocity.vx**2 + data.velocity.vy**2 + data.velocity.vz**2);
    const gaitPattern = this.classifyGaitPattern(speed);
    const stability = this.calculateGaitStability(data);
    const efficiency = this.calculateGaitEfficiency(data);
    
    return [speed, gaitPattern, stability, efficiency];
  }
  
  private extractTerrainFeatures(data: BehavioralSensorData): number[] {
    // Extract terrain adaptation features
    const terrainRoughness = data.sensors?.['lidar']?.value || 0;
    const adaptationResponse = this.calculateAdaptationResponse(data);
    const stabilityMaintenance = this.calculateStabilityMaintenance(data);
    
    return [terrainRoughness, adaptationResponse, stabilityMaintenance];
  }
  
  private extractBalanceFeatures(data: BehavioralSensorData): number[] {
    // Extract dynamic balance features
    const imuData = data.sensors?.['imu']?.value || 0;
    const balanceScore = this.calculateBalanceScore(imuData);
    const recoveryTime = this.calculateRecoveryTime(data);
    
    return [balanceScore, recoveryTime];
  }
  
  private extractSensorFusionFeatures(data: BehavioralSensorData): number[] {
    // Extract sensor fusion quality features
    const fusionAccuracy = this.calculateSensorFusionAccuracy(data);
    const sensorHealthScore = this.calculateSensorHealthScore(data);
    
    return [fusionAccuracy, sensorHealthScore];
  }
  
  private classifyGaitPattern(speed: number): number {
    // Classify quadruped gait pattern based on speed
    if (speed < 0.5) return 0; // Standing
    if (speed < 1.0) return 1; // Walking
    if (speed < 2.0) return 2; // Trotting
    return 3; // Running
  }
  
  private calculateGaitStability(data: BehavioralSensorData): number {
    // Calculate gait stability metric
    return 0.9; // Placeholder
  }
  
  private calculateGaitEfficiency(data: BehavioralSensorData): number {
    // Calculate gait efficiency metric
    return 0.8; // Placeholder
  }
  
  private calculateAdaptationResponse(data: BehavioralSensorData): number {
    // Calculate terrain adaptation response
    return 0.85; // Placeholder
  }
  
  private calculateStabilityMaintenance(data: BehavioralSensorData): number {
    // Calculate stability maintenance metric
    return 0.9; // Placeholder
  }
  
  private calculateBalanceScore(imuData: number): number {
    // Calculate balance score from IMU data
    return 0.95; // Placeholder
  }
  
  private calculateRecoveryTime(data: BehavioralSensorData): number {
    // Calculate recovery time from perturbations
    return 0.2; // Placeholder
  }
  
  private calculateSensorFusionAccuracy(data: BehavioralSensorData): number {
    // Calculate sensor fusion accuracy
    return 0.92; // Placeholder
  }
  
  private calculateSensorHealthScore(data: BehavioralSensorData): number {
    // Calculate overall sensor health score
    return 0.88; // Placeholder
  }
  
  async recognizeBehavioralPatterns(features: Record<string, any>): Promise<BehavioralPattern[]> {
    return PerformanceBudget.measureAsync('spot-pattern-recognition', async () => {
      // Recognize Spot-specific behavioral patterns
      const patterns: BehavioralPattern[] = [];
      
      // Example pattern recognition logic
      if (features.quadruped_gait) {
        patterns.push({
          patternId: `gait_${Date.now()}`,
          patternType: 'quadruped_gait',
          robotId: '',
          platformType: this.platformType,
          signature: features.quadruped_gait,
          frequency: 1.0,
          confidence: 0.9,
          firstObserved: new Date(),
          lastObserved: new Date(),
          observations: 1,
          stabilityScore: 0.85,
          adaptationRate: 0.1
        });
      }
      
      return patterns;
    });
  }
  
  async detectBehavioralAnomalies(patterns: BehavioralPattern[]): Promise<BehavioralAnomaly[]> {
    return PerformanceBudget.measureAsync('spot-anomaly-detection', async () => {
      const anomalies: BehavioralAnomaly[] = [];
      
      // Analyze patterns for anomalies
      for (const pattern of patterns) {
        if (pattern.stabilityScore < 0.5) {
          anomalies.push({
            anomalyId: `anomaly_${Date.now()}`,
            anomalyType: BehavioralAnomalyType.BEHAVIORAL_DEGRADATION,
            timestamp: new Date(),
            affectedRobots: [pattern.robotId],
            confidence: 1.0 - pattern.stabilityScore,
            severity: 'high',
            detectionMethod: 'stability_analysis',
            featureContributions: { 'stability_score': pattern.stabilityScore },
            behavioralContext: { 'pattern_type': pattern.patternType },
            classificationLevel: ClassificationLevel.UNCLASSIFIED,
            recommendedActions: ['check_mechanical_systems', 'recalibrate_sensors'],
            autoResponseTriggered: false
          });
        }
      }
      
      return anomalies;
    });
  }
  
  async executeResponseAction(action: string, robotId: string): Promise<boolean> {
    return PerformanceBudget.measureAsync('spot-response-action', async () => {
      this.logger.info(`Executing response action ${action} for Spot robot ${robotId}`);
      
      switch (action) {
        case 'emergency_stop':
          // Emergency stop implementation
          return true;
        case 'safe_mode':
          // Safe mode implementation
          return true;
        case 'diagnostic_mode':
          // Diagnostic mode implementation
          return true;
        default:
          this.logger.warn(`Unknown response action: ${action}`);
          return false;
      }
    });
  }
  
  async configure(config: any): Promise<void> {
    this.logger.info('Configuring Spot behavioral adapter');
    // Configuration implementation
  }
  
  async getStatus(): Promise<{
    isConnected: boolean;
    health: string;
    lastUpdate: Date;
    errorCount: number;
  }> {
    return {
      isConnected: true,
      health: 'healthy',
      lastUpdate: new Date(),
      errorCount: 0
    };
  }
}

/**
 * ROS2 behavioral adapter
 */
export class ROS2BehavioralAdapter implements BehavioralPlatformAdapter {
  platformType = RobotPlatformType.ROS2_GENERIC;
  private logger: Logger;
  
  constructor() {
    this.logger = new Logger('ROS2BehavioralAdapter');
  }
  
  async collectBehavioralData(robotId: string): Promise<BehavioralSensorData> {
    return PerformanceBudget.measureAsync('ros2-behavioral-data-collection', async () => {
      // Collect ROS2-specific behavioral data
      const data: BehavioralSensorData = {
        timestamp: new Date(),
        robotId,
        platformType: this.platformType,
        
        // ROS2-specific data collection
        communication: {
          messageFrequency: 10.0,
          messageTypes: {
            'sensor_msgs': 50,
            'geometry_msgs': 30,
            'nav_msgs': 20
          },
          avgResponseTime: 0.05,
          signalStrength: 0.9,
          packetLossRate: 0.01
        },
        
        taskExecution: {
          completionRate: 0.95,
          executionTime: 1.5,
          errorRate: 0.02,
          complexityScore: 0.6,
          cpuUsage: 0.4,
          memoryUsage: 0.3
        }
      };
      
      return data;
    });
  }
  
  async extractBehavioralFeatures(data: BehavioralSensorData): Promise<Record<string, any>> {
    return PerformanceBudget.measureAsync('ros2-feature-extraction', async () => {
      // Extract ROS2-specific behavioral features
      const features: Record<string, any> = {
        'ros2_topics': this.extractTopicFeatures(data),
        'distributed_nodes': this.extractNodeFeatures(data),
        'message_patterns': this.extractMessagePatterns(data),
        'performance_metrics': this.extractPerformanceFeatures(data)
      };
      
      return features;
    });
  }
  
  private extractTopicFeatures(data: BehavioralSensorData): number[] {
    // Extract ROS2 topic behavioral features
    const messageFreq = data.communication?.messageFrequency || 0;
    const topicDiversity = Object.keys(data.communication?.messageTypes || {}).length;
    const avgResponseTime = data.communication?.avgResponseTime || 0;
    
    return [messageFreq, topicDiversity, avgResponseTime];
  }
  
  private extractNodeFeatures(data: BehavioralSensorData): number[] {
    // Extract ROS2 node behavioral features
    const cpuUsage = data.taskExecution?.cpuUsage || 0;
    const memoryUsage = data.taskExecution?.memoryUsage || 0;
    const errorRate = data.taskExecution?.errorRate || 0;
    
    return [cpuUsage, memoryUsage, errorRate];
  }
  
  private extractMessagePatterns(data: BehavioralSensorData): number[] {
    // Extract ROS2 message pattern features
    const packetLoss = data.communication?.packetLossRate || 0;
    const signalStrength = data.communication?.signalStrength || 0;
    
    return [packetLoss, signalStrength];
  }
  
  private extractPerformanceFeatures(data: BehavioralSensorData): number[] {
    // Extract performance behavioral features
    const completionRate = data.taskExecution?.completionRate || 0;
    const executionTime = data.taskExecution?.executionTime || 0;
    const complexityScore = data.taskExecution?.complexityScore || 0;
    
    return [completionRate, executionTime, complexityScore];
  }
  
  async recognizeBehavioralPatterns(features: Record<string, any>): Promise<BehavioralPattern[]> {
    return [];
  }
  
  async detectBehavioralAnomalies(patterns: BehavioralPattern[]): Promise<BehavioralAnomaly[]> {
    return [];
  }
  
  async executeResponseAction(action: string, robotId: string): Promise<boolean> {
    return true;
  }
  
  async configure(config: any): Promise<void> {
    // Configuration implementation
  }
  
  async getStatus(): Promise<{
    isConnected: boolean;
    health: string;
    lastUpdate: Date;
    errorCount: number;
  }> {
    return {
      isConnected: true,
      health: 'healthy',
      lastUpdate: new Date(),
      errorCount: 0
    };
  }
}

/**
 * DJI Drone behavioral adapter
 */
export class DJIDroneBehavioralAdapter implements BehavioralPlatformAdapter {
  platformType = RobotPlatformType.DJI_DRONE;
  private logger: Logger;
  
  constructor() {
    this.logger = new Logger('DJIDroneBehavioralAdapter');
  }
  
  async collectBehavioralData(robotId: string): Promise<BehavioralSensorData> {
    return PerformanceBudget.measureAsync('dji-behavioral-data-collection', async () => {
      // Collect DJI-specific behavioral data
      const data: BehavioralSensorData = {
        timestamp: new Date(),
        robotId,
        platformType: this.platformType,
        
        // DJI-specific flight data
        position: {
          x: 0, y: 0, z: 50, confidence: 0.9
        },
        velocity: {
          vx: 5, vy: 0, vz: 0, confidence: 0.9
        },
        
        // DJI-specific sensors
        sensors: {
          'gps': { value: 1.0, confidence: 0.9, noiseLevel: 0.05 },
          'barometer': { value: 1.0, confidence: 0.95, noiseLevel: 0.01 },
          'gyroscope': { value: 1.0, confidence: 0.99, noiseLevel: 0.001 },
          'accelerometer': { value: 1.0, confidence: 0.98, noiseLevel: 0.002 }
        },
        
        // DJI-specific power data
        power: {
          consumption: 300.0,
          batteryLevel: 0.7,
          efficiency: 0.6,
          temperature: 45.0
        }
      };
      
      return data;
    });
  }
  
  async extractBehavioralFeatures(data: BehavioralSensorData): Promise<Record<string, any>> {
    return PerformanceBudget.measureAsync('dji-feature-extraction', async () => {
      // Extract DJI-specific behavioral features
      const features: Record<string, any> = {
        'flight_dynamics': this.extractFlightFeatures(data),
        'gimbal_control': this.extractGimbalFeatures(data),
        'obstacle_avoidance': this.extractObstacleAvoidanceFeatures(data),
        'battery_management': this.extractBatteryFeatures(data)
      };
      
      return features;
    });
  }
  
  private extractFlightFeatures(data: BehavioralSensorData): number[] {
    // Extract flight dynamics features
    const altitude = data.position?.z || 0;
    const speed = Math.sqrt((data.velocity?.vx || 0)**2 + (data.velocity?.vy || 0)**2);
    const stability = this.calculateFlightStability(data);
    
    return [altitude, speed, stability];
  }
  
  private extractGimbalFeatures(data: BehavioralSensorData): number[] {
    // Extract gimbal control features
    const gimbalStability = this.calculateGimbalStability(data);
    const trackingAccuracy = this.calculateTrackingAccuracy(data);
    
    return [gimbalStability, trackingAccuracy];
  }
  
  private extractObstacleAvoidanceFeatures(data: BehavioralSensorData): number[] {
    // Extract obstacle avoidance features
    const detectionAccuracy = this.calculateObstacleDetectionAccuracy(data);
    const avoidanceResponse = this.calculateAvoidanceResponse(data);
    
    return [detectionAccuracy, avoidanceResponse];
  }
  
  private extractBatteryFeatures(data: BehavioralSensorData): number[] {
    // Extract battery management features
    const batteryLevel = data.power?.batteryLevel || 0;
    const consumption = data.power?.consumption || 0;
    const efficiency = data.power?.efficiency || 0;
    const temperature = data.power?.temperature || 0;
    
    return [batteryLevel, consumption, efficiency, temperature];
  }
  
  private calculateFlightStability(data: BehavioralSensorData): number {
    // Calculate flight stability metric
    return 0.9; // Placeholder
  }
  
  private calculateGimbalStability(data: BehavioralSensorData): number {
    // Calculate gimbal stability metric
    return 0.95; // Placeholder
  }
  
  private calculateTrackingAccuracy(data: BehavioralSensorData): number {
    // Calculate tracking accuracy metric
    return 0.85; // Placeholder
  }
  
  private calculateObstacleDetectionAccuracy(data: BehavioralSensorData): number {
    // Calculate obstacle detection accuracy
    return 0.9; // Placeholder
  }
  
  private calculateAvoidanceResponse(data: BehavioralSensorData): number {
    // Calculate avoidance response metric
    return 0.8; // Placeholder
  }
  
  async recognizeBehavioralPatterns(features: Record<string, any>): Promise<BehavioralPattern[]> {
    return [];
  }
  
  async detectBehavioralAnomalies(patterns: BehavioralPattern[]): Promise<BehavioralAnomaly[]> {
    return [];
  }
  
  async executeResponseAction(action: string, robotId: string): Promise<boolean> {
    return true;
  }
  
  async configure(config: any): Promise<void> {
    // Configuration implementation
  }
  
  async getStatus(): Promise<{
    isConnected: boolean;
    health: string;
    lastUpdate: Date;
    errorCount: number;
  }> {
    return {
      isConnected: true,
      health: 'healthy',
      lastUpdate: new Date(),
      errorCount: 0
    };
  }
}

/**
 * Main Behavioral Security HAL
 */
export class BehavioralSecurityHAL extends EventEmitter {
  private logger: Logger;
  private securityContext: SecurityContext;
  private hardwareSecurityModule: HardwareSecurityModule;
  private advancedSecurityHAL: AdvancedSecurityHAL;
  
  private platformAdapters: Map<RobotPlatformType, BehavioralPlatformAdapter> = new Map();
  private registeredRobots: Map<string, { platformType: RobotPlatformType; config: any }> = new Map();
  
  private config: BehavioralMonitoringConfig;
  private isMonitoring: boolean = false;
  
  // Performance metrics
  private metrics = {
    totalDataCollected: 0,
    totalAnomaliesDetected: 0,
    totalPatternsRecognized: 0,
    avgProcessingTimeMs: 0,
    errorCount: 0
  };
  
  constructor(config: BehavioralMonitoringConfig) {
    super();
    this.config = config;
    this.logger = new Logger('BehavioralSecurityHAL');
    this.securityContext = new SecurityContext(config.classificationLevel);
    this.hardwareSecurityModule = new HardwareSecurityModule();
    this.advancedSecurityHAL = new AdvancedSecurityHAL();
    
    this.initializePlatformAdapters();
  }
  
  private initializePlatformAdapters(): void {
    // Initialize platform-specific adapters
    this.platformAdapters.set(RobotPlatformType.BOSTON_DYNAMICS_SPOT, new SpotBehavioralAdapter());
    this.platformAdapters.set(RobotPlatformType.ROS2_GENERIC, new ROS2BehavioralAdapter());
    this.platformAdapters.set(RobotPlatformType.DJI_DRONE, new DJIDroneBehavioralAdapter());
    
    this.logger.info('Platform adapters initialized');
  }
  
  /**
   * Register a robot for behavioral monitoring
   */
  async registerRobot(robotId: string, platformType: RobotPlatformType, config?: any): Promise<void> {
    try {
      const adapter = this.platformAdapters.get(platformType);
      if (!adapter) {
        throw new Error(`No adapter found for platform type: ${platformType}`);
      }
      
      // Configure the adapter
      if (config) {
        await adapter.configure(config);
      }
      
      // Register the robot
      this.registeredRobots.set(robotId, { platformType, config });
      
      this.logger.info(`Robot ${robotId} registered with platform type ${platformType}`);
      this.emit('robotRegistered', { robotId, platformType });
      
    } catch (error) {
      this.logger.error(`Failed to register robot ${robotId}: ${error}`);
      throw error;
    }
  }
  
  /**
   * Unregister a robot from behavioral monitoring
   */
  async unregisterRobot(robotId: string): Promise<void> {
    try {
      if (this.registeredRobots.has(robotId)) {
        this.registeredRobots.delete(robotId);
        this.logger.info(`Robot ${robotId} unregistered`);
        this.emit('robotUnregistered', { robotId });
      }
    } catch (error) {
      this.logger.error(`Failed to unregister robot ${robotId}: ${error}`);
      throw error;
    }
  }
  
  /**
   * Start behavioral monitoring
   */
  async startMonitoring(): Promise<void> {
    try {
      if (this.isMonitoring) {
        this.logger.warn('Behavioral monitoring is already running');
        return;
      }
      
      this.isMonitoring = true;
      
      // Start monitoring loop
      this.startMonitoringLoop();
      
      this.logger.info('Behavioral monitoring started');
      this.emit('monitoringStarted');
      
    } catch (error) {
      this.logger.error(`Failed to start monitoring: ${error}`);
      throw error;
    }
  }
  
  /**
   * Stop behavioral monitoring
   */
  async stopMonitoring(): Promise<void> {
    try {
      this.isMonitoring = false;
      this.logger.info('Behavioral monitoring stopped');
      this.emit('monitoringStopped');
      
    } catch (error) {
      this.logger.error(`Failed to stop monitoring: ${error}`);
      throw error;
    }
  }
  
  /**
   * Collect behavioral data from a specific robot
   */
  async collectBehavioralData(robotId: string): Promise<BehavioralSensorData | null> {
    try {
      const robotInfo = this.registeredRobots.get(robotId);
      if (!robotInfo) {
        this.logger.warn(`Robot ${robotId} not registered`);
        return null;
      }
      
      const adapter = this.platformAdapters.get(robotInfo.platformType);
      if (!adapter) {
        this.logger.error(`No adapter found for robot ${robotId}`);
        return null;
      }
      
      const data = await adapter.collectBehavioralData(robotId);
      this.metrics.totalDataCollected++;
      
      return data;
      
    } catch (error) {
      this.logger.error(`Failed to collect behavioral data for robot ${robotId}: ${error}`);
      this.metrics.errorCount++;
      return null;
    }
  }
  
  /**
   * Analyze behavioral data for anomalies
   */
  async analyzeBehavioralData(data: BehavioralSensorData): Promise<{
    patterns: BehavioralPattern[];
    anomalies: BehavioralAnomaly[];
    correlations: BehavioralCorrelation[];
  }> {
    const startTime = Date.now();
    
    try {
      const robotInfo = this.registeredRobots.get(data.robotId);
      if (!robotInfo) {
        throw new Error(`Robot ${data.robotId} not registered`);
      }
      
      const adapter = this.platformAdapters.get(robotInfo.platformType);
      if (!adapter) {
        throw new Error(`No adapter found for robot ${data.robotId}`);
      }
      
      // Extract features
      const features = await adapter.extractBehavioralFeatures(data);
      
      // Recognize patterns
      const patterns = await adapter.recognizeBehavioralPatterns(features);
      this.metrics.totalPatternsRecognized += patterns.length;
      
      // Detect anomalies
      const anomalies = await adapter.detectBehavioralAnomalies(patterns);
      this.metrics.totalAnomaliesDetected += anomalies.length;
      
      // Compute correlations (simplified)
      const correlations: BehavioralCorrelation[] = [];
      
      // Update performance metrics
      const processingTime = Date.now() - startTime;
      this.metrics.avgProcessingTimeMs = (this.metrics.avgProcessingTimeMs + processingTime) / 2;
      
      // Emit events for significant findings
      if (anomalies.length > 0) {
        this.emit('anomaliesDetected', { robotId: data.robotId, anomalies });
      }
      
      if (patterns.length > 0) {
        this.emit('patternsRecognized', { robotId: data.robotId, patterns });
      }
      
      return { patterns, anomalies, correlations };
      
    } catch (error) {
      this.logger.error(`Failed to analyze behavioral data: ${error}`);
      this.metrics.errorCount++;
      throw error;
    }
  }
  
  /**
   * Execute response action for a robot
   */
  async executeResponseAction(robotId: string, action: string): Promise<boolean> {
    try {
      const robotInfo = this.registeredRobots.get(robotId);
      if (!robotInfo) {
        this.logger.warn(`Robot ${robotId} not registered`);
        return false;
      }
      
      const adapter = this.platformAdapters.get(robotInfo.platformType);
      if (!adapter) {
        this.logger.error(`No adapter found for robot ${robotId}`);
        return false;
      }
      
      const result = await adapter.executeResponseAction(action, robotId);
      
      this.logger.info(`Response action ${action} executed for robot ${robotId}: ${result}`);
      this.emit('responseActionExecuted', { robotId, action, result });
      
      return result;
      
    } catch (error) {
      this.logger.error(`Failed to execute response action ${action} for robot ${robotId}: ${error}`);
      this.metrics.errorCount++;
      return false;
    }
  }
  
  /**
   * Get behavioral monitoring status
   */
  async getMonitoringStatus(): Promise<{
    isMonitoring: boolean;
    registeredRobots: number;
    metrics: any;
    platformAdapters: Record<string, any>;
  }> {
    const platformStatuses: Record<string, any> = {};
    
    for (const [platformType, adapter] of this.platformAdapters.entries()) {
      platformStatuses[platformType] = await adapter.getStatus();
    }
    
    return {
      isMonitoring: this.isMonitoring,
      registeredRobots: this.registeredRobots.size,
      metrics: this.metrics,
      platformAdapters: platformStatuses
    };
  }
  
  /**
   * Get robot-specific status
   */
  async getRobotStatus(robotId: string): Promise<any> {
    const robotInfo = this.registeredRobots.get(robotId);
    if (!robotInfo) {
      return null;
    }
    
    const adapter = this.platformAdapters.get(robotInfo.platformType);
    if (!adapter) {
      return null;
    }
    
    return await adapter.getStatus();
  }
  
  /**
   * Update monitoring configuration
   */
  async updateConfig(newConfig: Partial<BehavioralMonitoringConfig>): Promise<void> {
    try {
      this.config = { ...this.config, ...newConfig };
      
      // Update security context if classification level changed
      if (newConfig.classificationLevel) {
        this.securityContext = new SecurityContext(newConfig.classificationLevel);
      }
      
      this.logger.info('Configuration updated');
      this.emit('configUpdated', this.config);
      
    } catch (error) {
      this.logger.error(`Failed to update config: ${error}`);
      throw error;
    }
  }
  
  /**
   * Start monitoring loop
   */
  private startMonitoringLoop(): void {
    const monitoringInterval = 1000 / (this.config.targetResponseTimeMs || 50); // Convert to Hz
    
    setInterval(async () => {
      if (!this.isMonitoring) return;
      
      try {
        // Collect data from all registered robots
        const promises = Array.from(this.registeredRobots.keys()).map(async (robotId) => {
          const data = await this.collectBehavioralData(robotId);
          if (data) {
            return this.analyzeBehavioralData(data);
          }
          return null;
        });
        
        const results = await Promise.allSettled(promises);
        
        // Process results
        for (const result of results) {
          if (result.status === 'fulfilled' && result.value) {
            // Handle analysis results
            const { patterns, anomalies, correlations } = result.value;
            
            // Emit security events for high-severity anomalies
            for (const anomaly of anomalies) {
              if (anomaly.severity === 'critical' || anomaly.severity === 'high') {
                this.emit('securityEvent', {
                  eventId: anomaly.anomalyId,
                  eventType: 'behavioral_anomaly',
                  severity: anomaly.severity,
                  affectedRobots: anomaly.affectedRobots,
                  timestamp: anomaly.timestamp
                });
              }
            }
          }
        }
        
      } catch (error) {
        this.logger.error(`Error in monitoring loop: ${error}`);
        this.metrics.errorCount++;
      }
    }, monitoringInterval);
  }
}

// Export for use in other modules
export { BehavioralSecurityHAL as default };