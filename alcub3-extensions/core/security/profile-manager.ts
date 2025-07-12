/**
 * ALCUB3 Security Profile Manager
 * 
 * Core utilities for managing security profiles across the platform
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as yaml from 'js-yaml';

export enum SecurityProfileName {
  ENTERPRISE = 'ENTERPRISE',
  FEDERAL = 'FEDERAL', 
  CLASSIFIED = 'CLASSIFIED',
  CUSTOM = 'CUSTOM'
}

export interface SecurityProfileConfig {
  profile: {
    name: string;
    description: string;
    version: string;
    base_profile?: string;
  };
  classification: {
    enabled: boolean;
    max_level: string;
    levels: string[];
    validation: {
      mode: 'basic' | 'standard' | 'strict';
      cache_ttl: number;
      confidence_threshold: number;
    };
  };
  encryption: {
    algorithm: string;
    quantum_resistant?: {
      kem: string;
      signatures: string;
      hybrid_mode: boolean;
    };
    homomorphic?: {
      enabled: boolean;
      library: string;
    };
  };
  maestro: {
    enabled: boolean;
    layers: string[];
    features: Record<string, boolean>;
  };
  performance: {
    target_latency_ms: number;
    optimization: Record<string, boolean>;
  };
}

export class SecurityProfileManager {
  private static instance: SecurityProfileManager;
  private currentProfile: SecurityProfileConfig | null = null;
  private profilesDir: string;
  private configFile: string;

  private constructor() {
    this.profilesDir = path.join(__dirname, '../../../../01-security-platform/profiles');
    this.configFile = path.join(__dirname, '../../../../.alcub3/current-profile.json');
  }

  static getInstance(): SecurityProfileManager {
    if (!SecurityProfileManager.instance) {
      SecurityProfileManager.instance = new SecurityProfileManager();
    }
    return SecurityProfileManager.instance;
  }

  /**
   * Get the current active security profile
   */
  async getCurrentProfile(): Promise<SecurityProfileConfig> {
    if (this.currentProfile) {
      return this.currentProfile;
    }

    try {
      const data = await fs.readFile(this.configFile, 'utf-8');
      this.currentProfile = JSON.parse(data);
      return this.currentProfile!;
    } catch {
      // Default to ENTERPRISE if not configured
      return this.loadProfile(SecurityProfileName.ENTERPRISE);
    }
  }

  /**
   * Load a specific security profile
   */
  async loadProfile(name: SecurityProfileName | string): Promise<SecurityProfileConfig> {
    const filename = `${name.toLowerCase()}.yaml`;
    const filepath = path.join(this.profilesDir, filename);
    
    try {
      const content = await fs.readFile(filepath, 'utf-8');
      const profile = yaml.load(content) as SecurityProfileConfig;
      return profile;
    } catch (error) {
      throw new Error(`Failed to load profile ${name}: ${error.message}`);
    }
  }

  /**
   * Set the active security profile
   */
  async setProfile(profile: SecurityProfileConfig): Promise<void> {
    // Ensure directory exists
    const dir = path.dirname(this.configFile);
    await fs.mkdir(dir, { recursive: true });
    
    // Save profile
    await fs.writeFile(this.configFile, JSON.stringify(profile, null, 2));
    this.currentProfile = profile;
    
    // Clear any caches that depend on security profile
    this.clearSecurityCaches();
  }

  /**
   * Check if a feature is enabled in the current profile
   */
  async isFeatureEnabled(feature: string): Promise<boolean> {
    const profile = await this.getCurrentProfile();
    
    // Check common features
    switch (feature) {
      case 'quantum_crypto':
        return !!profile.encryption.quantum_resistant;
      case 'homomorphic':
        return !!profile.encryption.homomorphic?.enabled;
      case 'zero_trust':
        return profile.maestro.features.zero_trust || false;
      case 'air_gap':
        return profile.profile.name === 'CLASSIFIED';
      default:
        return profile.maestro.features[feature] || false;
    }
  }

  /**
   * Get performance budget for current profile
   */
  async getPerformanceBudget(operation: string): Promise<number> {
    const profile = await this.getCurrentProfile();
    const target = profile.performance.target_latency_ms;
    
    // Allocate budget based on operation type
    const budgets = {
      classification: target * 0.1,  // 10% of budget
      encryption: target * 0.2,      // 20% of budget
      authentication: target * 0.3,  // 30% of budget
      validation: target * 0.2,      // 20% of budget
      other: target * 0.2           // 20% of budget
    };
    
    return budgets[operation] || budgets.other;
  }

  /**
   * Get maximum classification level for current profile
   */
  async getMaxClassification(): Promise<string> {
    const profile = await this.getCurrentProfile();
    return profile.classification.max_level;
  }

  /**
   * Check if current profile supports a classification level
   */
  async supportsClassification(level: string): Promise<boolean> {
    const profile = await this.getCurrentProfile();
    const levels = profile.classification.levels;
    const levelIndex = levels.indexOf(level);
    const maxIndex = levels.indexOf(profile.classification.max_level);
    
    return levelIndex >= 0 && levelIndex <= maxIndex;
  }

  /**
   * Get MAESTRO layers enabled for current profile
   */
  async getEnabledMaestroLayers(): Promise<string[]> {
    const profile = await this.getCurrentProfile();
    return profile.maestro.layers;
  }

  /**
   * Validate profile transition
   */
  async canTransitionTo(targetProfile: SecurityProfileName): Promise<{ valid: boolean; warnings: string[] }> {
    const current = await this.getCurrentProfile();
    const target = await this.loadProfile(targetProfile);
    const warnings: string[] = [];
    
    // Check for downgrades
    if (current.classification.max_level === 'TOP_SECRET' && 
        target.classification.max_level === 'PROPRIETARY') {
      warnings.push('Downgrading from TOP_SECRET to PROPRIETARY requires data sanitization');
    }
    
    // Check for feature removal
    if (current.encryption.homomorphic?.enabled && !target.encryption.homomorphic?.enabled) {
      warnings.push('Homomorphic encryption will be disabled');
    }
    
    // Check performance impact
    if (target.performance.target_latency_ms > current.performance.target_latency_ms * 5) {
      warnings.push(`Performance may degrade by ${target.performance.target_latency_ms / current.performance.target_latency_ms}x`);
    }
    
    return { valid: true, warnings };
  }

  /**
   * Get security profile recommendations based on usage
   */
  async getRecommendation(requirements: {
    maxClassification: string;
    needsCompliance: boolean;
    performanceTarget: number;
    needsAirGap: boolean;
  }): Promise<SecurityProfileName> {
    if (requirements.needsAirGap || requirements.maxClassification.includes('SECRET')) {
      return SecurityProfileName.CLASSIFIED;
    }
    
    if (requirements.needsCompliance || requirements.maxClassification === 'CUI') {
      return SecurityProfileName.FEDERAL;
    }
    
    if (requirements.performanceTarget < 50) {
      return SecurityProfileName.ENTERPRISE;
    }
    
    return SecurityProfileName.FEDERAL; // Safe default
  }

  /**
   * Clear security-related caches when profile changes
   */
  private clearSecurityCaches(): void {
    // This would clear actual caches in production
    // For now, it's a placeholder for cache invalidation logic
    console.log('Security caches cleared for profile change');
  }

  /**
   * Export current profile for backup/sharing
   */
  async exportProfile(outputPath: string): Promise<void> {
    const profile = await this.getCurrentProfile();
    const yamlContent = yaml.dump(profile);
    await fs.writeFile(outputPath, yamlContent, 'utf-8');
  }

  /**
   * Get profile summary for display
   */
  async getProfileSummary(): Promise<{
    name: string;
    description: string;
    classification: string;
    performance: string;
    features: string[];
  }> {
    const profile = await this.getCurrentProfile();
    const features: string[] = [];
    
    if (profile.encryption.quantum_resistant) features.push('Quantum-Resistant Crypto');
    if (profile.encryption.homomorphic?.enabled) features.push('Homomorphic Encryption');
    if (profile.maestro.features.zero_trust) features.push('Zero-Trust Architecture');
    if (profile.maestro.features.byzantine_consensus) features.push('Byzantine Fault Tolerance');
    
    return {
      name: profile.profile.name,
      description: profile.profile.description,
      classification: profile.classification.max_level,
      performance: `<${profile.performance.target_latency_ms}ms`,
      features
    };
  }
}

// Export singleton instance
export const profileManager = SecurityProfileManager.getInstance();