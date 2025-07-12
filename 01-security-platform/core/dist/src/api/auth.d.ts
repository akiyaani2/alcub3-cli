/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { Request, Response, NextFunction } from 'express';
import { ClassificationLevel } from './classification.js';
interface APIKeyData {
    keyId: string;
    hashedKey: string;
    classification: ClassificationLevel;
    permissions: string[];
    createdAt: number;
    expiresAt?: number;
}
export declare class AuthenticationManager {
    private validApiKeys;
    private oauth2Config;
    private maestroCryptoPath;
    constructor();
    private initializeDefaultKeys;
    private generateSecureHash;
    /**
     * Validate API key using MAESTRO crypto utilities
     */
    validateApiKey(apiKey: string): Promise<{
        valid: boolean;
        keyData?: APIKeyData;
        error?: string;
    }>;
    /**
     * Interface with MAESTRO crypto utilities for signature validation
     */
    private validateSignatureWithMaestro;
    /**
     * OAuth2 authentication middleware (placeholder implementation)
     */
    validateOAuth2Token(token: string): Promise<{
        valid: boolean;
        userInfo?: any;
        error?: string;
    }>;
    /**
     * Generate new API key with MAESTRO crypto
     */
    generateApiKey(classification: ClassificationLevel, permissions: string[]): Promise<string>;
    /**
     * Generate secure signature using MAESTRO crypto utilities
     */
    private generateSignatureWithMaestro;
    /**
     * Revoke API key
     */
    revokeApiKey(keyId: string): boolean;
    /**
     * List all API keys (admin function)
     */
    listApiKeys(): Array<{
        keyId: string;
        classification: string;
        permissions: string[];
        createdAt: number;
    }>;
}
export declare const authManager: AuthenticationManager;
/**
 * Enhanced authentication middleware
 */
export declare const authenticationMiddleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export {};
