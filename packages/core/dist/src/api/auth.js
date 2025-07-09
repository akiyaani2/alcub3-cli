/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import path from 'path';
import crypto from 'crypto';
import { ClassificationLevel } from './classification.js';
export class AuthenticationManager {
    validApiKeys = new Map();
    oauth2Config;
    maestroCryptoPath;
    constructor() {
        this.maestroCryptoPath = path.join(__dirname, '../../../../security-framework/src/shared/crypto_utils.py');
        this.oauth2Config = {
            clientId: process.env.OAUTH2_CLIENT_ID || '',
            clientSecret: process.env.OAUTH2_CLIENT_SECRET || '',
            redirectUri: process.env.OAUTH2_REDIRECT_URI || '',
            scopes: ['read', 'write'],
            tokenEndpoint: process.env.OAUTH2_TOKEN_ENDPOINT || '',
            enabled: false, // Placeholder - not implemented yet
        };
        this.initializeDefaultKeys();
    }
    initializeDefaultKeys() {
        // Generate secure default API key using MAESTRO crypto
        const defaultKey = {
            keyId: 'default-key-001',
            hashedKey: this.generateSecureHash('alcub3-default-api-key'),
            classification: ClassificationLevel.UNCLASSIFIED,
            permissions: ['read', 'write', 'admin'],
            createdAt: Date.now(),
            expiresAt: Date.now() + 365 * 24 * 60 * 60 * 1000, // 1 year
        };
        this.validApiKeys.set(defaultKey.keyId, defaultKey);
    }
    generateSecureHash(input) {
        // Use HMAC-SHA256 for secure key hashing
        const secret = process.env.HMAC_SECRET || 'default-secret-change-in-production';
        return crypto.createHmac('sha256', secret).update(input).digest('hex');
    }
    /**
     * Validate API key using MAESTRO crypto utilities
     */
    async validateApiKey(apiKey) {
        try {
            // Extract key ID and signature from API key format: keyId.signature
            const [keyId, providedSignature] = apiKey.split('.');
            if (!keyId || !providedSignature) {
                return { valid: false, error: 'Invalid API key format' };
            }
            // Look up key data
            const keyData = this.validApiKeys.get(keyId);
            if (!keyData) {
                return { valid: false, error: 'API key not found' };
            }
            // Check expiration
            if (keyData.expiresAt && Date.now() > keyData.expiresAt) {
                return { valid: false, error: 'API key expired' };
            }
            // Validate signature using MAESTRO crypto
            const isValid = await this.validateSignatureWithMaestro(keyId, providedSignature, keyData.hashedKey);
            if (!isValid) {
                return { valid: false, error: 'Invalid API key signature' };
            }
            return { valid: true, keyData };
        }
        catch (error) {
            return { valid: false, error: `Authentication error: ${error}` };
        }
    }
    /**
     * Interface with MAESTRO crypto utilities for signature validation
     */
    async validateSignatureWithMaestro(keyId, signature, hashedKey) {
        try {
            // Use persistent MAESTRO service instead of spawning processes
            const axios = require('axios');
            const validationPayload = {
                operation: 'validate_api_key',
                key_id: keyId,
                signature: signature,
                hashed_key: hashedKey,
                timestamp: Date.now(),
            };
            // Try to use persistent MAESTRO service
            try {
                const response = await axios.post('http://127.0.0.1:8001/authenticate', validationPayload, {
                    timeout: 5000
                });
                return response.data.valid === true;
            }
            catch (serviceError) {
                // Fallback to local validation if service unavailable
                console.warn('MAESTRO service unavailable, using fallback validation');
                // Use HMAC validation as fallback (same as generateSignatureWithMaestro)
                const expectedSignature = crypto.createHmac('sha256', hashedKey).update(keyId).digest('hex');
                return signature === expectedSignature;
            }
        }
        catch (error) {
            console.error('Signature validation error:', error);
            return false;
        }
    }
    /**
     * OAuth2 authentication middleware (placeholder implementation)
     */
    async validateOAuth2Token(token) {
        // Placeholder for OAuth2 implementation
        if (!this.oauth2Config.enabled) {
            return { valid: false, error: 'OAuth2 authentication not enabled' };
        }
        // TODO: Implement OAuth2 token validation
        // - Validate JWT token signature
        // - Check token expiration
        // - Verify scopes and permissions
        // - Interface with OAuth2 provider
        return { valid: false, error: 'OAuth2 authentication not implemented yet' };
    }
    /**
     * Generate new API key with MAESTRO crypto
     */
    async generateApiKey(classification, permissions) {
        const keyId = `key-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
        const keySecret = crypto.randomBytes(32).toString('hex');
        const hashedKey = this.generateSecureHash(keySecret);
        const keyData = {
            keyId,
            hashedKey,
            classification,
            permissions,
            createdAt: Date.now(),
            expiresAt: Date.now() + 365 * 24 * 60 * 60 * 1000, // 1 year
        };
        this.validApiKeys.set(keyId, keyData);
        // Generate signature using MAESTRO crypto
        const signature = await this.generateSignatureWithMaestro(keyId, hashedKey);
        return `${keyId}.${signature}`;
    }
    /**
     * Generate secure signature using MAESTRO crypto utilities
     */
    async generateSignatureWithMaestro(keyId, hashedKey) {
        // For now, use HMAC as placeholder until full MAESTRO integration
        return crypto.createHmac('sha256', hashedKey).update(keyId).digest('hex');
    }
    /**
     * Revoke API key
     */
    revokeApiKey(keyId) {
        return this.validApiKeys.delete(keyId);
    }
    /**
     * List all API keys (admin function)
     */
    listApiKeys() {
        return Array.from(this.validApiKeys.values()).map((key) => ({
            keyId: key.keyId,
            classification: key.classification,
            permissions: key.permissions,
            createdAt: key.createdAt,
        }));
    }
}
// Singleton instance
export const authManager = new AuthenticationManager();
/**
 * Enhanced authentication middleware
 */
export const authenticationMiddleware = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const authHeader = req.headers['authorization'];
        // Try API key authentication first
        if (apiKey) {
            const result = await authManager.validateApiKey(apiKey);
            if (!result.valid) {
                res.status(401).json({ error: `Unauthorized: ${result.error}` });
                return;
            }
            // Attach key data to request for downstream middleware
            req.apiKeyData = result.keyData;
            next();
            return;
        }
        // Try OAuth2 authentication (placeholder)
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const result = await authManager.validateOAuth2Token(token);
            if (!result.valid) {
                res.status(401).json({ error: `Unauthorized: ${result.error}` });
                return;
            }
            // Attach user info to request
            req.userInfo = result.userInfo;
            next();
            return;
        }
        // No valid authentication found
        res
            .status(401)
            .json({ error: 'Unauthorized: Missing or invalid authentication' });
    }
    catch (error) {
        res.status(500).json({ error: `Authentication error: ${error}` });
    }
};
//# sourceMappingURL=auth.js.map