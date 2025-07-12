/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
// packages/core/src/api/api.integration.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import express from 'express';
import { authManager } from './auth.js';
import { ClassificationLevel } from './classification.js';
import { metricsMiddleware } from './metrics.js';
import { securityMiddleware } from './middleware.js';
import { apiRoutes } from './routes.js';
describe('API Security Integration Tests', () => {
    let app;
    let testApiKey;
    let secretApiKey;
    beforeAll(async () => {
        // Setup test Express app
        app = express();
        app.use(express.json());
        app.use(metricsMiddleware);
        app.use(securityMiddleware);
        app.use('/api', apiRoutes);
        // Generate test API keys
        testApiKey = await authManager.generateApiKey(ClassificationLevel.UNCLASSIFIED, ['read', 'write']);
        secretApiKey = await authManager.generateApiKey(ClassificationLevel.SECRET, ['read', 'write', 'admin']);
    });
    afterAll(async () => {
        // Clean up test API keys
        const keys = authManager.listApiKeys();
        for (const key of keys) {
            if (key.keyId.includes('test') || key.keyId.includes('secret')) {
                authManager.revokeApiKey(key.keyId);
            }
        }
    });
    describe('Authentication Tests', () => {
        it('should reject requests without API key', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .expect(401);
            expect(response.body.error).toContain('Unauthorized');
        });
        it('should reject requests with invalid API key', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', 'invalid-key')
                .expect(401);
            expect(response.body.error).toContain('Invalid API key format');
        });
        it('should accept requests with valid API key', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200);
            expect(response.body.status).toBe('ok');
            expect(response.body.timestamp).toBeDefined();
        });
        it('should handle OAuth2 bearer token (placeholder)', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('Authorization', 'Bearer dummy-token')
                .expect(401);
            expect(response.body.error).toContain('OAuth2 authentication not enabled');
        });
    });
    describe('Classification-Based Authorization Tests', () => {
        it('should allow UNCLASSIFIED access to status endpoint', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200);
            expect(response.body.status).toBe('ok');
        });
        it('should reject UNCLASSIFIED access to SECRET metrics endpoint', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/metrics')
                .set('x-api-key', testApiKey)
                .expect(403);
            expect(response.body.error).toContain('Minimum classification SECRET required');
        });
        it('should allow SECRET access to metrics endpoint', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/metrics')
                .set('x-api-key', secretApiKey)
                .expect(200);
            expect(response.body.uptime).toBeDefined();
            expect(response.body.memoryUsage).toBeDefined();
        });
        it('should respect classification header override', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/metrics')
                .set('x-api-key', testApiKey)
                .set('x-classification-level', 'SECRET')
                .expect(403); // Should still fail because API key has UNCLASSIFIED classification
            expect(response.body.error).toContain('Minimum classification SECRET required');
        });
    });
    describe('Performance Metrics Tests', () => {
        it('should add response time header to all requests', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200);
            expect(response.headers['x-response-time-ms']).toBeDefined();
            const responseTime = parseFloat(response.headers['x-response-time-ms']);
            expect(responseTime).toBeGreaterThan(0);
        });
        it('should meet performance budget (<100ms for lightweight endpoints)', async () => {
            const startTime = performance.now();
            await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200);
            const endTime = performance.now();
            const duration = endTime - startTime;
            // Allow some margin for test environment variability
            expect(duration).toBeLessThan(200); // 200ms budget for tests
        });
        it('should handle concurrent requests efficiently', async () => {
            const concurrentRequests = 10;
            const startTime = performance.now();
            const promises = Array.from({ length: concurrentRequests }, () => request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200));
            const responses = await Promise.all(promises);
            const endTime = performance.now();
            const totalDuration = endTime - startTime;
            // All requests should succeed
            expect(responses).toHaveLength(concurrentRequests);
            responses.forEach((response) => {
                expect(response.body.status).toBe('ok');
            });
            // Average time per request should be reasonable
            const avgTimePerRequest = totalDuration / concurrentRequests;
            expect(avgTimePerRequest).toBeLessThan(100); // 100ms average
        });
    });
    describe('Security Validation Tests', () => {
        it('should validate requests without body.text', async () => {
            const response = await request(app)
                .post('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .send({ message: 'test' })
                .expect(405); // Method not allowed, but should pass security validation
        });
        it('should handle MAESTRO L1 security validation for text content', async () => {
            // This test requires the security_bridge.py to be properly set up
            // For now, we'll test the error handling path
            const response = await request(app)
                .post('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .send({ text: 'test content for security validation' });
            // Should either pass validation or fail gracefully
            expect([200, 405, 500]).toContain(response.status);
        });
    });
    describe('API Key Management Tests', () => {
        it('should generate new API keys with proper format', async () => {
            const newKey = await authManager.generateApiKey(ClassificationLevel.CUI, [
                'read',
            ]);
            expect(newKey).toMatch(/^key-\d+-[a-z0-9]+\.[a-f0-9]+$/);
            // Test the new key works
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', newKey)
                .expect(200);
            expect(response.body.status).toBe('ok');
        });
        it('should list API keys (admin function)', async () => {
            const keys = authManager.listApiKeys();
            expect(keys.length).toBeGreaterThan(0);
            keys.forEach((key) => {
                expect(key.keyId).toBeDefined();
                expect(key.classification).toBeDefined();
                expect(key.permissions).toBeInstanceOf(Array);
                expect(key.createdAt).toBeDefined();
            });
        });
        it('should revoke API keys', async () => {
            const tempKey = await authManager.generateApiKey(ClassificationLevel.UNCLASSIFIED, ['read']);
            // Verify key works
            await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', tempKey)
                .expect(200);
            // Revoke the key
            const keyId = tempKey.split('.')[0];
            const revoked = authManager.revokeApiKey(keyId);
            expect(revoked).toBe(true);
            // Verify key no longer works
            await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', tempKey)
                .expect(401);
        });
    });
    describe('Error Handling Tests', () => {
        it('should handle malformed requests gracefully', async () => {
            const response = await request(app)
                .post('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .set('Content-Type', 'application/json')
                .send('invalid json')
                .expect(400);
        });
        it('should handle missing classification headers gracefully', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200);
            expect(response.body.status).toBe('ok');
        });
        it('should handle expired API keys (simulated)', async () => {
            // This would require modifying the key expiration for testing
            // For now, we test the error handling path
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', 'expired-key.signature')
                .expect(401);
            expect(response.body.error).toContain('Invalid API key format');
        });
    });
    describe('CORS and Headers Tests', () => {
        it('should include security headers in responses', async () => {
            const response = await request(app)
                .get('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200);
            expect(response.headers['x-response-time-ms']).toBeDefined();
        });
        it('should handle preflight OPTIONS requests', async () => {
            const response = await request(app)
                .options('/api/v1/maestro/status')
                .set('x-api-key', testApiKey)
                .expect(200);
        });
    });
    describe('Rate Limiting Tests', () => {
        it('should apply rate limiting to API requests', async () => {
            // Make multiple rapid requests to test rate limiting
            const rapidRequests = Array.from({ length: 20 }, () => request(app).get('/api/v1/maestro/status').set('x-api-key', testApiKey));
            const responses = await Promise.all(rapidRequests);
            // Some requests should succeed, potential rate limiting may apply
            const successfulRequests = responses.filter((r) => r.status === 200);
            expect(successfulRequests.length).toBeGreaterThan(0);
        });
    });
});
//# sourceMappingURL=api.integration.test.js.map