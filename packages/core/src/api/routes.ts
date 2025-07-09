/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// packages/core/src/api/routes.ts

import express, { Request, Response } from 'express';
import { maestroClient } from './enhanced_middleware.js';
import { authManager } from './auth.js';
import { cisaAPI } from './cisa_api.js';
import { jitAPI } from './jit_api.js';

const router = express.Router();

const maestroRouter = express.Router();

// Public status endpoint (UNCLASSIFIED)
maestroRouter.get('/status', async (_req: Request, res: Response) => {
  try {
    const serviceStatus = await maestroClient.getServiceStatus();
    res.json({ 
      api: 'ok', 
      maestroService: serviceStatus,
      timestamp: Date.now() 
    });
  } catch (error) {
    res.json({ 
      api: 'ok', 
      maestroService: 'unavailable',
      timestamp: Date.now() 
    });
  }
});

// Health check endpoint
maestroRouter.get('/health', (_req: Request, res: Response) => {
  res.json({ 
    status: 'healthy',
    version: '1.0.0',
    timestamp: Date.now() 
  });
});

// Protected metrics endpoint (SECRET+)
maestroRouter.get('/metrics', async (_req: Request, res: Response) => {
  try {
    const serviceStatus = await maestroClient.getServiceStatus();
    const apiKeys = authManager.listApiKeys();
    
    res.json({ 
      system: {
        uptime: process.uptime(), 
        memoryUsage: process.memoryUsage(),
        nodeVersion: process.version
      },
      maestro: serviceStatus,
      security: {
        activeApiKeys: apiKeys.length,
        authenticationEnabled: true
      },
      timestamp: Date.now()
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to gather metrics',
      timestamp: Date.now()
    });
  }
});

// Security validation endpoint
maestroRouter.post('/validate', async (req: Request, res: Response) => {
  try {
    // Security validation is handled by middleware
    // If we reach here, validation passed
    const validationResult = (req as any).securityValidation;
    
    res.json({
      message: 'Security validation passed',
      details: validationResult,
      timestamp: Date.now()
    });
  } catch (error) {
    res.status(500).json({
      error: 'Validation processing error',
      timestamp: Date.now()
    });
  }
});

// Admin endpoint for API key management (SECRET+)
maestroRouter.get('/admin/keys', (_req: Request, res: Response) => {
  try {
    const apiKeys = authManager.listApiKeys();
    res.json({
      keys: apiKeys,
      timestamp: Date.now()
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to list API keys',
      timestamp: Date.now()
    });
  }
});

// Admin endpoint to generate new API key (SECRET+)
maestroRouter.post('/admin/keys', async (req: Request, res: Response) => {
  try {
    const { classification = 'UNCLASSIFIED', permissions = ['read'] } = req.body;
    
    const newApiKey = await authManager.generateApiKey(classification, permissions);
    
    res.json({
      message: 'API key generated successfully',
      apiKey: newApiKey,
      classification,
      permissions,
      timestamp: Date.now()
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to generate API key',
      timestamp: Date.now()
    });
  }
});

// Mount under /v1/maestro
router.use('/v1/maestro', maestroRouter);

// Mount CISA Remediation Engine API
router.use('/v1/cisa', cisaAPI.createRouter());

// Mount JIT Privilege API
router.use('/v1/jit', jitAPI.createRouter());

export { router as apiRoutes };
