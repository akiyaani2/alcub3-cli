/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// packages/core/src/api/middleware.ts

import { Request, Response, NextFunction } from 'express';
import { spawn } from 'child_process';
import path from 'path';
import {
  ClassificationLevel,
  isClassificationAllowed,
} from './classification.js';
import { authenticationMiddleware } from './auth.js';

// Minimum classification requirements by route prefix
const CLASSIFICATION_RULES: Record<string, ClassificationLevel> = {
  '/api/v1/maestro/metrics': ClassificationLevel.SECRET,
  '/api/v1/maestro/status': ClassificationLevel.UNCLASSIFIED,
};

export const securityMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    // 1. Enhanced Authentication using MAESTRO crypto
    await authenticationMiddleware(req, res, async () => {
      const { body, headers } = req;

      // Get classification from authenticated API key or headers
      const apiKeyData = (req as any).apiKeyData;
      let userClassification = ClassificationLevel.UNCLASSIFIED;

      if (apiKeyData) {
        userClassification = apiKeyData.classification;
      } else {
        // Fallback to header-based classification
        const classificationHeader = String(
          headers['x-classification-level'] || 'UNCLASSIFIED',
        ).toUpperCase();
        userClassification = classificationHeader as ClassificationLevel;
      }

      // 2. Classification-aware authorization
      for (const [routePrefix, minLevel] of Object.entries(
        CLASSIFICATION_RULES,
      )) {
        if (req.path.startsWith(routePrefix)) {
          if (!isClassificationAllowed(userClassification, minLevel)) {
            res.status(403).json({
              error: `Forbidden: Minimum classification ${minLevel} required`,
              userClassification: userClassification,
            });
            return;
          }
          break;
        }
      }

      // 3. MAESTRO L1 Security Validation (only for requests with body.text)
      if (body && body.text) {
        const pythonPath = path.join(__dirname, 'security_bridge.py');
        const pythonProcess = spawn('python3', [pythonPath]);

        let result = '';
        pythonProcess.stdout.on('data', (data) => {
          result += data.toString();
        });

        pythonProcess.stdout.on('end', () => {
          try {
            const validationResult = JSON.parse(result);
            if (validationResult.is_valid) {
              next();
            } else {
              res.status(403).json({
                error: 'Forbidden: Security validation failed',
                details: validationResult,
              });
            }
          } catch (_error) {
            res.status(500).json({
              error:
                'Internal Server Error: Failed to parse security validation result',
            });
          }
        });

        pythonProcess.stderr.on('data', (data) => {
          console.error(`stderr: ${data}`);
          res.status(500).json({
            error:
              'Internal Server Error: An error occurred during security validation',
          });
        });

        // Pass the body and classification to the python script
        const requestData = { ...body, classification: userClassification };
        pythonProcess.stdin.write(JSON.stringify(requestData));
        pythonProcess.stdin.end();
      } else {
        // No validation needed for requests without body.text
        next();
      }
    });
  } catch (error) {
    res.status(500).json({
      error: `Security middleware error: ${error}`,
    });
  }
};

// Legacy middleware for backward compatibility
export const simpleSecurityMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const { headers } = req;
  const apiKey = headers['x-api-key'];

  if (!apiKey) {
    res.status(401).json({ error: 'Unauthorized: Missing API Key' });
    return;
  }

  if (apiKey !== 'dummy-api-key') {
    res.status(401).json({ error: 'Unauthorized: Invalid API Key' });
    return;
  }

  next();
};
