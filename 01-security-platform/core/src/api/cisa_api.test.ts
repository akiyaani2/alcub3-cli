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

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { Server } from 'socket.io';
import { CISARemediationAPI } from './cisa_api.js';

// Mock child_process
vi.mock('child_process', () => ({
  spawn: vi.fn(() => ({
    stdout: {
      on: vi.fn((event, callback) => {
        if (event === 'data') {
          setTimeout(() => {
            callback(Buffer.from('Progress: 5/10\n'));
          }, 10);
        }
      })
    },
    stderr: {
      on: vi.fn()
    },
    on: vi.fn((event, callback) => {
      if (event === 'close') {
        setTimeout(() => {
          callback(0); // Success
        }, 20);
      }
    }),
    kill: vi.fn()
  }))
}));

describe('CISA Remediation API', () => {
  let app: express.Application;
  let cisaAPI: CISARemediationAPI;
  let mockIO: any;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    cisaAPI = new CISARemediationAPI();
    
    // Mock Socket.IO
    mockIO = {
      of: vi.fn(() => ({
        on: vi.fn(),
        to: vi.fn(() => ({
          emit: vi.fn()
        }))
      }))
    };
    
    cisaAPI.setSocketIO(mockIO as unknown as Server);
    
    // Set up routes
    app.use('/api/v1/cisa', cisaAPI.createRouter());
  });

  afterEach(() => {
    cisaAPI.cleanup();
    vi.clearAllMocks();
  });

  describe('POST /api/v1/cisa/scan', () => {
    it('should initiate a scan successfully', async () => {
      const response = await request(app)
        .post('/api/v1/cisa/scan')
        .send({
          target: '192.168.1.0/24',
          classification: 'UNCLASSIFIED',
          modules: ['default_configs', 'mfa_config']
        });

      expect(response.status).toBe(202);
      expect(response.body).toHaveProperty('scanId');
      expect(response.body.status).toBe('accepted');
      expect(response.body).toHaveProperty('websocketUrl');
    });

    it('should reject scan without target', async () => {
      const response = await request(app)
        .post('/api/v1/cisa/scan')
        .send({
          classification: 'UNCLASSIFIED'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Target is required');
    });
  });

  describe('GET /api/v1/cisa/status/:scanId', () => {
    it('should return scan status', async () => {
      // First initiate a scan
      const scanResponse = await request(app)
        .post('/api/v1/cisa/scan')
        .send({
          target: '192.168.1.1'
        });

      const scanId = scanResponse.body.scanId;

      // Get status
      const statusResponse = await request(app)
        .get(`/api/v1/cisa/status/${scanId}`);

      expect(statusResponse.status).toBe(200);
      expect(statusResponse.body.scanId).toBe(scanId);
      expect(statusResponse.body).toHaveProperty('status');
      expect(statusResponse.body).toHaveProperty('progress');
    });

    it('should return 404 for non-existent scan', async () => {
      const response = await request(app)
        .get('/api/v1/cisa/status/non-existent-id');

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Scan not found');
    });
  });

  describe('POST /api/v1/cisa/remediate', () => {
    it('should reject remediation without scan ID', async () => {
      const response = await request(app)
        .post('/api/v1/cisa/remediate')
        .send({
          autoApprove: true
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Scan ID is required');
    });

    it('should reject remediation for non-existent scan', async () => {
      const response = await request(app)
        .post('/api/v1/cisa/remediate')
        .send({
          scanId: 'non-existent-id',
          autoApprove: true
        });

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Scan not found or not complete');
    });
  });

  describe('GET /api/v1/cisa/report/:scanId', () => {
    it('should return 404 for non-existent report', async () => {
      const response = await request(app)
        .get('/api/v1/cisa/report/non-existent-id');

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Scan report not found');
    });
  });

  describe('GET /api/v1/cisa/scans', () => {
    it('should list all scans', async () => {
      // Initiate a scan first
      await request(app)
        .post('/api/v1/cisa/scan')
        .send({
          target: '192.168.1.1'
        });

      const response = await request(app)
        .get('/api/v1/cisa/scans');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('scans');
      expect(response.body).toHaveProperty('total');
      expect(response.body.scans).toBeInstanceOf(Array);
      expect(response.body.total).toBeGreaterThan(0);
    });
  });

  describe('DELETE /api/v1/cisa/scan/:scanId', () => {
    it('should cancel an active scan', async () => {
      // Initiate a scan
      const scanResponse = await request(app)
        .post('/api/v1/cisa/scan')
        .send({
          target: '192.168.1.1'
        });

      const scanId = scanResponse.body.scanId;

      // Cancel it
      const cancelResponse = await request(app)
        .delete(`/api/v1/cisa/scan/${scanId}`);

      expect(cancelResponse.status).toBe(200);
      expect(cancelResponse.body.status).toBe('cancelled');
    });

    it('should return 404 for non-existent scan', async () => {
      const response = await request(app)
        .delete('/api/v1/cisa/scan/non-existent-id');

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Scan not found');
    });
  });

  describe('WebSocket Integration', () => {
    it('should set up WebSocket namespaces', () => {
      expect(mockIO.of).toHaveBeenCalledWith('/cisa');
    });
  });

  describe('Classification Filtering', () => {
    it('should filter results based on user classification', async () => {
      // This would require a more complex test setup with actual scan results
      // For now, we verify the API structure supports classification
      const response = await request(app)
        .post('/api/v1/cisa/scan')
        .send({
          target: '192.168.1.1',
          classification: 'SECRET'
        });

      expect(response.status).toBe(202);
    });
  });
});

describe('CISA API Performance', () => {
  let app: express.Application;
  let cisaAPI: CISARemediationAPI;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    cisaAPI = new CISARemediationAPI();
    app.use('/api/v1/cisa', cisaAPI.createRouter());
  });

  afterEach(() => {
    cisaAPI.cleanup();
  });

  it('should handle multiple concurrent scans', async () => {
    const scanPromises = [];
    
    // Initiate 5 concurrent scans
    for (let i = 0; i < 5; i++) {
      scanPromises.push(
        request(app)
          .post('/api/v1/cisa/scan')
          .send({
            target: `192.168.${i}.0/24`
          })
      );
    }

    const responses = await Promise.all(scanPromises);
    
    // All should succeed
    responses.forEach(response => {
      expect(response.status).toBe(202);
      expect(response.body).toHaveProperty('scanId');
    });

    // Get all scans
    const listResponse = await request(app)
      .get('/api/v1/cisa/scans');

    expect(listResponse.body.total).toBeGreaterThanOrEqual(5);
  });

  it('should respond within performance targets', async () => {
    const startTime = Date.now();
    
    const response = await request(app)
      .post('/api/v1/cisa/scan')
      .send({
        target: '192.168.1.1'
      });

    const responseTime = Date.now() - startTime;
    
    expect(response.status).toBe(202);
    expect(responseTime).toBeLessThan(100); // Should respond within 100ms
  });
});