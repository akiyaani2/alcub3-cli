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
import { JITPrivilegeAPI } from './jit_api.js';

// Mock child_process
vi.mock('child_process', () => ({
  spawn: vi.fn(() => ({
    stdout: {
      on: vi.fn((event, callback) => {
        if (event === 'data') {
          setTimeout(() => {
            // Mock successful approval response
            const response = {
              status: 'approved',
              sessionId: 'test-session-123',
              sessionToken: 'test-token-123',
              expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
              grantedRole: 'operator',
              grantedPermissions: ['read', 'write'],
              message: 'Privilege granted successfully'
            };
            callback(Buffer.from(JSON.stringify(response)));
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

describe('JIT Privilege API', () => {
  let app: express.Application;
  let jitAPI: JITPrivilegeAPI;
  let mockIO: any;
  let mockUser: any;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    // Mock user authentication middleware
    mockUser = {
      id: 'test-user-123',
      username: 'testuser',
      classification: 'SECRET',
      roles: ['operator'],
      failedAuthCount: 0
    };
    
    app.use((req: any, res, next) => {
      req.user = mockUser;
      next();
    });
    
    jitAPI = new JITPrivilegeAPI();
    
    // Mock Socket.IO
    mockIO = {
      of: vi.fn(() => ({
        on: vi.fn(),
        to: vi.fn(() => ({
          emit: vi.fn()
        }))
      })),
      to: vi.fn(() => ({
        emit: vi.fn()
      }))
    };
    
    jitAPI.setSocketIO(mockIO as unknown as Server);
    
    // Set up routes
    app.use('/api/v1/jit', jitAPI.createRouter());
  });

  afterEach(() => {
    jitAPI.cleanup();
    vi.clearAllMocks();
  });

  describe('POST /api/v1/jit/request', () => {
    it('should successfully request privilege escalation', async () => {
      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'operator',
          duration: 30,
          justification: 'Need to perform system maintenance',
          classification: 'SECRET',
          resources: ['/var/log', '/etc/config'],
          mfaVerified: true
        });

      expect(response.status).toBe(202);
      expect(response.body).toHaveProperty('status', 'approved');
      expect(response.body).toHaveProperty('sessionId');
      expect(response.body).toHaveProperty('sessionToken');
      expect(response.body).toHaveProperty('expiresAt');
      expect(response.body.grantedRole).toBe('operator');
    });

    it('should reject request without authentication', async () => {
      // Remove user
      app.use((req: any, res, next) => {
        req.user = null;
        next();
      });

      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'admin',
          justification: 'Testing'
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Authentication required');
    });

    it('should validate request parameters', async () => {
      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          // Missing required role
          justification: 'Test'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Role is required');
    });

    it('should validate justification length', async () => {
      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'admin',
          justification: 'Short'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Justification must be at least 10 characters');
    });

    it('should validate duration range', async () => {
      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'admin',
          duration: 600, // Too long
          justification: 'Testing duration validation'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Duration must be between 5 and 480 minutes');
    });

    it('should handle pending approval response', async () => {
      // Mock pending response
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const response = {
                status: 'pending',
                requestId: 'req-456',
                approversNotified: ['supervisor', 'security_team']
              };
              callback(Buffer.from(JSON.stringify(response)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'admin',
          duration: 60,
          justification: 'High privilege request requiring approval'
        });

      expect(response.status).toBe(202);
      expect(response.body.status).toBe('pending');
      expect(response.body).toHaveProperty('requestId');
      expect(response.body.approversNotified).toContain('supervisor');
    });

    it('should handle denial response', async () => {
      // Mock denial response
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const response = {
                status: 'denied',
                reason: 'Risk score too high'
              };
              callback(Buffer.from(JSON.stringify(response)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'superadmin',
          duration: 480,
          justification: 'Need full access to everything'
        });

      expect(response.status).toBe(403);
      expect(response.body.status).toBe('denied');
      expect(response.body.reason).toBe('Risk score too high');
    });
  });

  describe('GET /api/v1/jit/status/:id', () => {
    it('should get session status', async () => {
      // Mock session status response
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const status = {
                sessionId: 'session-123',
                userId: 'test-user-123',
                isActive: true,
                grantedRole: 'operator',
                expiresAt: new Date(Date.now() + 20 * 60 * 1000).toISOString(),
                timeRemaining: 1200,
                riskScore: 25.5
              };
              callback(Buffer.from(JSON.stringify(status)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .get('/api/v1/jit/status/session-123');

      expect(response.status).toBe(200);
      expect(response.body.sessionId).toBe('session-123');
      expect(response.body.isActive).toBe(true);
      expect(response.body.grantedRole).toBe('operator');
      expect(response.body).toHaveProperty('timeRemaining');
    });

    it('should return 404 for non-existent session', async () => {
      // Mock null response
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from('null'));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(1); // Non-zero exit
        })
      }));

      const response = await request(app)
        .get('/api/v1/jit/status/non-existent');

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Request or session not found');
    });

    it('should enforce access control for sessions', async () => {
      // Mock session for different user
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const status = {
                sessionId: 'session-123',
                userId: 'different-user', // Different user
                isActive: true,
                grantedRole: 'admin'
              };
              callback(Buffer.from(JSON.stringify(status)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .get('/api/v1/jit/status/session-123');

      expect(response.status).toBe(403);
      expect(response.body.error).toBe('Access denied');
    });
  });

  describe('POST /api/v1/jit/approve', () => {
    it('should process approval response', async () => {
      // Give user approval authority
      mockUser.roles = ['supervisor'];

      // Mock approval processing
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const result = {
                status: 'approved',
                message: 'Request approved',
                userId: 'requesting-user'
              };
              callback(Buffer.from(JSON.stringify(result)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .post('/api/v1/jit/approve')
        .send({
          approvalId: 'approval-123',
          approved: true,
          comments: 'Looks good to me'
        });

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('approved');
    });

    it('should require approval authority', async () => {
      // Regular user without approval roles
      mockUser.roles = ['operator'];

      const response = await request(app)
        .post('/api/v1/jit/approve')
        .send({
          approvalId: 'approval-123',
          approved: true
        });

      expect(response.status).toBe(403);
      expect(response.body.error).toBe('Approval authority required');
    });
  });

  describe('GET /api/v1/jit/sessions', () => {
    it('should list active sessions for user', async () => {
      // Mock sessions response
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const result = {
                sessions: [
                  {
                    sessionId: 'session-1',
                    userId: 'test-user-123',
                    grantedRole: 'operator',
                    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
                    riskScore: 20
                  },
                  {
                    sessionId: 'session-2',
                    userId: 'test-user-123',
                    grantedRole: 'admin',
                    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
                    riskScore: 45
                  }
                ]
              };
              callback(Buffer.from(JSON.stringify(result)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .get('/api/v1/jit/sessions');

      expect(response.status).toBe(200);
      expect(response.body.sessions).toHaveLength(2);
      expect(response.body.total).toBe(2);
    });

    it('should allow security admins to view all sessions', async () => {
      // Give user security admin role
      mockUser.roles = ['security_admin'];

      // Mock response
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const result = { sessions: [] };
              callback(Buffer.from(JSON.stringify(result)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .get('/api/v1/jit/sessions')
        .query({ userId: 'another-user' });

      expect(response.status).toBe(200);
      // Should accept the userId parameter
    });
  });

  describe('DELETE /api/v1/jit/session/:sessionId', () => {
    it('should revoke a session', async () => {
      // Mock getting session (for ownership check)
      const { spawn } = await import('child_process');
      let callCount = 0;
      
      (spawn as any).mockImplementation(() => {
        callCount++;
        
        if (callCount === 1) {
          // First call: get session status
          return {
            stdout: {
              on: vi.fn((event, callback) => {
                if (event === 'data') {
                  const status = {
                    sessionId: 'session-123',
                    userId: 'test-user-123', // Same as mock user
                    isActive: true
                  };
                  callback(Buffer.from(JSON.stringify(status)));
                }
              })
            },
            stderr: { on: vi.fn() },
            on: vi.fn((event, callback) => {
              if (event === 'close') callback(0);
            })
          };
        } else {
          // Second call: revoke session
          return {
            stdout: {
              on: vi.fn((event, callback) => {
                if (event === 'data') {
                  const result = {
                    status: 'revoked',
                    reason: 'Manual revocation by user'
                  };
                  callback(Buffer.from(JSON.stringify(result)));
                }
              })
            },
            stderr: { on: vi.fn() },
            on: vi.fn((event, callback) => {
              if (event === 'close') callback(0);
            })
          };
        }
      });

      const response = await request(app)
        .delete('/api/v1/jit/session/session-123')
        .send({
          reason: 'No longer needed'
        });

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('revoked');
    });

    it('should prevent revoking other users sessions', async () => {
      // Mock session for different user
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const status = {
                sessionId: 'session-123',
                userId: 'different-user',
                isActive: true
              };
              callback(Buffer.from(JSON.stringify(status)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .delete('/api/v1/jit/session/session-123')
        .send({ reason: 'Test' });

      expect(response.status).toBe(403);
      expect(response.body.error).toBe('Not authorized to revoke this session');
    });
  });

  describe('GET /api/v1/jit/stats', () => {
    it('should return statistics for security admins', async () => {
      // Give user security admin role
      mockUser.roles = ['security_admin'];

      // Mock stats response
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              const stats = {
                totalRequests: 150,
                autoApproved: 120,
                manuallyApproved: 20,
                denied: 10,
                revoked: 5,
                activeSessions: 15,
                approvalRate: 93.3,
                autoApprovalRate: 80.0,
                revocationRate: 3.4
              };
              callback(Buffer.from(JSON.stringify(stats)));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .get('/api/v1/jit/stats');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('totalRequests');
      expect(response.body).toHaveProperty('approvalRate');
      expect(response.body.totalRequests).toBe(150);
    });

    it('should deny stats access to regular users', async () => {
      // Regular user
      mockUser.roles = ['operator'];

      const response = await request(app)
        .get('/api/v1/jit/stats');

      expect(response.status).toBe(403);
      expect(response.body.error).toBe('Security admin access required');
    });
  });

  describe('WebSocket Integration', () => {
    it('should set up WebSocket namespaces', () => {
      expect(mockIO.of).toHaveBeenCalledWith('/jit');
    });

    it('should emit real-time updates on privilege request', async () => {
      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'operator',
          duration: 30,
          justification: 'Testing WebSocket updates'
        });

      expect(response.status).toBe(202);
      
      // Verify WebSocket emission
      expect(mockIO.to).toHaveBeenCalledWith('user:test-user-123');
    });
  });

  describe('Error Handling', () => {
    it('should handle Python process errors', async () => {
      // Mock process error
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: { on: vi.fn() },
        stderr: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from('Python error: Module not found'));
            }
          })
        },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(1); // Non-zero exit
          if (event === 'error') callback(new Error('spawn failed'));
        })
      }));

      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'admin',
          justification: 'Testing error handling'
        });

      expect(response.status).toBe(500);
    });

    it('should handle invalid JSON responses', async () => {
      // Mock invalid JSON
      const { spawn } = await import('child_process');
      (spawn as any).mockImplementationOnce(() => ({
        stdout: {
          on: vi.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from('Not valid JSON'));
            }
          })
        },
        stderr: { on: vi.fn() },
        on: vi.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      }));

      const response = await request(app)
        .post('/api/v1/jit/request')
        .send({
          role: 'admin',
          justification: 'Testing JSON parsing'
        });

      expect(response.status).toBe(500);
    });
  });

  describe('Cleanup', () => {
    it('should cleanup active processes on shutdown', () => {
      // Create some mock processes
      const mockProcess1 = { kill: vi.fn() };
      const mockProcess2 = { kill: vi.fn() };
      
      // Access private property for testing
      (jitAPI as any).activeProcesses.set('req1', mockProcess1);
      (jitAPI as any).activeProcesses.set('req2', mockProcess2);
      
      jitAPI.cleanup();
      
      expect(mockProcess1.kill).toHaveBeenCalled();
      expect(mockProcess2.kill).toHaveBeenCalled();
      expect((jitAPI as any).activeProcesses.size).toBe(0);
    });
  });
});

describe('JIT API Performance', () => {
  let app: express.Application;
  let jitAPI: JITPrivilegeAPI;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    // Mock user
    app.use((req: any, res, next) => {
      req.user = {
        id: 'perf-test-user',
        classification: 'UNCLASSIFIED',
        roles: ['operator']
      };
      next();
    });
    
    jitAPI = new JITPrivilegeAPI();
    app.use('/api/v1/jit', jitAPI.createRouter());
  });

  afterEach(() => {
    jitAPI.cleanup();
  });

  it('should handle concurrent requests efficiently', async () => {
    const requests = [];
    
    // Create 10 concurrent requests
    for (let i = 0; i < 10; i++) {
      requests.push(
        request(app)
          .post('/api/v1/jit/request')
          .send({
            role: 'operator',
            duration: 15,
            justification: `Concurrent test ${i}`
          })
      );
    }

    const responses = await Promise.all(requests);
    
    // All should succeed
    responses.forEach(response => {
      expect(response.status).toBe(202);
      expect(response.body).toHaveProperty('status');
    });
  });

  it('should respond within performance targets', async () => {
    const startTime = Date.now();
    
    const response = await request(app)
      .post('/api/v1/jit/request')
      .send({
        role: 'operator',
        duration: 15,
        justification: 'Performance testing'
      });

    const responseTime = Date.now() - startTime;
    
    expect(response.status).toBe(202);
    expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
  });
});