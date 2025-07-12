/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
// packages/core/src/api/server.ts
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import rateLimit from 'express-rate-limit';
import { enhancedMiddlewareStack } from './enhanced_middleware.js';
import { apiRoutes } from './routes.js';
import { cisaAPI } from './cisa_api.js';
import { jitAPI } from './jit_api.js';
import cors from 'cors';
const app = express();
// CORS configuration for security
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    optionsSuccessStatus: 200
}));
// Add middleware to parse JSON bodies with limits
app.use(express.json({
    limit: '10mb', // Prevent large payload attacks
    verify: (req, res, buf) => {
        // Add request validation here if needed
    }
}));
// Apply rate limiting to all API requests
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: {
        error: 'Too many requests from this IP, please try again later.',
        timestamp: new Date().toISOString()
    }
});
// Global error handler
app.use((err, req, res, next) => {
    console.error('API Error:', err);
    res.status(500).json({
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    });
});
// Apply enhanced middleware stack to all API routes
app.use('/api', limiter, ...enhancedMiddlewareStack, apiRoutes);
export const startApiServer = (port) => {
    // Create HTTP server
    const httpServer = createServer(app);
    // Create Socket.IO server
    const io = new Server(httpServer, {
        cors: {
            origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
            credentials: true
        }
    });
    // Set up Socket.IO for APIs
    cisaAPI.setSocketIO(io);
    jitAPI.setSocketIO(io);
    // Start server
    httpServer.listen(port, () => {
        console.log(`ALCUB3 API server listening on port ${port}`);
        console.log(`WebSocket server ready for real-time updates`);
    });
    // Graceful shutdown
    process.on('SIGTERM', () => {
        console.log('SIGTERM received, shutting down gracefully');
        cisaAPI.cleanup();
        jitAPI.cleanup();
        httpServer.close(() => {
            console.log('Server closed');
            process.exit(0);
        });
    });
};
//# sourceMappingURL=server.js.map