/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
// packages/core/src/api/server.ts
import express from 'express';
import rateLimit from 'express-rate-limit';
import { securityMiddleware } from './middleware.js';
import { apiRoutes } from './routes.js';
import { metricsMiddleware } from './metrics.js';
const app = express();
// Add middleware to parse JSON bodies
app.use(express.json());
// Metrics middleware (captures latency for all requests)
app.use(metricsMiddleware);
// Enhanced security middleware with MAESTRO crypto integration
app.use(securityMiddleware);
// Apply rate limiting to all API requests
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use('/api', limiter, securityMiddleware, apiRoutes);
export const startApiServer = (port) => {
    app.listen(port, () => {
        console.log(`ALCUB3 API server listening on port ${port}`);
    });
};
//# sourceMappingURL=server.js.map