/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
// packages/core/src/api/routes.ts
import express from 'express';
const router = express.Router();
const maestroRouter = express.Router();
// Public status endpoint (UNCLASSIFIED)
maestroRouter.get('/status', (_req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});
// Protected metrics endpoint (SECRET+)
maestroRouter.get('/metrics', (_req, res) => {
    // Placeholder metrics – in production gather real perf metrics
    res.json({ uptime: process.uptime(), memoryUsage: process.memoryUsage() });
});
// Mount under /v1/maestro
router.use('/v1/maestro', maestroRouter);
export { router as apiRoutes };
//# sourceMappingURL=routes.js.map