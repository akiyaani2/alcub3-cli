/*
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
/**
 * Simple latency measurement middleware that records time from request start
 * to response finish and sets `x-response-time-ms` header. Ensures the security
 * overhead target (<100 ms) is visible for monitoring.
 */
export const metricsMiddleware = (req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
        const end = process.hrtime.bigint();
        const durationMs = Number(end - start) / 1_000_000; // convert ns → ms
        res.setHeader('x-response-time-ms', durationMs.toFixed(2));
    });
    next();
};
//# sourceMappingURL=metrics.js.map