import { Request, Response, NextFunction } from 'express';
/**
 * Simple latency measurement middleware that records time from request start
 * to response finish and sets `x-response-time-ms` header. Ensures the security
 * overhead target (<100 ms) is visible for monitoring.
 */
export declare const metricsMiddleware: (req: Request, res: Response, next: NextFunction) => void;
