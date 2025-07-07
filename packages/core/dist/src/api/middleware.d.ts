/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { Request, Response, NextFunction } from 'express';
export declare const securityMiddleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const simpleSecurityMiddleware: (req: Request, res: Response, next: NextFunction) => void;
