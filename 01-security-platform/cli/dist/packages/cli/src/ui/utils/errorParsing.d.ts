/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { AuthType } from '@alcub3/alcub3-cli-core';
export interface ApiError {
    error: {
        code: number;
        message: string;
        status: string;
        details: unknown[];
    };
}
export declare function parseAndFormatApiError(error: unknown, authType?: AuthType): string;
