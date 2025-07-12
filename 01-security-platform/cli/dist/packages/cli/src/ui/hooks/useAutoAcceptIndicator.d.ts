/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { ApprovalMode, type Config } from '@alcub3/alcub3-cli-core';
export interface UseAutoAcceptIndicatorArgs {
    config: Config;
}
export declare function useAutoAcceptIndicator({ config, }: UseAutoAcceptIndicatorArgs): ApprovalMode;
