/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { Config } from '@alcub3/alcub3-cli-core';
export interface PrivacyState {
    isLoading: boolean;
    error?: string;
    isFreeTier?: boolean;
    dataCollectionOptIn?: boolean;
}
export declare const usePrivacySettings: (config: Config) => {
    privacyState: PrivacyState;
    updateDataCollectionOptIn: (optIn: boolean) => Promise<void>;
};
