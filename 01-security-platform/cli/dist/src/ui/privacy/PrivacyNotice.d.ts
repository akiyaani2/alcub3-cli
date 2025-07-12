/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { type Config } from '@alcub3/alcub3-cli-core';
interface PrivacyNoticeProps {
    onExit: () => void;
    config: Config;
}
export declare const PrivacyNotice: ({ onExit, config }: PrivacyNoticeProps) => import("react/jsx-runtime").JSX.Element;
export {};
