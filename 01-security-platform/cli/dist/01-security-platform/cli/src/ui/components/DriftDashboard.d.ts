/**
 * @license
 * Copyright 2024 ALCUB3 Systems
 * SPDX-License-Identifier: Apache-2.0
 *
 * ALCUB3 Configuration Drift Dashboard - Task 4.3.6
 *
 * Real-time dashboard for configuration drift monitoring with live updates,
 * metrics visualization, and MAESTRO-compliant reporting.
 */
import React from 'react';
interface DriftDashboardProps {
    refreshInterval?: number;
    userClearance?: string;
}
declare const DriftDashboard: React.FC<DriftDashboardProps>;
export { DriftDashboard };
