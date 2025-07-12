import { jsx as _jsx } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { createContext, useContext, useState, useMemo, useEffect, } from 'react';
import { uiTelemetryService, } from '@alcub3/alcub3-cli-core';
// --- Context Definition ---
const SessionStatsContext = createContext(undefined);
// --- Provider Component ---
export const SessionStatsProvider = ({ children, }) => {
    const [stats, setStats] = useState({
        sessionStartTime: new Date(),
        metrics: uiTelemetryService.getMetrics(),
        lastPromptTokenCount: 0,
    });
    useEffect(() => {
        const handleUpdate = ({ metrics, lastPromptTokenCount, }) => {
            setStats((prevState) => ({
                ...prevState,
                metrics,
                lastPromptTokenCount,
            }));
        };
        uiTelemetryService.on('update', handleUpdate);
        // Set initial state
        handleUpdate({
            metrics: uiTelemetryService.getMetrics(),
            lastPromptTokenCount: uiTelemetryService.getLastPromptTokenCount(),
        });
        return () => {
            uiTelemetryService.off('update', handleUpdate);
        };
    }, []);
    const value = useMemo(() => ({
        stats,
    }), [stats]);
    return (_jsx(SessionStatsContext.Provider, { value: value, children: children }));
};
// --- Consumer Hook ---
export const useSessionStats = () => {
    const context = useContext(SessionStatsContext);
    if (context === undefined) {
        throw new Error('useSessionStats must be used within a SessionStatsProvider');
    }
    return context;
};
//# sourceMappingURL=SessionContext.js.map