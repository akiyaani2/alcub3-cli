import { jsx as _jsx } from "react/jsx-runtime";
import { render } from 'ink-testing-library';
import { renderHook } from '@testing-library/react';
import { act } from 'react-dom/test-utils';
import { SessionStatsProvider, useSessionStats, } from './SessionContext.js';
import { describe, it, expect, vi } from 'vitest';
import { uiTelemetryService } from '@alcub3/alcub3-cli-core';
/**
 * A test harness component that uses the hook and exposes the context value
 * via a mutable ref. This allows us to interact with the context's functions
 * and assert against its state directly in our tests.
 */
const TestHarness = ({ contextRef, }) => {
    contextRef.current = useSessionStats();
    return null;
};
describe('SessionStatsContext', () => {
    it('should provide the correct initial state', () => {
        const contextRef = { current: undefined };
        render(_jsx(SessionStatsProvider, { children: _jsx(TestHarness, { contextRef: contextRef }) }));
        const stats = contextRef.current?.stats;
        expect(stats?.sessionStartTime).toBeInstanceOf(Date);
        expect(stats?.metrics).toBeDefined();
        expect(stats?.metrics.models).toEqual({});
    });
    it('should update metrics when the uiTelemetryService emits an update', () => {
        const contextRef = { current: undefined };
        render(_jsx(SessionStatsProvider, { children: _jsx(TestHarness, { contextRef: contextRef }) }));
        const newMetrics = {
            models: {
                'gemini-pro': {
                    api: {
                        totalRequests: 1,
                        totalErrors: 0,
                        totalLatencyMs: 123,
                    },
                    tokens: {
                        prompt: 100,
                        candidates: 200,
                        total: 300,
                        cached: 50,
                        thoughts: 20,
                        tool: 10,
                    },
                },
            },
            tools: {
                totalCalls: 1,
                totalSuccess: 1,
                totalFail: 0,
                totalDurationMs: 456,
                totalDecisions: {
                    accept: 1,
                    reject: 0,
                    modify: 0,
                },
                byName: {
                    'test-tool': {
                        count: 1,
                        success: 1,
                        fail: 0,
                        durationMs: 456,
                        decisions: {
                            accept: 1,
                            reject: 0,
                            modify: 0,
                        },
                    },
                },
            },
        };
        act(() => {
            uiTelemetryService.emit('update', {
                metrics: newMetrics,
                lastPromptTokenCount: 100,
            });
        });
        const stats = contextRef.current?.stats;
        expect(stats?.metrics).toEqual(newMetrics);
        expect(stats?.lastPromptTokenCount).toBe(100);
    });
    it('should throw an error when useSessionStats is used outside of a provider', () => {
        // Suppress console.error for this test since we expect an error
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => { });
        try {
            // Expect renderHook itself to throw when the hook is used outside a provider
            expect(() => {
                renderHook(() => useSessionStats());
            }).toThrow('useSessionStats must be used within a SessionStatsProvider');
        }
        finally {
            consoleSpy.mockRestore();
        }
    });
});
//# sourceMappingURL=SessionContext.test.js.map