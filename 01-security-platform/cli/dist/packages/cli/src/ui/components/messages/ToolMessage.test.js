import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import React from 'react';
import { render } from 'ink-testing-library';
import { ToolMessage } from './ToolMessage.js';
import { StreamingState, ToolCallStatus } from '../../types.js';
import { Text } from 'ink';
import { StreamingContext } from '../../contexts/StreamingContext.js';
// Mock child components or utilities if they are complex or have side effects
vi.mock('../GeminiRespondingSpinner.js', () => ({
    GeminiRespondingSpinner: ({ nonRespondingDisplay, }) => {
        const streamingState = React.useContext(StreamingContext);
        if (streamingState === StreamingState.Responding) {
            return _jsx(Text, { children: "MockRespondingSpinner" });
        }
        return nonRespondingDisplay ? _jsx(Text, { children: nonRespondingDisplay }) : null;
    },
}));
vi.mock('./DiffRenderer.js', () => ({
    DiffRenderer: function MockDiffRenderer({ diffContent, }) {
        return _jsxs(Text, { children: ["MockDiff:", diffContent] });
    },
}));
vi.mock('../../utils/MarkdownDisplay.js', () => ({
    MarkdownDisplay: function MockMarkdownDisplay({ text }) {
        return _jsxs(Text, { children: ["MockMarkdown:", text] });
    },
}));
// Helper to render with context
const renderWithContext = (ui, streamingState) => {
    const contextValue = streamingState;
    return render(_jsx(StreamingContext.Provider, { value: contextValue, children: ui }));
};
describe('<ToolMessage />', () => {
    const baseProps = {
        callId: 'tool-123',
        name: 'test-tool',
        description: 'A tool for testing',
        resultDisplay: 'Test result',
        status: ToolCallStatus.Success,
        terminalWidth: 80,
        confirmationDetails: undefined,
        emphasis: 'medium',
    };
    it('renders basic tool information', () => {
        const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps }), StreamingState.Idle);
        const output = lastFrame();
        expect(output).toContain('✔'); // Success indicator
        expect(output).toContain('test-tool');
        expect(output).toContain('A tool for testing');
        expect(output).toContain('MockMarkdown:Test result');
    });
    describe('ToolStatusIndicator rendering', () => {
        it('shows ✔ for Success status', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Success }), StreamingState.Idle);
            expect(lastFrame()).toContain('✔');
        });
        it('shows o for Pending status', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Pending }), StreamingState.Idle);
            expect(lastFrame()).toContain('o');
        });
        it('shows ? for Confirming status', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Confirming }), StreamingState.Idle);
            expect(lastFrame()).toContain('?');
        });
        it('shows - for Canceled status', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Canceled }), StreamingState.Idle);
            expect(lastFrame()).toContain('-');
        });
        it('shows x for Error status', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Error }), StreamingState.Idle);
            expect(lastFrame()).toContain('x');
        });
        it('shows paused spiner for Executing status when streamingState is Idle', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Executing }), StreamingState.Idle);
            expect(lastFrame()).toContain('⊷');
            expect(lastFrame()).not.toContain('MockRespondingSpinner');
            expect(lastFrame()).not.toContain('✔');
        });
        it('shows paused spiner for Executing status when streamingState is WaitingForConfirmation', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Executing }), StreamingState.WaitingForConfirmation);
            expect(lastFrame()).toContain('⊷');
            expect(lastFrame()).not.toContain('MockRespondingSpinner');
            expect(lastFrame()).not.toContain('✔');
        });
        it('shows MockRespondingSpinner for Executing status when streamingState is Responding', () => {
            const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, status: ToolCallStatus.Executing }), StreamingState.Responding);
            expect(lastFrame()).toContain('MockRespondingSpinner');
            expect(lastFrame()).not.toContain('✔');
        });
    });
    it('renders DiffRenderer for diff results', () => {
        const diffResult = {
            fileDiff: '--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-old\n+new',
            fileName: 'file.txt',
        };
        const { lastFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, resultDisplay: diffResult }), StreamingState.Idle);
        // Check that the output contains the MockDiff content as part of the whole message
        expect(lastFrame()).toMatch(/MockDiff:--- a\/file\.txt/);
    });
    it('renders emphasis correctly', () => {
        const { lastFrame: highEmphasisFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, emphasis: "high" }), StreamingState.Idle);
        // Check for trailing indicator or specific color if applicable (Colors are not easily testable here)
        expect(highEmphasisFrame()).toContain('←'); // Trailing indicator for high emphasis
        const { lastFrame: lowEmphasisFrame } = renderWithContext(_jsx(ToolMessage, { ...baseProps, emphasis: "low" }), StreamingState.Idle);
        // For low emphasis, the name and description might be dimmed (check for dimColor if possible)
        // This is harder to assert directly in text output without color checks.
        // We can at least ensure it doesn't have the high emphasis indicator.
        expect(lowEmphasisFrame()).not.toContain('←');
    });
});
//# sourceMappingURL=ToolMessage.test.js.map