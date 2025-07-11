import { jsx as _jsx } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { render } from 'ink-testing-library';
import { describe, it, expect, vi } from 'vitest';
import { ToolConfirmationMessage } from './ToolConfirmationMessage.js';
describe('ToolConfirmationMessage', () => {
    it('should not display urls if prompt and url are the same', () => {
        const confirmationDetails = {
            type: 'info',
            title: 'Confirm Web Fetch',
            prompt: 'https://example.com',
            urls: ['https://example.com'],
            onConfirm: vi.fn(),
        };
        const { lastFrame } = render(_jsx(ToolConfirmationMessage, { confirmationDetails: confirmationDetails, availableTerminalHeight: 30, terminalWidth: 80 }));
        expect(lastFrame()).not.toContain('URLs to fetch:');
    });
    it('should display urls if prompt and url are different', () => {
        const confirmationDetails = {
            type: 'info',
            title: 'Confirm Web Fetch',
            prompt: 'fetch https://github.com/google/gemini-react/blob/main/README.md',
            urls: [
                'https://raw.githubusercontent.com/google/gemini-react/main/README.md',
            ],
            onConfirm: vi.fn(),
        };
        const { lastFrame } = render(_jsx(ToolConfirmationMessage, { confirmationDetails: confirmationDetails, availableTerminalHeight: 30, terminalWidth: 80 }));
        expect(lastFrame()).toContain('URLs to fetch:');
        expect(lastFrame()).toContain('- https://raw.githubusercontent.com/google/gemini-react/main/README.md');
    });
});
//# sourceMappingURL=ToolConfirmationMessage.test.js.map