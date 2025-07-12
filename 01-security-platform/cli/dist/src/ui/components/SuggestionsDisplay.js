import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { Box, Text } from 'ink';
import { Colors } from '../colors.js';
export const MAX_SUGGESTIONS_TO_SHOW = 8;
export function SuggestionsDisplay({ suggestions, activeIndex, isLoading, width, scrollOffset, userInput, }) {
    if (isLoading) {
        return (_jsx(Box, { paddingX: 1, width: width, children: _jsx(Text, { color: "gray", children: "Loading suggestions..." }) }));
    }
    if (suggestions.length === 0) {
        return null; // Don't render anything if there are no suggestions
    }
    // Calculate the visible slice based on scrollOffset
    const startIndex = scrollOffset;
    const endIndex = Math.min(scrollOffset + MAX_SUGGESTIONS_TO_SHOW, suggestions.length);
    const visibleSuggestions = suggestions.slice(startIndex, endIndex);
    return (_jsxs(Box, { flexDirection: "column", paddingX: 1, width: width, children: [scrollOffset > 0 && _jsx(Text, { color: Colors.Foreground, children: "\u25B2" }), visibleSuggestions.map((suggestion, index) => {
                const originalIndex = startIndex + index;
                const isActive = originalIndex === activeIndex;
                const textColor = isActive ? Colors.AccentPurple : Colors.Gray;
                return (_jsx(Box, { width: width, children: _jsxs(Box, { flexDirection: "row", children: [userInput.startsWith('/') ? (
                            // only use box model for (/) command mode
                            _jsx(Box, { width: 20, flexShrink: 0, children: _jsx(Text, { color: textColor, children: suggestion.label }) })) : (
                            // use regular text for other modes (@ context)
                            _jsx(Text, { color: textColor, children: suggestion.label })), suggestion.description ? (_jsx(Box, { flexGrow: 1, children: _jsx(Text, { color: textColor, wrap: "wrap", children: suggestion.description }) })) : null] }) }, `${suggestion}-${originalIndex}`));
            }), endIndex < suggestions.length && _jsx(Text, { color: "gray", children: "\u25BC" }), suggestions.length > MAX_SUGGESTIONS_TO_SHOW && (_jsxs(Text, { color: "gray", children: ["(", activeIndex + 1, "/", suggestions.length, ")"] }))] }));
}
//# sourceMappingURL=SuggestionsDisplay.js.map