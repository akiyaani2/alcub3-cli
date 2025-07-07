import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import React from 'react';
import { Text, Box } from 'ink';
import { Colors } from '../colors.js';
/**
 * Custom table renderer for markdown tables
 * We implement our own instead of using ink-table due to module compatibility issues
 */
export const TableRenderer = ({ headers, rows, terminalWidth, }) => {
    // Calculate column widths
    const columnWidths = headers.map((header, index) => {
        const headerWidth = header.length;
        const maxRowWidth = Math.max(...rows.map((row) => (row[index] || '').length));
        return Math.max(headerWidth, maxRowWidth) + 2; // Add padding
    });
    // Ensure table fits within terminal width
    const totalWidth = columnWidths.reduce((sum, width) => sum + width + 1, 1);
    const scaleFactor = totalWidth > terminalWidth ? terminalWidth / totalWidth : 1;
    const adjustedWidths = columnWidths.map((width) => Math.floor(width * scaleFactor));
    const renderCell = (content, width, isHeader = false) => {
        // The actual space for content inside the padding
        const contentWidth = Math.max(0, width - 2);
        let cellContent = content;
        if (content.length > contentWidth) {
            if (contentWidth <= 3) {
                // Not enough space for '...'
                cellContent = content.substring(0, contentWidth);
            }
            else {
                cellContent = content.substring(0, contentWidth - 3) + '...';
            }
        }
        // Pad the content to fill the cell
        const padded = cellContent.padEnd(contentWidth, ' ');
        if (isHeader) {
            return (_jsx(Text, { bold: true, color: Colors.AccentCyan, children: padded }));
        }
        return _jsx(Text, { children: padded });
    };
    const renderRow = (cells, isHeader = false) => (_jsxs(Box, { flexDirection: "row", children: [_jsx(Text, { children: "\u2502 " }), cells.map((cell, index) => (_jsxs(React.Fragment, { children: [renderCell(cell, adjustedWidths[index] || 0, isHeader), _jsx(Text, { children: " \u2502 " })] }, index)))] }));
    const renderSeparator = () => {
        const separator = adjustedWidths
            .map((width) => '─'.repeat(Math.max(0, (width || 0) - 2)))
            .join('─┼─');
        return _jsxs(Text, { children: ["\u251C\u2500", separator, "\u2500\u2524"] });
    };
    const renderTopBorder = () => {
        const border = adjustedWidths
            .map((width) => '─'.repeat(Math.max(0, (width || 0) - 2)))
            .join('─┬─');
        return _jsxs(Text, { children: ["\u250C\u2500", border, "\u2500\u2510"] });
    };
    const renderBottomBorder = () => {
        const border = adjustedWidths
            .map((width) => '─'.repeat(Math.max(0, (width || 0) - 2)))
            .join('─┴─');
        return _jsxs(Text, { children: ["\u2514\u2500", border, "\u2500\u2518"] });
    };
    return (_jsxs(Box, { flexDirection: "column", marginY: 1, children: [renderTopBorder(), renderRow(headers, true), renderSeparator(), rows.map((row, index) => (_jsx(React.Fragment, { children: renderRow(row) }, index))), renderBottomBorder()] }));
};
//# sourceMappingURL=TableRenderer.js.map