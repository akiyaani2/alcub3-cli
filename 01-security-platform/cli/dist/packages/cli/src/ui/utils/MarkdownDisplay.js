import { Fragment as _Fragment, jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import React from 'react';
import { Text, Box } from 'ink';
import { Colors } from '../colors.js';
import { colorizeCode } from './CodeColorizer.js';
import { TableRenderer } from './TableRenderer.js';
// Constants for Markdown parsing and rendering
const BOLD_MARKER_LENGTH = 2; // For "**"
const ITALIC_MARKER_LENGTH = 1; // For "*" or "_"
const STRIKETHROUGH_MARKER_LENGTH = 2; // For "~~"
const INLINE_CODE_MARKER_LENGTH = 1; // For "`"
const UNDERLINE_TAG_START_LENGTH = 3; // For "<u>"
const UNDERLINE_TAG_END_LENGTH = 4; // For "</u>"
const EMPTY_LINE_HEIGHT = 1;
const CODE_BLOCK_PADDING = 1;
const LIST_ITEM_PREFIX_PADDING = 1;
const LIST_ITEM_TEXT_FLEX_GROW = 1;
const MarkdownDisplayInternal = ({ text, isPending, availableTerminalHeight, terminalWidth, }) => {
    if (!text)
        return _jsx(_Fragment, {});
    const lines = text.split('\n');
    const headerRegex = /^ *(#{1,4}) +(.*)/;
    const codeFenceRegex = /^ *(`{3,}|~{3,}) *(\w*?) *$/;
    const ulItemRegex = /^([ \t]*)([-*+]) +(.*)/;
    const olItemRegex = /^([ \t]*)(\d+)\. +(.*)/;
    const hrRegex = /^ *([-*_] *){3,} *$/;
    const tableRowRegex = /^\s*\|(.+)\|\s*$/;
    const tableSeparatorRegex = /^\s*\|?\s*(:?-+:?)\s*(\|\s*(:?-+:?)\s*)+\|?\s*$/;
    const contentBlocks = [];
    let inCodeBlock = false;
    let codeBlockContent = [];
    let codeBlockLang = null;
    let codeBlockFence = '';
    let inTable = false;
    let tableRows = [];
    let tableHeaders = [];
    lines.forEach((line, index) => {
        const key = `line-${index}`;
        if (inCodeBlock) {
            const fenceMatch = line.match(codeFenceRegex);
            if (fenceMatch &&
                fenceMatch[1].startsWith(codeBlockFence[0]) &&
                fenceMatch[1].length >= codeBlockFence.length) {
                contentBlocks.push(_jsx(RenderCodeBlock, { content: codeBlockContent, lang: codeBlockLang, isPending: isPending, availableTerminalHeight: availableTerminalHeight, terminalWidth: terminalWidth }, key));
                inCodeBlock = false;
                codeBlockContent = [];
                codeBlockLang = null;
                codeBlockFence = '';
            }
            else {
                codeBlockContent.push(line);
            }
            return;
        }
        const codeFenceMatch = line.match(codeFenceRegex);
        const headerMatch = line.match(headerRegex);
        const ulMatch = line.match(ulItemRegex);
        const olMatch = line.match(olItemRegex);
        const hrMatch = line.match(hrRegex);
        const tableRowMatch = line.match(tableRowRegex);
        const tableSeparatorMatch = line.match(tableSeparatorRegex);
        if (codeFenceMatch) {
            inCodeBlock = true;
            codeBlockFence = codeFenceMatch[1];
            codeBlockLang = codeFenceMatch[2] || null;
        }
        else if (tableRowMatch && !inTable) {
            // Potential table start - check if next line is separator
            if (index + 1 < lines.length &&
                lines[index + 1].match(tableSeparatorRegex)) {
                inTable = true;
                tableHeaders = tableRowMatch[1].split('|').map((cell) => cell.trim());
                tableRows = [];
            }
            else {
                // Not a table, treat as regular text
                contentBlocks.push(_jsx(Box, { children: _jsx(Text, { wrap: "wrap", children: _jsx(RenderInline, { text: line }) }) }, key));
            }
        }
        else if (inTable && tableSeparatorMatch) {
            // Skip separator line - already handled
        }
        else if (inTable && tableRowMatch) {
            // Add table row
            const cells = tableRowMatch[1].split('|').map((cell) => cell.trim());
            // Ensure row has same column count as headers
            while (cells.length < tableHeaders.length) {
                cells.push('');
            }
            if (cells.length > tableHeaders.length) {
                cells.length = tableHeaders.length;
            }
            tableRows.push(cells);
        }
        else if (inTable && !tableRowMatch) {
            // End of table
            if (tableHeaders.length > 0 && tableRows.length > 0) {
                contentBlocks.push(_jsx(RenderTable, { headers: tableHeaders, rows: tableRows, terminalWidth: terminalWidth }, `table-${contentBlocks.length}`));
            }
            inTable = false;
            tableRows = [];
            tableHeaders = [];
            // Process current line as normal
            if (line.trim().length > 0) {
                contentBlocks.push(_jsx(Box, { children: _jsx(Text, { wrap: "wrap", children: _jsx(RenderInline, { text: line }) }) }, key));
            }
        }
        else if (hrMatch) {
            contentBlocks.push(_jsx(Box, { children: _jsx(Text, { dimColor: true, children: "---" }) }, key));
        }
        else if (headerMatch) {
            const level = headerMatch[1].length;
            const headerText = headerMatch[2];
            let headerNode = null;
            switch (level) {
                case 1:
                    headerNode = (_jsx(Text, { bold: true, color: Colors.AccentCyan, children: _jsx(RenderInline, { text: headerText }) }));
                    break;
                case 2:
                    headerNode = (_jsx(Text, { bold: true, color: Colors.AccentBlue, children: _jsx(RenderInline, { text: headerText }) }));
                    break;
                case 3:
                    headerNode = (_jsx(Text, { bold: true, children: _jsx(RenderInline, { text: headerText }) }));
                    break;
                case 4:
                    headerNode = (_jsx(Text, { italic: true, color: Colors.Gray, children: _jsx(RenderInline, { text: headerText }) }));
                    break;
                default:
                    headerNode = (_jsx(Text, { children: _jsx(RenderInline, { text: headerText }) }));
                    break;
            }
            if (headerNode)
                contentBlocks.push(_jsx(Box, { children: headerNode }, key));
        }
        else if (ulMatch) {
            const leadingWhitespace = ulMatch[1];
            const marker = ulMatch[2];
            const itemText = ulMatch[3];
            contentBlocks.push(_jsx(RenderListItem, { itemText: itemText, type: "ul", marker: marker, leadingWhitespace: leadingWhitespace }, key));
        }
        else if (olMatch) {
            const leadingWhitespace = olMatch[1];
            const marker = olMatch[2];
            const itemText = olMatch[3];
            contentBlocks.push(_jsx(RenderListItem, { itemText: itemText, type: "ol", marker: marker, leadingWhitespace: leadingWhitespace }, key));
        }
        else {
            if (line.trim().length === 0) {
                if (contentBlocks.length > 0 && !inCodeBlock) {
                    contentBlocks.push(_jsx(Box, { height: EMPTY_LINE_HEIGHT }, key));
                }
            }
            else {
                contentBlocks.push(_jsx(Box, { children: _jsx(Text, { wrap: "wrap", children: _jsx(RenderInline, { text: line }) }) }, key));
            }
        }
    });
    if (inCodeBlock) {
        contentBlocks.push(_jsx(RenderCodeBlock, { content: codeBlockContent, lang: codeBlockLang, isPending: isPending, availableTerminalHeight: availableTerminalHeight, terminalWidth: terminalWidth }, "line-eof"));
    }
    // Handle table at end of content
    if (inTable && tableHeaders.length > 0 && tableRows.length > 0) {
        contentBlocks.push(_jsx(RenderTable, { headers: tableHeaders, rows: tableRows, terminalWidth: terminalWidth }, `table-${contentBlocks.length}`));
    }
    return _jsx(_Fragment, { children: contentBlocks });
};
const RenderInlineInternal = ({ text }) => {
    const nodes = [];
    let lastIndex = 0;
    const inlineRegex = /(\*\*.*?\*\*|\*.*?\*|_.*?_|~~.*?~~|\[.*?\]\(.*?\)|`+.+?`+|<u>.*?<\/u>)/g;
    let match;
    while ((match = inlineRegex.exec(text)) !== null) {
        if (match.index > lastIndex) {
            nodes.push(_jsx(Text, { children: text.slice(lastIndex, match.index) }, `t-${lastIndex}`));
        }
        const fullMatch = match[0];
        let renderedNode = null;
        const key = `m-${match.index}`;
        try {
            if (fullMatch.startsWith('**') &&
                fullMatch.endsWith('**') &&
                fullMatch.length > BOLD_MARKER_LENGTH * 2) {
                renderedNode = (_jsx(Text, { bold: true, children: fullMatch.slice(BOLD_MARKER_LENGTH, -BOLD_MARKER_LENGTH) }, key));
            }
            else if (fullMatch.length > ITALIC_MARKER_LENGTH * 2 &&
                ((fullMatch.startsWith('*') && fullMatch.endsWith('*')) ||
                    (fullMatch.startsWith('_') && fullMatch.endsWith('_'))) &&
                !/\w/.test(text.substring(match.index - 1, match.index)) &&
                !/\w/.test(text.substring(inlineRegex.lastIndex, inlineRegex.lastIndex + 1)) &&
                !/\S[./\\]/.test(text.substring(match.index - 2, match.index)) &&
                !/[./\\]\S/.test(text.substring(inlineRegex.lastIndex, inlineRegex.lastIndex + 2))) {
                renderedNode = (_jsx(Text, { italic: true, children: fullMatch.slice(ITALIC_MARKER_LENGTH, -ITALIC_MARKER_LENGTH) }, key));
            }
            else if (fullMatch.startsWith('~~') &&
                fullMatch.endsWith('~~') &&
                fullMatch.length > STRIKETHROUGH_MARKER_LENGTH * 2) {
                renderedNode = (_jsx(Text, { strikethrough: true, children: fullMatch.slice(STRIKETHROUGH_MARKER_LENGTH, -STRIKETHROUGH_MARKER_LENGTH) }, key));
            }
            else if (fullMatch.startsWith('`') &&
                fullMatch.endsWith('`') &&
                fullMatch.length > INLINE_CODE_MARKER_LENGTH) {
                const codeMatch = fullMatch.match(/^(`+)(.+?)\1$/s);
                if (codeMatch && codeMatch[2]) {
                    renderedNode = (_jsx(Text, { color: Colors.AccentPurple, children: codeMatch[2] }, key));
                }
                else {
                    renderedNode = (_jsx(Text, { color: Colors.AccentPurple, children: fullMatch.slice(INLINE_CODE_MARKER_LENGTH, -INLINE_CODE_MARKER_LENGTH) }, key));
                }
            }
            else if (fullMatch.startsWith('[') &&
                fullMatch.includes('](') &&
                fullMatch.endsWith(')')) {
                const linkMatch = fullMatch.match(/\[(.*?)\]\((.*?)\)/);
                if (linkMatch) {
                    const linkText = linkMatch[1];
                    const url = linkMatch[2];
                    renderedNode = (_jsxs(Text, { children: [linkText, _jsxs(Text, { color: Colors.AccentBlue, children: [" (", url, ")"] })] }, key));
                }
            }
            else if (fullMatch.startsWith('<u>') &&
                fullMatch.endsWith('</u>') &&
                fullMatch.length >
                    UNDERLINE_TAG_START_LENGTH + UNDERLINE_TAG_END_LENGTH - 1 // -1 because length is compared to combined length of start and end tags
            ) {
                renderedNode = (_jsx(Text, { underline: true, children: fullMatch.slice(UNDERLINE_TAG_START_LENGTH, -UNDERLINE_TAG_END_LENGTH) }, key));
            }
        }
        catch (e) {
            console.error('Error parsing inline markdown part:', fullMatch, e);
            renderedNode = null;
        }
        nodes.push(renderedNode ?? _jsx(Text, { children: fullMatch }, key));
        lastIndex = inlineRegex.lastIndex;
    }
    if (lastIndex < text.length) {
        nodes.push(_jsx(Text, { children: text.slice(lastIndex) }, `t-${lastIndex}`));
    }
    return _jsx(_Fragment, { children: nodes.filter((node) => node !== null) });
};
const RenderInline = React.memo(RenderInlineInternal);
const RenderCodeBlockInternal = ({ content, lang, isPending, availableTerminalHeight, terminalWidth, }) => {
    const MIN_LINES_FOR_MESSAGE = 1; // Minimum lines to show before the "generating more" message
    const RESERVED_LINES = 2; // Lines reserved for the message itself and potential padding
    if (isPending && availableTerminalHeight !== undefined) {
        const MAX_CODE_LINES_WHEN_PENDING = Math.max(0, availableTerminalHeight - CODE_BLOCK_PADDING * 2 - RESERVED_LINES);
        if (content.length > MAX_CODE_LINES_WHEN_PENDING) {
            if (MAX_CODE_LINES_WHEN_PENDING < MIN_LINES_FOR_MESSAGE) {
                // Not enough space to even show the message meaningfully
                return (_jsx(Box, { padding: CODE_BLOCK_PADDING, children: _jsx(Text, { color: Colors.Gray, children: "... code is being written ..." }) }));
            }
            const truncatedContent = content.slice(0, MAX_CODE_LINES_WHEN_PENDING);
            const colorizedTruncatedCode = colorizeCode(truncatedContent.join('\n'), lang, availableTerminalHeight, terminalWidth - CODE_BLOCK_PADDING * 2);
            return (_jsxs(Box, { flexDirection: "column", padding: CODE_BLOCK_PADDING, children: [colorizedTruncatedCode, _jsx(Text, { color: Colors.Gray, children: "... generating more ..." })] }));
        }
    }
    const fullContent = content.join('\n');
    const colorizedCode = colorizeCode(fullContent, lang, availableTerminalHeight, terminalWidth - CODE_BLOCK_PADDING * 2);
    return (_jsx(Box, { flexDirection: "column", padding: CODE_BLOCK_PADDING, width: terminalWidth, flexShrink: 0, children: colorizedCode }));
};
const RenderCodeBlock = React.memo(RenderCodeBlockInternal);
const RenderListItemInternal = ({ itemText, type, marker, leadingWhitespace = '', }) => {
    const prefix = type === 'ol' ? `${marker}. ` : `${marker} `;
    const prefixWidth = prefix.length;
    const indentation = leadingWhitespace.length;
    return (_jsxs(Box, { paddingLeft: indentation + LIST_ITEM_PREFIX_PADDING, flexDirection: "row", children: [_jsx(Box, { width: prefixWidth, children: _jsx(Text, { children: prefix }) }), _jsx(Box, { flexGrow: LIST_ITEM_TEXT_FLEX_GROW, children: _jsx(Text, { wrap: "wrap", children: _jsx(RenderInline, { text: itemText }) }) })] }));
};
const RenderListItem = React.memo(RenderListItemInternal);
const RenderTableInternal = ({ headers, rows, terminalWidth, }) => (_jsx(TableRenderer, { headers: headers, rows: rows, terminalWidth: terminalWidth }));
const RenderTable = React.memo(RenderTableInternal);
export const MarkdownDisplay = React.memo(MarkdownDisplayInternal);
//# sourceMappingURL=MarkdownDisplay.js.map