/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import stripAnsi from 'strip-ansi';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import pathMod from 'path';
import { useState, useCallback, useEffect, useMemo, useReducer } from 'react';
import stringWidth from 'string-width';
import { unescapePath } from '@alcub3/alcub3-cli-core';
import { toCodePoints, cpLen, cpSlice } from '../../utils/textUtils.js';
// Simple helper for word‑wise ops.
function isWordChar(ch) {
    if (ch === undefined) {
        return false;
    }
    return !/[\s,.;!?]/.test(ch);
}
/**
 * Strip characters that can break terminal rendering.
 *
 * Strip ANSI escape codes and control characters except for line breaks.
 * Control characters such as delete break terminal UI rendering.
 */
function stripUnsafeCharacters(str) {
    const stripped = stripAnsi(str);
    return toCodePoints(stripAnsi(stripped))
        .filter((char) => {
        if (char.length > 1)
            return false;
        const code = char.codePointAt(0);
        if (code === undefined) {
            return false;
        }
        const isUnsafe = code === 127 || (code <= 31 && code !== 13 && code !== 10);
        return !isUnsafe;
    })
        .join('');
}
function clamp(v, min, max) {
    return v < min ? min : v > max ? max : v;
}
function calculateInitialCursorPosition(initialLines, offset) {
    let remainingChars = offset;
    let row = 0;
    while (row < initialLines.length) {
        const lineLength = cpLen(initialLines[row]);
        // Add 1 for the newline character (except for the last line)
        const totalCharsInLineAndNewline = lineLength + (row < initialLines.length - 1 ? 1 : 0);
        if (remainingChars <= lineLength) {
            // Cursor is on this line
            return [row, remainingChars];
        }
        remainingChars -= totalCharsInLineAndNewline;
        row++;
    }
    // Offset is beyond the text, place cursor at the end of the last line
    if (initialLines.length > 0) {
        const lastRow = initialLines.length - 1;
        return [lastRow, cpLen(initialLines[lastRow])];
    }
    return [0, 0]; // Default for empty text
}
export function offsetToLogicalPos(text, offset) {
    let row = 0;
    let col = 0;
    let currentOffset = 0;
    if (offset === 0)
        return [0, 0];
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineLength = cpLen(line);
        const lineLengthWithNewline = lineLength + (i < lines.length - 1 ? 1 : 0);
        if (offset <= currentOffset + lineLength) {
            // Check against lineLength first
            row = i;
            col = offset - currentOffset;
            return [row, col];
        }
        else if (offset <= currentOffset + lineLengthWithNewline) {
            // Check if offset is the newline itself
            row = i;
            col = lineLength; // Position cursor at the end of the current line content
            // If the offset IS the newline, and it's not the last line, advance to next line, col 0
            if (offset === currentOffset + lineLengthWithNewline &&
                i < lines.length - 1) {
                return [i + 1, 0];
            }
            return [row, col]; // Otherwise, it's at the end of the current line content
        }
        currentOffset += lineLengthWithNewline;
    }
    // If offset is beyond the text length, place cursor at the end of the last line
    // or [0,0] if text is empty
    if (lines.length > 0) {
        row = lines.length - 1;
        col = cpLen(lines[row]);
    }
    else {
        row = 0;
        col = 0;
    }
    return [row, col];
}
// Helper to calculate visual lines and map cursor positions
function calculateVisualLayout(logicalLines, logicalCursor, viewportWidth) {
    const visualLines = [];
    const logicalToVisualMap = [];
    const visualToLogicalMap = [];
    let currentVisualCursor = [0, 0];
    logicalLines.forEach((logLine, logIndex) => {
        logicalToVisualMap[logIndex] = [];
        if (logLine.length === 0) {
            // Handle empty logical line
            logicalToVisualMap[logIndex].push([visualLines.length, 0]);
            visualToLogicalMap.push([logIndex, 0]);
            visualLines.push('');
            if (logIndex === logicalCursor[0] && logicalCursor[1] === 0) {
                currentVisualCursor = [visualLines.length - 1, 0];
            }
        }
        else {
            // Non-empty logical line
            let currentPosInLogLine = 0; // Tracks position within the current logical line (code point index)
            const codePointsInLogLine = toCodePoints(logLine);
            while (currentPosInLogLine < codePointsInLogLine.length) {
                let currentChunk = '';
                let currentChunkVisualWidth = 0;
                let numCodePointsInChunk = 0;
                let lastWordBreakPoint = -1; // Index in codePointsInLogLine for word break
                let numCodePointsAtLastWordBreak = 0;
                // Iterate through code points to build the current visual line (chunk)
                for (let i = currentPosInLogLine; i < codePointsInLogLine.length; i++) {
                    const char = codePointsInLogLine[i];
                    const charVisualWidth = stringWidth(char);
                    if (currentChunkVisualWidth + charVisualWidth > viewportWidth) {
                        // Character would exceed viewport width
                        if (lastWordBreakPoint !== -1 &&
                            numCodePointsAtLastWordBreak > 0 &&
                            currentPosInLogLine + numCodePointsAtLastWordBreak < i) {
                            // We have a valid word break point to use, and it's not the start of the current segment
                            currentChunk = codePointsInLogLine
                                .slice(currentPosInLogLine, currentPosInLogLine + numCodePointsAtLastWordBreak)
                                .join('');
                            numCodePointsInChunk = numCodePointsAtLastWordBreak;
                        }
                        else {
                            // No word break, or word break is at the start of this potential chunk, or word break leads to empty chunk.
                            // Hard break: take characters up to viewportWidth, or just the current char if it alone is too wide.
                            if (numCodePointsInChunk === 0 &&
                                charVisualWidth > viewportWidth) {
                                // Single character is wider than viewport, take it anyway
                                currentChunk = char;
                                numCodePointsInChunk = 1;
                            }
                            else if (numCodePointsInChunk === 0 &&
                                charVisualWidth <= viewportWidth) {
                                // This case should ideally be caught by the next iteration if the char fits.
                                // If it doesn't fit (because currentChunkVisualWidth was already > 0 from a previous char that filled the line),
                                // then numCodePointsInChunk would not be 0.
                                // This branch means the current char *itself* doesn't fit an empty line, which is handled by the above.
                                // If we are here, it means the loop should break and the current chunk (which is empty) is finalized.
                            }
                        }
                        break; // Break from inner loop to finalize this chunk
                    }
                    currentChunk += char;
                    currentChunkVisualWidth += charVisualWidth;
                    numCodePointsInChunk++;
                    // Check for word break opportunity (space)
                    if (char === ' ') {
                        lastWordBreakPoint = i; // Store code point index of the space
                        // Store the state *before* adding the space, if we decide to break here.
                        numCodePointsAtLastWordBreak = numCodePointsInChunk - 1; // Chars *before* the space
                    }
                }
                // If the inner loop completed without breaking (i.e., remaining text fits)
                // or if the loop broke but numCodePointsInChunk is still 0 (e.g. first char too wide for empty line)
                if (numCodePointsInChunk === 0 &&
                    currentPosInLogLine < codePointsInLogLine.length) {
                    // This can happen if the very first character considered for a new visual line is wider than the viewport.
                    // In this case, we take that single character.
                    const firstChar = codePointsInLogLine[currentPosInLogLine];
                    currentChunk = firstChar;
                    numCodePointsInChunk = 1; // Ensure we advance
                }
                // If after everything, numCodePointsInChunk is still 0 but we haven't processed the whole logical line,
                // it implies an issue, like viewportWidth being 0 or less. Avoid infinite loop.
                if (numCodePointsInChunk === 0 &&
                    currentPosInLogLine < codePointsInLogLine.length) {
                    // Force advance by one character to prevent infinite loop if something went wrong
                    currentChunk = codePointsInLogLine[currentPosInLogLine];
                    numCodePointsInChunk = 1;
                }
                logicalToVisualMap[logIndex].push([
                    visualLines.length,
                    currentPosInLogLine,
                ]);
                visualToLogicalMap.push([logIndex, currentPosInLogLine]);
                visualLines.push(currentChunk);
                // Cursor mapping logic
                // Note: currentPosInLogLine here is the start of the currentChunk within the logical line.
                if (logIndex === logicalCursor[0]) {
                    const cursorLogCol = logicalCursor[1]; // This is a code point index
                    if (cursorLogCol >= currentPosInLogLine &&
                        cursorLogCol < currentPosInLogLine + numCodePointsInChunk // Cursor is within this chunk
                    ) {
                        currentVisualCursor = [
                            visualLines.length - 1,
                            cursorLogCol - currentPosInLogLine, // Visual col is also code point index within visual line
                        ];
                    }
                    else if (cursorLogCol === currentPosInLogLine + numCodePointsInChunk &&
                        numCodePointsInChunk > 0) {
                        // Cursor is exactly at the end of this non-empty chunk
                        currentVisualCursor = [
                            visualLines.length - 1,
                            numCodePointsInChunk,
                        ];
                    }
                }
                const logicalStartOfThisChunk = currentPosInLogLine;
                currentPosInLogLine += numCodePointsInChunk;
                // If the chunk processed did not consume the entire logical line,
                // and the character immediately following the chunk is a space,
                // advance past this space as it acted as a delimiter for word wrapping.
                if (logicalStartOfThisChunk + numCodePointsInChunk <
                    codePointsInLogLine.length &&
                    currentPosInLogLine < codePointsInLogLine.length && // Redundant if previous is true, but safe
                    codePointsInLogLine[currentPosInLogLine] === ' ') {
                    currentPosInLogLine++;
                }
            }
            // After all chunks of a non-empty logical line are processed,
            // if the cursor is at the very end of this logical line, update visual cursor.
            if (logIndex === logicalCursor[0] &&
                logicalCursor[1] === codePointsInLogLine.length // Cursor at end of logical line
            ) {
                const lastVisualLineIdx = visualLines.length - 1;
                if (lastVisualLineIdx >= 0 &&
                    visualLines[lastVisualLineIdx] !== undefined) {
                    currentVisualCursor = [
                        lastVisualLineIdx,
                        cpLen(visualLines[lastVisualLineIdx]), // Cursor at end of last visual line for this logical line
                    ];
                }
            }
        }
    });
    // If the entire logical text was empty, ensure there's one empty visual line.
    if (logicalLines.length === 0 ||
        (logicalLines.length === 1 && logicalLines[0] === '')) {
        if (visualLines.length === 0) {
            visualLines.push('');
            if (!logicalToVisualMap[0])
                logicalToVisualMap[0] = [];
            logicalToVisualMap[0].push([0, 0]);
            visualToLogicalMap.push([0, 0]);
        }
        currentVisualCursor = [0, 0];
    }
    // Handle cursor at the very end of the text (after all processing)
    // This case might be covered by the loop end condition now, but kept for safety.
    else if (logicalCursor[0] === logicalLines.length - 1 &&
        logicalCursor[1] === cpLen(logicalLines[logicalLines.length - 1]) &&
        visualLines.length > 0) {
        const lastVisLineIdx = visualLines.length - 1;
        currentVisualCursor = [lastVisLineIdx, cpLen(visualLines[lastVisLineIdx])];
    }
    return {
        visualLines,
        visualCursor: currentVisualCursor,
        logicalToVisualMap,
        visualToLogicalMap,
    };
}
const historyLimit = 100;
export function textBufferReducer(state, action) {
    const pushUndo = (currentState) => {
        const snapshot = {
            lines: [...currentState.lines],
            cursorRow: currentState.cursorRow,
            cursorCol: currentState.cursorCol,
        };
        const newStack = [...currentState.undoStack, snapshot];
        if (newStack.length > historyLimit) {
            newStack.shift();
        }
        return { ...currentState, undoStack: newStack, redoStack: [] };
    };
    const currentLine = (r) => state.lines[r] ?? '';
    const currentLineLen = (r) => cpLen(currentLine(r));
    switch (action.type) {
        case 'set_text': {
            let nextState = state;
            if (action.pushToUndo !== false) {
                nextState = pushUndo(state);
            }
            const newContentLines = action.payload
                .replace(/\r\n?/g, '\n')
                .split('\n');
            const lines = newContentLines.length === 0 ? [''] : newContentLines;
            const lastNewLineIndex = lines.length - 1;
            return {
                ...nextState,
                lines,
                cursorRow: lastNewLineIndex,
                cursorCol: cpLen(lines[lastNewLineIndex] ?? ''),
                preferredCol: null,
            };
        }
        case 'insert': {
            const nextState = pushUndo(state);
            const newLines = [...nextState.lines];
            let newCursorRow = nextState.cursorRow;
            let newCursorCol = nextState.cursorCol;
            const currentLine = (r) => newLines[r] ?? '';
            const str = stripUnsafeCharacters(action.payload.replace(/\r\n/g, '\n').replace(/\r/g, '\n'));
            const parts = str.split('\n');
            const lineContent = currentLine(newCursorRow);
            const before = cpSlice(lineContent, 0, newCursorCol);
            const after = cpSlice(lineContent, newCursorCol);
            if (parts.length > 1) {
                newLines[newCursorRow] = before + parts[0];
                const remainingParts = parts.slice(1);
                const lastPartOriginal = remainingParts.pop() ?? '';
                newLines.splice(newCursorRow + 1, 0, ...remainingParts);
                newLines.splice(newCursorRow + parts.length - 1, 0, lastPartOriginal + after);
                newCursorRow = newCursorRow + parts.length - 1;
                newCursorCol = cpLen(lastPartOriginal);
            }
            else {
                newLines[newCursorRow] = before + parts[0] + after;
                newCursorCol = cpLen(before) + cpLen(parts[0]);
            }
            return {
                ...nextState,
                lines: newLines,
                cursorRow: newCursorRow,
                cursorCol: newCursorCol,
                preferredCol: null,
            };
        }
        case 'backspace': {
            const nextState = pushUndo(state);
            const newLines = [...nextState.lines];
            let newCursorRow = nextState.cursorRow;
            let newCursorCol = nextState.cursorCol;
            const currentLine = (r) => newLines[r] ?? '';
            if (newCursorCol === 0 && newCursorRow === 0)
                return state;
            if (newCursorCol > 0) {
                const lineContent = currentLine(newCursorRow);
                newLines[newCursorRow] =
                    cpSlice(lineContent, 0, newCursorCol - 1) +
                        cpSlice(lineContent, newCursorCol);
                newCursorCol--;
            }
            else if (newCursorRow > 0) {
                const prevLineContent = currentLine(newCursorRow - 1);
                const currentLineContentVal = currentLine(newCursorRow);
                const newCol = cpLen(prevLineContent);
                newLines[newCursorRow - 1] = prevLineContent + currentLineContentVal;
                newLines.splice(newCursorRow, 1);
                newCursorRow--;
                newCursorCol = newCol;
            }
            return {
                ...nextState,
                lines: newLines,
                cursorRow: newCursorRow,
                cursorCol: newCursorCol,
                preferredCol: null,
            };
        }
        case 'set_viewport_width': {
            if (action.payload === state.viewportWidth) {
                return state;
            }
            return { ...state, viewportWidth: action.payload };
        }
        case 'move': {
            const { dir } = action.payload;
            const { lines, cursorRow, cursorCol, viewportWidth } = state;
            const visualLayout = calculateVisualLayout(lines, [cursorRow, cursorCol], viewportWidth);
            const { visualLines, visualCursor, visualToLogicalMap } = visualLayout;
            let newVisualRow = visualCursor[0];
            let newVisualCol = visualCursor[1];
            let newPreferredCol = state.preferredCol;
            const currentVisLineLen = cpLen(visualLines[newVisualRow] ?? '');
            switch (dir) {
                case 'left':
                    newPreferredCol = null;
                    if (newVisualCol > 0) {
                        newVisualCol--;
                    }
                    else if (newVisualRow > 0) {
                        newVisualRow--;
                        newVisualCol = cpLen(visualLines[newVisualRow] ?? '');
                    }
                    break;
                case 'right':
                    newPreferredCol = null;
                    if (newVisualCol < currentVisLineLen) {
                        newVisualCol++;
                    }
                    else if (newVisualRow < visualLines.length - 1) {
                        newVisualRow++;
                        newVisualCol = 0;
                    }
                    break;
                case 'up':
                    if (newVisualRow > 0) {
                        if (newPreferredCol === null)
                            newPreferredCol = newVisualCol;
                        newVisualRow--;
                        newVisualCol = clamp(newPreferredCol, 0, cpLen(visualLines[newVisualRow] ?? ''));
                    }
                    break;
                case 'down':
                    if (newVisualRow < visualLines.length - 1) {
                        if (newPreferredCol === null)
                            newPreferredCol = newVisualCol;
                        newVisualRow++;
                        newVisualCol = clamp(newPreferredCol, 0, cpLen(visualLines[newVisualRow] ?? ''));
                    }
                    break;
                case 'home':
                    newPreferredCol = null;
                    newVisualCol = 0;
                    break;
                case 'end':
                    newPreferredCol = null;
                    newVisualCol = currentVisLineLen;
                    break;
                case 'wordLeft': {
                    const { cursorRow, cursorCol, lines } = state;
                    if (cursorCol === 0 && cursorRow === 0)
                        return state;
                    let newCursorRow = cursorRow;
                    let newCursorCol = cursorCol;
                    if (cursorCol === 0) {
                        newCursorRow--;
                        newCursorCol = cpLen(lines[newCursorRow] ?? '');
                    }
                    else {
                        const lineContent = lines[cursorRow];
                        const arr = toCodePoints(lineContent);
                        let start = cursorCol;
                        let onlySpaces = true;
                        for (let i = 0; i < start; i++) {
                            if (isWordChar(arr[i])) {
                                onlySpaces = false;
                                break;
                            }
                        }
                        if (onlySpaces && start > 0) {
                            start--;
                        }
                        else {
                            while (start > 0 && !isWordChar(arr[start - 1]))
                                start--;
                            while (start > 0 && isWordChar(arr[start - 1]))
                                start--;
                        }
                        newCursorCol = start;
                    }
                    return {
                        ...state,
                        cursorRow: newCursorRow,
                        cursorCol: newCursorCol,
                        preferredCol: null,
                    };
                }
                case 'wordRight': {
                    const { cursorRow, cursorCol, lines } = state;
                    if (cursorRow === lines.length - 1 &&
                        cursorCol === cpLen(lines[cursorRow] ?? '')) {
                        return state;
                    }
                    let newCursorRow = cursorRow;
                    let newCursorCol = cursorCol;
                    const lineContent = lines[cursorRow] ?? '';
                    const arr = toCodePoints(lineContent);
                    if (cursorCol >= arr.length) {
                        newCursorRow++;
                        newCursorCol = 0;
                    }
                    else {
                        let end = cursorCol;
                        while (end < arr.length && !isWordChar(arr[end]))
                            end++;
                        while (end < arr.length && isWordChar(arr[end]))
                            end++;
                        newCursorCol = end;
                    }
                    return {
                        ...state,
                        cursorRow: newCursorRow,
                        cursorCol: newCursorCol,
                        preferredCol: null,
                    };
                }
                default:
                    break;
            }
            if (visualToLogicalMap[newVisualRow]) {
                const [logRow, logStartCol] = visualToLogicalMap[newVisualRow];
                return {
                    ...state,
                    cursorRow: logRow,
                    cursorCol: clamp(logStartCol + newVisualCol, 0, cpLen(state.lines[logRow] ?? '')),
                    preferredCol: newPreferredCol,
                };
            }
            return state;
        }
        case 'delete': {
            const { cursorRow, cursorCol, lines } = state;
            const lineContent = currentLine(cursorRow);
            if (cursorCol < currentLineLen(cursorRow)) {
                const nextState = pushUndo(state);
                const newLines = [...nextState.lines];
                newLines[cursorRow] =
                    cpSlice(lineContent, 0, cursorCol) +
                        cpSlice(lineContent, cursorCol + 1);
                return { ...nextState, lines: newLines, preferredCol: null };
            }
            else if (cursorRow < lines.length - 1) {
                const nextState = pushUndo(state);
                const nextLineContent = currentLine(cursorRow + 1);
                const newLines = [...nextState.lines];
                newLines[cursorRow] = lineContent + nextLineContent;
                newLines.splice(cursorRow + 1, 1);
                return { ...nextState, lines: newLines, preferredCol: null };
            }
            return state;
        }
        case 'delete_word_left': {
            const { cursorRow, cursorCol } = state;
            if (cursorCol === 0 && cursorRow === 0)
                return state;
            if (cursorCol === 0) {
                // Act as a backspace
                const nextState = pushUndo(state);
                const prevLineContent = currentLine(cursorRow - 1);
                const currentLineContentVal = currentLine(cursorRow);
                const newCol = cpLen(prevLineContent);
                const newLines = [...nextState.lines];
                newLines[cursorRow - 1] = prevLineContent + currentLineContentVal;
                newLines.splice(cursorRow, 1);
                return {
                    ...nextState,
                    lines: newLines,
                    cursorRow: cursorRow - 1,
                    cursorCol: newCol,
                    preferredCol: null,
                };
            }
            const nextState = pushUndo(state);
            const lineContent = currentLine(cursorRow);
            const arr = toCodePoints(lineContent);
            let start = cursorCol;
            let onlySpaces = true;
            for (let i = 0; i < start; i++) {
                if (isWordChar(arr[i])) {
                    onlySpaces = false;
                    break;
                }
            }
            if (onlySpaces && start > 0) {
                start--;
            }
            else {
                while (start > 0 && !isWordChar(arr[start - 1]))
                    start--;
                while (start > 0 && isWordChar(arr[start - 1]))
                    start--;
            }
            const newLines = [...nextState.lines];
            newLines[cursorRow] =
                cpSlice(lineContent, 0, start) + cpSlice(lineContent, cursorCol);
            return {
                ...nextState,
                lines: newLines,
                cursorCol: start,
                preferredCol: null,
            };
        }
        case 'delete_word_right': {
            const { cursorRow, cursorCol, lines } = state;
            const lineContent = currentLine(cursorRow);
            const arr = toCodePoints(lineContent);
            if (cursorCol >= arr.length && cursorRow === lines.length - 1)
                return state;
            if (cursorCol >= arr.length) {
                // Act as a delete
                const nextState = pushUndo(state);
                const nextLineContent = currentLine(cursorRow + 1);
                const newLines = [...nextState.lines];
                newLines[cursorRow] = lineContent + nextLineContent;
                newLines.splice(cursorRow + 1, 1);
                return { ...nextState, lines: newLines, preferredCol: null };
            }
            const nextState = pushUndo(state);
            let end = cursorCol;
            while (end < arr.length && !isWordChar(arr[end]))
                end++;
            while (end < arr.length && isWordChar(arr[end]))
                end++;
            const newLines = [...nextState.lines];
            newLines[cursorRow] =
                cpSlice(lineContent, 0, cursorCol) + cpSlice(lineContent, end);
            return { ...nextState, lines: newLines, preferredCol: null };
        }
        case 'kill_line_right': {
            const { cursorRow, cursorCol, lines } = state;
            const lineContent = currentLine(cursorRow);
            if (cursorCol < currentLineLen(cursorRow)) {
                const nextState = pushUndo(state);
                const newLines = [...nextState.lines];
                newLines[cursorRow] = cpSlice(lineContent, 0, cursorCol);
                return { ...nextState, lines: newLines };
            }
            else if (cursorRow < lines.length - 1) {
                // Act as a delete
                const nextState = pushUndo(state);
                const nextLineContent = currentLine(cursorRow + 1);
                const newLines = [...nextState.lines];
                newLines[cursorRow] = lineContent + nextLineContent;
                newLines.splice(cursorRow + 1, 1);
                return { ...nextState, lines: newLines, preferredCol: null };
            }
            return state;
        }
        case 'kill_line_left': {
            const { cursorRow, cursorCol } = state;
            if (cursorCol > 0) {
                const nextState = pushUndo(state);
                const lineContent = currentLine(cursorRow);
                const newLines = [...nextState.lines];
                newLines[cursorRow] = cpSlice(lineContent, cursorCol);
                return {
                    ...nextState,
                    lines: newLines,
                    cursorCol: 0,
                    preferredCol: null,
                };
            }
            return state;
        }
        case 'undo': {
            const stateToRestore = state.undoStack[state.undoStack.length - 1];
            if (!stateToRestore)
                return state;
            const currentSnapshot = {
                lines: [...state.lines],
                cursorRow: state.cursorRow,
                cursorCol: state.cursorCol,
            };
            return {
                ...state,
                ...stateToRestore,
                undoStack: state.undoStack.slice(0, -1),
                redoStack: [...state.redoStack, currentSnapshot],
            };
        }
        case 'redo': {
            const stateToRestore = state.redoStack[state.redoStack.length - 1];
            if (!stateToRestore)
                return state;
            const currentSnapshot = {
                lines: [...state.lines],
                cursorRow: state.cursorRow,
                cursorCol: state.cursorCol,
            };
            return {
                ...state,
                ...stateToRestore,
                redoStack: state.redoStack.slice(0, -1),
                undoStack: [...state.undoStack, currentSnapshot],
            };
        }
        case 'replace_range': {
            const { startRow, startCol, endRow, endCol, text } = action.payload;
            if (startRow > endRow ||
                (startRow === endRow && startCol > endCol) ||
                startRow < 0 ||
                startCol < 0 ||
                endRow >= state.lines.length ||
                (endRow < state.lines.length && endCol > currentLineLen(endRow))) {
                return state; // Invalid range
            }
            const nextState = pushUndo(state);
            const newLines = [...nextState.lines];
            const sCol = clamp(startCol, 0, currentLineLen(startRow));
            const eCol = clamp(endCol, 0, currentLineLen(endRow));
            const prefix = cpSlice(currentLine(startRow), 0, sCol);
            const suffix = cpSlice(currentLine(endRow), eCol);
            const normalisedReplacement = text
                .replace(/\r\n/g, '\n')
                .replace(/\r/g, '\n');
            const replacementParts = normalisedReplacement.split('\n');
            // Replace the content
            if (startRow === endRow) {
                newLines[startRow] = prefix + normalisedReplacement + suffix;
            }
            else {
                const firstLine = prefix + replacementParts[0];
                if (replacementParts.length === 1) {
                    // Single line of replacement text, but spanning multiple original lines
                    newLines.splice(startRow, endRow - startRow + 1, firstLine + suffix);
                }
                else {
                    // Multi-line replacement text
                    const lastLine = replacementParts[replacementParts.length - 1] + suffix;
                    const middleLines = replacementParts.slice(1, -1);
                    newLines.splice(startRow, endRow - startRow + 1, firstLine, ...middleLines, lastLine);
                }
            }
            const finalCursorRow = startRow + replacementParts.length - 1;
            const finalCursorCol = (replacementParts.length > 1 ? 0 : sCol) +
                cpLen(replacementParts[replacementParts.length - 1]);
            return {
                ...nextState,
                lines: newLines,
                cursorRow: finalCursorRow,
                cursorCol: finalCursorCol,
                preferredCol: null,
            };
        }
        case 'move_to_offset': {
            const { offset } = action.payload;
            const [newRow, newCol] = offsetToLogicalPos(state.lines.join('\n'), offset);
            return {
                ...state,
                cursorRow: newRow,
                cursorCol: newCol,
                preferredCol: null,
            };
        }
        case 'create_undo_snapshot': {
            return pushUndo(state);
        }
        default: {
            const exhaustiveCheck = action;
            console.error(`Unknown action encountered: ${exhaustiveCheck}`);
            return state;
        }
    }
}
// --- End of reducer logic ---
export function useTextBuffer({ initialText = '', initialCursorOffset = 0, viewport, stdin, setRawMode, onChange, isValidPath, }) {
    const initialState = useMemo(() => {
        const lines = initialText.split('\n');
        const [initialCursorRow, initialCursorCol] = calculateInitialCursorPosition(lines.length === 0 ? [''] : lines, initialCursorOffset);
        return {
            lines: lines.length === 0 ? [''] : lines,
            cursorRow: initialCursorRow,
            cursorCol: initialCursorCol,
            preferredCol: null,
            undoStack: [],
            redoStack: [],
            clipboard: null,
            selectionAnchor: null,
            viewportWidth: viewport.width,
        };
    }, [initialText, initialCursorOffset, viewport.width]);
    const [state, dispatch] = useReducer(textBufferReducer, initialState);
    const { lines, cursorRow, cursorCol, preferredCol, selectionAnchor } = state;
    const text = useMemo(() => lines.join('\n'), [lines]);
    const visualLayout = useMemo(() => calculateVisualLayout(lines, [cursorRow, cursorCol], state.viewportWidth), [lines, cursorRow, cursorCol, state.viewportWidth]);
    const { visualLines, visualCursor } = visualLayout;
    const [visualScrollRow, setVisualScrollRow] = useState(0);
    useEffect(() => {
        if (onChange) {
            onChange(text);
        }
    }, [text, onChange]);
    useEffect(() => {
        dispatch({ type: 'set_viewport_width', payload: viewport.width });
    }, [viewport.width]);
    // Update visual scroll (vertical)
    useEffect(() => {
        const { height } = viewport;
        let newVisualScrollRow = visualScrollRow;
        if (visualCursor[0] < visualScrollRow) {
            newVisualScrollRow = visualCursor[0];
        }
        else if (visualCursor[0] >= visualScrollRow + height) {
            newVisualScrollRow = visualCursor[0] - height + 1;
        }
        if (newVisualScrollRow !== visualScrollRow) {
            setVisualScrollRow(newVisualScrollRow);
        }
    }, [visualCursor, visualScrollRow, viewport]);
    const insert = useCallback((ch) => {
        if (/[\n\r]/.test(ch)) {
            dispatch({ type: 'insert', payload: ch });
            return;
        }
        const minLengthToInferAsDragDrop = 3;
        if (ch.length >= minLengthToInferAsDragDrop) {
            let potentialPath = ch;
            if (potentialPath.length > 2 &&
                potentialPath.startsWith("'") &&
                potentialPath.endsWith("'")) {
                potentialPath = ch.slice(1, -1);
            }
            potentialPath = potentialPath.trim();
            if (isValidPath(unescapePath(potentialPath))) {
                ch = `@${potentialPath}`;
            }
        }
        let currentText = '';
        for (const char of toCodePoints(ch)) {
            if (char.codePointAt(0) === 127) {
                if (currentText.length > 0) {
                    dispatch({ type: 'insert', payload: currentText });
                    currentText = '';
                }
                dispatch({ type: 'backspace' });
            }
            else {
                currentText += char;
            }
        }
        if (currentText.length > 0) {
            dispatch({ type: 'insert', payload: currentText });
        }
    }, [isValidPath]);
    const newline = useCallback(() => {
        dispatch({ type: 'insert', payload: '\n' });
    }, []);
    const backspace = useCallback(() => {
        dispatch({ type: 'backspace' });
    }, []);
    const del = useCallback(() => {
        dispatch({ type: 'delete' });
    }, []);
    const move = useCallback((dir) => {
        dispatch({ type: 'move', payload: { dir } });
    }, []);
    const undo = useCallback(() => {
        dispatch({ type: 'undo' });
    }, []);
    const redo = useCallback(() => {
        dispatch({ type: 'redo' });
    }, []);
    const setText = useCallback((newText) => {
        dispatch({ type: 'set_text', payload: newText });
    }, []);
    const deleteWordLeft = useCallback(() => {
        dispatch({ type: 'delete_word_left' });
    }, []);
    const deleteWordRight = useCallback(() => {
        dispatch({ type: 'delete_word_right' });
    }, []);
    const killLineRight = useCallback(() => {
        dispatch({ type: 'kill_line_right' });
    }, []);
    const killLineLeft = useCallback(() => {
        dispatch({ type: 'kill_line_left' });
    }, []);
    const openInExternalEditor = useCallback(async (opts = {}) => {
        const editor = opts.editor ??
            process.env['VISUAL'] ??
            process.env['EDITOR'] ??
            (process.platform === 'win32' ? 'notepad' : 'vi');
        const tmpDir = fs.mkdtempSync(pathMod.join(os.tmpdir(), 'gemini-edit-'));
        const filePath = pathMod.join(tmpDir, 'buffer.txt');
        fs.writeFileSync(filePath, text, 'utf8');
        dispatch({ type: 'create_undo_snapshot' });
        const wasRaw = stdin?.isRaw ?? false;
        try {
            setRawMode?.(false);
            const { status, error } = spawnSync(editor, [filePath], {
                stdio: 'inherit',
            });
            if (error)
                throw error;
            if (typeof status === 'number' && status !== 0)
                throw new Error(`External editor exited with status ${status}`);
            let newText = fs.readFileSync(filePath, 'utf8');
            newText = newText.replace(/\r\n?/g, '\n');
            dispatch({ type: 'set_text', payload: newText, pushToUndo: false });
        }
        catch (err) {
            console.error('[useTextBuffer] external editor error', err);
        }
        finally {
            if (wasRaw)
                setRawMode?.(true);
            try {
                fs.unlinkSync(filePath);
            }
            catch {
                /* ignore */
            }
            try {
                fs.rmdirSync(tmpDir);
            }
            catch {
                /* ignore */
            }
        }
    }, [text, stdin, setRawMode]);
    const handleInput = useCallback((key) => {
        const { sequence: input } = key;
        if (key.name === 'return' ||
            input === '\r' ||
            input === '\n' ||
            input === '\\\r' // VSCode terminal represents shift + enter this way
        )
            newline();
        else if (key.name === 'left' && !key.meta && !key.ctrl)
            move('left');
        else if (key.ctrl && key.name === 'b')
            move('left');
        else if (key.name === 'right' && !key.meta && !key.ctrl)
            move('right');
        else if (key.ctrl && key.name === 'f')
            move('right');
        else if (key.name === 'up')
            move('up');
        else if (key.name === 'down')
            move('down');
        else if ((key.ctrl || key.meta) && key.name === 'left')
            move('wordLeft');
        else if (key.meta && key.name === 'b')
            move('wordLeft');
        else if ((key.ctrl || key.meta) && key.name === 'right')
            move('wordRight');
        else if (key.meta && key.name === 'f')
            move('wordRight');
        else if (key.name === 'home')
            move('home');
        else if (key.ctrl && key.name === 'a')
            move('home');
        else if (key.name === 'end')
            move('end');
        else if (key.ctrl && key.name === 'e')
            move('end');
        else if (key.ctrl && key.name === 'w')
            deleteWordLeft();
        else if ((key.meta || key.ctrl) &&
            (key.name === 'backspace' || input === '\x7f'))
            deleteWordLeft();
        else if ((key.meta || key.ctrl) && key.name === 'delete')
            deleteWordRight();
        else if (key.name === 'backspace' ||
            input === '\x7f' ||
            (key.ctrl && key.name === 'h'))
            backspace();
        else if (key.name === 'delete' || (key.ctrl && key.name === 'd'))
            del();
        else if (input && !key.ctrl && !key.meta) {
            insert(input);
        }
    }, [newline, move, deleteWordLeft, deleteWordRight, backspace, del, insert]);
    const renderedVisualLines = useMemo(() => visualLines.slice(visualScrollRow, visualScrollRow + viewport.height), [visualLines, visualScrollRow, viewport.height]);
    const replaceRange = useCallback((startRow, startCol, endRow, endCol, text) => {
        dispatch({
            type: 'replace_range',
            payload: { startRow, startCol, endRow, endCol, text },
        });
    }, []);
    const replaceRangeByOffset = useCallback((startOffset, endOffset, replacementText) => {
        const [startRow, startCol] = offsetToLogicalPos(text, startOffset);
        const [endRow, endCol] = offsetToLogicalPos(text, endOffset);
        replaceRange(startRow, startCol, endRow, endCol, replacementText);
    }, [text, replaceRange]);
    const moveToOffset = useCallback((offset) => {
        dispatch({ type: 'move_to_offset', payload: { offset } });
    }, []);
    const returnValue = {
        lines,
        text,
        cursor: [cursorRow, cursorCol],
        preferredCol,
        selectionAnchor,
        allVisualLines: visualLines,
        viewportVisualLines: renderedVisualLines,
        visualCursor,
        visualScrollRow,
        setText,
        insert,
        newline,
        backspace,
        del,
        move,
        undo,
        redo,
        replaceRange,
        replaceRangeByOffset,
        moveToOffset,
        deleteWordLeft,
        deleteWordRight,
        killLineRight,
        killLineLeft,
        handleInput,
        openInExternalEditor,
    };
    return returnValue;
}
//# sourceMappingURL=text-buffer.js.map