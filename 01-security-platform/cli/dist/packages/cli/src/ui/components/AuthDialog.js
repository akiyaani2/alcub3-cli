import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import { Colors } from '../colors.js';
import { RadioButtonSelect } from './shared/RadioButtonSelect.js';
import { SettingScope } from '../../config/settings.js';
import { AuthType } from '@alcub3/alcub3-cli-core';
import { validateAuthMethod } from '../../config/auth.js';
export function AuthDialog({ onSelect, settings, initialErrorMessage, }) {
    const [errorMessage, setErrorMessage] = useState(initialErrorMessage || null);
    const items = [
        { label: 'Login with Google', value: AuthType.LOGIN_WITH_GOOGLE },
        { label: 'Gemini API Key (AI Studio)', value: AuthType.USE_GEMINI },
        { label: 'Vertex AI', value: AuthType.USE_VERTEX_AI },
    ];
    let initialAuthIndex = items.findIndex((item) => item.value === settings.merged.selectedAuthType);
    if (initialAuthIndex === -1) {
        initialAuthIndex = 0;
    }
    const handleAuthSelect = (authMethod) => {
        const error = validateAuthMethod(authMethod);
        if (error) {
            setErrorMessage(error);
        }
        else {
            setErrorMessage(null);
            onSelect(authMethod, SettingScope.User);
        }
    };
    useInput((_input, key) => {
        if (key.escape) {
            if (settings.merged.selectedAuthType === undefined) {
                // Prevent exiting if no auth method is set
                setErrorMessage('You must select an auth method to proceed. Press Ctrl+C twice to exit.');
                return;
            }
            onSelect(undefined, SettingScope.User);
        }
    });
    return (_jsxs(Box, { borderStyle: "round", borderColor: Colors.Gray, flexDirection: "column", padding: 1, width: "100%", children: [_jsx(Text, { bold: true, children: "Select Auth Method" }), _jsx(RadioButtonSelect, { items: items, initialIndex: initialAuthIndex, onSelect: handleAuthSelect, isFocused: true }), errorMessage && (_jsx(Box, { marginTop: 1, children: _jsx(Text, { color: Colors.AccentRed, children: errorMessage }) })), _jsx(Box, { marginTop: 1, children: _jsx(Text, { color: Colors.Gray, children: "(Use Enter to select)" }) }), _jsx(Box, { marginTop: 1, children: _jsx(Text, { children: "Terms of Services and Privacy Notice for Gemini CLI" }) }), _jsx(Box, { marginTop: 1, children: _jsx(Text, { color: Colors.AccentBlue, children: 'https://github.com/google-gemini/gemini-cli/blob/main/docs/tos-privacy.md' }) })] }));
}
//# sourceMappingURL=AuthDialog.js.map