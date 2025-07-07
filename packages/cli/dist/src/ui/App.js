import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import { Box, measureElement, Static, Text, useStdin, useStdout, useInput, } from 'ink';
import { StreamingState, MessageType } from './types.js';
import { useTerminalSize } from './hooks/useTerminalSize.js';
import { useGeminiStream } from './hooks/useGeminiStream.js';
import { useLoadingIndicator } from './hooks/useLoadingIndicator.js';
import { useThemeCommand } from './hooks/useThemeCommand.js';
import { useAuthCommand } from './hooks/useAuthCommand.js';
import { useEditorSettings } from './hooks/useEditorSettings.js';
import { useSlashCommandProcessor } from './hooks/slashCommandProcessor.js';
import { useAutoAcceptIndicator } from './hooks/useAutoAcceptIndicator.js';
import { useConsoleMessages } from './hooks/useConsoleMessages.js';
import { Header } from './components/Header.js';
import { LoadingIndicator } from './components/LoadingIndicator.js';
import { AutoAcceptIndicator } from './components/AutoAcceptIndicator.js';
import { ShellModeIndicator } from './components/ShellModeIndicator.js';
import { InputPrompt } from './components/InputPrompt.js';
import { Footer } from './components/Footer.js';
import { ThemeDialog } from './components/ThemeDialog.js';
import { AuthDialog } from './components/AuthDialog.js';
import { AuthInProgress } from './components/AuthInProgress.js';
import { EditorSettingsDialog } from './components/EditorSettingsDialog.js';
import { Colors } from './colors.js';
import { Help } from './components/Help.js';
import { loadHierarchicalGeminiMemory } from '../config/config.js';
import { Tips } from './components/Tips.js';
import { useConsolePatcher } from './components/ConsolePatcher.js';
import { DetailedMessagesDisplay } from './components/DetailedMessagesDisplay.js';
import { HistoryItemDisplay } from './components/HistoryItemDisplay.js';
import { ContextSummaryDisplay } from './components/ContextSummaryDisplay.js';
import { useHistory } from './hooks/useHistoryManager.js';
import process from 'node:process';
import { getErrorMessage, getAllGeminiMdFilenames, ApprovalMode, isEditorAvailable, } from '@alcub3/alcub3-cli-core';
import { validateAuthMethod } from '../config/auth.js';
import { useLogger } from './hooks/useLogger.js';
import { StreamingContext } from './contexts/StreamingContext.js';
import { SessionStatsProvider, useSessionStats, } from './contexts/SessionContext.js';
import { useGitBranchName } from './hooks/useGitBranchName.js';
import { useBracketedPaste } from './hooks/useBracketedPaste.js';
import { useTextBuffer } from './components/shared/text-buffer.js';
import * as fs from 'fs';
import { UpdateNotification } from './components/UpdateNotification.js';
import { checkForUpdates } from './utils/updateCheck.js';
import ansiEscapes from 'ansi-escapes';
import { OverflowProvider } from './contexts/OverflowContext.js';
import { ShowMoreLines } from './components/ShowMoreLines.js';
import { PrivacyNotice } from './privacy/PrivacyNotice.js';
const CTRL_EXIT_PROMPT_DURATION_MS = 1000;
export const AppWrapper = (props) => (_jsx(SessionStatsProvider, { children: _jsx(App, { ...props }) }));
const App = ({ config, settings, startupWarnings = [] }) => {
    useBracketedPaste();
    const [updateMessage, setUpdateMessage] = useState(null);
    const { stdout } = useStdout();
    useEffect(() => {
        checkForUpdates().then(setUpdateMessage);
    }, []);
    const { history, addItem, clearItems, loadHistory } = useHistory();
    const { consoleMessages, handleNewMessage, clearConsoleMessages: clearConsoleMessagesState, } = useConsoleMessages();
    const { stats: sessionStats } = useSessionStats();
    const [staticNeedsRefresh, setStaticNeedsRefresh] = useState(false);
    const [staticKey, setStaticKey] = useState(0);
    const refreshStatic = useCallback(() => {
        stdout.write(ansiEscapes.clearTerminal);
        setStaticKey((prev) => prev + 1);
    }, [setStaticKey, stdout]);
    const [geminiMdFileCount, setGeminiMdFileCount] = useState(0);
    const [debugMessage, setDebugMessage] = useState('');
    const [showHelp, setShowHelp] = useState(false);
    const [themeError, setThemeError] = useState(null);
    const [authError, setAuthError] = useState(null);
    const [editorError, setEditorError] = useState(null);
    const [footerHeight, setFooterHeight] = useState(0);
    const [corgiMode, setCorgiMode] = useState(false);
    const [currentModel, setCurrentModel] = useState(config.getModel());
    const [shellModeActive, setShellModeActive] = useState(false);
    const [showErrorDetails, setShowErrorDetails] = useState(false);
    const [showToolDescriptions, setShowToolDescriptions] = useState(false);
    const [ctrlCPressedOnce, setCtrlCPressedOnce] = useState(false);
    const [quittingMessages, setQuittingMessages] = useState(null);
    const ctrlCTimerRef = useRef(null);
    const [ctrlDPressedOnce, setCtrlDPressedOnce] = useState(false);
    const ctrlDTimerRef = useRef(null);
    const [constrainHeight, setConstrainHeight] = useState(true);
    const [showPrivacyNotice, setShowPrivacyNotice] = useState(false);
    const openPrivacyNotice = useCallback(() => {
        setShowPrivacyNotice(true);
    }, []);
    const errorCount = useMemo(() => consoleMessages.filter((msg) => msg.type === 'error').length, [consoleMessages]);
    const { isThemeDialogOpen, openThemeDialog, handleThemeSelect, handleThemeHighlight, } = useThemeCommand(settings, setThemeError, addItem);
    const { isAuthDialogOpen, openAuthDialog, handleAuthSelect, isAuthenticating, cancelAuthentication, } = useAuthCommand(settings, setAuthError, config);
    useEffect(() => {
        if (settings.merged.selectedAuthType) {
            const error = validateAuthMethod(settings.merged.selectedAuthType);
            if (error) {
                setAuthError(error);
                openAuthDialog();
            }
        }
    }, [settings.merged.selectedAuthType, openAuthDialog, setAuthError]);
    const { isEditorDialogOpen, openEditorDialog, handleEditorSelect, exitEditorDialog, } = useEditorSettings(settings, setEditorError, addItem);
    const toggleCorgiMode = useCallback(() => {
        setCorgiMode((prev) => !prev);
    }, []);
    const performMemoryRefresh = useCallback(async () => {
        addItem({
            type: MessageType.INFO,
            text: 'Refreshing hierarchical memory (GEMINI.md or other context files)...',
        }, Date.now());
        try {
            const { memoryContent, fileCount } = await loadHierarchicalGeminiMemory(process.cwd(), config.getDebugMode(), config.getFileService(), config.getExtensionContextFilePaths());
            config.setUserMemory(memoryContent);
            config.setGeminiMdFileCount(fileCount);
            setGeminiMdFileCount(fileCount);
            addItem({
                type: MessageType.INFO,
                text: `Memory refreshed successfully. ${memoryContent.length > 0 ? `Loaded ${memoryContent.length} characters from ${fileCount} file(s).` : 'No memory content found.'}`,
            }, Date.now());
            if (config.getDebugMode()) {
                console.log(`[DEBUG] Refreshed memory content in config: ${memoryContent.substring(0, 200)}...`);
            }
        }
        catch (error) {
            const errorMessage = getErrorMessage(error);
            addItem({
                type: MessageType.ERROR,
                text: `Error refreshing memory: ${errorMessage}`,
            }, Date.now());
            console.error('Error refreshing memory:', error);
        }
    }, [config, addItem]);
    // Watch for model changes (e.g., from Flash fallback)
    useEffect(() => {
        const checkModelChange = () => {
            const configModel = config.getModel();
            if (configModel !== currentModel) {
                setCurrentModel(configModel);
            }
        };
        // Check immediately and then periodically
        checkModelChange();
        const interval = setInterval(checkModelChange, 1000); // Check every second
        return () => clearInterval(interval);
    }, [config, currentModel]);
    // Set up Flash fallback handler
    useEffect(() => {
        const flashFallbackHandler = async (currentModel, fallbackModel) => {
            // Add message to UI history
            addItem({
                type: MessageType.INFO,
                text: `⚡ Slow response times detected. Automatically switching from ${currentModel} to ${fallbackModel} for faster responses for the remainder of this session.
⚡ To avoid this you can either upgrade to Standard tier. See: https://goo.gle/set-up-gemini-code-assist
⚡ Or you can utilize a Gemini API Key. See: https://goo.gle/gemini-cli-docs-auth#gemini-api-key
⚡ You can switch authentication methods by typing /auth`,
            }, Date.now());
            return true; // Always accept the fallback
        };
        config.setFlashFallbackHandler(flashFallbackHandler);
    }, [config, addItem]);
    const { handleSlashCommand, slashCommands, pendingHistoryItems: pendingSlashCommandHistoryItems, } = useSlashCommandProcessor(config, settings, history, addItem, clearItems, loadHistory, refreshStatic, setShowHelp, setDebugMessage, openThemeDialog, openAuthDialog, openEditorDialog, performMemoryRefresh, toggleCorgiMode, showToolDescriptions, setQuittingMessages, openPrivacyNotice);
    const pendingHistoryItems = [...pendingSlashCommandHistoryItems];
    const { rows: terminalHeight, columns: terminalWidth } = useTerminalSize();
    const isInitialMount = useRef(true);
    const { stdin, setRawMode } = useStdin();
    const isValidPath = useCallback((filePath) => {
        try {
            return fs.existsSync(filePath) && fs.statSync(filePath).isFile();
        }
        catch (_e) {
            return false;
        }
    }, []);
    const widthFraction = 0.9;
    const inputWidth = Math.max(20, Math.floor(terminalWidth * widthFraction) - 3);
    const suggestionsWidth = Math.max(60, Math.floor(terminalWidth * 0.8));
    const buffer = useTextBuffer({
        initialText: '',
        viewport: { height: 10, width: inputWidth },
        stdin,
        setRawMode,
        isValidPath,
    });
    const handleExit = useCallback((pressedOnce, setPressedOnce, timerRef) => {
        if (pressedOnce) {
            if (timerRef.current) {
                clearTimeout(timerRef.current);
            }
            const quitCommand = slashCommands.find((cmd) => cmd.name === 'quit' || cmd.altName === 'exit');
            if (quitCommand) {
                quitCommand.action('quit', '', '');
            }
            else {
                process.exit(0);
            }
        }
        else {
            setPressedOnce(true);
            timerRef.current = setTimeout(() => {
                setPressedOnce(false);
                timerRef.current = null;
            }, CTRL_EXIT_PROMPT_DURATION_MS);
        }
    }, [slashCommands]);
    useInput((input, key) => {
        let enteringConstrainHeightMode = false;
        if (!constrainHeight) {
            // Automatically re-enter constrain height mode if the user types
            // anything. When constrainHeight==false, the user will experience
            // significant flickering so it is best to disable it immediately when
            // the user starts interacting with the app.
            enteringConstrainHeightMode = true;
            setConstrainHeight(true);
        }
        if (key.ctrl && input === 'o') {
            setShowErrorDetails((prev) => !prev);
        }
        else if (key.ctrl && input === 't') {
            const newValue = !showToolDescriptions;
            setShowToolDescriptions(newValue);
            const mcpServers = config.getMcpServers();
            if (Object.keys(mcpServers || {}).length > 0) {
                handleSlashCommand(newValue ? '/mcp desc' : '/mcp nodesc');
            }
        }
        else if (key.ctrl && (input === 'c' || input === 'C')) {
            handleExit(ctrlCPressedOnce, setCtrlCPressedOnce, ctrlCTimerRef);
        }
        else if (key.ctrl && (input === 'd' || input === 'D')) {
            if (buffer.text.length > 0) {
                // Do nothing if there is text in the input.
                return;
            }
            handleExit(ctrlDPressedOnce, setCtrlDPressedOnce, ctrlDTimerRef);
        }
        else if (key.ctrl && input === 's' && !enteringConstrainHeightMode) {
            setConstrainHeight(false);
        }
    });
    useConsolePatcher({
        onNewMessage: handleNewMessage,
        debugMode: config.getDebugMode(),
    });
    useEffect(() => {
        if (config) {
            setGeminiMdFileCount(config.getGeminiMdFileCount());
        }
    }, [config]);
    const getPreferredEditor = useCallback(() => {
        const editorType = settings.merged.preferredEditor;
        const isValidEditor = isEditorAvailable(editorType);
        if (!isValidEditor) {
            openEditorDialog();
            return;
        }
        return editorType;
    }, [settings, openEditorDialog]);
    const onAuthError = useCallback(() => {
        setAuthError('reauth required');
        openAuthDialog();
    }, [openAuthDialog, setAuthError]);
    const { streamingState, submitQuery, initError, pendingHistoryItems: pendingGeminiHistoryItems, thought, } = useGeminiStream(config.getGeminiClient(), history, addItem, setShowHelp, config, setDebugMessage, handleSlashCommand, shellModeActive, getPreferredEditor, onAuthError, performMemoryRefresh);
    pendingHistoryItems.push(...pendingGeminiHistoryItems);
    const { elapsedTime, currentLoadingPhrase } = useLoadingIndicator(streamingState);
    const showAutoAcceptIndicator = useAutoAcceptIndicator({ config });
    const handleFinalSubmit = useCallback((submittedValue) => {
        const trimmedValue = submittedValue.trim();
        if (trimmedValue.length > 0) {
            submitQuery(trimmedValue);
        }
    }, [submitQuery]);
    const logger = useLogger();
    const [userMessages, setUserMessages] = useState([]);
    useEffect(() => {
        const fetchUserMessages = async () => {
            const pastMessagesRaw = (await logger?.getPreviousUserMessages()) || []; // Newest first
            const currentSessionUserMessages = history
                .filter((item) => item.type === 'user' &&
                typeof item.text === 'string' &&
                item.text.trim() !== '')
                .map((item) => item.text)
                .reverse(); // Newest first, to match pastMessagesRaw sorting
            // Combine, with current session messages being more recent
            const combinedMessages = [
                ...currentSessionUserMessages,
                ...pastMessagesRaw,
            ];
            // Deduplicate consecutive identical messages from the combined list (still newest first)
            const deduplicatedMessages = [];
            if (combinedMessages.length > 0) {
                deduplicatedMessages.push(combinedMessages[0]); // Add the newest one unconditionally
                for (let i = 1; i < combinedMessages.length; i++) {
                    if (combinedMessages[i] !== combinedMessages[i - 1]) {
                        deduplicatedMessages.push(combinedMessages[i]);
                    }
                }
            }
            // Reverse to oldest first for useInputHistory
            setUserMessages(deduplicatedMessages.reverse());
        };
        fetchUserMessages();
    }, [history, logger]);
    const isInputActive = streamingState === StreamingState.Idle && !initError;
    const handleClearScreen = useCallback(() => {
        clearItems();
        clearConsoleMessagesState();
        console.clear();
        refreshStatic();
    }, [clearItems, clearConsoleMessagesState, refreshStatic]);
    const mainControlsRef = useRef(null);
    const pendingHistoryItemRef = useRef(null);
    useEffect(() => {
        if (mainControlsRef.current) {
            const fullFooterMeasurement = measureElement(mainControlsRef.current);
            setFooterHeight(fullFooterMeasurement.height);
        }
    }, [terminalHeight, consoleMessages, showErrorDetails]);
    const staticExtraHeight = /* margins and padding */ 3;
    const availableTerminalHeight = useMemo(() => terminalHeight - footerHeight - staticExtraHeight, [terminalHeight, footerHeight]);
    useEffect(() => {
        // skip refreshing Static during first mount
        if (isInitialMount.current) {
            isInitialMount.current = false;
            return;
        }
        // debounce so it doesn't fire up too often during resize
        const handler = setTimeout(() => {
            setStaticNeedsRefresh(false);
            refreshStatic();
        }, 300);
        return () => {
            clearTimeout(handler);
        };
    }, [terminalWidth, terminalHeight, refreshStatic]);
    useEffect(() => {
        if (streamingState === StreamingState.Idle && staticNeedsRefresh) {
            setStaticNeedsRefresh(false);
            refreshStatic();
        }
    }, [streamingState, refreshStatic, staticNeedsRefresh]);
    const filteredConsoleMessages = useMemo(() => {
        if (config.getDebugMode()) {
            return consoleMessages;
        }
        return consoleMessages.filter((msg) => msg.type !== 'debug');
    }, [consoleMessages, config]);
    const branchName = useGitBranchName(config.getTargetDir());
    const contextFileNames = useMemo(() => {
        const fromSettings = settings.merged.contextFileName;
        if (fromSettings) {
            return Array.isArray(fromSettings) ? fromSettings : [fromSettings];
        }
        return getAllGeminiMdFilenames();
    }, [settings.merged.contextFileName]);
    if (quittingMessages) {
        return (_jsx(Box, { flexDirection: "column", marginBottom: 1, children: quittingMessages.map((item) => (_jsx(HistoryItemDisplay, { availableTerminalHeight: constrainHeight ? availableTerminalHeight : undefined, terminalWidth: terminalWidth, item: item, isPending: false, config: config }, item.id))) }));
    }
    const mainAreaWidth = Math.floor(terminalWidth * 0.9);
    const debugConsoleMaxHeight = Math.floor(Math.max(terminalHeight * 0.2, 5));
    // Arbitrary threshold to ensure that items in the static area are large
    // enough but not too large to make the terminal hard to use.
    const staticAreaMaxItemHeight = Math.max(terminalHeight * 4, 100);
    return (_jsx(StreamingContext.Provider, { value: streamingState, children: _jsxs(Box, { flexDirection: "column", marginBottom: 1, width: "90%", children: [updateMessage && _jsx(UpdateNotification, { message: updateMessage }), _jsx(Static, { items: [
                        _jsxs(Box, { flexDirection: "column", children: [_jsx(Header, { terminalWidth: terminalWidth }), !settings.merged.hideTips && _jsx(Tips, { config: config })] }, "header"),
                        ...history.map((h) => (_jsx(HistoryItemDisplay, { terminalWidth: mainAreaWidth, availableTerminalHeight: staticAreaMaxItemHeight, item: h, isPending: false, config: config }, h.id))),
                    ], children: (item) => item }, staticKey), _jsx(OverflowProvider, { children: _jsxs(Box, { ref: pendingHistoryItemRef, flexDirection: "column", children: [pendingHistoryItems.map((item, i) => (_jsx(HistoryItemDisplay, { availableTerminalHeight: constrainHeight ? availableTerminalHeight : undefined, terminalWidth: mainAreaWidth, 
                                // TODO(taehykim): It seems like references to ids aren't necessary in
                                // HistoryItemDisplay. Refactor later. Use a fake id for now.
                                item: { ...item, id: 0 }, isPending: true, config: config, isFocused: !isEditorDialogOpen }, i))), _jsx(ShowMoreLines, { constrainHeight: constrainHeight })] }) }), showHelp && _jsx(Help, { commands: slashCommands }), _jsxs(Box, { flexDirection: "column", ref: mainControlsRef, children: [startupWarnings.length > 0 && (_jsx(Box, { borderStyle: "round", borderColor: Colors.AccentYellow, paddingX: 1, marginY: 1, flexDirection: "column", children: startupWarnings.map((warning, index) => (_jsx(Text, { color: Colors.AccentYellow, children: warning }, index))) })), isThemeDialogOpen ? (_jsxs(Box, { flexDirection: "column", children: [themeError && (_jsx(Box, { marginBottom: 1, children: _jsx(Text, { color: Colors.AccentRed, children: themeError }) })), _jsx(ThemeDialog, { onSelect: handleThemeSelect, onHighlight: handleThemeHighlight, settings: settings, availableTerminalHeight: constrainHeight
                                        ? terminalHeight - staticExtraHeight
                                        : undefined, terminalWidth: mainAreaWidth })] })) : isAuthenticating ? (_jsx(AuthInProgress, { onTimeout: () => {
                                setAuthError('Authentication timed out. Please try again.');
                                cancelAuthentication();
                                openAuthDialog();
                            } })) : isAuthDialogOpen ? (_jsx(Box, { flexDirection: "column", children: _jsx(AuthDialog, { onSelect: handleAuthSelect, settings: settings, initialErrorMessage: authError }) })) : isEditorDialogOpen ? (_jsxs(Box, { flexDirection: "column", children: [editorError && (_jsx(Box, { marginBottom: 1, children: _jsx(Text, { color: Colors.AccentRed, children: editorError }) })), _jsx(EditorSettingsDialog, { onSelect: handleEditorSelect, settings: settings, onExit: exitEditorDialog })] })) : showPrivacyNotice ? (_jsx(PrivacyNotice, { onExit: () => setShowPrivacyNotice(false), config: config })) : (_jsxs(_Fragment, { children: [_jsx(LoadingIndicator, { thought: streamingState === StreamingState.WaitingForConfirmation ||
                                        config.getAccessibility()?.disableLoadingPhrases
                                        ? undefined
                                        : thought, currentLoadingPhrase: config.getAccessibility()?.disableLoadingPhrases
                                        ? undefined
                                        : currentLoadingPhrase, elapsedTime: elapsedTime }), _jsxs(Box, { marginTop: 1, display: "flex", justifyContent: "space-between", width: "100%", children: [_jsxs(Box, { children: [process.env.GEMINI_SYSTEM_MD && (_jsx(Text, { color: Colors.AccentRed, children: "|\u2310\u25A0_\u25A0| " })), ctrlCPressedOnce ? (_jsx(Text, { color: Colors.AccentYellow, children: "Press Ctrl+C again to exit." })) : ctrlDPressedOnce ? (_jsx(Text, { color: Colors.AccentYellow, children: "Press Ctrl+D again to exit." })) : (_jsx(ContextSummaryDisplay, { geminiMdFileCount: geminiMdFileCount, contextFileNames: contextFileNames, mcpServers: config.getMcpServers(), showToolDescriptions: showToolDescriptions }))] }), _jsxs(Box, { children: [showAutoAcceptIndicator !== ApprovalMode.DEFAULT &&
                                                    !shellModeActive && (_jsx(AutoAcceptIndicator, { approvalMode: showAutoAcceptIndicator })), shellModeActive && _jsx(ShellModeIndicator, {})] })] }), showErrorDetails && (_jsx(OverflowProvider, { children: _jsxs(Box, { flexDirection: "column", children: [_jsx(DetailedMessagesDisplay, { messages: filteredConsoleMessages, maxHeight: constrainHeight ? debugConsoleMaxHeight : undefined, width: inputWidth }), _jsx(ShowMoreLines, { constrainHeight: constrainHeight })] }) })), isInputActive && (_jsx(InputPrompt, { buffer: buffer, inputWidth: inputWidth, suggestionsWidth: suggestionsWidth, onSubmit: handleFinalSubmit, userMessages: userMessages, onClearScreen: handleClearScreen, config: config, slashCommands: slashCommands, shellModeActive: shellModeActive, setShellModeActive: setShellModeActive }))] })), initError && streamingState !== StreamingState.Responding && (_jsx(Box, { borderStyle: "round", borderColor: Colors.AccentRed, paddingX: 1, marginBottom: 1, children: history.find((item) => item.type === 'error' && item.text?.includes(initError))?.text ? (_jsx(Text, { color: Colors.AccentRed, children: history.find((item) => item.type === 'error' && item.text?.includes(initError))?.text })) : (_jsxs(_Fragment, { children: [_jsxs(Text, { color: Colors.AccentRed, children: ["Initialization Error: ", initError] }), _jsxs(Text, { color: Colors.AccentRed, children: [' ', "Please check API key and configuration."] })] })) })), _jsx(Footer, { model: currentModel, targetDir: config.getTargetDir(), debugMode: config.getDebugMode(), branchName: branchName, debugMessage: debugMessage, corgiMode: corgiMode, errorCount: errorCount, showErrorDetails: showErrorDetails, showMemoryUsage: config.getDebugMode() || config.getShowMemoryUsage(), promptTokenCount: sessionStats.lastPromptTokenCount })] })] }) }));
};
//# sourceMappingURL=App.js.map