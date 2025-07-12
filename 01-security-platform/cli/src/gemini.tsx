/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ALCUB3 CLI Entry Point
 * 
 * This file extends the base Gemini CLI with ALCUB3 features.
 */

import React from 'react';
import { render } from 'ink';
import { AppWrapper } from '@gemini-core/cli/src/ui/App.js';
import { loadCliConfig } from '@gemini-core/cli/src/config/config.js';
import { readStdin } from '@gemini-core/cli/src/utils/readStdin.js';
import { basename } from 'node:path';
import v8 from 'node:v8';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { start_sandbox } from '@gemini-core/cli/src/utils/sandbox.js';
import {
  LoadedSettings,
  loadSettings,
  SettingScope,
  USER_SETTINGS_PATH,
} from '@gemini-core/cli/src/config/settings.js';
import { themeManager } from '@gemini-core/cli/src/ui/themes/theme-manager.js';
import { getStartupWarnings } from '@gemini-core/cli/src/utils/startupWarnings.js';
import { runNonInteractive } from '@gemini-core/cli/src/nonInteractiveCli.js';
import { loadExtensions, Extension } from '@gemini-core/cli/src/config/extension.js';
import { cleanupCheckpoints } from '@gemini-core/cli/src/utils/cleanup.js';
import {
  ApprovalMode,
  Config,
  EditTool,
  ShellTool,
  WriteFileTool,
  sessionId,
  logUserPrompt,
  AuthType,
} from '@gemini-core/core/src/index.js';
import { validateAuthMethod } from '@gemini-core/cli/src/config/auth.js';
import { setMaxSizedBoxDebugging } from '@gemini-core/cli/src/ui/components/shared/MaxSizedBox.js';
import { Command } from 'commander';

// Import ALCUB3 commands
import { registerClearanceCommands } from './commands/clearance.js';
import { registerMaestroCommands } from './commands/maestro.js';
import { createConfigurationDriftCommand } from './commands/configuration-drift.js';

// Re-export everything from Gemini
export * from '@gemini-core/cli/src/gemini.js';

// Import the main function from Gemini
import geminiMain from '@gemini-core/cli/src/gemini.js';

// Extend the main function to add ALCUB3 commands
export default async function alcub3Main() {
  // Get the program from gemini
  const program = new Command();
  
  // Register ALCUB3 commands
  registerClearanceCommands(program);
  registerMaestroCommands(program);
  program.addCommand(createConfigurationDriftCommand());
  
  // Call the original Gemini main with our extended program
  if (typeof geminiMain === 'function') {
    return geminiMain();
  }
}