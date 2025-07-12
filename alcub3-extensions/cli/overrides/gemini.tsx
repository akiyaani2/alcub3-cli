/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ALCUB3 Override for Gemini CLI Entry Point
 * 
 * This file extends the Gemini CLI with ALCUB3-specific commands
 * while maintaining compatibility with upstream Gemini updates.
 */

import { Command } from 'commander';
import { registerClearanceCommands } from '../commands/clearance.js';
import { registerMaestroCommands } from '../commands/maestro.js';
import { createConfigurationDriftCommand } from '../commands/configuration-drift.js';

/**
 * Register ALCUB3-specific commands on the CLI program
 * This is called after Gemini's standard setup
 */
export function registerAlcub3Commands(program: Command): void {
  // Register security commands
  registerClearanceCommands(program);
  registerMaestroCommands(program);
  
  // Register drift detection
  program.addCommand(createConfigurationDriftCommand());
  
  // Add any future ALCUB3 commands here
}

/**
 * Export everything from the original gemini.tsx
 * This ensures we inherit all Gemini functionality
 */
export * from '@gemini-core/cli/src/gemini.js';