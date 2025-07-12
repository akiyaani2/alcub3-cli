/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ALCUB3 CLI Entry Point
 * 
 * This file imports the base Gemini CLI and extends it with ALCUB3 features.
 * It ensures clean separation between Gemini core and ALCUB3 extensions.
 */

// Import everything from Gemini core
export * from '@gemini-core/cli/src/gemini.js';

// Import ALCUB3 command registration
import { registerAlcub3Commands } from '@alcub3/cli/overrides/gemini.js';

// Get the default export from Gemini (if any)
import geminiMain from '@gemini-core/cli/src/gemini.js';

// Extend with ALCUB3 functionality
if (typeof geminiMain === 'function') {
  // If gemini exports a main function, wrap it
  const originalMain = geminiMain;
  export default function alcub3Main(...args: any[]) {
    // Register ALCUB3 commands before running
    if (args[0]?.constructor?.name === 'Command') {
      registerAlcub3Commands(args[0]);
    }
    return originalMain(...args);
  };
} else {
  // If it's not a function export, just re-export
  export default geminiMain;
}

// Note: The actual command registration happens in the override file