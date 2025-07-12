#!/usr/bin/env node

/**
 * Refactor Inventory Script
 * Analyzes the current codebase to identify:
 * 1. Original Gemini files (unmodified)
 * 2. Modified Gemini files 
 * 3. New ALCUB3 files
 */

import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';
import crypto from 'crypto';

const INVENTORY_OUTPUT = 'REFACTOR_INVENTORY.md';
const GEMINI_TEMP_DIR = '.gemini-original';

// Directories to analyze
const CURRENT_LOCATIONS = {
  core: '01-security-platform/core/src',
  cli: '01-security-platform/cli/src',
  packages: 'packages'
};

// Files to ignore
const IGNORE_PATTERNS = [
  'node_modules',
  'dist',
  'coverage',
  '.git',
  '*.log',
  '*.map'
];

async function main() {
  console.log('🔍 Starting refactor inventory analysis...\n');

  // Create temporary directory for original Gemini
  console.log('📥 Checking out original Gemini code...');
  await checkoutOriginalGemini();

  // Analyze files
  console.log('\n📊 Analyzing file differences...');
  const inventory = await analyzeFiles();

  // Generate report
  console.log('\n📝 Generating inventory report...');
  await generateReport(inventory);

  // Cleanup
  console.log('\n🧹 Cleaning up...');
  await cleanup();

  console.log(`\n✅ Complete! See ${INVENTORY_OUTPUT} for results.`);
}

async function checkoutOriginalGemini() {
  try {
    // Create temp directory
    await fs.mkdir(GEMINI_TEMP_DIR, { recursive: true });
    
    // Use git to export original Gemini files
    execSync(`git archive upstream/main | tar -x -C ${GEMINI_TEMP_DIR}`, {
      stdio: 'inherit'
    });
  } catch (error) {
    console.error('Failed to checkout original Gemini:', error.message);
    process.exit(1);
  }
}

async function analyzeFiles() {
  const inventory = {
    original: [],      // Unmodified Gemini files
    modified: [],      // Modified Gemini files
    alcub3: [],        // New ALCUB3 files
    geminiOnly: []     // Files in Gemini but not in current
  };

  // Analyze current structure
  for (const [key, dir] of Object.entries(CURRENT_LOCATIONS)) {
    console.log(`\nAnalyzing ${key}: ${dir}`);
    
    if (await fileExists(dir)) {
      await analyzeDirectory(dir, inventory);
    }
  }

  // Find Gemini files not in current structure
  await findGeminiOnlyFiles(inventory);

  return inventory;
}

async function analyzeDirectory(dir, inventory, basePath = '') {
  const files = await fs.readdir(dir, { withFileTypes: true });

  for (const file of files) {
    const filePath = path.join(dir, file.name);
    const relativePath = path.join(basePath, file.name);

    // Skip ignored patterns
    if (shouldIgnore(file.name)) continue;

    if (file.isDirectory()) {
      await analyzeDirectory(filePath, inventory, relativePath);
    } else if (file.isFile() && isSourceFile(file.name)) {
      await categorizeFile(filePath, relativePath, inventory);
    }
  }
}

async function categorizeFile(filePath, relativePath, inventory) {
  // Try to find corresponding Gemini file
  const geminiPaths = [
    path.join(GEMINI_TEMP_DIR, 'packages/core/src', relativePath),
    path.join(GEMINI_TEMP_DIR, 'packages/cli/src', relativePath),
    path.join(GEMINI_TEMP_DIR, relativePath)
  ];

  let foundInGemini = false;
  let isModified = false;

  for (const geminiPath of geminiPaths) {
    if (await fileExists(geminiPath)) {
      foundInGemini = true;
      
      // Compare file contents
      const currentHash = await getFileHash(filePath);
      const geminiHash = await getFileHash(geminiPath);
      
      if (currentHash === geminiHash) {
        inventory.original.push({
          current: filePath,
          gemini: geminiPath,
          relativePath
        });
      } else {
        inventory.modified.push({
          current: filePath,
          gemini: geminiPath,
          relativePath
        });
        isModified = true;
      }
      break;
    }
  }

  if (!foundInGemini) {
    inventory.alcub3.push({
      current: filePath,
      relativePath
    });
  }
}

async function findGeminiOnlyFiles(inventory) {
  const geminiDirs = [
    path.join(GEMINI_TEMP_DIR, 'packages/core/src'),
    path.join(GEMINI_TEMP_DIR, 'packages/cli/src')
  ];

  for (const dir of geminiDirs) {
    if (await fileExists(dir)) {
      await findGeminiOnly(dir, inventory, '');
    }
  }
}

async function findGeminiOnly(dir, inventory, basePath) {
  const files = await fs.readdir(dir, { withFileTypes: true });

  for (const file of files) {
    const filePath = path.join(dir, file.name);
    const relativePath = path.join(basePath, file.name);

    if (shouldIgnore(file.name)) continue;

    if (file.isDirectory()) {
      await findGeminiOnly(filePath, inventory, relativePath);
    } else if (file.isFile() && isSourceFile(file.name)) {
      // Check if this file exists in our current structure
      const exists = inventory.original.some(f => f.relativePath === relativePath) ||
                    inventory.modified.some(f => f.relativePath === relativePath);
      
      if (!exists) {
        inventory.geminiOnly.push({
          gemini: filePath,
          relativePath
        });
      }
    }
  }
}

async function generateReport(inventory) {
  const report = `# ALCUB3 Refactor Inventory
Generated: ${new Date().toISOString()}

## Summary
- **Original Gemini files**: ${inventory.original.length}
- **Modified Gemini files**: ${inventory.modified.length}
- **New ALCUB3 files**: ${inventory.alcub3.length}
- **Gemini-only files**: ${inventory.geminiOnly.length}

## Original Gemini Files (Unmodified)
These files can be moved directly to \`gemini-core/\`.

${inventory.original.map(f => `- ${f.current} → gemini-core/${f.relativePath}`).join('\n')}

## Modified Gemini Files
These files need to be analyzed for extraction to \`alcub3-extensions/\`.

${inventory.modified.map(f => `- ${f.current} (modified from ${f.gemini})`).join('\n')}

## New ALCUB3 Files
These files are entirely new and belong in \`alcub3-extensions/\`.

${inventory.alcub3.map(f => `- ${f.current}`).join('\n')}

## Gemini Files Not in Current Structure
These files exist in Gemini but not in our current structure.

${inventory.geminiOnly.map(f => `- ${f.gemini}`).join('\n')}

## Next Steps
1. Create \`gemini-core/\` directory structure
2. Move original files to \`gemini-core/\`
3. Create \`alcub3-extensions/\` directory structure
4. Extract modifications from modified files
5. Move new ALCUB3 files to appropriate locations
6. Update all import paths
7. Reconfigure build system
`;

  await fs.writeFile(INVENTORY_OUTPUT, report);
}

// Helper functions
async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function getFileHash(filePath) {
  const content = await fs.readFile(filePath, 'utf8');
  return crypto.createHash('sha256').update(content).digest('hex');
}

function shouldIgnore(fileName) {
  return IGNORE_PATTERNS.some(pattern => {
    if (pattern.includes('*')) {
      const regex = new RegExp(pattern.replace('*', '.*'));
      return regex.test(fileName);
    }
    return fileName === pattern;
  });
}

function isSourceFile(fileName) {
  const extensions = ['.ts', '.tsx', '.js', '.jsx', '.json', '.yaml', '.yml'];
  return extensions.some(ext => fileName.endsWith(ext));
}

async function cleanup() {
  try {
    await fs.rm(GEMINI_TEMP_DIR, { recursive: true, force: true });
  } catch (error) {
    console.warn('Warning: Could not clean up temporary directory');
  }
}

// Run the script
main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});