#!/usr/bin/env node

/**
 * Move ALCUB3-specific Files Script
 * Moves custom ALCUB3 files to alcub3-extensions directory
 */

import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';

const INVENTORY_FILE = 'REFACTOR_INVENTORY.md';
const DRY_RUN = process.argv.includes('--dry-run');

async function main() {
  console.log(`🚀 Starting ALCUB3 file migration... ${DRY_RUN ? '(DRY RUN)' : ''}\n`);

  // Read inventory
  const inventory = await fs.readFile(INVENTORY_FILE, 'utf8');
  
  // Extract ALCUB3 files section
  const alcub3Section = inventory.match(/## New ALCUB3 Files[\s\S]*?(?=##|$)/);
  if (!alcub3Section) {
    console.error('Could not find ALCUB3 files section in inventory');
    process.exit(1);
  }

  // Parse file mappings
  const fileLines = alcub3Section[0]
    .split('\n')
    .filter(line => line.startsWith('- '))
    .map(line => line.substring(2));

  console.log(`Found ${fileLines.length} ALCUB3 files to move\n`);

  let movedCount = 0;
  let errorCount = 0;

  for (const source of fileLines) {
    try {
      const destination = determineDestination(source);
      await moveFile(source, destination);
      movedCount++;
    } catch (error) {
      console.error(`❌ Failed to move ${source}: ${error.message}`);
      errorCount++;
    }
  }

  console.log(`\n✅ Summary:`);
  console.log(`   Moved: ${movedCount} files`);
  console.log(`   Errors: ${errorCount} files`);
  
  if (!DRY_RUN && movedCount > 0) {
    console.log('\n📝 Creating git commit...');
    await createCommit(movedCount);
  }
}

function determineDestination(source) {
  // Commands go to alcub3-extensions/cli/commands/
  if (source.includes('/commands/') && source.endsWith('.ts')) {
    const filename = path.basename(source);
    return `alcub3-extensions/cli/commands/${filename}`;
  }
  
  // API files go to alcub3-extensions/core/api/
  if (source.includes('/api/') && source.endsWith('.ts')) {
    const filename = path.basename(source);
    return `alcub3-extensions/core/api/${filename}`;
  }
  
  // Security files in packages go to alcub3-extensions
  if (source.includes('packages/') && source.includes('/security/')) {
    const filename = path.basename(source);
    return `alcub3-extensions/core/security/${filename}`;
  }
  
  // UI components like DriftDashboard
  if (source.includes('/components/') && source.includes('Drift')) {
    const filename = path.basename(source);
    return `alcub3-extensions/cli/components/${filename}`;
  }
  
  // Test setup and generated files
  if (source.includes('test-setup.ts') || source.includes('generated/')) {
    // These can stay where they are for now
    return null;
  }
  
  // Performance budget
  if (source.includes('performance-budget')) {
    const filename = path.basename(source);
    return `alcub3-extensions/core/utils/${filename}`;
  }
  
  // Default: preserve relative structure
  const relativePath = source.replace(/^01-security-platform\/(core|cli)\/src\//, '');
  if (source.includes('core/src/')) {
    return `alcub3-extensions/core/${relativePath}`;
  } else if (source.includes('cli/src/')) {
    return `alcub3-extensions/cli/${relativePath}`;
  }
  
  // Unknown file - don't move
  return null;
}

async function moveFile(source, destination) {
  if (!destination) {
    console.log(`⏭️  Skipping: ${source} (no clear destination)`);
    return;
  }

  // Check if source exists
  try {
    await fs.access(source);
  } catch {
    throw new Error(`Source file does not exist: ${source}`);
  }

  // Create destination directory
  const destDir = path.dirname(destination);
  
  if (DRY_RUN) {
    console.log(`Would move: ${source} → ${destination}`);
    return;
  }

  await fs.mkdir(destDir, { recursive: true });
  
  // Move the file
  await fs.rename(source, destination);
  console.log(`✓ Moved: ${source} → ${destination}`);
  
  // Git add both old and new locations
  execSync(`git add "${source}" "${destination}"`, { stdio: 'pipe' });
}

async function createCommit(fileCount) {
  try {
    const message = `refactor: Move ${fileCount} ALCUB3-specific files to alcub3-extensions

Part of the ALCUB3 refactoring to separate Gemini core from ALCUB3 extensions.
These files contain ALCUB3-specific functionality.`;

    execSync(`git commit -m "${message}"`, { stdio: 'inherit' });
    console.log('✅ Git commit created');
  } catch (error) {
    console.warn('⚠️  Could not create git commit. You may need to commit manually.');
  }
}

// Run the script
main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});