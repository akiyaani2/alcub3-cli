#!/usr/bin/env node

/**
 * Move Unmodified Gemini Files Script
 * Moves original Gemini files to gemini-core directory
 */

import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';

const INVENTORY_FILE = 'REFACTOR_INVENTORY.md';
const DRY_RUN = process.argv.includes('--dry-run');

async function main() {
  console.log(`🚀 Starting Gemini file migration... ${DRY_RUN ? '(DRY RUN)' : ''}\n`);

  // Read inventory
  const inventory = await fs.readFile(INVENTORY_FILE, 'utf8');
  
  // Extract original files section
  const originalFilesSection = inventory.match(/## Original Gemini Files \(Unmodified\)[\s\S]*?(?=##|$)/);
  if (!originalFilesSection) {
    console.error('Could not find original files section in inventory');
    process.exit(1);
  }

  // Parse file mappings
  const fileLines = originalFilesSection[0]
    .split('\n')
    .filter(line => line.startsWith('- '))
    .map(line => line.substring(2));

  console.log(`Found ${fileLines.length} unmodified Gemini files to move\n`);

  let movedCount = 0;
  let errorCount = 0;

  for (const line of fileLines) {
    const [source, , destination] = line.split(' ');
    
    if (!source || !destination) {
      console.error(`❌ Invalid line format: ${line}`);
      errorCount++;
      continue;
    }

    try {
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

async function moveFile(source, destination) {
  // Fix destination path to maintain proper structure
  let fixedDestination = destination;
  
  // Determine if this is a core or cli file and adjust path
  if (source.includes('01-security-platform/core/src/')) {
    // Extract the path after src/
    const relativePath = source.replace('01-security-platform/core/src/', '');
    fixedDestination = `gemini-core/core/src/${relativePath}`;
  } else if (source.includes('01-security-platform/cli/src/')) {
    // Extract the path after src/
    const relativePath = source.replace('01-security-platform/cli/src/', '');
    fixedDestination = `gemini-core/cli/src/${relativePath}`;
  }

  // Check if source exists
  try {
    await fs.access(source);
  } catch {
    throw new Error(`Source file does not exist: ${source}`);
  }

  // Create destination directory
  const destDir = path.dirname(fixedDestination);
  
  if (DRY_RUN) {
    console.log(`Would move: ${source} → ${fixedDestination}`);
    return;
  }

  await fs.mkdir(destDir, { recursive: true });
  
  // Move the file
  await fs.rename(source, fixedDestination);
  console.log(`✓ Moved: ${source} → ${fixedDestination}`);
  
  // Git add both old and new locations
  execSync(`git add "${source}" "${fixedDestination}"`, { stdio: 'pipe' });
}

async function createCommit(fileCount) {
  try {
    const message = `refactor: Move ${fileCount} unmodified Gemini files to gemini-core

Part of the ALCUB3 refactoring to separate Gemini core from ALCUB3 extensions.
These files are unmodified from the original Gemini CLI.`;

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