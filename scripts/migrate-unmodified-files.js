#!/usr/bin/env node

/**
 * Migrate unmodified files from 01-security-platform to gemini-core
 */

import fs from 'fs/promises';
import path from 'path';

const DRY_RUN = process.argv.includes('--dry-run');

async function main() {
  console.log('📦 Migrating unmodified files to gemini-core...\n');
  console.log(DRY_RUN ? '🔍 DRY RUN MODE - No files will be moved\n' : '');
  
  // Read analysis results
  const analysis = JSON.parse(
    await fs.readFile('modification-analysis.json', 'utf8')
  );
  
  const filesToMove = analysis.files.noChangesDetected || [];
  console.log(`Found ${filesToMove.length} unmodified files to move\n`);
  
  let movedCount = 0;
  const errors = [];
  
  for (const file of filesToMove) {
    const sourcePath = file.path;
    
    // Determine destination path
    let destPath;
    if (sourcePath.includes('01-security-platform/core/src/')) {
      destPath = sourcePath.replace('01-security-platform/core/src/', 'gemini-core/core/src/');
    } else if (sourcePath.includes('01-security-platform/cli/src/')) {
      destPath = sourcePath.replace('01-security-platform/cli/src/', 'gemini-core/cli/src/');
    } else {
      console.log(`⚠️  Skipping ${sourcePath} - unexpected path structure`);
      continue;
    }
    
    try {
      if (!DRY_RUN) {
        // Create destination directory
        await fs.mkdir(path.dirname(destPath), { recursive: true });
        
        // Move the file
        await fs.rename(sourcePath, destPath);
      }
      
      console.log(`✓ ${sourcePath} → ${destPath}`);
      movedCount++;
    } catch (error) {
      console.error(`✗ Error moving ${sourcePath}: ${error.message}`);
      errors.push({ file: sourcePath, error: error.message });
    }
  }
  
  console.log(`\n✅ Summary: ${movedCount}/${filesToMove.length} files ${DRY_RUN ? 'would be' : ''} moved`);
  if (errors.length > 0) {
    console.log(`❌ ${errors.length} errors occurred`);
  }
  
  if (DRY_RUN) {
    console.log('\n💡 Run without --dry-run to actually move files');
  }
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});