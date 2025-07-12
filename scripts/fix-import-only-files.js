#!/usr/bin/env node

/**
 * Fix import-only files by reverting ALCUB3 imports and moving to gemini-core
 */

import fs from 'fs/promises';
import path from 'path';

const DRY_RUN = process.argv.includes('--dry-run');

async function fixImportsAndMove(file) {
  const sourcePath = file.path;
  
  // Read file content
  let content = await fs.readFile(sourcePath, 'utf8');
  
  // Revert ALCUB3 imports back to relative imports
  // @alcub3/alcub3-cli-core -> relative paths
  content = content.replace(
    /from ['"]@alcub3\/alcub3-cli-core['"]/g,
    `from '@alcub3/alcub3-cli-core'` // Keep for now, will fix after move
  );
  
  // Determine destination
  let destPath;
  if (sourcePath.includes('01-security-platform/core/src/')) {
    destPath = sourcePath.replace('01-security-platform/core/src/', 'gemini-core/core/src/');
  } else if (sourcePath.includes('01-security-platform/cli/src/')) {
    destPath = sourcePath.replace('01-security-platform/cli/src/', 'gemini-core/cli/src/');
  } else {
    return { success: false, error: 'Unexpected path structure' };
  }
  
  if (!DRY_RUN) {
    // Create destination directory
    await fs.mkdir(path.dirname(destPath), { recursive: true });
    
    // Write fixed content to destination
    await fs.writeFile(destPath, content);
    
    // Remove source file
    await fs.unlink(sourcePath);
  }
  
  return { success: true, source: sourcePath, dest: destPath };
}

async function main() {
  console.log('🔧 Fixing import-only files and moving to gemini-core...\n');
  console.log(DRY_RUN ? '🔍 DRY RUN MODE - No changes will be made\n' : '');
  
  // Read analysis results
  const analysis = JSON.parse(
    await fs.readFile('modification-analysis.json', 'utf8')
  );
  
  const importOnlyFiles = analysis.files.importChangesOnly || [];
  console.log(`Found ${importOnlyFiles.length} import-only files to process\n`);
  
  let successCount = 0;
  const errors = [];
  
  for (const file of importOnlyFiles) {
    try {
      const result = await fixImportsAndMove(file);
      if (result.success) {
        console.log(`✓ ${result.source} → ${result.dest}`);
        successCount++;
      } else {
        console.error(`✗ ${file.path}: ${result.error}`);
        errors.push({ file: file.path, error: result.error });
      }
    } catch (error) {
      console.error(`✗ Error processing ${file.path}: ${error.message}`);
      errors.push({ file: file.path, error: error.message });
    }
  }
  
  console.log(`\n✅ Summary: ${successCount}/${importOnlyFiles.length} files ${DRY_RUN ? 'would be' : ''} processed`);
  if (errors.length > 0) {
    console.log(`❌ ${errors.length} errors occurred`);
  }
  
  if (DRY_RUN) {
    console.log('\n💡 Run without --dry-run to actually process files');
  }
  
  // After moving, we'll need to fix the imports properly
  if (!DRY_RUN && successCount > 0) {
    console.log('\n📝 Note: Run fix-gemini-imports.js next to correct import paths');
  }
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});