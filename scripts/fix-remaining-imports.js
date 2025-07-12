#!/usr/bin/env node

/**
 * Fix imports in remaining 01-security-platform files
 */

import fs from 'fs/promises';
import path from 'path';
import { glob } from 'glob';

const DRY_RUN = process.argv.includes('--dry-run');

async function fixImports(filePath) {
  let content = await fs.readFile(filePath, 'utf8');
  let modified = false;
  
  // Determine if this is a core or cli file
  const isCore = filePath.includes('/core/');
  const isCli = filePath.includes('/cli/');
  
  if (isCore) {
    // Fix relative imports to point to gemini-core
    // Pattern: from './something' or '../something' -> '@gemini-core/core/src/something'
    content = content.replace(
      /from ['"]\.\/((?!api|security|utils\/performance-budget|config\/env|types\/express)[\w\/\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/$1.js'`
    );
    
    content = content.replace(
      /from ['"]\.\.\/\.\.\/((?!api|security)[\w\/\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/$1.js'`
    );
    
    // Special case for ../index.js
    content = content.replace(
      /from ['"]\.\.\/index\.js['"]/g,
      `from '@gemini-core/core/src/index.js'`
    );
    
    modified = content.includes('@gemini-core/');
  }
  
  if (isCli) {
    // Fix relative imports for CLI files
    content = content.replace(
      /from ['"]\.\/((?!commands|ui\/components\/DriftDashboard)[\w\/\-]+)\.js['"]/g,
      `from '@gemini-core/cli/src/$1.js'`
    );
    
    modified = content.includes('@gemini-core/');
  }
  
  // Fix any @alcub3/alcub3-cli-core imports
  if (content.includes('@alcub3/alcub3-cli-core')) {
    content = content.replace(
      /from ['"]@alcub3\/alcub3-cli-core['"]/g,
      `from '@gemini-core/core/src/index.js'`
    );
    modified = true;
  }
  
  return { content, modified };
}

async function main() {
  console.log('🔧 Fixing imports in remaining 01-security-platform files...\n');
  console.log(DRY_RUN ? '🔍 DRY RUN MODE - No files will be modified\n' : '');
  
  // Find all TypeScript files in 01-security-platform
  const files = await glob('01-security-platform/**/*.{ts,tsx}', {
    ignore: ['**/node_modules/**', '**/dist/**']
  });
  
  console.log(`Found ${files.length} files to check\n`);
  
  let modifiedCount = 0;
  const errors = [];
  
  for (const file of files) {
    try {
      const result = await fixImports(file);
      
      if (result.modified) {
        if (!DRY_RUN) {
          await fs.writeFile(file, result.content);
        }
        console.log(`✓ Fixed imports in ${file}`);
        modifiedCount++;
      }
    } catch (error) {
      console.error(`✗ Error processing ${file}: ${error.message}`);
      errors.push({ file, error: error.message });
    }
  }
  
  console.log(`\n✅ Summary: ${modifiedCount}/${files.length} files ${DRY_RUN ? 'would be' : ''} modified`);
  if (errors.length > 0) {
    console.log(`❌ ${errors.length} errors occurred`);
  }
  
  if (DRY_RUN) {
    console.log('\n💡 Run without --dry-run to actually fix imports');
  }
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});