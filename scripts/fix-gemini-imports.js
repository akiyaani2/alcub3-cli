#!/usr/bin/env node

/**
 * Fix imports in gemini-core files after migration
 */

import fs from 'fs/promises';
import path from 'path';
import { glob } from 'glob';

const DRY_RUN = process.argv.includes('--dry-run');

async function fixFileImports(filePath) {
  let content = await fs.readFile(filePath, 'utf8');
  let modified = false;
  
  // Fix @alcub3/alcub3-cli-core imports
  if (content.includes('@alcub3/alcub3-cli-core')) {
    content = content.replace(
      /from ['"]@alcub3\/alcub3-cli-core['"]/g,
      `from '../index.js'`
    );
    modified = true;
  }
  
  // Fix any remaining workspace imports
  if (content.includes('workspace:')) {
    content = content.replace(/workspace:\*/g, '*');
    modified = true;
  }
  
  return { content, modified };
}

async function main() {
  console.log('🔧 Fixing imports in gemini-core files...\n');
  console.log(DRY_RUN ? '🔍 DRY RUN MODE - No files will be modified\n' : '');
  
  // Find all TypeScript/JavaScript files in gemini-core
  const files = await glob('gemini-core/**/*.{ts,tsx,js,jsx}', {
    ignore: ['**/node_modules/**', '**/dist/**']
  });
  
  console.log(`Found ${files.length} files to check\n`);
  
  let modifiedCount = 0;
  const errors = [];
  
  for (const file of files) {
    try {
      const result = await fixFileImports(file);
      
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