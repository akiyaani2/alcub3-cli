#!/usr/bin/env node

/**
 * Fix TypeScript imports that use .js extensions
 * 
 * In ES modules, TypeScript expects .js extensions in imports even for .ts files.
 * However, some imports might be missing the extension or have incorrect paths.
 */

import fs from 'fs/promises';
import path from 'path';
import { glob } from 'glob';

const DRY_RUN = process.argv.includes('--dry-run');

async function fixImports(filePath) {
  let content = await fs.readFile(filePath, 'utf8');
  let modified = false;
  const originalContent = content;
  
  // Fix imports that are missing .js extension
  // Pattern: from './something' or '../something' (without .js)
  content = content.replace(
    /from ['"](\.[^'"]+)(?<!\.js)(?<!\.json)(?<!\.css)(?<!\.tsx)(?<!\.ts)['"]/g,
    (match, importPath) => {
      // Don't add .js to directory imports or already correct imports
      if (importPath.endsWith('/') || importPath.includes('.js')) {
        return match;
      }
      // Skip node_modules imports
      if (importPath.includes('node_modules')) {
        return match;
      }
      return `from '${importPath}.js'`;
    }
  );
  
  // Fix @gemini-core imports that are missing paths
  content = content.replace(
    /from ['"]@gemini-core\/core\/src\/([\w\/\-]+)['"]/g,
    (match, path) => {
      if (!path.endsWith('.js')) {
        return `from '@gemini-core/core/src/${path}.js'`;
      }
      return match;
    }
  );
  
  // Fix @gemini-core imports that point to wrong paths
  content = content.replace(
    /@gemini-core\/core\/src\/([\w\/\-]+)(?:\.js)?/g,
    '@gemini-core/core/src/$1.js'
  );
  
  content = content.replace(
    /@gemini-core\/cli\/src\/([\w\/\-]+)(?:\.js)?/g,
    '@gemini-core/cli/src/$1.js'
  );
  
  // Fix incorrect relative imports in test files
  if (filePath.includes('.test.')) {
    // Fix imports like '../tools/memoryTool.js' that should be @gemini-core
    content = content.replace(
      /from ['"]\.\.\/tools\/([\w\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/tools/$1.js'`
    );
    
    content = content.replace(
      /from ['"]\.\.\/config\/([\w\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/config/$1.js'`
    );
    
    content = content.replace(
      /from ['"]\.\.\/core\/([\w\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/core/$1.js'`
    );
    
    content = content.replace(
      /from ['"]\.\.\/utils\/([\w\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/utils/$1.js'`
    );
    
    content = content.replace(
      /from ['"]\.\.\/services\/([\w\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/services/$1.js'`
    );
    
    content = content.replace(
      /from ['"]\.\.\/telemetry\/([\w\-]+)\.js['"]/g,
      `from '@gemini-core/core/src/telemetry/$1.js'`
    );
  }
  
  // Fix oauth2 import specifically
  content = content.replace(
    /from ['"]@gemini-core\/core\/src\/oauth2\.js['"]/g,
    `from '@gemini-core/core/src/code_assist/oauth2.js'`
  );
  
  modified = content !== originalContent;
  
  return { content, modified };
}

async function main() {
  console.log('🔧 Fixing TypeScript .js imports...\n');
  console.log(DRY_RUN ? '🔍 DRY RUN MODE - No files will be modified\n' : '');
  
  // Find all TypeScript files
  const patterns = [
    '01-security-platform/**/*.{ts,tsx}',
    'gemini-core/**/*.{ts,tsx}',
    'alcub3-extensions/**/*.{ts,tsx}'
  ];
  
  let allFiles = [];
  for (const pattern of patterns) {
    const files = await glob(pattern, {
      ignore: ['**/node_modules/**', '**/dist/**']
    });
    allFiles = allFiles.concat(files);
  }
  
  console.log(`Found ${allFiles.length} files to check\n`);
  
  let modifiedCount = 0;
  const errors = [];
  
  for (const file of allFiles) {
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
  
  console.log(`\n✅ Summary: ${modifiedCount}/${allFiles.length} files ${DRY_RUN ? 'would be' : ''} modified`);
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