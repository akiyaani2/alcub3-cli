#!/usr/bin/env node

/**
 * Analyze Import Changes Script
 * Identifies files that only have import path changes vs actual code modifications
 */

import fs from 'fs/promises';
import path from 'path';

const MODIFIED_FILES_DIR = '01-security-platform';
const IMPORT_PATTERN = /@alcub3\/alcub3-cli-core/g;

async function analyzeFile(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    
    // Check if file contains ALCUB3 imports
    const hasAlcubImports = IMPORT_PATTERN.test(content);
    
    // Simple heuristic: if the only changes are import paths, it's import-only
    // Look for ALCUB3-specific code patterns
    const alcubPatterns = [
      /SecurityContext/,
      /MAESTRO/,
      /classification/i,
      /clearance/i,
      /air[\s-]?gap/i,
      /ALCUB3/,
      /drift/i,
      /JIT/,
      /CISA/
    ];
    
    const hasAlcubCode = alcubPatterns.some(pattern => pattern.test(content));
    
    return {
      path: filePath,
      hasAlcubImports,
      hasAlcubCode,
      lineCount: content.split('\n').length
    };
  } catch (error) {
    return {
      path: filePath,
      error: error.message
    };
  }
}

async function main() {
  console.log('🔍 Analyzing import changes in modified files...\n');
  
  // Read the inventory to get list of modified files
  const inventory = await fs.readFile('REFACTOR_INVENTORY.md', 'utf8');
  
  // Extract modified files section
  const modifiedSection = inventory.match(/## Modified Gemini Files[\s\S]*?(?=##|$)/);
  if (!modifiedSection) {
    console.error('Could not find modified files section');
    process.exit(1);
  }
  
  // Parse file paths
  const filePaths = modifiedSection[0]
    .split('\n')
    .filter(line => line.startsWith('- '))
    .map(line => line.match(/- (.*?) \(/)?.[1])
    .filter(Boolean);
  
  console.log(`Found ${filePaths.length} files to analyze\n`);
  
  const results = {
    importOnly: [],
    hasAlcubCode: [],
    errors: []
  };
  
  // Analyze each file
  for (const filePath of filePaths) {
    const analysis = await analyzeFile(filePath);
    
    if (analysis.error) {
      results.errors.push(analysis);
    } else if (analysis.hasAlcubCode) {
      results.hasAlcubCode.push(analysis);
    } else if (analysis.hasAlcubImports) {
      results.importOnly.push(analysis);
    }
  }
  
  // Generate report
  console.log('📊 Analysis Results:\n');
  console.log(`Import-only changes: ${results.importOnly.length} files`);
  console.log(`Files with ALCUB3 code: ${results.hasAlcubCode.length} files`);
  console.log(`Errors: ${results.errors.length} files\n`);
  
  if (results.hasAlcubCode.length > 0) {
    console.log('🔧 Files with ALCUB3-specific code:');
    results.hasAlcubCode.forEach(file => {
      console.log(`  - ${file.path}`);
    });
    console.log('');
  }
  
  // Save detailed results
  const report = {
    summary: {
      total: filePaths.length,
      importOnly: results.importOnly.length,
      hasAlcubCode: results.hasAlcubCode.length,
      errors: results.errors.length
    },
    files: results,
    recommendation: results.importOnly.length > 100 
      ? 'Most files only have import changes. Consider automated import reversal.'
      : 'Significant ALCUB3 modifications found. Use override pattern.'
  };
  
  await fs.writeFile(
    'IMPORT_ANALYSIS.json',
    JSON.stringify(report, null, 2)
  );
  
  console.log('✅ Analysis complete! See IMPORT_ANALYSIS.json for details.');
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});