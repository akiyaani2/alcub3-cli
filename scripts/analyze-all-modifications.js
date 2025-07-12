#!/usr/bin/env node

/**
 * Comprehensive analysis of all modified files
 */

import fs from 'fs/promises';
import path from 'path';

async function analyzeFile(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    
    // Check for various import patterns that indicate modification
    const modifiedImportPatterns = [
      /@alcub3\/alcub3-cli-core/,
      /from ['"]\.\.\/\.\.\/.*['"]/, // Relative imports that might be changed
    ];
    
    const hasModifiedImports = modifiedImportPatterns.some(pattern => pattern.test(content));
    
    // Check for ALCUB3-specific code
    const alcubPatterns = [
      /SecurityContext/,
      /MAESTRO/,
      /classification/i,
      /clearance/i,
      /air[\s-]?gap/i,
      /ALCUB3/,
      /drift/i,
      /JIT/,
      /CISA/,
      /profile[\s-]?manager/i,
      /security[\s-]?profile/i
    ];
    
    const hasAlcubCode = alcubPatterns.some(pattern => pattern.test(content));
    
    // Check if it's a test file
    const isTest = filePath.includes('.test.') || filePath.includes('.spec.');
    
    // Get file type
    const ext = path.extname(filePath);
    const fileType = filePath.includes('/tools/') ? 'tool' :
                    filePath.includes('/core/') ? 'core' :
                    filePath.includes('/config/') ? 'config' :
                    filePath.includes('/ui/') ? 'ui' :
                    filePath.includes('/hooks/') ? 'hook' :
                    'other';
    
    return {
      path: filePath,
      hasModifiedImports,
      hasAlcubCode,
      isTest,
      fileType,
      ext,
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
  console.log('🔍 Comprehensive analysis of modified files...\n');
  
  // Read the inventory
  const inventory = await fs.readFile('REFACTOR_INVENTORY.md', 'utf8');
  
  // Extract modified files
  const modifiedSection = inventory.match(/## Modified Gemini Files[\s\S]*?(?=##|$)/);
  const filePaths = modifiedSection[0]
    .split('\n')
    .filter(line => line.startsWith('- '))
    .map(line => line.match(/- (.*?) \(/)?.[1])
    .filter(Boolean);
  
  console.log(`Analyzing ${filePaths.length} files...\n`);
  
  const results = {
    withAlcubCode: [],
    importChangesOnly: [],
    noChangesDetected: [],
    testFiles: [],
    errors: []
  };
  
  // Analyze each file
  for (const filePath of filePaths) {
    const analysis = await analyzeFile(filePath);
    
    if (analysis.error) {
      results.errors.push(analysis);
    } else if (analysis.isTest) {
      results.testFiles.push(analysis);
    } else if (analysis.hasAlcubCode) {
      results.withAlcubCode.push(analysis);
    } else if (analysis.hasModifiedImports) {
      results.importChangesOnly.push(analysis);
    } else {
      results.noChangesDetected.push(analysis);
    }
  }
  
  // Generate detailed report
  const report = `# Comprehensive Modification Analysis

## Summary
- **Total Modified Files**: ${filePaths.length}
- **Files with ALCUB3 Code**: ${results.withAlcubCode.length}
- **Import Changes Only**: ${results.importChangesOnly.length}
- **Test Files**: ${results.testFiles.length}
- **No Changes Detected**: ${results.noChangesDetected.length}
- **Errors**: ${results.errors.length}

## Files Requiring Override Pattern (${results.withAlcubCode.length})
${results.withAlcubCode.map(f => `- ${f.path} (${f.fileType})`).join('\n')}

## Files with Import Changes Only (${results.importChangesOnly.length})
These can be moved back to gemini-core with import fixes:
${results.importChangesOnly.slice(0, 10).map(f => `- ${f.path}`).join('\n')}
${results.importChangesOnly.length > 10 ? `... and ${results.importChangesOnly.length - 10} more` : ''}

## Test Files (${results.testFiles.length})
${results.testFiles.slice(0, 5).map(f => `- ${f.path}`).join('\n')}
${results.testFiles.length > 5 ? `... and ${results.testFiles.length - 5} more` : ''}

## Files to Investigate (${results.noChangesDetected.length})
These files are marked as modified but no changes detected:
${results.noChangesDetected.slice(0, 10).map(f => `- ${f.path}`).join('\n')}
${results.noChangesDetected.length > 10 ? `... and ${results.noChangesDetected.length - 10} more` : ''}

## Recommendation
Based on this analysis:
1. Only ${results.withAlcubCode.length} files need override patterns
2. ${results.importChangesOnly.length} files can be moved to gemini-core with import fixes
3. ${results.noChangesDetected.length} files may not actually be modified

This is excellent for maintainability!
`;
  
  await fs.writeFile('COMPREHENSIVE_ANALYSIS.md', report);
  
  // Save JSON for scripting
  await fs.writeFile('modification-analysis.json', JSON.stringify({
    summary: {
      total: filePaths.length,
      withAlcubCode: results.withAlcubCode.length,
      importOnly: results.importChangesOnly.length,
      testFiles: results.testFiles.length,
      noChanges: results.noChangesDetected.length
    },
    files: results
  }, null, 2));
  
  console.log('✅ Analysis complete! See COMPREHENSIVE_ANALYSIS.md');
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});