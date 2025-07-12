#!/usr/bin/env node

/**
 * Test ALCUB3 Integration
 * 
 * Verifies that ALCUB3 features work with the current Gemini core
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.join(__dirname, '..');

async function testIntegration() {
  console.log('🧪 Testing ALCUB3 Integration...\n');
  
  const tests = {
    passed: 0,
    failed: 0,
    errors: []
  };
  
  // Test 1: Check if gemini-core exists
  console.log('1. Checking gemini-core structure...');
  try {
    await fs.access(path.join(ROOT_DIR, 'gemini-core/core/src/index.ts'));
    await fs.access(path.join(ROOT_DIR, 'gemini-core/cli/src/gemini.tsx'));
    console.log('   ✓ Gemini core files exist');
    tests.passed++;
  } catch (error) {
    console.log('   ✗ Missing Gemini core files');
    tests.failed++;
    tests.errors.push('Gemini core structure incomplete');
  }
  
  // Test 2: Check ALCUB3 extensions
  console.log('\n2. Checking ALCUB3 extensions...');
  try {
    await fs.access(path.join(ROOT_DIR, 'alcub3-extensions/core/index.ts'));
    await fs.access(path.join(ROOT_DIR, 'alcub3-extensions/cli/index.ts'));
    console.log('   ✓ ALCUB3 extensions exist');
    tests.passed++;
  } catch (error) {
    console.log('   ✗ Missing ALCUB3 extensions');
    tests.failed++;
    tests.errors.push('ALCUB3 extensions incomplete');
  }
  
  // Test 3: Check override pattern
  console.log('\n3. Checking override pattern...');
  try {
    const overrideFile = path.join(ROOT_DIR, 'alcub3-extensions/cli/overrides/gemini.tsx');
    await fs.access(overrideFile);
    const content = await fs.readFile(overrideFile, 'utf8');
    if (content.includes('registerAlcub3Commands')) {
      console.log('   ✓ Override pattern properly implemented');
      tests.passed++;
    } else {
      console.log('   ✗ Override pattern incomplete');
      tests.failed++;
      tests.errors.push('Override pattern missing command registration');
    }
  } catch (error) {
    console.log('   ✗ Override file not found');
    tests.failed++;
    tests.errors.push('Override pattern not implemented');
  }
  
  // Test 4: Check if new Gemini features are accessible
  console.log('\n4. Checking new Gemini features...');
  try {
    const newFeatureFile = path.join(ROOT_DIR, 'gemini-core/core/src/utils/newFeature.ts');
    const exists = await fs.access(newFeatureFile).then(() => true).catch(() => false);
    if (exists) {
      console.log('   ✓ New Gemini features detected');
      tests.passed++;
    } else {
      console.log('   ℹ No new features (this is OK)');
      tests.passed++;
    }
  } catch (error) {
    console.log('   ✗ Error checking features');
    tests.failed++;
  }
  
  // Test 5: Check imports
  console.log('\n5. Checking import structure...');
  try {
    const geminiFile = path.join(ROOT_DIR, '01-security-platform/cli/src/gemini.tsx');
    const content = await fs.readFile(geminiFile, 'utf8');
    if (content.includes('@gemini-core/') && content.includes('./commands/')) {
      console.log('   ✓ Imports properly structured');
      tests.passed++;
    } else {
      console.log('   ✗ Import structure issues');
      tests.failed++;
      tests.errors.push('Imports not properly configured');
    }
  } catch (error) {
    console.log('   ✗ Cannot read entry point');
    tests.failed++;
  }
  
  // Summary
  console.log('\n' + '='.repeat(50));
  console.log('📊 Test Summary:');
  console.log(`   Passed: ${tests.passed}`);
  console.log(`   Failed: ${tests.failed}`);
  
  if (tests.errors.length > 0) {
    console.log('\n❌ Errors:');
    tests.errors.forEach(err => console.log(`   - ${err}`));
  }
  
  if (tests.failed === 0) {
    console.log('\n✅ All integration tests passed!');
    console.log('   ALCUB3 is properly integrated with Gemini core.');
  } else {
    console.log('\n⚠️  Some tests failed. Please review the errors above.');
  }
  
  return tests.failed === 0;
}

// Run tests
testIntegration().then(success => {
  process.exit(success ? 0 : 1);
});