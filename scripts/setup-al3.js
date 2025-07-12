#!/usr/bin/env node

/**
 * Setup AL3 Developer CLI
 * 
 * Installs the al3 command for local development
 */

import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, '..');

console.log('🔧 Setting up AL3 Developer CLI...\n');

try {
  // Ensure we're in the right directory
  process.chdir(ROOT_DIR);
  
  // Install dependencies if needed
  console.log('📦 Checking dependencies...');
  execSync('npm install', { stdio: 'inherit' });
  
  // Create global link
  console.log('\n🔗 Creating global link for al3 command...');
  execSync('npm link', { stdio: 'inherit' });
  
  console.log('\n✅ Setup complete!');
  console.log('\nYou can now use the "al3" command from anywhere:');
  console.log('  al3 help      - Show available commands');
  console.log('  al3 status    - Check project status');
  console.log('  al3 start     - Start ALCUB3 CLI\n');
  
} catch (error) {
  console.error('❌ Setup failed:', error.message);
  console.error('\nTry running manually:');
  console.error('  cd', ROOT_DIR);
  console.error('  npm install');
  console.error('  npm link');
  process.exit(1);
}