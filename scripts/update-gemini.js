#!/usr/bin/env node

/**
 * Update Gemini CLI Script
 * 
 * This script helps you update the Gemini core while preserving ALCUB3 extensions
 */

import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.join(__dirname, '..');

const GEMINI_REPO = 'https://github.com/google/gemini-cli.git';
const TEMP_DIR = path.join(ROOT_DIR, '.gemini-update-temp');
const GEMINI_CORE_DIR = path.join(ROOT_DIR, 'gemini-core');

async function checkForUpdates() {
  console.log('🔍 Checking for Gemini updates...\n');
  
  try {
    // Clone to temp directory
    execSync(`rm -rf ${TEMP_DIR}`, { stdio: 'ignore' });
    execSync(`git clone --depth=1 ${GEMINI_REPO} ${TEMP_DIR}`, { 
      stdio: 'pipe' 
    });
    
    // Get latest commit hash
    const latestHash = execSync('git rev-parse HEAD', {
      cwd: TEMP_DIR,
      encoding: 'utf8'
    }).trim();
    
    // Check if we have a record of current version
    let currentHash = '';
    try {
      currentHash = await fs.readFile(
        path.join(GEMINI_CORE_DIR, '.gemini-version'),
        'utf8'
      );
    } catch (e) {
      // No version file yet
    }
    
    if (currentHash === latestHash) {
      console.log('✅ Gemini is up to date!');
      return false;
    } else {
      console.log(`📦 New Gemini version available: ${latestHash}`);
      return { latestHash, currentHash };
    }
  } catch (error) {
    console.error('❌ Error checking for updates:', error.message);
    return false;
  }
}

async function performUpdate(versionInfo) {
  console.log('\n🚀 Updating Gemini core...\n');
  
  try {
    // Backup current gemini-core
    const backupDir = `${GEMINI_CORE_DIR}.backup-${Date.now()}`;
    console.log(`📦 Backing up current version to ${backupDir}`);
    await fs.rename(GEMINI_CORE_DIR, backupDir);
    
    // Copy new files
    console.log('📝 Copying new Gemini files...');
    await fs.mkdir(GEMINI_CORE_DIR, { recursive: true });
    
    // Copy packages/core to gemini-core/core
    await copyDirectory(
      path.join(TEMP_DIR, 'packages/core'),
      path.join(GEMINI_CORE_DIR, 'core')
    );
    
    // Copy packages/cli to gemini-core/cli
    await copyDirectory(
      path.join(TEMP_DIR, 'packages/cli'),
      path.join(GEMINI_CORE_DIR, 'cli')
    );
    
    // Save version info
    await fs.writeFile(
      path.join(GEMINI_CORE_DIR, '.gemini-version'),
      versionInfo.latestHash
    );
    
    // Clean up temp directory
    execSync(`rm -rf ${TEMP_DIR}`, { stdio: 'ignore' });
    
    console.log('\n✅ Update complete!');
    console.log(`\n📝 Next steps:
1. Run 'npm test' to verify everything works
2. Check for any breaking changes in ALCUB3 overrides
3. Update imports if needed
4. Remove backup directory if everything works: ${backupDir}`);
    
    return true;
  } catch (error) {
    console.error('❌ Error during update:', error.message);
    return false;
  }
}

async function copyDirectory(src, dest) {
  await fs.mkdir(dest, { recursive: true });
  const entries = await fs.readdir(src, { withFileTypes: true });
  
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    
    if (entry.isDirectory()) {
      await copyDirectory(srcPath, destPath);
    } else {
      await fs.copyFile(srcPath, destPath);
    }
  }
}

async function main() {
  console.log('🤖 ALCUB3 Gemini Update Tool\n');
  
  const updateInfo = await checkForUpdates();
  
  if (!updateInfo) {
    return;
  }
  
  // Ask for confirmation
  console.log('\n⚠️  This will replace the gemini-core directory.');
  console.log('A backup will be created automatically.');
  console.log('\nProceed with update? (y/N): ');
  
  // Simple confirmation for now (in real usage, use readline)
  if (process.argv.includes('--yes')) {
    await performUpdate(updateInfo);
  } else {
    console.log('\nRun with --yes to confirm update');
  }
}

// Add npm scripts
console.log(`
To use this tool, add these scripts to your package.json:

"update:check": "node scripts/update-gemini.js",
"update:gemini": "node scripts/update-gemini.js --yes"
`);

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});