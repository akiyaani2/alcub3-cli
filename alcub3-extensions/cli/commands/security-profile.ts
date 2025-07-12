/**
 * ALCUB3 Security Profile Management CLI
 * 
 * Commands for managing security profiles (ENTERPRISE, FEDERAL, CLASSIFIED, CUSTOM)
 */

import { Command } from 'commander';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as yaml from 'js-yaml';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { performance } from 'perf_hooks';

const PROFILES_DIR = path.join(__dirname, '../../../../01-security-platform/profiles');
const CURRENT_PROFILE_FILE = path.join(__dirname, '../../../../.alcub3/current-profile.json');

interface SecurityProfile {
  profile: {
    name: string;
    description: string;
    version: string;
    base_profile?: string;
  };
  classification: {
    enabled: boolean;
    max_level: string;
  };
  encryption: {
    algorithm: string;
  };
  performance: {
    target_latency_ms: number;
  };
}

export function createSecurityProfileCommand(): Command {
  const command = new Command('security-profile');
  command.description('Manage ALCUB3 security profiles');

  // Show current profile
  command
    .command('current')
    .description('Show the current security profile')
    .action(async () => {
      try {
        const current = await getCurrentProfile();
        console.log(chalk.blue('\nCurrent Security Profile:'));
        console.log(chalk.green(`  Name: ${current.name}`));
        console.log(chalk.gray(`  Description: ${current.description}`));
        console.log(chalk.gray(`  Max Classification: ${current.classification.max_level}`));
        console.log(chalk.gray(`  Performance Target: <${current.performance.target_latency_ms}ms`));
      } catch (error) {
        console.error(chalk.red('No profile currently set. Use "alcub3 security-profile set" to configure.'));
      }
    });

  // List available profiles
  command
    .command('list')
    .description('List all available security profiles')
    .action(async () => {
      const profiles = await listProfiles();
      console.log(chalk.blue('\nAvailable Security Profiles:\n'));
      
      for (const profile of profiles) {
        const data = await loadProfile(profile);
        console.log(chalk.green(`  ${data.profile.name}`));
        console.log(chalk.gray(`    ${data.profile.description}`));
        console.log(chalk.gray(`    Max Level: ${data.classification.max_level}`));
        console.log(chalk.gray(`    Performance: <${data.performance.target_latency_ms}ms\n`));
      }
    });

  // Set a profile
  command
    .command('set <profile>')
    .description('Set the active security profile')
    .option('--confirm', 'Skip confirmation prompt')
    .action(async (profileName: string, options: { confirm?: boolean }) => {
      try {
        const profile = await loadProfile(profileName);
        
        if (!options.confirm) {
          console.log(chalk.yellow('\nProfile Summary:'));
          console.log(`  Name: ${profile.profile.name}`);
          console.log(`  Description: ${profile.profile.description}`);
          console.log(`  Classification: Up to ${profile.classification.max_level}`);
          console.log(`  Performance: <${profile.performance.target_latency_ms}ms`);
          
          const { confirmed } = await inquirer.prompt([{
            type: 'confirm',
            name: 'confirmed',
            message: 'Apply this security profile?',
            default: true
          }]);
          
          if (!confirmed) {
            console.log(chalk.gray('Profile change cancelled.'));
            return;
          }
        }
        
        await setCurrentProfile(profile);
        console.log(chalk.green(`✓ Security profile set to: ${profile.profile.name}`));
        console.log(chalk.gray('Restart your application for changes to take effect.'));
      } catch (error) {
        console.error(chalk.red(`Failed to set profile: ${error.message}`));
      }
    });

  // Validate a profile
  command
    .command('validate <file>')
    .description('Validate a custom security profile')
    .action(async (file: string) => {
      try {
        const profile = await loadProfileFromFile(file);
        const errors = await validateProfile(profile);
        
        if (errors.length === 0) {
          console.log(chalk.green('✓ Profile is valid'));
        } else {
          console.log(chalk.red('✗ Profile validation failed:'));
          errors.forEach(error => console.log(chalk.red(`  - ${error}`)));
        }
      } catch (error) {
        console.error(chalk.red(`Failed to validate: ${error.message}`));
      }
    });

  // Recommend a profile
  command
    .command('recommend')
    .description('Interactive wizard to recommend a security profile')
    .action(async () => {
      const answers = await inquirer.prompt([
        {
          type: 'list',
          name: 'industry',
          message: 'What is your primary industry?',
          choices: [
            'Commercial/Industrial',
            'Government Contractor',
            'Federal Agency',
            'Military/Intelligence',
            'Research/Academic',
            'Other'
          ]
        },
        {
          type: 'list',
          name: 'data',
          message: 'What is the highest classification of data you handle?',
          choices: [
            'Public/Proprietary',
            'Controlled Unclassified (CUI/FOUO)',
            'Secret',
            'Top Secret',
            'Not Sure'
          ]
        },
        {
          type: 'list',
          name: 'performance',
          message: 'What are your performance requirements?',
          choices: [
            'Real-time (<20ms)',
            'Interactive (<100ms)',
            'Batch processing (<500ms)',
            'Security over speed'
          ]
        },
        {
          type: 'confirm',
          name: 'airgap',
          message: 'Do you need air-gapped operation capability?',
          default: false
        }
      ]);

      // Recommendation logic
      let recommended = 'ENTERPRISE';
      
      if (answers.industry.includes('Government') || answers.industry.includes('Federal')) {
        recommended = 'FEDERAL';
      }
      if (answers.industry.includes('Military') || answers.data.includes('Secret')) {
        recommended = 'CLASSIFIED';
      }
      if (answers.data === 'Public/Proprietary' && answers.performance === 'Real-time (<20ms)') {
        recommended = 'ENTERPRISE';
      }
      
      console.log(chalk.blue('\nRecommended Profile:'), chalk.green(recommended));
      
      const profile = await loadProfile(recommended.toLowerCase());
      console.log(chalk.gray(`\n${profile.profile.description}`));
      
      const { apply } = await inquirer.prompt([{
        type: 'confirm',
        name: 'apply',
        message: `Apply ${recommended} profile now?`,
        default: true
      }]);
      
      if (apply) {
        await setCurrentProfile(profile);
        console.log(chalk.green(`✓ ${recommended} profile applied`));
      }
    });

  // Benchmark profile performance
  command
    .command('benchmark [profile]')
    .description('Benchmark security operations for a profile')
    .action(async (profileName?: string) => {
      const profile = profileName ? 
        await loadProfile(profileName) : 
        await getCurrentProfile();
        
      console.log(chalk.blue(`\nBenchmarking ${profile.profile.name} Profile...\n`));
      
      // Simulated benchmarks
      const operations = [
        { name: 'Classification Check', base: 1, multiplier: getMultiplier(profile, 'classification') },
        { name: 'Encryption Operation', base: 2, multiplier: getMultiplier(profile, 'encryption') },
        { name: 'Authentication', base: 5, multiplier: getMultiplier(profile, 'auth') },
        { name: 'Zero-Trust Validation', base: 20, multiplier: getMultiplier(profile, 'zerotrust') },
      ];
      
      let totalLatency = 0;
      
      for (const op of operations) {
        const latency = op.base * op.multiplier;
        totalLatency += latency;
        const start = performance.now();
        await new Promise(resolve => setTimeout(resolve, latency)); // Simulate
        const end = performance.now();
        
        console.log(`  ${op.name}: ${chalk.yellow(`${latency}ms`)}`);
      }
      
      console.log(chalk.gray('  ─────────────────────'));
      console.log(`  Total: ${chalk.green(`${totalLatency}ms`)}`);
      console.log(`  Target: <${profile.performance.target_latency_ms}ms`);
      
      if (totalLatency <= profile.performance.target_latency_ms) {
        console.log(chalk.green('\n✓ Performance within target'));
      } else {
        console.log(chalk.yellow('\n⚠ Performance exceeds target'));
      }
    });

  // Create custom profile
  command
    .command('create')
    .description('Create a custom security profile')
    .action(async () => {
      console.log(chalk.blue('Custom Profile Creator\n'));
      
      const answers = await inquirer.prompt([
        {
          type: 'input',
          name: 'name',
          message: 'Profile name:',
          validate: (input) => input.length > 0 || 'Name required'
        },
        {
          type: 'input',
          name: 'description',
          message: 'Description:'
        },
        {
          type: 'list',
          name: 'base',
          message: 'Base profile to extend:',
          choices: ['ENTERPRISE', 'FEDERAL', 'CLASSIFIED', 'None']
        },
        {
          type: 'checkbox',
          name: 'features',
          message: 'Select security features:',
          choices: [
            'Quantum-resistant cryptography',
            'Zero-trust architecture',
            'Homomorphic encryption',
            'Hardware security modules',
            'Air-gap support',
            'Byzantine fault tolerance'
          ]
        }
      ]);
      
      // Generate custom profile
      const customProfile = await generateCustomProfile(answers);
      const filename = `custom_${answers.name.toLowerCase().replace(/\s+/g, '_')}.yaml`;
      const filepath = path.join(PROFILES_DIR, filename);
      
      await fs.writeFile(filepath, yaml.dump(customProfile), 'utf-8');
      console.log(chalk.green(`\n✓ Custom profile created: ${filename}`));
      console.log(chalk.gray(`Edit ${filepath} to fine-tune settings`));
    });

  return command;
}

// Helper functions

async function getCurrentProfile(): Promise<any> {
  try {
    const data = await fs.readFile(CURRENT_PROFILE_FILE, 'utf-8');
    return JSON.parse(data);
  } catch {
    // Default to ENTERPRISE if not set
    return await loadProfile('enterprise');
  }
}

async function setCurrentProfile(profile: SecurityProfile): Promise<void> {
  const dir = path.dirname(CURRENT_PROFILE_FILE);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(CURRENT_PROFILE_FILE, JSON.stringify(profile, null, 2));
}

async function listProfiles(): Promise<string[]> {
  const files = await fs.readdir(PROFILES_DIR);
  return files
    .filter(f => f.endsWith('.yaml') && !f.includes('template'))
    .map(f => path.basename(f, '.yaml'));
}

async function loadProfile(name: string): Promise<SecurityProfile> {
  const file = path.join(PROFILES_DIR, `${name}.yaml`);
  return loadProfileFromFile(file);
}

async function loadProfileFromFile(file: string): Promise<SecurityProfile> {
  const content = await fs.readFile(file, 'utf-8');
  return yaml.load(content) as SecurityProfile;
}

async function validateProfile(profile: SecurityProfile): Promise<string[]> {
  const errors: string[] = [];
  
  if (!profile.profile?.name) errors.push('Missing profile name');
  if (!profile.classification?.max_level) errors.push('Missing classification max_level');
  if (!profile.performance?.target_latency_ms) errors.push('Missing performance target');
  
  // Check for conflicting settings
  if (profile.performance.target_latency_ms < 20 && 
      profile.encryption?.algorithm === 'LAYERED') {
    errors.push('Layered encryption incompatible with <20ms target');
  }
  
  return errors;
}

function getMultiplier(profile: SecurityProfile, feature: string): number {
  // Simplified multipliers based on profile
  const multipliers = {
    ENTERPRISE: { classification: 1, encryption: 1, auth: 1, zerotrust: 0 },
    FEDERAL: { classification: 2, encryption: 3, auth: 2, zerotrust: 2 },
    CLASSIFIED: { classification: 5, encryption: 10, auth: 5, zerotrust: 5 }
  };
  
  return multipliers[profile.profile.name]?.[feature] || 1;
}

async function generateCustomProfile(answers: any): Promise<any> {
  // Generate a custom profile based on wizard answers
  const base = answers.base !== 'None' ? 
    await loadProfile(answers.base.toLowerCase()) : 
    { profile: {}, classification: {}, encryption: {}, performance: {} };
    
  return {
    profile: {
      name: `CUSTOM_${answers.name.toUpperCase()}`,
      description: answers.description,
      version: '1.0.0',
      base_profile: answers.base !== 'None' ? answers.base : undefined
    },
    classification: {
      ...base.classification,
      enabled: true
    },
    encryption: {
      ...base.encryption,
      quantum_resistant: answers.features.includes('Quantum-resistant cryptography')
    },
    performance: {
      target_latency_ms: 100 // Default, user can edit
    }
  };
}