#!/usr/bin/env node

/**
 * Extract Modifications Script
 * Analyzes modified Gemini files and creates override structure
 */

import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';

const INVENTORY_FILE = 'REFACTOR_INVENTORY.md';
const MODIFICATIONS_OUTPUT = 'MODIFICATIONS_PLAN.md';

async function main() {
  console.log('🔍 Analyzing modified Gemini files...\n');

  // Read inventory
  const inventory = await fs.readFile(INVENTORY_FILE, 'utf8');
  
  // Extract modified files section
  const modifiedSection = inventory.match(/## Modified Gemini Files[\s\S]*?(?=##|$)/);
  if (!modifiedSection) {
    console.error('Could not find modified files section in inventory');
    process.exit(1);
  }

  // Parse file mappings
  const fileLines = modifiedSection[0]
    .split('\n')
    .filter(line => line.startsWith('- '))
    .map(line => {
      const match = line.match(/- (.*?) \(modified from (.*?)\)/);
      return match ? { current: match[1], original: match[2] } : null;
    })
    .filter(Boolean);

  console.log(`Found ${fileLines.length} modified files to analyze\n`);

  const modifications = {
    criticalFiles: [],      // Files that are heavily modified and critical
    minorChanges: [],       // Files with minor modifications
    importUpdates: [],      // Files that just need import updates
    overrideNeeded: []      // Files that need override pattern
  };

  // Analyze each file
  for (const file of fileLines) {
    const analysis = await analyzeFile(file);
    categorizeFile(file, analysis, modifications);
  }

  // Generate plan
  await generatePlan(modifications);
  
  console.log(`\n✅ Analysis complete! See ${MODIFICATIONS_OUTPUT} for the plan.`);
}

async function analyzeFile({ current, original }) {
  // Get diff size to understand modification extent
  try {
    const diffOutput = execSync(
      `git diff --no-index --stat "${original}" "${current}" 2>/dev/null || true`,
      { encoding: 'utf8' }
    );
    
    const stats = parseDiffStats(diffOutput);
    
    // Analyze the type of file
    const fileType = getFileType(current);
    
    return {
      ...stats,
      fileType,
      critical: isCriticalFile(current),
      canOverride: canUseOverridePattern(current)
    };
  } catch (error) {
    return {
      insertions: 0,
      deletions: 0,
      fileType: 'unknown',
      critical: false,
      canOverride: false
    };
  }
}

function parseDiffStats(diffOutput) {
  const match = diffOutput.match(/(\d+) insertions?\(\+\), (\d+) deletions?/);
  if (match) {
    return {
      insertions: parseInt(match[1]),
      deletions: parseInt(match[2])
    };
  }
  return { insertions: 0, deletions: 0 };
}

function getFileType(filePath) {
  if (filePath.includes('/tools/')) return 'tool';
  if (filePath.includes('/core/client')) return 'core-client';
  if (filePath.includes('/config/')) return 'config';
  if (filePath.includes('/ui/')) return 'ui';
  if (filePath.includes('/hooks/')) return 'hook';
  if (filePath.includes('/utils/')) return 'util';
  return 'other';
}

function isCriticalFile(filePath) {
  const criticalPaths = [
    'client.ts',
    'config.ts',
    'geminiChat.ts',
    'App.tsx',
    'tool-registry.ts'
  ];
  
  return criticalPaths.some(critical => filePath.includes(critical));
}

function canUseOverridePattern(filePath) {
  // Classes and services can use inheritance
  const overridable = [
    'client.ts',
    'Chat.ts',
    'Service',
    'Manager',
    'Registry'
  ];
  
  return overridable.some(pattern => filePath.includes(pattern));
}

function categorizeFile(file, analysis, modifications) {
  const totalChanges = analysis.insertions + analysis.deletions;
  
  if (analysis.critical && totalChanges > 50) {
    modifications.criticalFiles.push({ ...file, ...analysis });
  } else if (totalChanges < 10) {
    modifications.minorChanges.push({ ...file, ...analysis });
  } else if (analysis.canOverride) {
    modifications.overrideNeeded.push({ ...file, ...analysis });
  } else {
    modifications.importUpdates.push({ ...file, ...analysis });
  }
}

async function generatePlan(modifications) {
  const plan = `# Modifications Extraction Plan
Generated: ${new Date().toISOString()}

## Summary
- **Critical Files**: ${modifications.criticalFiles.length} (need careful extraction)
- **Override Pattern**: ${modifications.overrideNeeded.length} (can use inheritance)
- **Minor Changes**: ${modifications.minorChanges.length} (small modifications)
- **Import Updates**: ${modifications.importUpdates.length} (mainly import changes)

## Strategy

### Phase 1: Critical Files (Priority: HIGH)
These files have significant modifications and are core to the system.

${modifications.criticalFiles.map(f => `- **${f.current}**
  - Changes: +${f.insertions}/-${f.deletions} lines
  - Type: ${f.fileType}
  - Action: Create override class in alcub3-extensions/`).join('\n')}

### Phase 2: Override Pattern Files (Priority: MEDIUM)
These can use inheritance to extend Gemini functionality.

${modifications.overrideNeeded.slice(0, 10).map(f => `- ${f.current} (+${f.insertions}/-${f.deletions})`).join('\n')}
${modifications.overrideNeeded.length > 10 ? `... and ${modifications.overrideNeeded.length - 10} more` : ''}

### Phase 3: Minor Changes (Priority: LOW)
These have minimal changes and might just need import updates.

${modifications.minorChanges.slice(0, 10).map(f => `- ${f.current} (+${f.insertions}/-${f.deletions})`).join('\n')}
${modifications.minorChanges.length > 10 ? `... and ${modifications.minorChanges.length - 10} more` : ''}

## Implementation Plan

### 1. Create Override Structure
\`\`\`
alcub3-extensions/
├── core/
│   └── overrides/
│       ├── client.ts         # Extends GeminiClient
│       ├── config.ts         # Extends GeminiConfig
│       └── geminiChat.ts     # Extends GeminiChat
└── cli/
    └── overrides/
        ├── App.tsx           # Extends GeminiApp
        └── hooks/            # Modified hooks
\`\`\`

### 2. Import Mapping
Create a TypeScript path mapping to redirect imports:

\`\`\`json
{
  "compilerOptions": {
    "paths": {
      "@gemini-core/*": ["./gemini-core/*"],
      "@alcub3/*": ["./alcub3-extensions/*"],
      "@alcub3/core": ["./alcub3-extensions/core/index.ts"],
      "@alcub3/cli": ["./alcub3-extensions/cli/index.ts"]
    }
  }
}
\`\`\`

### 3. Example Override Pattern
\`\`\`typescript
// alcub3-extensions/core/overrides/client.ts
import { GeminiClient } from '@gemini-core/core/src/core/client';
import { SecurityContext } from '../security/context';

export class AlcubClient extends GeminiClient {
  private security: SecurityContext;
  
  constructor(config: AlcubConfig) {
    super(config);
    this.security = new SecurityContext(config.security);
  }
  
  // Override specific methods with security enhancements
  async sendMessage(message: string) {
    const classified = await this.security.classify(message);
    return super.sendMessage(classified);
  }
}
\`\`\`

## Next Steps
1. Start with critical files
2. Create override classes
3. Update imports throughout codebase
4. Test each component
5. Remove old files from 01-security-platform
`;

  await fs.writeFile(MODIFICATIONS_OUTPUT, plan);
}

// Run the script
main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});