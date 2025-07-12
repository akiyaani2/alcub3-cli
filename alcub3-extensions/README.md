# ALCUB3 Extensions

This directory contains all ALCUB3-specific modifications and extensions to the Gemini CLI.

## Structure

```
alcub3-extensions/
├── cli/
│   ├── commands/      # Custom ALCUB3 commands (maestro, clearance, etc.)
│   └── overrides/     # Modified Gemini CLI components
└── core/
    ├── security/      # ALCUB3 security additions
    └── overrides/     # Modified Gemini Core components
```

## Development Guidelines

### Adding New Features

New ALCUB3 features go here:
```typescript
// alcub3-extensions/cli/commands/security-profile.ts
export function createSecurityProfileCommand() {
  // Your new command
}
```

### Modifying Gemini Behavior

Use inheritance to override Gemini functionality:
```typescript
// alcub3-extensions/core/overrides/client.ts
import { GeminiClient } from '@gemini-core/core';
import { SecurityContext } from '../security/context';

export class AlcubClient extends GeminiClient {
  private security: SecurityContext;
  
  constructor(config: AlcubConfig) {
    super(config);
    this.security = new SecurityContext(config.security);
  }
  
  // Override specific methods
  async sendMessage(message: string) {
    const classified = await this.security.classify(message);
    return super.sendMessage(classified);
  }
}
```

### Import Patterns

```typescript
// Import from Gemini Core
import { GeminiClient } from '@gemini-core/core';

// Import from ALCUB3 extensions
import { SecurityProfile } from '@alcub3/security';

// Import from domain modules
import { MaestroFramework } from '@alcub3/maestro';
```

## Categories

### Custom Commands (`/cli/commands/`)
- `security-profile.ts` - Security profile management
- `maestro.ts` - MAESTRO framework commands
- `clearance.ts` - Clearance management
- `jit.ts` - Just-in-time privilege escalation
- `configuration-drift.ts` - Drift detection

### Security Extensions (`/core/security/`)
- `profile-manager.ts` - Security profile management
- `classification.ts` - Data classification
- `air-gap.ts` - Air-gap operations

### Overrides (`/*/overrides/`)
Files here extend or modify Gemini behavior while maintaining compatibility.