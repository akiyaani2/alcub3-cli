# ALCUB3 Developer Commands

This document is for internal development use while building the ALCUB3 platform. These commands help streamline the development workflow and maintain the separation between Gemini core and ALCUB3 extensions.

## Quick Start

After cloning the repository, install the `al3` command:

```bash
npm install
npm link  # Makes 'al3' available globally
```

## AL3 Command Reference

The `al3` CLI provides quick access to common development tasks:

### Basic Commands

```bash
al3 start          # Start ALCUB3 CLI
al3 status         # Show project status (git, build, integration)
al3 watch          # Watch mode for development
al3 help           # Show all available commands
```

### Build Commands

```bash
al3 build          # Full production build
al3 build:dev      # Fast development build (no optimization)
al3 build:core     # Build core package only
al3 build:cli      # Build CLI package only
```

### Testing

```bash
al3 test                # Run unit tests
al3 test:integration    # Test ALCUB3-Gemini integration
al3 test:update        # Simulate Gemini update and test
```

### Gemini Updates

```bash
al3 update:check    # Check for Gemini CLI updates
al3 update:gemini   # Update Gemini core (creates backup)
```

### Development Workflow

```bash
al3 preflight      # Full validation: clean, install, format, lint, build, test
al3 clean          # Clean all build artifacts
al3 lint           # Run ESLint
al3 lint:fix       # Auto-fix linting issues
al3 format         # Format with Prettier
```

### Security

```bash
al3 security:check   # Run security regression tests
al3 security:audit   # Check dependencies for vulnerabilities
```

### Task Management

```bash
al3 task add "Description"    # Create new task
al3 task list                 # View all tasks
al3 task next                 # Get next priority task
al3 task show 1               # View task details
al3 task done 1               # Mark task as completed
al3 task expand 1             # Break task into subtasks
```

## Development Workflows

### Starting Fresh

```bash
# Clone and setup
git clone <repo>
cd alcub3-cli
al3 setup:dev      # Set up git hooks and best practices
al3 preflight      # Ensure everything builds and tests pass
```

### Daily Development

```bash
# Start your day
al3 status         # Check project status
al3 task next      # See what to work on

# During development
al3 watch          # Auto-rebuild on changes
al3 test           # Run tests frequently

# Before committing
al3 lint:fix       # Fix any linting issues
al3 test           # Ensure tests pass
```

### Updating Gemini

```bash
# Check for updates
al3 update:check

# If updates available
al3 update:gemini              # Updates with backup
al3 test:integration           # Verify integration still works
npm test                       # Run full test suite
```

### Working with Tasks

```bash
# Planning a feature
al3 task add "Implement air-gap MCP server"
al3 task expand 1              # AI breaks it into subtasks

# Working on tasks
al3 task show 1                # View details
al3 task done 1                # Mark completed
al3 task list                  # See progress
```

## Project Structure

After refactoring, the project maintains clean separation:

```
alcub3-cli/
├── gemini-core/           # Unmodified Gemini CLI code
│   ├── core/              # Core functionality
│   └── cli/               # CLI interface
├── alcub3-extensions/     # ALCUB3-specific code
│   ├── core/              # Core extensions
│   └── cli/               # CLI extensions
├── 01-security-platform/  # Main entry point
│   ├── core/              # Imports from gemini-core + extensions
│   └── cli/               # Imports from gemini-core + extensions
└── scripts/               # Development scripts
    ├── update-gemini.js   # Gemini update mechanism
    └── test-alcub3-integration.js  # Integration tests
```

## Key Development Principles

### 1. Minimal Overrides
- Only `01-security-platform/cli/src/gemini.tsx` contains ALCUB3 code
- Everything else imports cleanly from `gemini-core`
- This ensures easy updates from upstream Gemini

### 2. Import Patterns
```typescript
// Import Gemini functionality
import { SomeFeature } from '@gemini-core/core';

// Import ALCUB3 extensions
import { SecurityFeature } from '@alcub3/core';
```

### 3. Testing Strategy
- Always run `al3 test:integration` after changes
- Run `al3 test:update` periodically to ensure update compatibility
- Use `al3 preflight` before major commits

### 4. Update Philosophy
- Check for Gemini updates weekly: `al3 update:check`
- Test updates in a branch first
- Always backup before updating (automatic)
- Verify ALCUB3 features after updates

## Common Issues

### Build Failures
```bash
al3 clean          # Clean everything
npm install        # Reinstall dependencies
al3 build:dev      # Try dev build first
```

### Import Errors
- Ensure all imports use `.js` extension
- Check tsconfig.json path mappings
- Verify workspace dependencies

### Integration Test Failures
```bash
# Check file structure
ls -la gemini-core/
ls -la alcub3-extensions/
ls -la 01-security-platform/

# Verify override file
cat 01-security-platform/cli/src/gemini.tsx
```

## Environment Variables

```bash
# Enable debug output
DEBUG=* al3 build

# Skip tests in preflight
SKIP_TESTS=1 al3 preflight

# Use specific Node version
NODE_VERSION=18 al3 start
```

## Advanced Commands

For complex operations, use npm scripts directly:

```bash
# Performance testing
npm run test:perf

# End-to-end tests
npm run test:e2e

# Generate git commit info
npm run generate

# Version management
npm run release:version
```

## Next Steps

As we approach platform completion, we'll create customer-facing commands:
- `alcub3` - Production CLI
- `alcub3-server` - MCP server mode
- `alcub3-robotics` - Robotics interface

For now, `al3` handles all internal development needs efficiently.

## Tips

1. **Use Task Master**: For any feature taking 3+ steps, create a task first
2. **Test Often**: Run `al3 test` frequently during development
3. **Check Status**: Use `al3 status` to see overall project health
4. **Stay Updated**: Weekly `al3 update:check` keeps you current with Gemini

---

Remember: This is our internal development tool. Customer-facing commands will be designed separately with appropriate documentation and security considerations.