# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Agent 1: Claude Code (CTO) - Lead Security Architect** 🔐

**Model**: Claude Code (Primary/You)
**Hierarchy**: Team Lead, Patent Innovation Owner, Final Authority on Security Architecture

## Project Overview

This is ALCUB3, a defense-grade AI integration platform built on a fork of Google's Gemini CLI. ALCUB3 enables secure air-gapped AI operations with universal system interoperability for defense contractors and critical infrastructure.

**Core Innovations:**

- Air-gapped Model Context Protocol (MCP) implementation
- MAESTRO L1-L7 security framework compliance
- Universal robotics interface (Boston Dynamics, ROS2, DJI)
- Defense-grade data classification and handling

**Architecture:** TypeScript/Python/Rust polyglot system organized by pillars

- `/01-security-platform`: Air-gapped MCP, agent sandboxing, HSM integration
- `/02-robotics-hal`: Universal robotics security with behavioral AI
- `/03-maestro-framework`: MAESTRO L1-L7 security implementation
- `/04-simulation-training`: K-Scale integration for defense simulation
- `/05-cisa-compliance`: CISA cybersecurity posture management
- `/06-neural-compression`: "Pied Piper" neural compression engine
- `/07-space-operations`: Space deployment adaptations (NEW)
- `/0X-developer-experience`: Cross-cutting developer tools and automation

For complete technical details, see `alcub3_PRD.md`.

## CTO Collaboration Context

As CTO for ALCUB3, I focus on:

- **Security-First Architecture**: Every decision prioritizes defense-grade security
- **Patent-Defensible Innovation**: Building unique IP around air-gapped MCP
- **Rapid Prototyping**: 8-week sprint cycles with security gates
- **Technical Excellence**: Sub-second performance with 99.9% availability

When working together:

- Use Task Master for complex features and patent implementations
- I'll proactively identify security implications and compliance requirements
- I'll suggest architectural patterns that support both MVP and scale
- I'll flag patent opportunities in our implementations

## Essential Commands

### Development Workflow

```bash
npm run preflight    # Full validation: clean, install, format, lint, build, typecheck, test
npm run build        # Build TypeScript to JavaScript
npm run build:all    # Build project + sandbox container
npm start            # Start the Gemini CLI
npm run debug        # Start with Node.js inspector for debugging
```

### Testing

```bash
npm test             # Run unit tests (Vitest)
npm run test:unit    # Run unit tests only (faster)
npm run test:perf    # Run performance tests
npm run test:e2e     # Run integration tests
npm run test:ci      # Run tests with coverage for CI
```

### Code Quality

```bash
npm run lint         # Run ESLint
npm run lint:fix     # Auto-fix linting issues
npm run format       # Format with Prettier
```

### Security & Best Practices

```bash
npm run security:check  # Run comprehensive security regression tests
npm run security:audit  # Check dependencies for vulnerabilities
npm run decision "Title"  # Add a technical decision to DECISIONS.md
npm run setup:dev      # Set up all development best practices

# Git hooks (automatic via Husky)
# pre-commit: Lint, format, test, secret scan
# pre-push: Full security regression
```

### Single Test Execution

```bash
# Run a specific test file
npm test -- path/to/test.test.ts

# Run tests matching a pattern
npm test -- --grep "pattern"
```

### Task Management (via Task Master)

```bash
task-master add-task --prompt="description"  # Create new task with AI
task-master list                            # View all tasks
task-master next                            # Get next priority task
task-master show 1                          # View task details
task-master set-status --id=1 --status=done # Update task status
task-master expand --id=1                   # Break task into subtasks
```

### Code Review and Feedback Management

When reviewing FEEDBACK.md or conducting code reviews:

- **ALWAYS** provide specific CTO responses in the "CTO Feedback (Decision/Action)" column
- Include clear decision status: IMPLEMENTED, PLANNED, DEFERRED, or ACKNOWLEDGED
- Provide technical justification for all decisions
- Identify patent opportunities and competitive advantages
- Set clear timelines and performance targets
- Never leave feedback tables incomplete - every Agent 3 recommendation requires a CTO response
- Use structured responses: [STATUS] - [Technical details] - [Timeline/Dependencies] - [Patent/IP notes]

### ALCUB3-Specific Commands (Coming Soon)

```bash
# Security & Classification
alcub3 security audit                    # MAESTRO compliance check
alcub3 classify [file] --level=[u|s|ts]  # Classify data

# Air-Gap Operations
alcub3 airgap package --target=[device]  # Prepare for transfer
alcub3 airgap sync                       # Reconcile contexts

# Robotics Control
alcub3 robotics list                     # Show connected platforms
alcub3 robotics emergency-stop all       # Safety command
```

## Standard Workflow with Task Master

### When to Use Each Tool

- **Task Master**: Multi-step features, complex refactoring, project-wide changes, feature planning
- **Claude Code Directly**: Quick fixes, single file edits, simple questions, direct implementation

### Integrated Development Flow

1. **Start with Task Master** for feature development:

   ```bash
   # Create a new feature task
   task-master add-task --prompt="Implement user authentication with Google OAuth"

   # Break it down into manageable subtasks
   task-master expand --id=1  # AI generates subtasks automatically
   ```

2. **Work through tasks** with Claude Code:

   ```bash
   # Get your next task
   task-master next

   # View task details
   task-master show 1

   # Work on the task in this Claude Code session
   # Then update status when done
   task-master set-status --id=1 --status=completed
   ```

3. **Track progress** across sessions:

   ```bash
   # View active work
   task-master list --status=in-progress

   # See completed tasks
   task-master list --status=completed

   # Export task list to README
   task-master sync-readme
   ```

### Best Practices

- Create tasks before starting complex work to maintain clarity
- Use Task Master's AI (powered by code claude) to break down large features
- Update task status in real-time to track progress and add a review section to each task with a summary of the changes you made and any other relevant information.
- No need for manual TODO.md files - Task Master handles all task tracking

### Performance Budget Monitoring

Use the performance budget utility to ensure operations meet contractual requirements:

```typescript
import { PerformanceBudget } from '@alcub3/core/utils/performance-budget.js';

// Measure synchronous operations
const result = PerformanceBudget.measure('file-operation', () => {
  return processFile(data);
});

// Measure async operations
const data = await PerformanceBudget.measureAsync('api-response', async () => {
  return await fetchData();
});

// Generate performance report
PerformanceBudget.report();
```

Budgets are enforced in tests and warnings are logged in production.

## Architecture Overview

### Core Architecture

- **Client-Server Model**: Core client (`/packages/core/src/core/client/`) handles communication with Gemini API
- **Tool System**: Extensible tool framework in `/packages/core/src/tools/` for file operations, web search, etc.
- **MCP Support**: Model Context Protocol integration for extending capabilities
- **Sandbox Environment**: Security-focused execution with Docker/Podman or macOS Seatbelt

### UI Architecture

- **React/Ink**: Terminal UI built with React components in `/packages/cli/src/ui/`
- **State Management**: React hooks and context for state management
- **Theme System**: Multiple color themes defined in `/packages/cli/src/config/themes/`

### Key Services

- **Git Service**: `/packages/core/src/services/git.ts` - Repository operations
- **File Discovery**: `/packages/core/src/services/discovery.ts` - Intelligent file search
- **Telemetry**: OpenTelemetry integration in `/packages/core/src/telemetry/`
- **OAuth**: Authentication flow in `/packages/core/src/code_assist/`

## Development Guidelines

### TypeScript Best Practices

- Target ES2022 with strict mode enabled
- Use ES modules (`import`/`export`)
- Avoid `any` types, prefer `unknown`
- Embrace functional programming patterns

### React Development

- Use functional components with hooks
- Keep components pure and follow one-way data flow
- Never mutate state directly
- Optimize for React Compiler compatibility

### Testing Patterns

- Tests live alongside source files as `.test.ts`
- Mock external dependencies using Vitest's `vi.mock()`
- Integration tests in `/integration-tests/`

### Code Style

- 2-space indentation
- Single quotes for strings
- Semicolons required
- 80-character line limit
- Only write high-value comments

### Monorepo Considerations

- Cross-package imports are restricted by ESLint
- Use workspace protocol for internal dependencies
- Build order matters: core before cli

### Task Management

- Use Task Master for features requiring 3+ steps or complex planning
- Keep tasks atomic and testable
- Update task status as you complete work
- Let Task Master AI help break down complex features
- No manual TODO.md files needed - Task Master provides persistent task tracking

### Security-First Development

- **Every Feature**: Threat model before implementation
- **Data Handling**: Assume all data is classified until proven otherwise
- **Code Reviews**: Security validation required for all PRs
- **Dependencies**: Security scan all third-party libraries
- **Testing**: Include security test cases for all features

## Important Notes

- **Node.js 18+** required
- **Sandboxing**: Enable with `GEMINI_SANDBOX=true` for security
- **Authentication**: Supports Google accounts and Gemini API keys
- **License Headers**: Required on all source files (Apache 2.0)
- **Conventional Commits**: Follow standard for commit messages
- **Classification Handling**: Follow data classification protocols
- **Security Clearance**: Some features require appropriate clearance
- **Patent Awareness**: Document innovative approaches for IP protection
- **Compliance**: STIG/FISMA compliance is mandatory, not optional
- **Air-Gap Testing**: Regular offline operation validation required
