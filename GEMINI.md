# Gemini Agent Context for ALCUB3

This file provides guidance to me, Gemini, when working on the ALCUB3 codebase. It outlines the project's architecture, development practices, and strategic context to ensure my contributions are secure, compliant, and aligned with the project's goals.

## 🎯 Project Overview & Strategic Context

**Product Vision**: ALCUB3 is the **"Universal API for Defense AI Security"**—the world's first NSA/CISA-compliant AI integration platform for defense and critical infrastructure. We enable secure, air-gapped AI operations with universal system interoperability.

**Core Mission**: To provide a defense-grade AI integration platform built on a fork of Google's Gemini CLI, enhanced with 37+ patent-protected technologies worth $158.8B+ in addressable market opportunity.

**Six-Pillar Strategic Architecture**:

1. **Universal Security Platform Foundation**: Air-gapped MCP operations, agent sandboxing, classification-native design
2. **Universal Robotics Security Platform**: Boston Dynamics + ROS2 + DJI integration with Universal Security HAL
3. **MAESTRO Security Framework**: L1-L7 real-time security monitoring with cross-layer threat correlation
4. **Defense Simulation & Training Platform**: K-Scale Labs integration with contested environment training
5. **CISA Cybersecurity Posture Management**: Top 10 misconfiguration remediation automation
6. **🔥 Neural Compression Engine**: The "Defense Pied Piper" - 40-60% compression ratios with FIPS compliance

**Core Innovations (37+ Patent-Protected)**:

- **Air-Gapped Model Context Protocol (MCP)**: First platform supporting 30+ day offline AI operations with .atpkg secure transfer
- **Universal Robotics Security HAL**: Single API controlling 20+ robotic platforms with real-time security validation
- **Neural Compression Breakthrough**: Transformer-based compression achieving 40-60% ratios with classification preservation
- **MAESTRO L1-L7 Security Framework**: Defense-grade security with <1ms threat correlation
- **K-Scale Defense Simulation**: Enhanced ksim integration with contested environment training
- **Classification-Native Design**: Built-in UNCLASSIFIED → TOP SECRET data handling

## 🤖 My Role & Collaboration Context

As an AI assistant, my primary role is to accelerate development while adhering to stringent security and architectural standards.

- **Security-First Architecture**: Every change must prioritize defense-grade security with threat modeling before implementation
- **Patent-Defensible Innovation**: Flag new innovations and protect existing 37+ patent-pending technologies
- **Technical Excellence**: Target sub-second performance and 99.9% availability
- **Task-Driven Workflow**: Use Task Master for complex features requiring multiple steps
- **Current Focus**: Phase 3 Advanced Integration - K-Scale simulation, CISA compliance, neural compression

## 🛠️ Essential Commands

### Primary Development Workflow

```bash
# Run the full suite of pre-flight checks: clean, install, format, lint, build, typecheck, and test.
npm run preflight
```

### Individual Development Steps

```bash
# Build the TypeScript code to JavaScript
npm run build

# Start the ALCUB3 CLI for interactive use
npm start

# Run all unit tests using Vitest
npm test

# Run end-to-end integration tests
npm run test:e2e

# Check for linting errors
npm run lint

# Automatically fix linting errors
npm run lint:fix
```

### Running a Single Test

```bash
# Run a specific test file by its path
npm test -- packages/core/src/services/git.test.ts

# Run tests that match a specific name or pattern
npm test -- --grep "Authentication"
```

## ✅ Task Management (Task Master)

Use the `task-master` CLI tool for features requiring multiple steps or complex planning.

- **When to use Task Master**: Multi-step features, complex refactoring, project-wide changes
- **When to work directly**: Quick fixes, single-file edits, simple questions

### Standard Task Master Workflow

1. **Create a task**:
   ```bash
   task-master add-task --prompt="Implement neural compression for MCP contexts"
   ```
2. **Break down the task**:
   ```bash
   task-master expand --id=<task_id>
   ```
3. **Work on the next task**:
   ```bash
   task-master next
   task-master show <task_id>
   # ...implement the changes...
   ```
4. **Update task status**:
   ```bash
   task-master set-status --id=<task_id> --status=completed
   ```

## 🏗️ Architecture Overview

ALCUB3 is a polyglot system designed for security and performance across 6 strategic pillars.

**Languages & Structure**:
- **TypeScript**: CLI & Core (`/packages/cli`, `/packages/core`)
- **Python**: Security framework, MCP server, robotics adapters (`/security-framework`, `/air-gap-mcp-server`, `/universal-robotics`)
- **Rust**: Performance-critical cryptographic operations

**Six-Pillar Architecture**:
- **Pillar 1**: Universal Security Platform Foundation (air-gapped MCP, agent sandboxing)
- **Pillar 2**: Universal Robotics Security Platform (Boston Dynamics, ROS2, DJI)
- **Pillar 3**: MAESTRO Security Framework (L1-L7 real-time monitoring)
- **Pillar 4**: Defense Simulation & Training (K-Scale Labs integration)
- **Pillar 5**: CISA Cybersecurity Posture Management (automated remediation)
- **Pillar 6**: Neural Compression Engine (40-60% compression with FIPS compliance)

**UI Architecture**: Terminal UI built with **React and Ink** in `/packages/cli/src/ui/` with React Hooks and Context for state management.

## 📜 Development Guidelines

### **Security-First Development**

- **Threat Model**: Always consider security implications before implementation
- **Data Handling**: Assume all data is classified until proven otherwise
- **Classification Awareness**: Use provided classification services for all data operations
- **Dependencies**: All third-party libraries must be security-scanned
- **Testing**: Security test cases are mandatory for all new features

### Building and Testing

- **Pre-flight Check**: Always run `npm run preflight` before submitting changes
- **Testing Framework**: **Vitest** for unit tests, co-located with source files (`*.test.ts`)
- **Mocking**: Use `vi.mock()` for dependencies, place critical mocks at top of test files
- **Coverage**: Maintain high test coverage especially for security-critical components

### TypeScript Best Practices

- **Strict Mode**: ES2022 compliance with TypeScript strict mode
- **ES Modules**: Use `import`/`export` syntax
- **Type Safety**: Avoid `any`, prefer `unknown` with type-safe narrowing
- **Plain Objects**: Prefer `type`/`interface` over `class` syntax
- **Encapsulation**: Use module boundaries for API definition

### React (Ink) Development

- Use functional components with Hooks
- Keep rendering logic pure (no side effects)
- Never mutate state directly
- Optimize for React Compiler compatibility
- Avoid premature optimization with `useMemo`/`useCallback`

### Code Style & Review

- **Formatting**: Use Prettier (2-space indentation, single quotes, semicolons)
- **Comments**: Only high-value comments explaining "why", not "what"
- **Feedback**: All code review feedback goes to `FEEDBACK.md`
- **Conventional Commits**: Follow standard commit message format

## 🎯 Current Development Focus

### **Phase 3: Advanced Integration** (Weeks 17-24)

**Immediate Priorities**:
- **Task 3.5**: Unified Robotics C2 Interface (fleet management)
- **K-Scale Defense Simulation**: Enhanced ksim integration with defense security
- **CISA Compliance Module**: Top 10 cybersecurity misconfiguration remediation
- **Neural Compression Engine**: Transformer-based compression for air-gap optimization

**Key Performance Targets**:
- Security validation: <1ms (achieved)
- Robotics integration: 100% success rate (achieved)
- Patent innovations: 37+ filed (target exceeded)
- Compression ratios: 40-60% (breakthrough achievement)

## ❗ Important Notes

- **Node.js Version**: Requires **Node.js 18+**
- **Sandboxing**: Enable with `GEMINI_SANDBOX=true` for security-critical operations
- **Authentication**: Supports Google accounts, Gemini API keys, and PKI/CAC for defense
- **Rebranding**: Forked from Gemini CLI - internal APIs may still reference "gemini"
- **Classification Handling**: All data operations must respect classification boundaries
- **Patent Protection**: 37+ innovations are patent-pending - document new innovations
- **Market Position**: First-mover advantage in $158.8B+ defense AI security market
- **Competitive Moat**: Only platform with air-gapped operations + universal robotics + neural compression

---

*Current Status: Phase 3 Advanced Integration with 37+ patent innovations completed and production-ready platform achieving 1000x+ performance improvements in critical security operations.*
