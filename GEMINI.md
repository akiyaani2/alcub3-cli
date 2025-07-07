# Gemini Agent Context for ALCUB3

This file provides guidance to me, Gemini, when working on the ALCUB3 codebase. It outlines the project's architecture, development practices, and strategic context to ensure my contributions are secure, compliant, and aligned with the project's goals.

## 🎯 Project Overview & Strategic Context

**Product Vision**: ALCUB3 is the **"Stripe of Defense AI Integrations"**—the first NSA/CISA-compliant AI integration platform for defense and critical infrastructure. It enables secure, air-gapped AI operations with universal system interoperability.

**Core Mission**: To provide a defense-grade AI integration platform built on a fork of Google's Gemini CLI, enhanced with proprietary, patent-protected technologies.

**Three-Pillar Strategy**:

1.  **Red Team Operations**: AI-powered threat scenario generation and security testing in classified, air-gapped environments.
2.  **Synthetic Training**: AI-generated tactical scenarios for defense simulations, fulfilling requirements like the A254-019 Army SBIR.
3.  **Compliance & Integration**: Automated STIG/MAESTRO compliance and secure integration with existing defense systems.

**Core Innovations (Patent Protected)**:

- **Air-Gapped Model Context Protocol (MCP)**: The first platform supporting 30+ day offline AI operations with secure context persistence and transfer. (Located in `/air-gap-mcp-server/`)
- **Universal Robotics Interface**: A single, hardware-agnostic API to control and coordinate 20+ robotic platforms (ground, aerial, maritime), including Boston Dynamics, ROS2, and DJI. (Located in `/universal-robotics/` and `/packages/core/src/services/robotics/`)
- **Classification-Native Design**: Built-in support for data handling from Unclassified to Top Secret, with automatic classification inheritance. (Located in `/classification-manager/`)
- **MAESTRO L1-L7 Security Framework**: A comprehensive, defense-grade security implementation. (Located in `/security-framework/`)

## 🤖 My Role & Collaboration Context

As an AI assistant, my primary role is to accelerate development while adhering to the project's stringent security and architectural standards.

- **Security-First Architecture**: Every change must prioritize defense-grade security. I will threat model features before implementation and assume all data is classified until proven otherwise.
- **Patent-Defensible Innovation**: I must be aware of the patent-protected areas of the codebase and flag any new, potentially patentable innovations.
- **Technical Excellence**: I will strive for sub-second performance and 99.9% availability in the code I write.
- **Task-Driven Workflow**: I will use the Task Master tool for complex features, breaking them down into sub-tasks and tracking their status.

## 🛠️ Essential Commands

### Primary Development Workflow

```bash
# Run the full suite of pre-flight checks: clean, install, format, lint, build, typecheck, and test.
# This is the most important command to run before committing.
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

Use the `task-master` CLI tool to manage development tasks, especially for features requiring multiple steps or complex planning.

- **When to use Task Master**: For any feature, refactor, or change that involves more than a single file or a few simple edits.
- **When to work directly**: For quick fixes, single-file edits, or answering simple questions.

### Standard Task Master Workflow

1.  **Create a task**:
    ```bash
    task-master add-task --prompt="Implement secure file upload to classified storage"
    ```
2.  **Break down the task** (Task Master uses AI to suggest subtasks):
    ```bash
    task-master expand --id=<task_id>
    ```
3.  **Work on the next task**:
    ```bash
    task-master next
    task-master show <task_id>
    # ...implement the changes...
    ```
4.  **Update task status**:
    ```bash
    task-master set-status --id=<task_id> --status=completed
    ```

## 🏗️ Architecture Overview

ALCUB3 is a polyglot system designed for security and performance.

- **Languages**:
  - **TypeScript (CLI & Core)**: The primary language for the user-facing CLI and core business logic, forked from the original Gemini CLI.
  - **Python (Security & AI)**: Used for the MAESTRO security framework, MCP server, robotics adapters, and classification engine.
  - **Rust (Performance-Critical)**: Used for high-performance, memory-safe components like cryptographic operations.
- **Key Directories**:
  - `/packages/cli`: The user-facing CLI application (React/Ink).
  - `/packages/core`: Core client, tool system, and services (e.g., Git, File Discovery).
  - `/security-framework`: The MAESTRO L1-L7 security implementation (Python).
  - `/air-gap-mcp-server`: The patent-pending air-gapped MCP server (Python).
  - `/universal-robotics`: The hardware abstraction layer for robotics control (Python).
- **UI Architecture**: The terminal UI is built with **React and Ink** in `/packages/cli/src/ui/`. State is managed with React Hooks and Context.

## 📜 Development Guidelines

### **Security-First Development**

- **Threat Model**: Always consider the security implications of a feature _before_ implementation.
- **Data Handling**: Assume all data is classified. Use the provided classification services.
- **Dependencies**: All third-party libraries must be scanned for vulnerabilities.
- **Testing**: Security test cases are mandatory for all new features.

### Building and Testing

- **Pre-flight Check**: Always run `npm run preflight` before submitting changes. This command builds the code, runs all tests, checks types, and lints the code.
- **Testing Framework**: **Vitest** is the primary testing framework.
- **Test Location**: Tests are co-located with the source files they test (`*.test.ts` or `*.test.tsx`).
- **Mocking**: Use `vi.mock()` for mocking dependencies. For critical dependencies like `os` or `fs`, place mocks at the very top of the test file.

### TypeScript Best Practices

- **Strict Mode**: Code must be compliant with ES2022 and TypeScript's `strict` mode.
- **ES Modules**: Use `import`/`export`.
- **Type Safety**: **Do not use `any`**. Prefer `unknown` and perform type-safe narrowing. Use type assertions (`as Type`) only when absolutely necessary.
- **Plain Objects**: Prefer plain objects with `type` or `interface` definitions over `class` syntax.
- **Encapsulation**: Use module boundaries (`export`) to define public APIs. Unexported code is considered private.

### React (Ink) Development

- Use functional components with Hooks.
- Keep rendering logic pure (free of side effects).
- Do not mutate state directly. Use state setters and immutable patterns.
- Optimize for the React Compiler by writing simple, clear components. Avoid premature optimization with `useMemo` or `useCallback`.

### Code Style & Comments

- **Formatting**: Run `npm run format` (Prettier). 2-space indentation, single quotes, semicolons.
- **Comments**: Only add high-value comments that explain the _why_, not the _what_. Do not add comments to talk to me or explain your changes.

### Git & Commits

- **Conventional Commits**: Commit messages must follow the Conventional Commits standard.
- **Main Branch**: The main branch is `main`.

## ❗ Important Notes

- **Node.js Version**: Requires **Node.js 18+**.
- **Sandboxing**: For security-critical operations, enable sandboxing with `GEMINI_SANDBOX=true`.
- **Authentication**: The platform supports Google accounts, Gemini API keys, and PKI/CAC for defense environments.
- **Rebranding**: The codebase was forked from `Gemini CLI`. While user-facing text should say `ALCUB3`, many internal API calls, model names, and package names may still reference `gemini`. Be careful not to break these internal references.
