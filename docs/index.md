# Welcome to Gemini CLI documentation

This documentation provides a comprehensive guide to installing, using, and developing Gemini CLI. This tool lets you interact with Gemini models through a command-line interface.

## Overview

Gemini CLI brings the capabilities of Gemini models to your terminal in an interactive Read-Eval-Print Loop (REPL) environment. Gemini CLI consists of a client-side application (`packages/cli`) that communicates with a local server (`packages/core`), which in turn manages requests to the Gemini API and its AI models. Gemini CLI also contains a variety of tools for tasks such as performing file system operations, running shells, and web fetching, which are managed by `packages/core`.

## Navigating the documentation

This documentation is organized into the following sections:

- **[Execution and Deployment](./deployment.md):** Information for running Gemini CLI.
- **[Architecture Overview](./architecture.md):** Understand the high-level design of Gemini CLI, including its components and how they interact.
- **CLI Usage:** Documentation for `packages/cli`.
  - **[CLI Introduction](./cli/index.md):** Overview of the command-line interface.
  - **[Commands](./cli/commands.md):** Description of available CLI commands.
  - **[Configuration](./cli/configuration.md):** Information on configuring the CLI.
  - **[Checkpointing](./checkpointing.md):** Documentation for the checkpointing feature.
  - **[Extensions](./extension.md):** How to extend the CLI with new functionality.
  - **[Telemetry](./telemetry.md):** Overview of telemetry in the CLI.
- **Core Details:** Documentation for `packages/core`.
  - **[Core Introduction](./core/index.md):** Overview of the core component.
  - **[Tools API](./core/tools-api.md):** Information on how the core manages and exposes tools.
- **Tools:**
  - **[Tools Overview](./tools/index.md):** Overview of the available tools.
  - **[File System Tools](./tools/file-system.md):** Documentation for the `read_file` and `write_file` tools.
  - **[Multi-File Read Tool](./tools/multi-file.md):** Documentation for the `read_many_files` tool.
  - **[Shell Tool](./tools/shell.md):** Documentation for the `run_shell_command` tool.
  - **[Web Fetch Tool](./tools/web-fetch.md):** Documentation for the `web_fetch` tool.
  - **[Web Search Tool](./tools/web-search.md):** Documentation for the `google_web_search` tool.
  - **[Memory Tool](./tools/memory.md):** Documentation for the `save_memory` tool.
- **[Secure Key Management & Rotation](./key-management.md):** Documentation for secure key management and rotation.
- **[STIG Compliance Validation System](./stig-compliance.md):** Documentation for STIG compliance validation.
- **[Real-Time Security Monitoring & Alerting](./security-monitoring.md):** Documentation for real-time security monitoring and alerting.
- **[API Security Integration](./api-security-integration.md):** Documentation for API security integration.
- **[Security HAL Architecture Design](./security-hal-architecture.md):** Documentation for the Universal Security HAL.
- **[Boston Dynamics Spot Security Adapter](./spot-security-adapter.md):** Documentation for the Boston Dynamics Spot security adapter.
- **[ROS2 Security Integration](./ros2-security-integration.md):** Documentation for ROS2 security integration.
- **[DJI Drone Security Adapter](./dji-drone-security-adapter.md):** Documentation for DJI drone security adapter.
- **[AI Bias Detection & Mitigation](./ai-bias-detection.md):** FISMA-compliant AI fairness monitoring system.
- **[OWASP Top 10 + SAST/DAST](./owasp-sast-dast.md):** Comprehensive security controls with integrated testing.
- **[Agent Sandboxing & Integrity Verification](./agent-sandboxing.md):** Multi-layer agent isolation and behavioral monitoring.
- **[Unified Robotics C2 Interface](./unified-robotics-c2-interface.md):** Documentation for the Unified Robotics C2 Interface.
- **[Prompt Injection Prevention](./prompt-injection-prevention.md):** Documentation for prompt injection prevention.
- **[Performance Optimization](./performance-optimization.md):** Documentation for performance optimization efforts.
- **[Integration Testing](./integration-testing.md):** Documentation for integration testing strategy.
- **[Penetration Testing Framework](./penetration-testing-framework.md):** Documentation for the penetration testing framework.
- **[Air-Gap MCP Server Integration (Phase 4)](./air-gap-mcp-server-integration.md):** Documentation for advanced Air-Gap MCP server integration.
- **[Advanced Threat Intelligence (Phase 5)](./advanced-threat-intelligence.md):** Documentation for advanced threat intelligence capabilities.
- **[Contributing & Development Guide](../CONTRIBUTING.md):** Information for contributors and developers, including setup, building, testing, and coding conventions.
- **[NPM Workspaces and Publishing](./npm.md):** Details on how the project's packages are managed and published.
- **[Troubleshooting Guide](./troubleshooting.md):** Find solutions to common problems and FAQs.
- **[Terms of Service and Privacy Notice](./tos-privacy.md):** Information on the terms of service and privacy notices applicable to your use of Gemini CLI.

We hope this documentation helps you make the most of the Gemini CLI!
