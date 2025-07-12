# ALCUB3 Documentation

Welcome to ALCUB3's comprehensive documentation. ALCUB3 is a defense-grade AI security platform that enables secure air-gapped AI operations with universal system interoperability for defense contractors and critical infrastructure.

## 🆕 Major Architecture Update

We've refactored ALCUB3 to cleanly separate Gemini core from ALCUB3 extensions:

- **gemini-core/**: Unmodified Gemini CLI code (easily updatable)
- **alcub3-extensions/**: All ALCUB3-specific functionality  
- **Easy Updates**: Run `npm run update:gemini` to get latest Gemini

See [UPDATE_GUIDE.md](../UPDATE_GUIDE.md) for details on the new architecture.

## Documentation Structure

### 📚 [00 - Overview](./00-overview/)
Start here to understand ALCUB3's architecture and capabilities.
- [Getting Started](./00-overview/getting-started.md) - Quick start guide
- [Architecture Overview](./00-overview/architecture.md) - System design and components
- [Changelog](./00-overview/changelog.md) - Track new features and improvements
- [Original README](./00-overview/README.md) - Historical documentation

### 🚀 [01 - User Guide](./01-user-guide/)
Everything you need to use ALCUB3 effectively.
- [CLI Documentation](./01-user-guide/cli/) - Command-line interface guide
  - [Commands](./01-user-guide/cli/commands.md) - Available commands
  - [Configuration](./01-user-guide/cli/configuration.md) - Configuration options
  - [Authentication](./01-user-guide/cli/authentication.md) - Auth setup
- [Deployment Guide](./01-user-guide/deployment.md) - Installation and deployment
- [Troubleshooting](./01-user-guide/troubleshooting.md) - Common issues and solutions
- [Extensions](./01-user-guide/extension.md) - Extending functionality

### 🔧 [02 - Features](./02-features/)
Deep dives into ALCUB3's six-pillar architecture.

#### [Security Platform](./02-features/security-platform/)
- [Air-Gap MCP Server](./02-features/security-platform/air-gap-mcp-server-integration.md)
- [Agent Sandboxing](./02-features/security-platform/agent-sandboxing.md)
- [API Security](./02-features/security-platform/api-security.md)
- [Cryptography](./02-features/security-platform/cryptography.md)

#### [Robotics HAL](./02-features/robotics/)
- [Universal Security HAL](./02-features/robotics/security-hal-architecture.md)
- [Boston Dynamics Integration](./02-features/robotics/spot-security-adapter.md)
- [ROS2 Security](./02-features/robotics/ros2-security-integration.md)
- [Emergency Safety](./02-features/robotics/emergency-safety-systems.md)

#### [MAESTRO Framework](./02-features/maestro/)
- [L1-L7 Security Framework](./02-features/maestro/maestro-security-framework.md)
- [AI Bias Detection](./02-features/maestro/ai-bias-detection.md)
- [OWASP Integration](./02-features/maestro/owasp-sast-dast.md)

#### [CISA Compliance](./02-features/compliance/)
- [CISA Top 10 Remediation](./02-features/compliance/cisa-remediation-engine.md)
- [STIG Compliance](./02-features/compliance/stig-compliance.md)
- [NIST SP 800-171](./02-features/compliance/nist-800-171-compliance.md)
- [JIT Privileges](./02-features/compliance/jit-privilege-escalation.md)

### 👨‍💻 [03 - Developer](./03-developer/)
Resources for developers and contributors.
- [API Reference](./03-developer/api-reference/)
  - [Core APIs](./03-developer/api-reference/core/)
  - [Tools APIs](./03-developer/api-reference/tools/)
- [Deployment](./03-developer/deployment/)
  - [NPM Publishing](./03-developer/deployment/npm.md)
  - [Sandbox Environment](./03-developer/deployment/sandbox.md)
  - [Telemetry](./03-developer/deployment/telemetry.md)
- [Testing](./03-developer/testing/)
  - [Integration Testing](./03-developer/testing/integration-testing.md)
  - [Penetration Testing](./03-developer/testing/penetration-testing-framework.md)
  - [Performance Optimization](./03-developer/testing/performance-optimization.md)

### 🔐 [04 - Security](./04-security/)
Security documentation and best practices.
- [Security Overview](./04-security/README.md) - Comprehensive security guide
- [Security Best Practices](./04-security/security-best-practices.md) - Operational security

### 📖 [05 - Reference](./05-reference/)
Quick access to essential information.
- [Quick Reference](./05-reference/quick-reference.md) - Command cheat sheet
- [FAQ](./05-reference/faq.md) - Frequently asked questions
- [Glossary](./05-reference/glossary.md) - Terms and definitions
- [Pricing & Quotas](./05-reference/quota-and-pricing.md) - Usage limits
- [Terms of Service](./05-reference/tos-privacy.md) - Legal information

## Quick Links

### For New Users
1. Start with [Getting Started](./00-overview/getting-started.md)
2. Review [CLI Commands](./01-user-guide/cli/commands.md)
3. Check [FAQ](./05-reference/faq.md) for common questions

### For Developers
1. Read [Architecture Overview](./00-overview/architecture.md)
2. Explore [API Reference](./03-developer/api-reference/)
3. Review [Testing Guidelines](./03-developer/testing/)

### For Security Teams
1. Review [Security Overview](./04-security/README.md)
2. Implement [Security Best Practices](./04-security/security-best-practices.md)
3. Configure [CISA Compliance](./02-features/compliance/)

### For Robotics Engineers
1. Understand [Universal HAL](./02-features/robotics/security-hal-architecture.md)
2. Integrate [Platform Adapters](./02-features/robotics/)
3. Implement [Safety Systems](./02-features/robotics/emergency-safety-systems.md)

## Additional Resources

- **Strategic Documentation**: See `/00-strategic/` in the main repository
- **Patent Portfolio**: 58+ innovations in `/00-strategic/patents/`
- **Research Papers**: Technical research in `/00-strategic/research/`
- **Task Management**: Development tasks in Task Master system

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) in the repository root for contribution guidelines.

## Support

- **Documentation Issues**: File on [GitHub](https://github.com/alcub3/alcub3-cli/issues)
- **Security Issues**: Contact security@alcub3.dev
- **Enterprise Support**: Contact support@alcub3.dev

---

*Documentation Version: 2025.01.10*
*ALCUB3 Version: 1.0.0*