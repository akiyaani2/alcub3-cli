# Getting Started with ALCUB3

ALCUB3 is a defense-grade AI security platform that enables secure air-gapped AI operations with universal system interoperability for defense contractors and critical infrastructure.

## Prerequisites

- Node.js 18+ 
- npm 8+
- (Optional) Docker for containerized deployment
- (Optional) Hardware Security Module (HSM) for FIPS 140-2 compliance

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/your-org/alcub3-cli.git
cd alcub3-cli

# Install dependencies
npm install

# Build the project
npm run build
```

### 2. Basic Configuration

```bash
# Set up environment variables
cp .env.example .env

# Configure your security clearance level
export ALCUB3_CLEARANCE_LEVEL="UNCLASSIFIED"

# Set up air-gap mode (optional)
export ALCUB3_AIRGAP_MODE="true"
```

### 3. First Run

```bash
# Start ALCUB3 CLI
npm start

# Or use the direct command
alcub3
```

### 4. Basic Commands

```bash
# Check system status
alcub3 status

# Run security validation
alcub3 security validate

# Connect to a robot (example)
alcub3 robotics connect --platform=boston-dynamics --id=spot-001
```

## Next Steps

- [Configuration Guide](./configuration.md) - Detailed configuration options
- [User Tutorials](../01-user-guide/tutorials/) - Step-by-step guides
- [Security Setup](../04-security/security-operations.md) - Security configuration

## Getting Help

- Check the [Troubleshooting Guide](../01-user-guide/troubleshooting.md)
- Review the [FAQ](../05-reference/faq.md)
- File an issue on GitHub

## Security Notice

ALCUB3 is designed for defense-grade security. Always:
- Verify your classification level before accessing features
- Follow air-gap procedures when required
- Report security issues to security@alcub3.dev