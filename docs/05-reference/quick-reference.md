# ALCUB3 Quick Reference

## Essential Commands

### Basic Operations
```bash
alcub3                          # Start interactive CLI
alcub3 status                   # Check system status
alcub3 --help                   # Show help information
alcub3 --version               # Show version
```

### Security Commands
```bash
alcub3 security validate        # Run security validation
alcub3 security audit          # MAESTRO compliance check
alcub3 classify [file] --level=[u|s|ts]  # Classify data
alcub3 emergency-stop all      # Emergency shutdown
```

### Air-Gap Operations
```bash
alcub3 airgap package --target=[device]  # Prepare for transfer
alcub3 airgap sync             # Reconcile contexts
alcub3 airgap status           # Check air-gap mode
```

### Robotics Control
```bash
alcub3 robotics list           # Show connected platforms
alcub3 robotics connect --platform=boston-dynamics --id=spot-001
alcub3 robotics status --id=spot-001
alcub3 robotics emergency-stop all  # Safety command
```

### Development Commands
```bash
npm run preflight              # Full validation suite
npm run build                  # Build the project
npm test                       # Run unit tests
npm run security:check         # Security regression tests
```

## Environment Variables

### Core Configuration
```bash
ALCUB3_CLEARANCE_LEVEL         # Security clearance (UNCLASSIFIED|SECRET|TS)
ALCUB3_AIRGAP_MODE            # Enable air-gap mode (true|false)
ALCUB3_OFFLINE_DAYS           # Days of offline operation (default: 30)
ALCUB3_MODEL_CACHE            # Local model storage path
```

### Security Settings
```bash
ALCUB3_HSM_ENABLED            # Hardware security module (true|false)
ALCUB3_AUDIT_LEVEL            # Audit logging level (none|basic|full)
ALCUB3_ENCRYPTION_STRENGTH    # Encryption level (standard|high|quantum)
```

### Performance Tuning
```bash
ALCUB3_MAX_WORKERS            # Maximum worker threads
ALCUB3_CACHE_SIZE             # Cache size in MB
ALCUB3_TIMEOUT                # Operation timeout in seconds
```

## Configuration Files

### Main Configuration
```json
// .alcub3/config.json
{
  "security": {
    "clearanceLevel": "UNCLASSIFIED",
    "airgapMode": false,
    "auditLogging": true
  },
  "robotics": {
    "platforms": ["boston-dynamics", "ros2", "dji"],
    "safetyTimeout": 30
  },
  "performance": {
    "cacheSize": 512,
    "workers": 4
  }
}
```

### Platform Adapters
```yaml
# .alcub3/adapters/spot.yaml
platform: boston-dynamics
model: spot
version: 3.2.0
capabilities:
  - navigation
  - manipulation
  - inspection
security:
  encryption: required
  authentication: pki
```

## File Structure

```
project/
├── .alcub3/               # Configuration directory
│   ├── config.json       # Main configuration
│   ├── adapters/         # Platform adapter configs
│   └── keys/            # Security keys (HSM-backed)
├── 01-security-platform/ # Core security components
├── 02-robotics-hal/     # Robotics adapters
├── 03-maestro-framework/# Security framework
└── docs/                # Documentation
```

## Common Workflows

### First Time Setup
```bash
git clone https://github.com/alcub3/alcub3-cli.git
cd alcub3-cli
npm install
npm run build
alcub3 --init
```

### Classified Operations
```bash
export ALCUB3_CLEARANCE_LEVEL="SECRET"
export ALCUB3_AIRGAP_MODE="true"
alcub3 classify data.json --level=s
alcub3 airgap package --target=secure-device
```

### Robot Integration
```bash
alcub3 robotics discover
alcub3 robotics connect --platform=ros2 --url=ros2://192.168.1.100
alcub3 robotics execute --id=robot-001 --command="navigate" --target="waypoint-a"
```

## Troubleshooting

### Common Issues

**Connection Failed**
```bash
alcub3 diagnostics network
alcub3 security check-firewall
```

**Authentication Error**
```bash
alcub3 auth refresh
alcub3 auth validate --cert=/path/to/cert
```

**Performance Issues**
```bash
alcub3 perf analyze
alcub3 cache clear
export ALCUB3_MAX_WORKERS=8
```

## Security Levels

| Level | Description | Requirements |
|-------|------------|--------------|
| U | UNCLASSIFIED | Standard security |
| C | CONFIDENTIAL | Encryption required |
| S | SECRET | Air-gap recommended |
| TS | TOP SECRET | Air-gap mandatory |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Authentication failure |
| 4 | Security violation |
| 5 | Network error |
| 10 | Emergency stop |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+C | Cancel current operation |
| Ctrl+D | Exit CLI |
| Ctrl+L | Clear screen |
| Tab | Auto-complete |
| ↑/↓ | Command history |

## Support

- Documentation: https://docs.alcub3.dev
- Issues: https://github.com/alcub3/alcub3-cli/issues
- Security: security@alcub3.dev
- Enterprise: support@alcub3.dev