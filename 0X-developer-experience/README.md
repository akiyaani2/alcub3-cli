# Developer Automation Framework

This directory contains all developer productivity automation tools for the ALCUB3 project. These tools are designed to enhance developer efficiency while maintaining strict security boundaries with the defense-grade security framework.

## Overview

The Developer Automation Framework provides:
- **Task Completion Orchestration**: Automated workflows triggered on task completion
- **Patent Innovation Tracking**: Real-time detection of patentable innovations in code
- **Audit Documentation**: Blockchain-style immutable audit logging and reporting
- **Git Hooks**: Pre-commit and pre-push automation for quality assurance
- **Clean Security Integration**: Controlled interfaces to security framework

## Directory Structure

```
developer-automation/
├── src/
│   ├── task-completion/
│   │   └── task_completion_handler.py    # Main orchestration engine
│   ├── patent-tracking/
│   │   └── patent_innovation_tracker.py  # Patent detection system
│   ├── documentation/
│   │   └── audit_documentation_system.py # Audit and docs generation
│   ├── interfaces/
│   │   └── security_integration.py       # Clean interface to security
│   └── shared/
│       └── (common utilities)
├── hooks/
│   ├── install-hooks.sh                  # Hook installation script
│   ├── pre-commit                         # Pre-commit automation
│   ├── post-commit                        # Post-commit automation
│   └── pre-push                           # Pre-push automation
├── scripts/
│   └── (automation scripts)
└── tests/
    └── (test files)
```

## Quick Start

### Installation

```bash
# Install Python dependencies
pip install -r developer-automation/requirements.txt

# Install git hooks
cd developer-automation/hooks
./install-hooks.sh
```

### Basic Usage

```bash
# Run task completion handler
python developer-automation/src/task-completion/task_completion_handler.py --mode=full

# Run patent analysis only
python developer-automation/src/task-completion/task_completion_handler.py --mode=patent

# Run documentation generation
python developer-automation/src/task-completion/task_completion_handler.py --mode=docs

# Quick mode for fast feedback
python developer-automation/src/task-completion/task_completion_handler.py --mode=quick
```

## Components

### Task Completion Handler

The central orchestration engine that coordinates all automation activities:

- **Features**:
  - 6 execution modes (full, security, patent, docs, quick, ci_cd)
  - Parallel execution for performance
  - Smart caching to avoid redundant work
  - GitHub Actions integration
  - Detailed reporting and metrics

- **Usage**:
  ```python
  from task_completion_handler import TaskCompletionHandler
  
  handler = TaskCompletionHandler()
  results = await handler.run_complete_analysis(
      task_type="feature",
      changed_files=["src/api.py"],
      mode="full"
  )
  ```

### Patent Innovation Tracker

Automatically detects patentable innovations in your code:

- **Features**:
  - AST-based code analysis
  - ML-powered innovation scoring
  - Prior art monitoring
  - Patent claim generation
  - Innovation portfolio management

- **Innovation Types Detected**:
  - Novel algorithms
  - System architectures
  - Security methods
  - AI techniques
  - Data structures
  - Communication protocols

### Audit Documentation System

Blockchain-inspired immutable audit logging:

- **Features**:
  - SHA-256 linked audit chain
  - Tamper-proof logging
  - Compliance report generation
  - Technical documentation synthesis
  - Classification-aware handling

- **Document Types**:
  - Technical specifications
  - Security reports
  - Compliance documentation
  - Patent applications
  - Executive summaries

## Security Integration

The developer automation framework integrates with the security framework through controlled interfaces:

```python
from interfaces.security_integration import get_security_interface

# Get security interface
security = get_security_interface()
security.initialize()

# Request security test
results = security.request_security_test(
    test_type=SecurityTestType.COMPREHENSIVE,
    target_path="/path/to/code",
    options={"deep_scan": True}
)
```

## Configuration

### Environment Variables

```bash
# Set execution mode
export ALCUB3_AUTOMATION_MODE=full

# Enable debug logging
export ALCUB3_DEBUG=true

# Set classification level
export ALCUB3_CLASSIFICATION=unclassified
```

### Configuration Files

- `config/automation.yaml` - Main configuration
- `config/patents.yaml` - Patent tracking settings
- `config/security.yaml` - Security integration settings

## Best Practices

1. **Always run in appropriate mode**:
   - Use `quick` mode during development
   - Use `full` mode before commits
   - Use `ci_cd` mode in pipelines

2. **Review automation output**:
   - Check patent opportunities
   - Verify security findings
   - Review generated documentation

3. **Keep interfaces clean**:
   - Only use provided interfaces
   - Never directly import security internals
   - Maintain separation of concerns

## Troubleshooting

### Common Issues

1. **Import errors**: Ensure Python path includes both developer-automation and security-framework
2. **Permission errors**: Check file permissions on hooks directory
3. **Performance issues**: Use quick mode or specific component modes

### Debug Mode

```bash
# Enable debug logging
export ALCUB3_DEBUG=true
python developer-automation/src/task-completion/task_completion_handler.py --mode=full --debug
```

## Contributing

When adding new automation:

1. Place developer tools in `developer-automation/`
2. Place security tools in `security-framework/`
3. Use interfaces for cross-boundary communication
4. Add appropriate tests
5. Update documentation

## License

See main project LICENSE file.