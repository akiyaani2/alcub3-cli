# ALCUB3 Development Guide

## Quick Start

```bash
# Clone and setup
git clone https://github.com/alcub3/alcub3-cli.git
cd alcub3-cli
npm install
pip install -r requirements.txt

# Run development mode
npm run dev
```

## Repository Structure

ALCUB3 uses a numbered architecture that maps to our 6-pillar platform:

```
├── 00-strategic/        # CEO vision, patents, strategic decisions
├── 01-core-platform/    # Core CLI and API platform
├── 02-security-maestro/ # MAESTRO L1-L7 security framework  
├── 03-robotics-hal/     # Universal robotics HAL layer
├── 04-airgap-mcp/      # Air-gap MCP operations
├── 05-developer-experience/ # Developer tools & automation
```

## Development Workflow

### 1. Security-First Approach
Every feature begins with threat modeling:
```bash
# Before coding, run threat analysis
python 02-security-maestro/threat-modeler.py --feature="your-feature"
```

### 2. Task Management
Use the integrated task orchestration:
```bash
# Located in 05-developer-experience/automation/
python task-completion/task_completion_handler.py --mode=dev
```

### 3. Testing Requirements
- Unit tests required (minimum 80% coverage)
- Security regression tests must pass
- Performance budgets must be met

### 4. Code Style
- TypeScript: Strict mode, no `any` types
- Python: Type hints required, Black formatting
- All code must pass linting

## Key Commands

```bash
# Development
npm run dev              # Start development server
npm run test:unit       # Run unit tests
npm run security:check  # Security regression suite

# Building  
npm run build           # Build all packages
npm run build:cli      # Build CLI only

# Code Quality
npm run lint           # Run linters
npm run format         # Auto-format code
```

## Performance Requirements

All operations must meet performance budgets:
- API responses: <100ms
- File operations: <50ms  
- Security checks: <200ms

Use the performance budget utility:
```typescript
import { PerformanceBudget } from '@alcub3/core/utils/performance-budget';
```

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Follow security-first development
4. Ensure all tests pass
5. Submit PR with security review

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.