# ALCUB3 Directory Structure

*Last Updated: January 10, 2025*

## Overview

ALCUB3 uses a pillar-based architecture aligned with the seven-pillar defense AI platform. Each numbered directory represents a major architectural pillar, with supporting infrastructure in dot-prefixed directories and cross-cutting concerns in 0X-prefixed directories.

## Directory Structure

```
alcub3-cli/
├── 00-strategic/                    # Strategic planning, patents, vision
│   ├── decisions/                   # Technical decision records
│   ├── patents/                     # Patent documentation and tracking
│   │   ├── archive/                 # Historical patent documents
│   │   └── detailed/                # Detailed patent specifications
│   ├── grants-funding/              # Grant applications and funding
│   │   ├── active-applications/     # Current grant applications
│   │   ├── awarded/                 # Successfully awarded grants
│   │   └── templates/               # Application templates
│   └── vision/                      # Product vision and roadmap
│
├── 01-security-platform/            # PILLAR 1: Universal Security Platform Foundation
│   ├── core/                        # Core backend with security enhancements
│   ├── cli/                         # Enhanced CLI with defense-specific commands
│   ├── airgap-mcp/                  # Air-gapped Model Context Protocol (30+ day offline)
│   ├── agent-sandboxing/            # Agent execution sandboxing
│   ├── hsm-integration/             # Hardware Security Module integration
│   └── docs/                        # Security platform documentation
│
├── 02-robotics-hal/                 # PILLAR 2: Universal Robotics Security Platform
│   ├── src/                         # Source code
│   │   ├── universal-robotics/      # Universal robotics behavioral AI
│   │   ├── hal/                     # Hardware abstraction layer
│   │   └── ai/                      # AI-enhanced security features
│   ├── adapters/                    # Platform-specific adapters
│   │   ├── boston-dynamics/         # Spot robot integration
│   │   ├── ros2/                    # ROS2/SROS2 security bridge
│   │   ├── dji/                     # DJI drone security adapter
│   │   └── universal-robots/        # UR industrial robots
│   ├── swarm/                       # Swarm intelligence security
│   ├── physics/                     # Physics-aware safety validation
│   └── docs/                        # Robotics documentation
│
├── 03-maestro-framework/            # PILLAR 3: MAESTRO Security Framework (L1-L7)
│   ├── l1-l7/                       # All 7 security layers
│   ├── shared/                      # Cross-layer components
│   ├── monitoring/                  # Real-time security monitoring
│   ├── demos/                       # Security framework demonstrations
│   ├── tests/                       # Framework test suites
│   └── docs/                        # MAESTRO documentation
│
├── 04-simulation-platform/          # PILLAR 4: Universal Simulation Platform
│   ├── core/                        # Shared simulation infrastructure
│   │   ├── k-scale-integration/     # K-Scale Labs ksim foundation
│   │   ├── physics-engine/          # Universal physics simulation
│   │   ├── scenario-framework/      # Reusable scenario building blocks
│   │   └── sim-to-real/             # Universal sim-to-real transfer
│   ├── domains/                     # Domain-specific implementations
│   │   ├── defense/                 # Defense training scenarios
│   │   ├── industrial/              # Manufacturing/industry scenarios
│   │   └── space/                   # Space mission scenarios
│   └── docs/                        # Simulation documentation
│
├── 05-cisa-compliance/              # PILLAR 5: CISA Cybersecurity Posture Management
│   ├── top10-remediation/           # CISA Top 10 misconfiguration engine
│   ├── jit-privilege/               # Just-in-Time privilege escalation
│   ├── nist-compliance/             # NIST SP 800-171 automation
│   ├── stig-validation/             # STIG compliance validation
│   ├── drift-detection/             # Configuration drift detection
│   ├── network-segmentation/        # Network segmentation validation
│   └── docs/                        # Compliance documentation
│
├── 06-neural-compression/           # PILLAR 6: Neural Compression Engine
│   ├── transformer-engine/          # Transformer-based compression (40-60%)
│   ├── classification-aware/        # Security-preserving compression
│   ├── universal-codec/             # Universal data compression
│   ├── fips-algorithms/             # FIPS 140-2 compliant algorithms
│   ├── performance-optimization/    # Real-time performance (<100ms)
│   └── docs/                        # Compression documentation
│
├── 07-space-operations/             # PILLAR 7: Space Operations
│   ├── orbital-adapters/            # Minimal adaptations for orbital robotics
│   ├── satellite-management/        # Constellation security management
│   ├── cislunar-communications/     # Deep space communication optimization
│   └── docs/                        # Space operations documentation
│
├── 0X-developer-experience/         # Cross-cutting developer tools and automation
│   ├── automation/                  # Build and CI/CD automation
│   ├── onboarding/                  # Developer guides and setup
│   ├── workflows/                   # Development workflows
│   └── AGENT_COORDINATION.md        # Multi-agent development coordination
│
├── .build/                          # Build infrastructure
│   ├── scripts/                     # Build and utility scripts
│   ├── config/                      # Build configuration files
│   │   ├── .prettierrc.json         # Prettier configuration
│   │   ├── .lintstagedrc.json       # Lint-staged configuration
│   │   ├── eslint.config.js         # ESLint configuration
│   │   └── esbuild.config.js        # ESBuild configuration
│   └── integration-tests/           # E2E and integration tests
│
├── .logs/                           # Centralized logging infrastructure
│   ├── audit/                       # Security audit logs
│   ├── deployment/                  # Deployment and configuration logs
│   └── performance/                 # Performance metrics logs
│
├── .reports/                        # Generated reports and analytics
│   ├── patent-demos/                # Patent demonstration reports
│   └── innovation-tracking/         # Innovation portfolio reports
│
├── docs/                            # Central documentation hub
│   ├── api/                         # Generated API documentation
│   ├── architecture/                # Architecture decision records
│   └── index.md                     # Documentation navigation
│
└── [Root Files]
    ├── README.md                    # Project overview
    ├── package.json                 # NPM workspace configuration
    ├── tsconfig.json                # TypeScript configuration
    └── .gitignore                   # Git ignore rules
```

## Pillar Descriptions

### PILLAR 1: Universal Security Platform Foundation
- Air-gapped MCP server for 30+ day offline operations
- Agent sandboxing with hardware-enforced integrity
- HSM integration for FIPS 140-2 compliance
- Classification engine (UNCLASSIFIED → TOP SECRET)
- PKI/CAC authentication system

### PILLAR 2: Universal Robotics Security Platform
- Universal Security HAL supporting 20+ platforms
- Platform-specific adapters (Boston Dynamics, ROS2, DJI)
- Physics-aware safety validation
- Swarm intelligence and Byzantine consensus
- Emergency override systems

### PILLAR 3: MAESTRO Security Framework
- Complete L1-L7 security implementation
- Real-time monitoring and threat correlation
- Cross-layer security integration
- AI bias detection and mitigation
- Production-ready demos and testing

### PILLAR 4: Universal Simulation Platform
- Core simulation infrastructure shared across domains
- K-Scale Labs integration with ksim foundation
- Domain-specific scenarios (defense, industrial, space)
- Universal physics engine and scenario framework
- Secure sim-to-real transfer pipeline

### PILLAR 5: CISA Cybersecurity Posture Management
- CISA Top 10 misconfiguration remediation
- Just-in-Time privilege escalation
- Automated STIG compliance validation
- Configuration drift detection
- Network segmentation validation

### PILLAR 6: Neural Compression Engine
- Transformer-based compression (40-60% ratios)
- Classification-aware processing
- Universal data compression for all pillars
- FIPS 140-2 compliant algorithms
- Real-time performance optimization

### PILLAR 7: Space Operations
- Minimal adaptations for space deployment
- Orbital robotics security integration
- Satellite constellation management
- Cislunar communications optimization
- Leverages 95% of existing platform capabilities

## Documentation Strategy

Each pillar maintains its own `docs/` directory for pillar-specific documentation. The central `/docs/` directory serves as a navigation hub with cross-references to pillar documentation.

## Development Workflow

1. Strategic planning, patents, and grants in `00-strategic/`
2. Core development in numbered pillar directories (01-07)
3. Developer tools and automation in `0X-developer-experience/`
4. Build configuration in `.build/config/`
5. Centralized logging in `.logs/`
6. Generated reports in `.reports/`

## Recent Changes (January 10, 2025)

- Added PILLAR 7 for Space Operations
- Renamed `07-developer-experience` → `0X-developer-experience` (cross-cutting)
- Restructured `04-simulation-training` → `04-simulation-platform` with core/domains split
- Added `00-strategic/grants-funding/` for grant management
- Created `.logs/` for centralized logging
- Moved `universal-robotics/` → `02-robotics-hal/src/universal-robotics/`
- Removed empty directories (`IDE/`, `audit_logs/`)