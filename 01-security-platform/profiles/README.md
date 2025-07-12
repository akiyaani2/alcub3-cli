# ALCUB3 Security Profiles

## Quick Selection Guide

| Your Use Case | Recommended Profile | Key Features | Performance |
|---------------|-------------------|--------------|-------------|
| Commercial robotics | **ENTERPRISE** | Basic security, cloud-ready | <20ms |
| Government contract | **FEDERAL** | NIST compliance, quantum-ready | <100ms |
| Classified facility | **CLASSIFIED** | Air-gap, maximum security | <500ms |
| Unique requirements | **CUSTOM** | Mix and match features | Varies |

## Profile Comparison

### ENTERPRISE Profile
**Target Market**: Commercial and industrial customers
- Amazon warehouses
- Tesla factories  
- Logistics companies
- Manufacturing plants

**Key Features**:
- Standard encryption (AES-256)
- Basic classification (Public/Internal/Proprietary)
- OAuth2/JWT authentication
- MAESTRO L1-L3 (AI safety layers)
- Cloud-native deployment

**Use When**:
- Speed is critical
- Operating in trusted networks
- No government compliance requirements
- Standard commercial security is sufficient

### FEDERAL Profile
**Target Market**: Government and defense contractors
- Lockheed Martin
- Raytheon
- DoE facilities
- Critical infrastructure

**Key Features**:
- Quantum-resistant cryptography
- CUI/FOUO classification support
- CAC/PIV authentication
- MAESTRO L1-L6 (includes compliance)
- 30-day offline operation
- NIST/STIG compliance

**Use When**:
- Working on government contracts
- Handling CUI data
- Need future-proof encryption
- Compliance is mandatory

### CLASSIFIED Profile
**Target Market**: High-security operations
- Military installations
- Intelligence agencies
- Nuclear facilities
- Air-gapped networks

**Key Features**:
- Full classification system (up to TS/SCI)
- Homomorphic encryption
- Hardware security modules (HSM)
- Complete air-gap operation
- Byzantine fault tolerance
- MAESTRO L1-L7 (all layers)

**Use When**:
- Handling classified data
- Operating in air-gapped environments
- Maximum security required
- Performance is secondary to security

## Using Security Profiles

### 1. Check Current Profile
```bash
alcub3 security profile --current
```

### 2. List Available Profiles
```bash
alcub3 security profile --list
```

### 3. Set a Profile
```bash
# For new deployments
alcub3 security profile --set federal

# With confirmation
alcub3 security profile --set classified --confirm
```

### 4. Create Custom Profile
```bash
# Interactive wizard
alcub3 security profile --create

# From template
cp custom.template.yaml my_custom.yaml
# Edit my_custom.yaml
alcub3 security profile --validate my_custom.yaml
alcub3 security profile --set my_custom
```

## Migration Between Profiles

### Upgrading Security
```bash
# From ENTERPRISE to FEDERAL
alcub3 security migrate --from enterprise --to federal

# Review changes
alcub3 security migrate --from enterprise --to federal --dry-run
```

### Important Migration Notes
- **ENTERPRISE → FEDERAL**: Adds compliance overhead (~80ms)
- **FEDERAL → CLASSIFIED**: Requires air-gap preparation
- **Downgrading**: Not recommended without data sanitization

## Performance Impact

| Feature | ENTERPRISE | FEDERAL | CLASSIFIED |
|---------|------------|---------|------------|
| Basic Auth | 1ms | 5ms | 20ms |
| Encryption | 2ms | 10ms | 50ms |
| Classification | 1ms | 5ms | 10ms |
| Total API Call | ~10ms | ~50ms | ~200ms |

## Customization

### Common Customizations

1. **Space Operations** (NASA + Commercial speed)
```yaml
base_profile: "FEDERAL"
integrations:
  nasa_cfs:
    enabled: true
performance:
  target_latency_ms: 50  # Faster than standard FEDERAL
```

2. **Industrial + Compliance** (Manufacturing with NIST)
```yaml
base_profile: "ENTERPRISE"
compliance:
  mandatory: ["NIST-800-171"]
audit:
  level: "detailed"
  retention_days: 365
```

3. **Research Lab** (High security, flexible policy)
```yaml
base_profile: "CLASSIFIED"
zero_trust:
  policy_engine: "adaptive"  # Not "paranoid"
performance:
  target_latency_ms: 200  # Faster than standard CLASSIFIED
```

## Profile Validation

Before deploying, always validate:
```bash
# Check profile syntax
alcub3 security profile --validate federal.yaml

# Test performance impact
alcub3 security benchmark --profile federal

# Verify compliance
alcub3 security compliance --check --profile federal
```

## Support

- **Issues**: Open GitHub issue with profile tag
- **Questions**: security-profiles@alcub3.ai
- **Custom Profiles**: Contact professional services