# ALCUB3 Centralized Logging

## Overview

This directory contains centralized logs for the entire ALCUB3 platform. Logs are organized by category to facilitate security monitoring, performance analysis, and audit compliance.

## Directory Structure

```
.logs/
├── audit/           # Security audit logs
├── deployment/      # Deployment and configuration logs  
├── performance/     # Performance metrics and profiling
└── README.md        # This file
```

## Log Categories

### Audit Logs (`/audit/`)
Security-relevant events including:
- Authentication attempts
- Authorization decisions
- Classification changes
- Security violations
- Configuration modifications
- Access to sensitive resources

Format: `audit_YYYY-MM-DD.log`

### Deployment Logs (`/deployment/`)
System deployment and configuration events:
- Service startups/shutdowns
- Configuration changes
- Version deployments
- Migration activities
- Health check results

Format: `deployment_YYYY-MM-DD.log`

### Performance Logs (`/performance/`)
System performance metrics:
- Response time measurements
- Resource utilization
- Throughput statistics
- Error rates
- Performance budget violations

Format: `performance_YYYY-MM-DD.log`

## Log Format

All logs follow a structured format for easy parsing:

```
[TIMESTAMP] [LEVEL] [COMPONENT] [CLASSIFICATION] [USER] [ACTION] [DETAILS]
```

Example:
```
[2025-01-10T14:32:15.123Z] [INFO] [MAESTRO-L3] [UNCLASSIFIED] [system] [VALIDATION] Command validation completed in 3ms
```

## Security Considerations

- Logs may contain sensitive information
- Classification levels are preserved in log entries
- Audit logs are immutable once written
- Access to logs requires appropriate clearance

## Integration

Each pillar writes to the centralized logs:

```python
from alcub3.logging import get_logger

logger = get_logger('audit', component='robotics-hal')
logger.info('Robot command validated', 
    classification='SECRET',
    user=current_user,
    action='COMMAND_VALIDATION',
    details={'robot_id': 'spot-001', 'command': 'patrol'})
```

## Retention Policy

- **Audit Logs**: 7 years (compliance requirement)
- **Deployment Logs**: 90 days
- **Performance Logs**: 30 days

## Log Rotation

Logs are automatically rotated daily at midnight UTC:
- Current day: `category_YYYY-MM-DD.log`
- Previous days: Compressed as `category_YYYY-MM-DD.log.gz`

## Monitoring

Logs are monitored in real-time for:
- Security anomalies
- Performance degradation
- System errors
- Compliance violations

## Access Control

Log access follows ALCUB3 classification rules:
- UNCLASSIFIED logs: All authenticated users
- SECRET logs: SECRET clearance required
- TOP SECRET logs: TOP SECRET clearance required

## Backup

Logs are backed up according to classification:
- Daily encrypted backups
- Off-site replication for disaster recovery
- Air-gapped archive for audit logs

---

**Note**: All log files (`*.log`, `*.txt`) are ignored by git. Only the directory structure is versioned.