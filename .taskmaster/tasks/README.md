# Task Management System Documentation

## Overview

This directory contains the task management data for the ALCUB3 project using the `task-master` tool.

## IMPORTANT: Single Source of Truth

**The ONLY authoritative source for tasks is `tasks.json`**

- DO NOT create or maintain separate task text files (task_001.txt, etc.)
- DO NOT manually edit tasks outside of the task-master tool when possible
- All task updates should be made through task-master commands or by editing tasks.json directly

## File Structure

```
.taskmaster/tasks/
├── tasks.json          # ✅ PRIMARY: The single source of truth for all tasks
├── archive/            # 📦 Archived/legacy files (DO NOT USE)
├── validate_tasks.js   # 🔍 Validation script to check task structure
└── README.md          # 📚 This documentation
```

## Task Hierarchy

The ALCUB3 project uses a PILLAR-based task structure:

```
PILLAR 0: Market & Business Development (cross-cutting)
PILLAR 1: Universal Security Platform Foundation
PILLAR 2: Universal Robotics Security Platform
PILLAR 3: Defense Simulation & Training Platform
PILLAR 4: CISA Cybersecurity Posture Management
PILLAR 5: Neural Compression Engine
PILLAR 7: Space Operations
```

Note: There is no PILLAR 6 (it was renamed to PILLAR 0).

## Task Structure

Each PILLAR task can have:
- Subtasks (first level)
- Sub-subtasks (nested within subtasks)
- Further nesting as needed

Example:
```
PILLAR 1
  └─ Subtask 1.1: MAESTRO Security Framework
      └─ Sub-subtask 1.1.1: L1 Security Layer
      └─ Sub-subtask 1.1.2: L2 Security Layer
```

## Validation

Always validate the task structure after making changes:

```bash
cd .taskmaster/tasks
node validate_tasks.js
```

This will check for:
- Missing required fields (id, title, status, priority)
- Duplicate IDs
- Invalid dependencies
- Missing expected PILLARs

## Common Commands

```bash
# List all tasks
task-master list

# Show specific task details
task-master show 1

# Update task status
task-master set-status --id=1 --status=in-progress

# Add a new subtask
task-master add-subtask --parent=1 --title="New Subtask"
```

## Preventing Synchronization Issues

### DO:
- ✅ Use `tasks.json` as the single source of truth
- ✅ Run validation after manual edits
- ✅ Use task-master commands for updates when possible
- ✅ Keep regular backups (automated daily)

### DON'T:
- ❌ Create separate task files (task_001.txt, etc.)
- ❌ Maintain multiple JSON files with different task structures
- ❌ Edit tasks in multiple places
- ❌ Ignore validation warnings

## Backup Strategy

Backups are automatically created:
- Before major updates
- Daily automated backups
- Stored in the `archive/` directory with timestamps

## Recovery

If tasks.json becomes corrupted:

1. Check for recent backups:
   ```bash
   ls -la archive/tasks*.json
   ```

2. Validate backup integrity:
   ```bash
   jq . archive/tasks_backup_YYYYMMDD_HHMMSS.json > /dev/null && echo "Valid"
   ```

3. Restore from backup:
   ```bash
   cp archive/tasks_backup_YYYYMMDD_HHMMSS.json tasks.json
   ```

4. Validate restored file:
   ```bash
   node validate_tasks.js
   ```

## Technical Details

- Format: JSON
- Encoding: UTF-8
- Max file size: No limit, but keep under 10MB for performance
- Structure: Hierarchical with master -> tasks -> subtasks

---

**Last Updated**: January 11, 2025
**Maintained By**: ALCUB3 Development Team