#!/bin/bash

# Task Backup Script
# Automatically backs up tasks.json with validation

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TASKS_FILE="$SCRIPT_DIR/tasks.json"
ARCHIVE_DIR="$SCRIPT_DIR/archive"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$ARCHIVE_DIR/tasks_backup_$TIMESTAMP.json"

# Create archive directory if it doesn't exist
mkdir -p "$ARCHIVE_DIR"

# Check if tasks.json exists
if [ ! -f "$TASKS_FILE" ]; then
    echo "❌ Error: tasks.json not found!"
    exit 1
fi

# Validate current tasks.json
echo "🔍 Validating current tasks.json..."
if jq . "$TASKS_FILE" > /dev/null 2>&1; then
    echo "✅ Current tasks.json is valid JSON"
else
    echo "⚠️  Warning: Current tasks.json has JSON errors!"
    echo "Creating backup anyway..."
fi

# Create backup
echo "💾 Creating backup: $BACKUP_FILE"
cp "$TASKS_FILE" "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "✅ Backup created successfully"
    
    # Run validation on backup
    if [ -f "$SCRIPT_DIR/validate_tasks.js" ]; then
        echo "🔍 Running validation on backup..."
        node "$SCRIPT_DIR/validate_tasks.js" "$BACKUP_FILE" 2>/dev/null || true
    fi
    
    # Clean up old backups (keep last 30)
    echo "🧹 Cleaning up old backups (keeping last 30)..."
    ls -t "$ARCHIVE_DIR"/tasks_backup_*.json 2>/dev/null | tail -n +31 | xargs -r rm
    
    # Show backup stats
    BACKUP_COUNT=$(ls "$ARCHIVE_DIR"/tasks_backup_*.json 2>/dev/null | wc -l)
    BACKUP_SIZE=$(du -sh "$BACKUP_FILE" | cut -f1)
    echo "📊 Backup stats: $BACKUP_COUNT backups total, latest size: $BACKUP_SIZE"
else
    echo "❌ Error: Failed to create backup!"
    exit 1
fi

echo "✨ Backup complete!"