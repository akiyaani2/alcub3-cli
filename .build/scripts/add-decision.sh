#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: ./scripts/add-decision.sh \"Decision title\""
  exit 1
fi

echo "" >> DECISIONS.md
echo "## $(date +%Y-%m-%d): $1" >> DECISIONS.md
echo "**Why**: " >> DECISIONS.md
echo "**Trade-off**: " >> DECISIONS.md
echo "" >> DECISIONS.md
echo "✅ Added decision to DECISIONS.md - please fill in the details"

# Try to open in VSCode or default editor
if command -v code &> /dev/null; then
  code DECISIONS.md
elif [ -n "$EDITOR" ]; then
  $EDITOR DECISIONS.md
else
  echo "   Edit DECISIONS.md to complete the entry"
fi