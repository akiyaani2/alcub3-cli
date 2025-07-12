#!/bin/bash

# Install Git Hooks for Task Validation

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../../" && pwd )"
GIT_HOOKS_DIR="$PROJECT_ROOT/.git/hooks"
PRE_COMMIT_HOOK="$GIT_HOOKS_DIR/pre-commit"

echo "📦 Installing Task Validation Git Hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$GIT_HOOKS_DIR"

# Create pre-commit hook content
cat > "$PRE_COMMIT_HOOK" << 'EOF'
#!/bin/bash

# Task Validation Pre-Commit Hook

# Check if tasks.json is being committed
if git diff --cached --name-only | grep -q ".taskmaster/tasks/tasks.json"; then
    echo "🔍 Validating tasks.json before commit..."
    
    # Get the project root
    PROJECT_ROOT=$(git rev-parse --show-toplevel)
    TASKS_DIR="$PROJECT_ROOT/.taskmaster/tasks"
    
    # Check if validation script exists
    if [ -f "$TASKS_DIR/validate_tasks.js" ]; then
        # Run validation
        cd "$TASKS_DIR"
        node validate_tasks.js
        
        if [ $? -ne 0 ]; then
            echo "❌ Task validation failed! Please fix errors before committing."
            exit 1
        else
            echo "✅ Task validation passed!"
        fi
    else
        echo "⚠️  Warning: validate_tasks.js not found, skipping validation"
    fi
fi

# Continue with commit
exit 0
EOF

# Make the hook executable
chmod +x "$PRE_COMMIT_HOOK"

echo "✅ Git hooks installed successfully!"
echo ""
echo "The following hook has been installed:"
echo "  - pre-commit: Validates tasks.json structure before committing"
echo ""
echo "To bypass validation (not recommended), use: git commit --no-verify"