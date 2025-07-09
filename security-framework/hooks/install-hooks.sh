#!/bin/bash
# ALCUB3 Git Hooks Installation Script

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 ALCUB3 Security Hooks Installer${NC}"
echo "===================================="

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo -e "${RED}Error: Not in a git repository root directory${NC}"
    echo "Please run this script from the root of your ALCUB3 repository"
    exit 1
fi

# Check if security framework exists
if [ ! -d "security-framework" ]; then
    echo -e "${RED}Error: Security framework not found${NC}"
    echo "Please ensure the security-framework directory exists"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Function to install a hook
install_hook() {
    local hook_name=$1
    local source_path="security-framework/hooks/$hook_name"
    local dest_path=".git/hooks/$hook_name"
    
    if [ ! -f "$source_path" ]; then
        echo -e "${YELLOW}Warning: $hook_name not found at $source_path${NC}"
        return 1
    fi
    
    # Check if hook already exists
    if [ -f "$dest_path" ]; then
        echo -e "${YELLOW}Backing up existing $hook_name to $dest_path.backup${NC}"
        cp "$dest_path" "$dest_path.backup"
    fi
    
    # Copy and make executable
    cp "$source_path" "$dest_path"
    chmod +x "$dest_path"
    
    echo -e "${GREEN}✓ Installed $hook_name${NC}"
    return 0
}

# Install hooks
echo ""
echo "Installing git hooks..."
echo "-----------------------"

install_hook "pre-push"
install_hook "post-commit"

# Create default configuration directory
echo ""
echo "Setting up configuration..."
echo "--------------------------"

mkdir -p .alcub3/config

# Create default task completion handler config
if [ ! -f ".alcub3/config/task-completion.yml" ]; then
    cat > .alcub3/config/task-completion.yml << 'EOF'
# ALCUB3 Task Completion Handler Configuration
# This file configures how the automated security and patent analysis runs

# Default execution mode
execution_mode: full

# Parallel execution settings
parallel_execution: true
max_workers: 4
timeout_minutes: 30

# Security testing configuration
security_tests:
  # Red team automation (comprehensive adversarial testing)
  red_team: true
  
  # AI fuzzing (mutation-based testing)
  fuzzing: true
  
  # Chaos engineering (resilience testing)
  chaos: false  # Disabled by default for safety
  
  # Adversarial AI testing (ML attack generation)
  adversarial: true

# Patent analysis configuration
patent_analysis:
  # Enable patent innovation detection
  enabled: true
  
  # Search for prior art (slower but more thorough)
  prior_art_search: true
  
  # Generate patent claims automatically
  claim_generation: true

# Documentation generation
documentation:
  # Technical implementation guide
  technical_guide: true
  
  # Security analysis report
  security_report: true
  
  # Compliance attestation
  compliance: true
  
  # Patent application draft
  patent_draft: true

# Quality thresholds
thresholds:
  # Minimum security score to pass (0-100)
  security_score_minimum: 85
  
  # Minimum patent score to report (1-5)
  patent_score_minimum: 3
  
  # Maximum performance degradation allowed (%)
  performance_degradation_max: 10

# Hook-specific overrides
hooks:
  pre_push:
    execution_mode: quick
    timeout_minutes: 5
    security_tests:
      red_team: false
      chaos: false
    patent_analysis:
      enabled: false
  
  post_commit:
    execution_mode: patent
    patent_analysis:
      prior_art_search: false  # Faster for local analysis

# Classification handling
classification:
  # Default classification for unmarked content
  default: unclassified
  
  # Auto-detect classification from commit messages
  auto_detect: true
  
  # Patterns for classification detection
  patterns:
    secret: ["[SECRET]", "[S]"]
    top_secret: ["[TOP-SECRET]", "[TS]"]
EOF
    echo -e "${GREEN}✓ Created default configuration at .alcub3/config/task-completion.yml${NC}"
else
    echo -e "${BLUE}Configuration already exists at .alcub3/config/task-completion.yml${NC}"
fi

# Add .alcub3 directories to .gitignore if not already there
if ! grep -q "^\.alcub3_patents" .gitignore 2>/dev/null; then
    echo "" >> .gitignore
    echo "# ALCUB3 Security Framework" >> .gitignore
    echo ".alcub3_patents/" >> .gitignore
    echo ".alcub3_patent_notification" >> .gitignore
    echo "security-report-*.json" >> .gitignore
    echo -e "${GREEN}✓ Updated .gitignore${NC}"
fi

# Create Python requirements if needed
if [ ! -f "security-framework/requirements.txt" ]; then
    cat > security-framework/requirements.txt << 'EOF'
# ALCUB3 Security Framework Requirements
asyncio
aiofiles
numpy>=1.21.0
pyyaml>=5.4
jinja2>=3.0.0
markdown>=3.3.0
requests>=2.26.0
cryptography>=3.4.7
pytest>=6.2.0
pytest-asyncio>=0.15.0
pytest-cov>=2.12.0
bandit>=1.7.0
safety>=1.10.0
mypy>=0.910
pylint>=2.9.0
black>=21.6b0
EOF
    echo -e "${GREEN}✓ Created requirements.txt${NC}"
fi

echo ""
echo -e "${GREEN}✅ Installation complete!${NC}"
echo ""
echo "Git hooks installed:"
echo "- pre-push: Runs quick security validation before pushing"
echo "- post-commit: Runs patent analysis in background after commits"
echo ""
echo "Configuration file: .alcub3/config/task-completion.yml"
echo ""
echo -e "${YELLOW}⚠️  Note: Make sure to install Python dependencies:${NC}"
echo "cd security-framework && pip install -r requirements.txt"
echo ""
echo -e "${BLUE}To disable hooks temporarily, use:${NC}"
echo "git push --no-verify  # Skip pre-push hook"
echo "git commit --no-verify  # Skip post-commit hook"
echo ""
echo -e "${BLUE}To uninstall hooks:${NC}"
echo "rm .git/hooks/pre-push .git/hooks/post-commit"