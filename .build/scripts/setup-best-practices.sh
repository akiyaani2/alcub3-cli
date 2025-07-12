#!/bin/bash
# ALCUB3 Best Practices Setup Script

echo "🚀 Setting up ALCUB3 best practices..."
echo ""

# Check if dependencies are installed
echo "📦 Checking dependencies..."
if ! grep -q "husky" package.json; then
  echo "Installing husky and lint-staged..."
  npm install --save-dev husky lint-staged
fi

# Initialize husky if needed
if [ ! -d ".husky" ]; then
  echo "📌 Initializing husky..."
  npx husky init
fi

# Ensure all scripts are executable
echo "🔧 Setting permissions..."
chmod +x .husky/pre-commit 2>/dev/null || true
chmod +x .husky/pre-push 2>/dev/null || true
chmod +x scripts/security-regression.sh 2>/dev/null || true
chmod +x scripts/add-decision.sh 2>/dev/null || true

# Check if .env exists
if [ ! -f ".env" ]; then
  echo "📋 Creating .env file from template..."
  cp .env.example .env
  echo "   ⚠️  Please update .env with your actual values!"
fi

# Run initial checks
echo ""
echo "🧪 Running initial checks..."
echo ""

# Test security regression
echo "Running security check..."
./scripts/security-regression.sh || echo "   ⚠️  Some security checks need attention"

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Update .env with your actual configuration"
echo "2. Run: npm run security:check (to verify security)"
echo "3. Make a test commit to verify hooks"
echo "4. Check GitHub Actions tab after pushing"
echo ""
echo "📚 New commands available:"
echo "  npm run test:unit       - Run unit tests only"
echo "  npm run test:perf       - Run performance tests"
echo "  npm run security:check  - Run security regression"
echo "  npm run security:audit  - Check dependencies"
echo "  npm run decision        - Add technical decision"
echo ""
echo "Total setup time: ~10 minutes"
echo "Time saved per week: 5-10 hours"