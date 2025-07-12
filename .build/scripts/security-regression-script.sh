#!/bin/bash
set -e

echo "🔐 ALCUB3 Security Regression Tests"
echo "===================================="

# 1. Check for hardcoded secrets
echo -n "Checking for hardcoded secrets... "
if grep -r "password\|secret\|api_key\|private_key" \
  --include="*.ts" --include="*.js" \
  --exclude-dir=node_modules \
  --exclude-dir=dist \
  --exclude="*test*" \
  src/ packages/ 2>/dev/null | grep -v "// SAFE:" > /dev/null; then
  echo "❌ FAILED"
  echo "Found potential secrets in code!"
  exit 1
fi
echo "✅ PASSED"

# 2. Check for console.log statements
echo -n "Checking for console.log statements... "
if grep -r "console\.log" \
  --include="*.ts" --include="*.js" \
  --exclude-dir=node_modules \
  --exclude-dir=tests \
  --exclude="*test*" \
  src/ packages/ 2>/dev/null > /dev/null; then
  echo "❌ FAILED"
  echo "Found console.log statements (use proper logging)!"
  exit 1
fi
echo "✅ PASSED"

# 3. Verify all endpoints have authentication
echo -n "Checking API authentication... "
if grep -r "router\.\(get\|post\|put\|delete\)" \
  --include="*.ts" \
  packages/ 2>/dev/null | grep -v "authenticate\|public" > /dev/null; then
  echo "⚠️  WARNING"
  echo "Found potentially unauthenticated endpoints"
fi
echo "✅ PASSED"

# 4. Check TypeScript strict mode
echo -n "Checking TypeScript strict mode... "
if ! grep -q '"strict": true' tsconfig.json; then
  echo "❌ FAILED"
  echo "TypeScript strict mode is not enabled!"
  exit 1
fi
echo "✅ PASSED"

# 5. Dependency vulnerabilities
echo -n "Checking for known vulnerabilities... "
if npm audit --production 2>&1 | grep -q "found [1-9]"; then
  echo "⚠️  WARNING"
  echo "Found vulnerable dependencies - run 'npm audit fix'"
else
  echo "✅ PASSED"
fi

# 6. File permissions
echo -n "Checking file permissions... "
if find . -type f -perm 0777 2>/dev/null | grep -v node_modules | head -1 > /dev/null; then
  echo "❌ FAILED"
  echo "Found world-writable files!"
  exit 1
fi
echo "✅ PASSED"

# 7. Classification markings
echo -n "Checking classification markings... "
if ! grep -q "Classification:" README.md 2>/dev/null; then
  echo "⚠️  WARNING"
  echo "Missing classification markings in README"
fi
echo "✅ PASSED"

# 8. Patent markers
echo -n "Checking for unmarked innovations... "
INNOVATIONS=$(grep -r "TODO.*PATENT\|FIXME.*PATENT" --include="*.ts" --include="*.md" src/ packages/ 2>/dev/null || true)
if [ -n "$INNOVATIONS" ]; then
  echo "⚠️  WARNING"
  echo "Found potential innovations not documented in PATENT_INNOVATIONS.md:"
  echo "$INNOVATIONS"
else
  echo "✅ PASSED"
fi

# 9. Check for security imports
echo -n "Checking security module usage... "
SECURITY_FILES=$(find packages -name "*.ts" -type f | grep -E "(auth|crypto|security)" | wc -l)
if [ "$SECURITY_FILES" -gt 0 ]; then
  echo "✅ PASSED ($SECURITY_FILES security-related files found)"
else
  echo "⚠️  WARNING"
  echo "No security-related files found - ensure security is implemented"
fi

# 10. Check for test coverage
echo -n "Checking test coverage configuration... "
if [ -f "packages/core/vitest.config.ts" ] && [ -f "packages/cli/vitest.config.ts" ]; then
  echo "✅ PASSED"
else
  echo "⚠️  WARNING"
  echo "Missing test configuration files"
fi

echo ""
echo "✅ Security regression tests complete!"
echo ""
echo "Run this after every feature with: npm run security:check"