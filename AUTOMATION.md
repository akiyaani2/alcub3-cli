# ALCUB3 Development Automation Guide

This document describes all the automated workflows in the ALCUB3 project. Most development tasks are automated through Git hooks, eliminating the need to remember complex commands.

## 🚀 Overview

ALCUB3 uses Git hooks to automate repetitive tasks during your normal development workflow. You don't need to remember any special commands - just use Git normally and the automation handles the rest.

## 🎣 Git Hooks

All hooks are managed by Husky and located in `.husky/`

### pre-commit
**When:** Before every commit  
**What it does:**
- ✨ **Auto-formats** your code (Prettier)
- 🔧 **Auto-fixes** linting issues (ESLint)
- 🧪 Runs unit tests
- 🔍 Scans for hardcoded secrets
- 💡 Detects patent opportunities
- ⚡ Validates performance annotations
- 📋 Checks for task references
- 📄 Warns about missing file headers
- 🚫 Detects console.log statements
- 📚 Reminds about documentation for new files

**No manual action needed** - formatting and linting are automatic!

### commit-msg
**When:** After writing commit message  
**What it does:**
- ✅ Validates conventional commit format
- 📏 Ensures minimum message length
- 🔒 Suggests classification markers for sensitive areas
- 📋 Validates task references
- 💡 Detects patent keywords
- 🎯 Provides helpful examples if format is wrong

**Format:** `type(scope): subject`  
**Example:** `feat(security): add quantum-resistant encryption`

### post-commit
**When:** After successful commit  
**What it does:**
- ✅ Auto-completes referenced tasks
- 📚 Reminds about documentation for significant changes
- 💡 Logs patent opportunities
- ⚡ Tracks performance changes
- 📋 Updates Task Master automatically

### pre-push
**When:** Before pushing to remote  
**What it does:**
- 🏗️ Verifies build succeeds
- 🧪 Ensures 80% test coverage
- 🔒 Runs security scans
- 🎯 Detects classification markers
- ⚡ Validates performance

### post-checkout
**When:** After switching branches  
**What it does:**
- 📦 **Auto-installs** dependencies if package.json changed
- 🔧 Switches to branch-specific environment
- 📋 Syncs Task Master for branch
- 🗄️ Alerts about new migrations
- 🔒 Warns about classified branches
- 📚 Notes documentation changes
- ⚡ Checks build freshness
- 🏗️ Alerts about pillar-specific setup

**No need to run `npm install` manually!**

### post-merge
**When:** After merging branches  
**What it does:**
- 📦 **Auto-installs** dependencies if needed
- 🗄️ Alerts about new migrations
- 📋 Syncs tasks
- 🏗️ Runs build check
- 📚 Notes strategic document updates

### prepare-commit-msg
**When:** Before commit message editor opens  
**What it does:**
- 🎨 **Auto-adds** commit type based on changes
- 🏷️ **Auto-adds** scope based on affected pillar
- 📋 **Auto-adds** task references from code
- ✨ **Auto-adds** appropriate emoji

### pre-rebase
**When:** Before rebasing  
**What it does:**
- 🔒 Warns about classified commits
- 💡 Identifies patent-related commits
- 🛡️ Flags security-critical changes
- 📦 Alerts about large commits
- 📸 Creates backup of important metadata

## 🤖 What Gets Automated

### Things You Never Need to Do Manually:
- ❌ Run formatter before commit
- ❌ Fix linting issues manually
- ❌ Remember to run `npm install` after checkout
- ❌ Update task status after commit
- ❌ Add commit type/scope manually
- ❌ Check for security issues before push

### Things That Happen Automatically:
- ✅ Code formatting (Prettier)
- ✅ Lint fixes (ESLint)
- ✅ Dependency installation
- ✅ Task status updates
- ✅ Commit message formatting
- ✅ Security scanning
- ✅ Performance validation
- ✅ Test execution

## 📝 Common Workflows

### Starting a New Feature
```bash
git checkout -b feature/my-feature
# Dependencies auto-install, environment switches, tasks sync
# Just start coding!
```

### Making a Commit
```bash
git add .
git commit -m "add new feature"
# Auto-formats code, fixes linting, adds commit type
# Becomes: "feat: add new feature ✨"
```

### Switching Branches
```bash
git checkout main
# Dependencies update automatically
# No need to run npm install
```

### Pushing Changes
```bash
git push
# Build verified, tests run, security checked
# Only pushes if everything passes
```

## 🛠️ GitHub Actions

Automated CI/CD workflows in `.github/workflows/`:

### ci.yml
- Runs on every push/PR
- Builds, lints, tests
- Posts coverage reports

### Others
- Various automated triage and security workflows
- Nightly releases
- Community reports

## 🔧 Configuration

- **Husky**: `.husky/` directory
- **Lint-staged**: `.build/config/.lintstagedrc.json`
- **ESLint**: `.build/config/eslint.config.js`
- **Prettier**: `.build/config/.prettierrc.json`

## 💡 Tips

1. **Let automation work for you** - Don't manually format or lint
2. **Write simple commit messages** - Hooks enhance them
3. **Trust the process** - If a hook fails, it's protecting you
4. **Check hook output** - Provides helpful context and reminders

## 🚨 Troubleshooting

### Hook Not Running
```bash
npx husky install
```

### Bypass a Hook (Emergency Only)
```bash
git commit --no-verify -m "emergency fix"
```

### Reset Hooks
```bash
rm -rf .husky
npx husky install
npm run prepare
```

## 📚 Related Documentation

- `CLAUDE.md` - AI assistance guide
- `00-strategic/process/DEVELOPMENT_PROCESS.md` - Development workflow
- `.taskmaster/README.md` - Task management

---

Remember: **You don't need to memorize commands**. Git hooks handle everything automatically during your normal workflow!