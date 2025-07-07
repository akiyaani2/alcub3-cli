# ALCUB3 Development Setup

## Quick Start

### 1. Node.js Dependencies

```bash
npm install
```

### 2. Python Dependencies (Virtual Environment)

```bash
# Create virtual environment (only needed once)
python3 -m venv .venv

# Activate virtual environment (needed each time)
source .venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Deactivate when done (optional)
deactivate
```

### 3. Build & Run

```bash
npm run build
npm start
```

## Development Workflow

**For each development session:**

```bash
# 1. Activate Python environment
source .venv/bin/activate

# 2. Run your development commands
npm run dev
# or other commands...

# 3. Deactivate when done (optional)
deactivate
```

## Environment Management

- **Node.js packages**: Managed by `package.json` and `npm`
- **Python packages**: Managed by `requirements.txt` and virtual environment
- **Virtual environment**: Located in `.venv/` (ignored by git)

## Troubleshooting

If you see Python import errors:

```bash
# Make sure virtual environment is activated
source .venv/bin/activate
which pip  # Should point to .venv/bin/pip
```

If packages are missing:

```bash
pip install -r requirements.txt
```
