# Gemini Core

This directory contains the **unmodified** Google Gemini CLI code.

## ⚠️ IMPORTANT: DO NOT MODIFY FILES IN THIS DIRECTORY

All modifications should be made in:
- `/alcub3-extensions/` - For overrides and extensions
- `/01-security-platform/` and other domain directories - For ALCUB3-specific features

## Purpose

This separation allows us to:
1. Clearly distinguish between Gemini and ALCUB3 code
2. Easily update Gemini code if needed (by replacing this directory)
3. Maintain clean architecture boundaries
4. Simplify onboarding for new developers

## Structure

```
gemini-core/
├── cli/
│   └── src/        # Original Gemini CLI source
└── core/
    └── src/        # Original Gemini Core source
```

## Original Source

Forked from: https://github.com/google-gemini/gemini-cli
Last sync: 2025-01-12 (v0.1.11)

## For Developers

When you need to modify Gemini behavior:
1. **DON'T** modify files here
2. **DO** create an override in `/alcub3-extensions/`
3. **DO** use inheritance/composition to extend functionality

Example:
```typescript
// ❌ DON'T: Modify gemini-core/core/src/client.ts

// ✅ DO: Create alcub3-extensions/core/src/client.ts
import { GeminiClient } from '@gemini-core/core';

export class AlcubClient extends GeminiClient {
  // Your modifications here
}
```