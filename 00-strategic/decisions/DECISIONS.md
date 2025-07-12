# Technical Decisions

*One paragraph per decision. Focus on WHY, not HOW.*

## 2025-07-09: Monorepo Architecture
**Why**: Need atomic commits across security boundaries. Can't risk partial updates between core and security framework.
**Trade-off**: More complex build setup, but security integrity is worth it.

## 2025-07-09: TypeScript Everywhere
**Why**: Type safety critical for defense contracts. Catches errors at compile time, not in production.
**Trade-off**: Slightly slower development, but prevents runtime errors.

## 2025-07-09: Custom Crypto Implementation
**Why**: Standard libraries assume internet connectivity. Need air-gap compatible crypto.
**Trade-off**: More code to maintain, but required for offline operation.

## 2025-07-09: Forked from Google Gemini CLI
**Why**: Proven foundation with enterprise-grade architecture. Faster to enhance than build from scratch.
**Trade-off**: Need to maintain compatibility while adding defense features.

## 2025-07-09: Performance Budgets in Code
**Why**: Sub-100ms requirement is contractual. Automated enforcement prevents regression.
**Trade-off**: Additional test complexity, but ensures compliance.

## 2025-07-09: Husky for Git Hooks
**Why**: Prevent secrets and broken code from entering repository. Critical for security compliance.
**Trade-off**: Slightly slower commits, but catches issues before they spread.

## 2025-01-10: Hybrid Patent Documentation Strategy
**Why**: Need both centralized tracking for legal efficiency and distributed technical specs for developer context. Pure centralization loses implementation details, pure distribution loses oversight.
**Trade-off**: Slight documentation overhead, but ensures complete IP protection and developer clarity.

## Template for new decisions:
## YYYY-MM-DD: [Decision]
**Why**: [1-2 sentences on the problem/need]
**Trade-off**: [What we gain vs what we sacrifice]