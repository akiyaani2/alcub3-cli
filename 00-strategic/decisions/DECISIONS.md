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

## 2025-01-12: Customer-Centric Security Profiles
**Why**: Single security configuration too rigid. Enterprise needs speed, federal needs compliance, classified needs maximum security. ~70% of potential customers over-secured with one-size-fits-all approach.
**Trade-off**: More complex initial setup, but 10x improvement in development velocity and right-sized security per customer segment.

## 2025-01-12: MAESTRO as Universal Security Orchestrator
**Why**: Security tools proliferation creates integration complexity. Need unified orchestration layer that scales with customer needs, not separate systems per security level.
**Trade-off**: Single point of coordination risk, but massive simplification of security management and consistent API across all profiles.

## 2025-01-12: Homomorphic Encryption as Optional Feature
**Why**: 100-1000x performance penalty unacceptable for 95% of use cases. Only needed for computing on encrypted data in untrusted environments. Most customers choose trusted compute instead.
**Trade-off**: Reduced default capabilities, but massive performance improvement for majority of deployments.

## 2025-01-12: Strategic OSS Integration Strategy
**Why**: Build vs buy analysis showed 2+ year advantage integrating best-in-class OSS. K-Scale for simulation, Cosmos for physics AI, Open-RMF for fleet management saves thousands of dev hours.
**Trade-off**: External dependency management complexity, but 10x faster time-to-market with proven, tested components.

## 2025-01-12: Air-Gap First Architecture
**Why**: Defense customers require 30+ day offline operation. Internet connectivity assumptions break in contested environments. Competitive differentiator for federal market worth $50B+.
**Trade-off**: Complex state synchronization and larger deployment packages, but opens entire federal market and enables true resilience.

## Template for new decisions:
## YYYY-MM-DD: [Decision]
**Why**: [1-2 sentences on the problem/need]
**Trade-off**: [What we gain vs what we sacrifice]