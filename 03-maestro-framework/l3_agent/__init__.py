"""
MAESTRO Layer 3: Agent Framework Security
Air-Gapped Agent Security Implementation

This module implements MAESTRO L3 security controls for AI agent frameworks
in air-gapped defense environments.

MAESTRO L3 Threat Landscape:
- Agent Hijacking: Unauthorized control of AI agents
- Goal Manipulation: Altering agent objectives
- Privilege Escalation: Agents gaining unauthorized access
- Multi-Agent Collusion: Coordinated malicious behavior
- Agent Communication Interception: Eavesdropping on agent interactions

Patent Innovations:
- Agent behavior validation and anomaly detection
- Secure agent-to-agent communication protocols
- Real-time agent authorization and access control
"""

from .agent_security import AgentFrameworkSecurity

__all__ = ["AgentFrameworkSecurity"]
