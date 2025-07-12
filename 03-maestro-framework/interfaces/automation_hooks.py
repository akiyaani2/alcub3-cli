#!/usr/bin/env python3
"""
Security Framework Automation Hooks
===================================

Hooks for developer automation tools to integrate with security framework.
This module defines the contracts and callbacks that automation tools can
use while maintaining security boundaries.

Key Principles:
- Security policies always take precedence
- All automation must be auditable
- Fail-secure defaults
- No direct access to security internals

Classification: Unclassified//For Official Use Only
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum
import hashlib
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AutomationEventType(Enum):
    """Types of automation events that can trigger security actions."""
    PRE_COMMIT = "pre_commit"
    POST_COMMIT = "post_commit"
    PRE_PUSH = "pre_push"
    TASK_COMPLETE = "task_complete"
    BUILD_START = "build_start"
    BUILD_COMPLETE = "build_complete"
    DEPLOY_START = "deploy_start"
    DEPLOY_COMPLETE = "deploy_complete"


class SecurityPolicy(Enum):
    """Security policies that can be enforced."""
    BLOCK = "block"          # Block the operation
    WARN = "warn"            # Warn but allow
    AUDIT = "audit"          # Audit and allow
    ALLOW = "allow"          # Allow without action


class AutomationHookInterface(ABC):
    """Abstract interface for automation hooks."""
    
    @abstractmethod
    def validate_event(
        self,
        event_type: AutomationEventType,
        context: Dict[str, Any]
    ) -> Tuple[SecurityPolicy, Optional[str]]:
        """
        Validate an automation event against security policies.
        
        Args:
            event_type: Type of automation event
            context: Event context and metadata
            
        Returns:
            Tuple of (policy decision, optional message)
        """
        pass
    
    @abstractmethod
    def register_callback(
        self,
        event_type: AutomationEventType,
        callback: Callable
    ) -> bool:
        """
        Register a callback for security events.
        
        Args:
            event_type: Event type to register for
            callback: Callback function
            
        Returns:
            bool: True if registration successful
        """
        pass


class SecurityAutomationHooks(AutomationHookInterface):
    """
    Implementation of automation hooks for the security framework.
    
    This class manages the interaction between developer automation
    and security policies.
    """
    
    def __init__(self):
        """Initialize the automation hooks."""
        self._callbacks: Dict[AutomationEventType, List[Callable]] = {}
        self._policy_cache: Dict[str, SecurityPolicy] = {}
        self._audit_log = []
        
    def validate_event(
        self,
        event_type: AutomationEventType,
        context: Dict[str, Any]
    ) -> Tuple[SecurityPolicy, Optional[str]]:
        """
        Validate an automation event against security policies.
        
        Args:
            event_type: Type of automation event
            context: Event context and metadata
            
        Returns:
            Tuple of (policy decision, optional message)
        """
        try:
            # Generate event hash for caching
            event_hash = self._generate_event_hash(event_type, context)
            
            # Check cache first
            if event_hash in self._policy_cache:
                policy = self._policy_cache[event_hash]
                logger.debug(f"Using cached policy {policy} for event {event_type}")
                return policy, None
            
            # Evaluate security policies
            policy, message = self._evaluate_policies(event_type, context)
            
            # Cache the decision
            self._policy_cache[event_hash] = policy
            
            # Audit the event
            self._audit_event(event_type, context, policy, message)
            
            # Trigger callbacks
            self._trigger_callbacks(event_type, context, policy)
            
            return policy, message
            
        except Exception as e:
            logger.error(f"Error validating event: {e}")
            # Fail secure - block on error
            return SecurityPolicy.BLOCK, f"Security validation error: {str(e)}"
    
    def register_callback(
        self,
        event_type: AutomationEventType,
        callback: Callable
    ) -> bool:
        """
        Register a callback for security events.
        
        Args:
            event_type: Event type to register for
            callback: Callback function
            
        Returns:
            bool: True if registration successful
        """
        try:
            if event_type not in self._callbacks:
                self._callbacks[event_type] = []
            
            self._callbacks[event_type].append(callback)
            logger.info(f"Registered callback for {event_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register callback: {e}")
            return False
    
    def _generate_event_hash(
        self,
        event_type: AutomationEventType,
        context: Dict[str, Any]
    ) -> str:
        """Generate a hash for event caching."""
        event_data = {
            'type': event_type.value,
            'context': context
        }
        event_json = json.dumps(event_data, sort_keys=True)
        return hashlib.sha256(event_json.encode()).hexdigest()
    
    def _evaluate_policies(
        self,
        event_type: AutomationEventType,
        context: Dict[str, Any]
    ) -> Tuple[SecurityPolicy, Optional[str]]:
        """Evaluate security policies for the event."""
        # Default policies by event type
        default_policies = {
            AutomationEventType.PRE_COMMIT: SecurityPolicy.AUDIT,
            AutomationEventType.POST_COMMIT: SecurityPolicy.ALLOW,
            AutomationEventType.PRE_PUSH: SecurityPolicy.WARN,
            AutomationEventType.TASK_COMPLETE: SecurityPolicy.AUDIT,
            AutomationEventType.BUILD_START: SecurityPolicy.ALLOW,
            AutomationEventType.BUILD_COMPLETE: SecurityPolicy.AUDIT,
            AutomationEventType.DEPLOY_START: SecurityPolicy.BLOCK,
            AutomationEventType.DEPLOY_COMPLETE: SecurityPolicy.AUDIT,
        }
        
        # Get default policy
        policy = default_policies.get(event_type, SecurityPolicy.BLOCK)
        
        # Check for security-sensitive patterns
        if self._contains_security_changes(context):
            if event_type in [AutomationEventType.PRE_PUSH, AutomationEventType.DEPLOY_START]:
                return SecurityPolicy.BLOCK, "Security changes require manual review"
            else:
                return SecurityPolicy.WARN, "Security changes detected"
        
        # Check for classified data
        if self._contains_classified_data(context):
            return SecurityPolicy.BLOCK, "Classified data detected"
        
        return policy, None
    
    def _contains_security_changes(self, context: Dict[str, Any]) -> bool:
        """Check if context contains security-related changes."""
        security_patterns = [
            'security-framework',
            'crypto',
            'auth',
            'key',
            'secret',
            'password',
            'certificate'
        ]
        
        context_str = json.dumps(context).lower()
        return any(pattern in context_str for pattern in security_patterns)
    
    def _contains_classified_data(self, context: Dict[str, Any]) -> bool:
        """Check if context contains classified data markers."""
        classification_markers = [
            'classified',
            'secret',
            'top secret',
            'sci',
            'noforn'
        ]
        
        context_str = json.dumps(context).lower()
        return any(marker in context_str for marker in classification_markers)
    
    def _audit_event(
        self,
        event_type: AutomationEventType,
        context: Dict[str, Any],
        policy: SecurityPolicy,
        message: Optional[str]
    ):
        """Audit the automation event."""
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type.value,
            'policy': policy.value,
            'message': message,
            'context_summary': self._summarize_context(context)
        }
        
        self._audit_log.append(audit_entry)
        logger.info(f"Audit: {event_type.value} -> {policy.value}")
    
    def _summarize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of context for audit logging."""
        summary = {}
        
        # Extract key information
        if 'files' in context:
            summary['file_count'] = len(context['files'])
            summary['file_types'] = list(set(
                f.split('.')[-1] for f in context['files'] if '.' in f
            ))
        
        if 'user' in context:
            summary['user'] = context['user']
        
        if 'commit_message' in context:
            summary['commit_message'] = context['commit_message'][:100]
        
        return summary
    
    def _trigger_callbacks(
        self,
        event_type: AutomationEventType,
        context: Dict[str, Any],
        policy: SecurityPolicy
    ):
        """Trigger registered callbacks for the event."""
        if event_type in self._callbacks:
            for callback in self._callbacks[event_type]:
                try:
                    callback(event_type, context, policy)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
    
    def get_audit_log(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit log entries.
        
        Args:
            start_time: Optional start time filter
            end_time: Optional end time filter
            
        Returns:
            List of audit entries
        """
        if not start_time and not end_time:
            return self._audit_log.copy()
        
        filtered_log = []
        for entry in self._audit_log:
            entry_time = datetime.fromisoformat(entry['timestamp'])
            
            if start_time and entry_time < start_time:
                continue
            if end_time and entry_time > end_time:
                continue
                
            filtered_log.append(entry)
        
        return filtered_log


# Singleton instance
_automation_hooks = None


def get_automation_hooks() -> SecurityAutomationHooks:
    """Get or create the automation hooks instance."""
    global _automation_hooks
    if _automation_hooks is None:
        _automation_hooks = SecurityAutomationHooks()
    return _automation_hooks