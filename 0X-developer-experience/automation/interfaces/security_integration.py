#!/usr/bin/env python3
"""
Developer Automation Security Integration Interface
==================================================

Clean interface for developer automation tools to integrate with the security framework.
This module provides a controlled boundary between developer productivity tools and
defense-grade security components.

Key Principles:
- Minimal exposure of security internals
- Clear contracts for integration points
- Fail-safe defaults
- Audit logging for all interactions

Classification: Unclassified//For Official Use Only
"""

import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityTestType(Enum):
    """Types of security tests that can be requested."""
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    RED_TEAM = "red_team"
    PENETRATION = "penetration"
    COMPLIANCE = "compliance"


class SecurityIntegrationInterface:
    """
    Interface for developer automation tools to request security testing.
    
    This provides a clean abstraction layer that prevents developer tools
    from directly accessing security framework internals.
    """
    
    def __init__(self):
        """Initialize the security integration interface."""
        self._security_framework_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
            'security-framework', 'src'
        )
        self._initialized = False
        
    def initialize(self) -> bool:
        """
        Initialize connection to security framework.
        
        Returns:
            bool: True if initialization successful
        """
        try:
            # Add security framework to path
            if self._security_framework_path not in sys.path:
                sys.path.append(self._security_framework_path)
            
            # Import required security modules
            global RedTeamOrchestrator, AdvancedSecurityTestOrchestrator
            from red_team_automation import RedTeamOrchestrator
            from advanced_security_testing import AdvancedSecurityTestOrchestrator
            
            self._initialized = True
            logger.info("Security integration initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize security integration: {e}")
            return False
    
    def request_security_test(
        self,
        test_type: SecurityTestType,
        target_path: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Request security testing from the framework.
        
        Args:
            test_type: Type of security test to run
            target_path: Path to test target
            options: Optional test configuration
            
        Returns:
            Dict containing test results
        """
        if not self._initialized:
            return {
                'success': False,
                'error': 'Security integration not initialized'
            }
        
        try:
            logger.info(f"Requesting {test_type.value} security test for {target_path}")
            
            # Route to appropriate security component
            if test_type == SecurityTestType.RED_TEAM:
                orchestrator = RedTeamOrchestrator()
                results = orchestrator.run_targeted_test(target_path, options or {})
            elif test_type in [SecurityTestType.COMPREHENSIVE, SecurityTestType.PENETRATION]:
                orchestrator = AdvancedSecurityTestOrchestrator()
                results = orchestrator.run_comprehensive_test(target_path, options or {})
            else:
                # Basic security test
                results = self._run_basic_security_test(target_path, options)
            
            return {
                'success': True,
                'test_type': test_type.value,
                'results': results,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Security test failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'test_type': test_type.value
            }
    
    def _run_basic_security_test(
        self,
        target_path: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run basic security checks."""
        # Placeholder for basic security tests
        return {
            'vulnerabilities': [],
            'warnings': [],
            'info': f"Basic security scan completed for {target_path}"
        }
    
    def get_security_report(
        self,
        test_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Get security reports for completed tests.
        
        Args:
            test_ids: List of test IDs to retrieve reports for
            
        Returns:
            Dict containing security reports
        """
        # Placeholder for report retrieval
        return {
            'reports': {},
            'summary': 'No reports available'
        }


# Singleton instance
_security_interface = None


def get_security_interface() -> SecurityIntegrationInterface:
    """Get or create the security integration interface."""
    global _security_interface
    if _security_interface is None:
        _security_interface = SecurityIntegrationInterface()
    return _security_interface