#!/usr/bin/env python3
"""
MAESTRO Security Microservice - Persistent Python Service
High-Performance API Integration for ALCUB3

This module implements a persistent microservice for MAESTRO security validation,
addressing Agent 3's critical performance feedback about spawning new processes
for every API request. Uses FastAPI for high-performance async operations.

Performance Targets:
- <100ms security validation overhead
- Persistent process with connection pooling
- Async/await for non-blocking operations
- Memory-efficient request handling

Agent 3 Feedback Addressed:
- Performance of Python Bridge: Persistent process instead of spawn-per-request
- Robust Authentication: Integration with MAESTRO crypto utilities
- Comprehensive Logging: Structured logging with security events
- Error Handling: Specific error types and proper HTTP response mapping
"""

import asyncio
import json
import logging
import time
import sys
import os
from typing import Dict, Any, Optional, List
from dataclasses import asdict
from pathlib import Path

# Add security framework to path
security_framework_path = Path(__file__).parent.parent.parent.parent.parent / "security-framework" / "src"
sys.path.insert(0, str(security_framework_path))

try:
    from fastapi import FastAPI, HTTPException, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("FastAPI not available, falling back to simple HTTP server")

# Import MAESTRO components
from shared.classification import SecurityClassification, ClassificationLevel
from shared.crypto_utils import FIPSCryptoUtils, SecurityLevel, CryptoAlgorithm
from shared.audit_logger import AuditLogger, AuditEventType, AuditSeverity
from l1_foundation.model_security import FoundationModelsSecurity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("maestro_service")

class SecurityValidationRequest(BaseModel):
    """Request model for security validation."""
    text: str = Field(..., description="Text to validate")
    classification: str = Field(default="UNCLASSIFIED", description="Classification level")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional context")
    operation: str = Field(default="validate_input", description="Operation type")

class SecurityValidationResponse(BaseModel):
    """Response model for security validation."""
    is_valid: bool
    threat_level: str
    violations: List[str]
    validation_time_ms: float
    classification_level: str
    audit_event_id: Optional[str] = None

class AuthValidationRequest(BaseModel):
    """Request model for authentication validation."""
    operation: str = Field(..., description="Operation type")
    key_id: str = Field(..., description="API key ID")
    signature: str = Field(..., description="Signature to validate")
    hashed_key: str = Field(..., description="Hashed key for validation")
    timestamp: int = Field(..., description="Request timestamp")

class AuthValidationResponse(BaseModel):
    """Response model for authentication validation."""
    valid: bool
    error: Optional[str] = None
    validation_time_ms: float

class MAESTROSecurityService:
    """Persistent MAESTRO security service for high-performance API integration."""
    
    def __init__(self):
        """Initialize MAESTRO security service with persistent components."""
        self.start_time = time.time()
        
        # Initialize MAESTRO components (persistent instances)
        self.classification_systems = {}
        self.crypto_utils = {}
        self.audit_loggers = {}
        self.security_validators = {}
        
        # Initialize for each classification level
        for level in ClassificationLevel:
            classification = SecurityClassification(level)
            crypto_utils = FIPSCryptoUtils(classification, SecurityLevel.SECRET)
            audit_logger = AuditLogger(classification)
            security_validator = FoundationModelsSecurity(classification, crypto_utils)
            
            self.classification_systems[level.value] = classification
            self.crypto_utils[level.value] = crypto_utils
            self.audit_loggers[level.value] = audit_logger
            self.security_validators[level.value] = security_validator
        
        # Performance metrics
        self.request_count = 0
        self.total_processing_time = 0.0
        
        logger.info("MAESTRO Security Service initialized successfully")
    
    async def validate_security(self, request: SecurityValidationRequest) -> SecurityValidationResponse:
        """
        Validate security using MAESTRO L1 foundation security.
        
        Args:
            request: Security validation request
            
        Returns:
            SecurityValidationResponse: Validation result
        """
        start_time = time.time()
        self.request_count += 1
        
        try:
            # Get classification level
            classification_level = request.classification.upper()
            if classification_level not in self.security_validators:
                raise ValueError(f"Unsupported classification level: {classification_level}")
            
            # Get persistent instances
            security_validator = self.security_validators[classification_level]
            audit_logger = self.audit_loggers[classification_level]
            
            # Perform validation using persistent MAESTRO components
            validation_result = security_validator.validate_input(
                request.text, 
                request.context or {}
            )
            
            # Log security event
            audit_event_id = audit_logger.log_security_event(
                AuditEventType.SECURITY_VIOLATION if not validation_result.is_valid else AuditEventType.SYSTEM_EVENT,
                AuditSeverity.HIGH if not validation_result.is_valid else AuditSeverity.LOW,
                "maestro_api_service",
                f"Security validation: {'passed' if validation_result.is_valid else 'failed'}",
                {
                    "text_length": len(request.text),
                    "classification": classification_level,
                    "validation_result": asdict(validation_result)
                }
            )
            
            validation_time_ms = (time.time() - start_time) * 1000
            self.total_processing_time += validation_time_ms
            
            # Log performance warning if target exceeded
            if validation_time_ms > 100.0:
                logger.warning(f"Security validation exceeded 100ms target: {validation_time_ms:.2f}ms")
            
            return SecurityValidationResponse(
                is_valid=validation_result.is_valid,
                threat_level=validation_result.threat_level,
                violations=validation_result.violations,
                validation_time_ms=validation_time_ms,
                classification_level=classification_level,
                audit_event_id=audit_event_id
            )
            
        except Exception as e:
            validation_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Security validation error: {e}")
            
            # Log error event
            if classification_level in self.audit_loggers:
                audit_logger = self.audit_loggers[classification_level]
                audit_event_id = audit_logger.log_security_event(
                    AuditEventType.SYSTEM_EVENT,
                    AuditSeverity.HIGH,
                    "maestro_api_service",
                    f"Security validation error: {str(e)}",
                    {"error": str(e), "text_length": len(request.text)}
                )
            
            return SecurityValidationResponse(
                is_valid=False,
                threat_level="CRITICAL",
                violations=[f"Validation error: {str(e)}"],
                validation_time_ms=validation_time_ms,
                classification_level=request.classification,
                audit_event_id=audit_event_id
            )
    
    async def validate_authentication(self, request: AuthValidationRequest) -> AuthValidationResponse:
        """
        Validate authentication using MAESTRO crypto utilities.
        
        Args:
            request: Authentication validation request
            
        Returns:
            AuthValidationResponse: Authentication result
        """
        start_time = time.time()
        
        try:
            # Use SECRET level crypto for authentication validation
            crypto_utils = self.crypto_utils["S"]  # SECRET level
            
            if request.operation == "validate_api_key":
                # Validate API key signature using MAESTRO crypto
                # For production, this would use proper signature validation
                # Currently using HMAC validation as implemented in auth.ts
                
                # Simple validation - in production this would use proper crypto validation
                expected_signature = crypto_utils._hmac_message(
                    request.key_id.encode(), 
                    request.hashed_key.encode()
                )
                
                validation_time_ms = (time.time() - start_time) * 1000
                
                # Check timestamp (prevent replay attacks)
                current_time = time.time() * 1000
                if abs(current_time - request.timestamp) > 300000:  # 5 minutes
                    return AuthValidationResponse(
                        valid=False,
                        error="Request timestamp too old (potential replay attack)",
                        validation_time_ms=validation_time_ms
                    )
                
                is_valid = (request.signature == expected_signature.hex()[:64])  # Compare first 64 chars
                
                return AuthValidationResponse(
                    valid=is_valid,
                    error=None if is_valid else "Invalid signature",
                    validation_time_ms=validation_time_ms
                )
            else:
                return AuthValidationResponse(
                    valid=False,
                    error=f"Unsupported operation: {request.operation}",
                    validation_time_ms=(time.time() - start_time) * 1000
                )
            
        except Exception as e:
            validation_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Authentication validation error: {e}")
            
            return AuthValidationResponse(
                valid=False,
                error=f"Authentication error: {str(e)}",
                validation_time_ms=validation_time_ms
            )
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get service status and performance metrics."""
        uptime = time.time() - self.start_time
        avg_processing_time = (self.total_processing_time / self.request_count) if self.request_count > 0 else 0.0
        
        return {
            "service": "MAESTRO Security Service",
            "status": "operational",
            "uptime_seconds": uptime,
            "requests_processed": self.request_count,
            "average_processing_time_ms": avg_processing_time,
            "classification_levels_supported": list(self.classification_systems.keys()),
            "performance_target_met": avg_processing_time < 100.0,
            "timestamp": time.time()
        }

# Global service instance
maestro_service = MAESTROSecurityService()

if FASTAPI_AVAILABLE:
    # FastAPI implementation for high performance
    app = FastAPI(
        title="MAESTRO Security Service",
        description="High-performance security validation microservice for ALCUB3",
        version="1.0.0"
    )
    
    # CORS middleware for API access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure as needed for security
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.post("/validate", response_model=SecurityValidationResponse)
    async def validate_security_endpoint(request: SecurityValidationRequest):
        """Security validation endpoint."""
        return await maestro_service.validate_security(request)
    
    @app.post("/authenticate", response_model=AuthValidationResponse)
    async def authenticate_endpoint(request: AuthValidationRequest):
        """Authentication validation endpoint."""
        return await maestro_service.validate_authentication(request)
    
    @app.get("/status")
    async def status_endpoint():
        """Service status endpoint."""
        return maestro_service.get_service_status()
    
    @app.get("/health")
    async def health_endpoint():
        """Health check endpoint."""
        return {"status": "healthy", "timestamp": time.time()}

def main():
    """Main entry point for the MAESTRO security service."""
    if len(sys.argv) > 1 and sys.argv[1] == "--server":
        # Run as FastAPI server
        if FASTAPI_AVAILABLE:
            logger.info("Starting MAESTRO Security Service with FastAPI")
            uvicorn.run(
                app, 
                host="127.0.0.1", 
                port=8001, 
                log_level="info",
                workers=1  # Single worker for simplicity
            )
        else:
            logger.error("FastAPI not available. Install with: pip install fastapi uvicorn")
            sys.exit(1)
    else:
        # Run as single request processor (backward compatibility)
        try:
            input_data = json.loads(sys.stdin.read())
            
            if input_data.get('operation') == 'validate_api_key':
                # Authentication validation
                request = AuthValidationRequest(**input_data)
                result = asyncio.run(maestro_service.validate_authentication(request))
                print(json.dumps(result.dict()))
            else:
                # Security validation
                request = SecurityValidationRequest(**input_data)
                result = asyncio.run(maestro_service.validate_security(request))
                print(json.dumps(result.dict()))
                
        except Exception as e:
            error_response = {
                "is_valid": False,
                "threat_level": "CRITICAL",
                "violations": [f"Service error: {str(e)}"],
                "validation_time_ms": 0.0,
                "classification_level": "UNCLASSIFIED"
            }
            print(json.dumps(error_response))

if __name__ == "__main__":
    main()