"""
MAESTRO Audit Logger - Defense-Grade Security Event Logging
Patent-Pending Classification-Aware Audit Trail System

This module implements comprehensive audit logging for air-gapped defense AI operations,
with automatic classification inheritance and STIG-compliant audit trail generation.

Key Features:
- Classification-aware logging with automatic sanitization
- STIG-compliant audit trail format (ASD STIG V5R1)
- Real-time security event correlation
- Air-gapped operation with local storage
- Cryptographic audit log integrity

Compliance:
- FISMA SP 800-171 Audit and Accountability
- STIG ASD V5R1 Category II Audit Controls
- NIST 800-53 AU Family Controls
"""

import json
import time
import hashlib
import hmac
import threading
import queue
import re
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from pathlib import Path
from collections import deque

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class AuditEventType(Enum):
    """Types of security events for audit logging."""
    AUTHENTICATION = "auth"
    AUTHORIZATION = "authz" 
    DATA_ACCESS = "data_access"
    CLASSIFICATION_EVENT = "classification"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_EVENT = "system"
    THREAT_DETECTION = "threat_detection"
    COMPLIANCE_CHECK = "compliance"

class AuditSeverity(Enum):
    """Audit event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AuditEvent:
    """Structured audit event for defense operations."""
    event_id: str
    timestamp: float
    event_type: AuditEventType
    severity: AuditSeverity
    classification_level: str
    source_component: str
    description: str
    details: Dict[str, Any]
    user_context: Optional[Dict] = None
    outcome: str = "success"
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    
    def to_stig_format(self) -> str:
        """Convert to STIG-compliant audit format."""
        # STIG format: timestamp|event_type|severity|source|description|outcome
        return f"{self.timestamp}|{self.event_type.value}|{self.severity.value}|{self.source_component}|{self.description}|{self.outcome}"

class AuditLogger:
    """
    Patent-Pending Classification-Aware Audit System
    
    This class implements comprehensive audit logging for MAESTRO security framework
    with patent-pending innovations for classification-aware audit trails and
    real-time security event correlation in air-gapped environments.
    """
    
    def __init__(self, classification_system, audit_dir: str = "./audit_logs", async_logging: bool = True):
        """Initialize audit logging system.
        
        Args:
            classification_system: SecurityClassification instance
            audit_dir: Directory for audit log storage
            async_logging: Enable asynchronous logging for performance
        """
        self.classification = classification_system
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(exist_ok=True)
        self.async_logging = async_logging
        
        # Thread safety components
        self._events_lock = threading.RLock()
        self._state_lock = threading.RLock()
        
        # Asynchronous logging setup
        if async_logging:
            self._log_queue = queue.Queue()
            self._logging_thread = None
            self._shutdown_event = threading.Event()
            self._start_async_logging()
        
        # Initialize audit components
        self._initialize_audit_integrity()
        self._initialize_classification_sanitizer()
        self._initialize_event_correlator()
        
        # Patent Innovation: Classification-aware audit state
        self._audit_state = {
            "total_events": 0,
            "security_events": 0,
            "classification_violations": 0,
            "last_integrity_check": time.time(),
            "integrity_mode": "enabled" if CRYPTO_AVAILABLE else "disabled"
        }
        
        self.logger = logging.getLogger(f"alcub3.audit.{self.classification.default_level.value}")
        self.logger.info(f"MAESTRO Audit Logger initialized (integrity: {self._audit_state['integrity_mode']}, async: {async_logging})")
    
    def _initialize_audit_integrity(self):
        """Initialize cryptographic audit log integrity."""
        if CRYPTO_AVAILABLE:
            # Generate audit integrity key
            password = b"alcub3_audit_integrity_key"
            salt = b"maestro_audit_salt"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            self._integrity_key = kdf.derive(password)
        else:
            self._integrity_key = None
            self.logger.warning("Cryptographic audit integrity disabled")
    
    def _initialize_classification_sanitizer(self):
        """Initialize classification-aware log sanitization."""
        # Patent Innovation: Automatic classification sanitization patterns
        self._sanitization_patterns = {
            "SECRET": {
                "replace_patterns": [
                    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN-REDACTED]"),  # SSN
                    (r"\b[A-Z]{2}\d{8}\b", "[ID-REDACTED]"),         # Military ID
                    (r"password[\s]*[:=][\s]*\S+", "password=[REDACTED]"),
                ],
                "classification_markers": ["SECRET", "CONFIDENTIAL", "CLASSIFIED"]
            },
            "TOP_SECRET": {
                "replace_patterns": [
                    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED]"),
                    (r"\b[A-Z0-9]{8,}\b", "[REDACTED]"),
                    (r"\S+@\S+\.\S+", "[EMAIL-REDACTED]"),
                ],
                "classification_markers": ["TOP SECRET", "TS", "CODEWORD"]
            }
        }
    
    def _initialize_event_correlator(self):
        """Initialize thread-safe real-time security event correlation."""
        # Patent Innovation: Real-time threat pattern correlation
        self._correlation_window = 300  # 5 minutes
        self._recent_events = deque(maxlen=1000)  # Thread-safe deque with size limit
        self._threat_patterns = {
            "authentication_failure_burst": {
                "event_type": AuditEventType.AUTHENTICATION,
                "threshold": 5,
                "timeframe": 60
            },
            "classification_violation_pattern": {
                "event_type": AuditEventType.CLASSIFICATION_EVENT,
                "threshold": 3,
                "timeframe": 300
            },
            "security_violation_sequence": {
                "event_type": AuditEventType.SECURITY_VIOLATION,
                "threshold": 2,
                "timeframe": 180
            }
        }
    
    def log_security_event(self, event_type: AuditEventType, severity: AuditSeverity,
                          source: str, description: str, details: Dict = None,
                          user_context: Dict = None, outcome: str = "success") -> str:
        """
        Log a security event with classification-aware processing.
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            source: Source component or module
            description: Event description
            details: Additional event details
            user_context: User context information
            outcome: Event outcome (success/failure/error)
            
        Returns:
            str: Unique event ID
        """
        # Generate unique event ID
        event_id = self._generate_event_id()
        
        # Create audit event
        event = AuditEvent(
            event_id=event_id,
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            classification_level=self.classification.default_level.value,
            source_component=source,
            description=description,
            details=details or {},
            user_context=user_context,
            outcome=outcome
        )
        
        # Apply classification-aware sanitization
        sanitized_event = self._sanitize_event(event)
        
        # Write to audit log
        self._write_audit_event(sanitized_event)
        
        # Update audit state with thread safety
        with self._state_lock:
            self._audit_state["total_events"] += 1
            if event_type in [AuditEventType.SECURITY_VIOLATION, AuditEventType.THREAT_DETECTION]:
                self._audit_state["security_events"] += 1
            if event_type == AuditEventType.CLASSIFICATION_EVENT:
                self._audit_state["classification_violations"] += 1
        
        # Perform real-time correlation (but not for threat detection events to avoid recursion)
        if event_type != AuditEventType.THREAT_DETECTION:
            self._correlate_event(sanitized_event)
        
        # Log to system logger based on severity
        if severity == AuditSeverity.CRITICAL:
            self.logger.critical(f"AUDIT: {description} [{event_id}]")
        elif severity == AuditSeverity.HIGH:
            self.logger.error(f"AUDIT: {description} [{event_id}]")
        elif severity == AuditSeverity.MEDIUM:
            self.logger.warning(f"AUDIT: {description} [{event_id}]")
        else:
            self.logger.info(f"AUDIT: {description} [{event_id}]")
        
        return event_id
    
    def _start_async_logging(self):
        """Start asynchronous logging thread."""
        def logging_worker():
            while not self._shutdown_event.is_set():
                try:
                    # Get event from queue with timeout
                    event_data = self._log_queue.get(timeout=1.0)
                    if event_data is None:  # Shutdown signal
                        break
                    
                    # Write event to file
                    self._write_audit_event_sync(event_data)
                    self._log_queue.task_done()
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    self.logger.error(f"Async logging error: {e}")
        
        self._logging_thread = threading.Thread(target=logging_worker, daemon=True)
        self._logging_thread.start()
    
    def _generate_event_id(self) -> str:
        """Generate unique audit event ID."""
        timestamp = str(int(time.time() * 1000000))  # Microseconds
        classification = self.classification.default_level.value
        hash_input = f"{timestamp}:{classification}:{self._audit_state['total_events']}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _sanitize_event(self, event: AuditEvent) -> AuditEvent:
        """Apply classification-aware sanitization to audit event."""
        # Patent Innovation: Automatic classification-based sanitization
        classification_level = event.classification_level
        
        if classification_level in self._sanitization_patterns:
            patterns = self._sanitization_patterns[classification_level]
            
            # Sanitize description
            sanitized_description = event.description
            for pattern, replacement in patterns["replace_patterns"]:
                sanitized_description = re.sub(pattern, replacement, sanitized_description)
            
            # Sanitize details
            sanitized_details = self._sanitize_dict(event.details, patterns["replace_patterns"])
            
            # Create sanitized event
            return AuditEvent(
                event_id=event.event_id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                severity=event.severity,
                classification_level=event.classification_level,
                source_component=event.source_component,
                description=sanitized_description,
                details=sanitized_details,
                user_context=event.user_context,
                outcome=event.outcome
            )
        
        return event
    
    def _sanitize_dict(self, data: Dict, patterns: List) -> Dict:
        """Recursively sanitize dictionary data including nested structures."""
        if not data:
            return data
            
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized_value = value
                for pattern, replacement in patterns:
                    sanitized_value = re.sub(pattern, replacement, sanitized_value)
                sanitized[key] = sanitized_value
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value, patterns)
            elif isinstance(value, list):
                sanitized[key] = self._sanitize_list(value, patterns)
            elif isinstance(value, (int, float, bool)):
                sanitized[key] = value
            else:
                # Convert other types to string and sanitize
                str_value = str(value)
                for pattern, replacement in patterns:
                    str_value = re.sub(pattern, replacement, str_value)
                sanitized[key] = str_value
        
        return sanitized
    
    def _sanitize_list(self, data: List, patterns: List) -> List:
        """Recursively sanitize list data including nested structures."""
        sanitized = []
        for item in data:
            if isinstance(item, str):
                sanitized_item = item
                for pattern, replacement in patterns:
                    sanitized_item = re.sub(pattern, replacement, sanitized_item)
                sanitized.append(sanitized_item)
            elif isinstance(item, dict):
                sanitized.append(self._sanitize_dict(item, patterns))
            elif isinstance(item, list):
                sanitized.append(self._sanitize_list(item, patterns))
            else:
                sanitized.append(item)
        
        return sanitized
    
    def _write_audit_event(self, event: AuditEvent):
        """Write audit event to persistent storage (with async support)."""
        if self.async_logging:
            # Queue event for asynchronous writing
            try:
                self._log_queue.put(event, timeout=1.0)
            except queue.Full:
                self.logger.error("Audit log queue full, writing synchronously")
                self._write_audit_event_sync(event)
        else:
            # Write synchronously
            self._write_audit_event_sync(event)
    
    def _write_audit_event_sync(self, event: AuditEvent):
        """Write audit event to persistent storage synchronously."""
        # Determine audit file based on classification and date
        date_str = time.strftime("%Y%m%d", time.localtime(event.timestamp))
        classification = event.classification_level.lower()
        audit_file = self.audit_dir / f"alcub3_audit_{classification}_{date_str}.log"
        
        try:
            # Prepare audit record with proper enum serialization
            event_dict = asdict(event)
            # Convert enums to strings for JSON serialization
            event_dict["event_type"] = event.event_type.value
            event_dict["severity"] = event.severity.value
            
            audit_record = {
                "event": event_dict,
                "stig_format": event.to_stig_format(),
                "integrity_hash": self._calculate_integrity_hash(event),
                "integrity_status": self._audit_state["integrity_mode"]
            }
            
            # Write to audit file
            with open(audit_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(audit_record, sort_keys=True) + "\n")
                
        except Exception as e:
            self.logger.error(f"Failed to write audit event: {e}")
    
    def _calculate_integrity_hash(self, event: AuditEvent) -> str:
        """Calculate cryptographic integrity hash for audit event."""
        if not self._integrity_key:
            return "integrity_disabled"
        
        # Create consistent hash input using JSON serialization
        hash_data = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "classification_level": event.classification_level,
            "source_component": event.source_component,
            "description": event.description,
            "outcome": event.outcome
        }
        
        # Serialize with consistent ordering
        hash_input = json.dumps(hash_data, sort_keys=True, separators=(',', ':'))
        
        # Calculate HMAC for integrity
        return hmac.new(
            self._integrity_key,
            hash_input.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def _correlate_event(self, event: AuditEvent):
        """Perform thread-safe real-time security event correlation."""
        with self._events_lock:
            # Add to recent events (thread-safe deque)
            self._recent_events.append(event)
            
            # Clean old events outside correlation window
            current_time = time.time()
            while (self._recent_events and 
                   current_time - self._recent_events[0].timestamp > self._correlation_window):
                self._recent_events.popleft()
        
        # Check for threat patterns
        self._check_threat_patterns()
    
    def _check_threat_patterns(self):
        """Check for known threat patterns in recent events with thread safety."""
        current_time = time.time()
        
        with self._events_lock:
            # Create snapshot of recent events to avoid holding lock too long
            recent_events_snapshot = list(self._recent_events)
        
        for pattern_name, pattern_config in self._threat_patterns.items():
            # Find matching events in timeframe
            matching_events = [
                e for e in recent_events_snapshot
                if (e.event_type == pattern_config["event_type"] and
                    current_time - e.timestamp <= pattern_config["timeframe"])
            ]
            
            # Check if threshold exceeded
            if len(matching_events) >= pattern_config["threshold"]:
                # Generate correlation ID for related events
                correlation_id = self._generate_correlation_id(pattern_name, matching_events)
                
                self.log_security_event(
                    AuditEventType.THREAT_DETECTION,
                    AuditSeverity.HIGH,
                    "audit_correlator",
                    f"Threat pattern detected: {pattern_name}",
                    {
                        "pattern": pattern_name,
                        "event_count": len(matching_events),
                        "threshold": pattern_config["threshold"],
                        "timeframe": pattern_config["timeframe"],
                        "correlation_id": correlation_id,
                        "related_events": [e.event_id for e in matching_events]
                    }
                )
    
    def _generate_correlation_id(self, pattern_name: str, events: List[AuditEvent]) -> str:
        """Generate correlation ID for related events."""
        event_ids = sorted([e.event_id for e in events])
        event_ids_joined = "-".join(event_ids)
        correlation_input = f"{pattern_name}:{event_ids_joined}"
        return hashlib.sha256(correlation_input.encode()).hexdigest()[:12]
    
    def get_audit_metrics(self) -> Dict:
        """Get comprehensive audit metrics with thread safety."""
        with self._state_lock:
            with self._events_lock:
                return {
                    "total_events": self._audit_state["total_events"],
                    "security_events": self._audit_state["security_events"],
                    "classification_violations": self._audit_state["classification_violations"],
                    "recent_event_count": len(self._recent_events),
                    "last_integrity_check": self._audit_state["last_integrity_check"],
                    "crypto_available": CRYPTO_AVAILABLE,
                    "integrity_mode": self._audit_state["integrity_mode"],
                    "async_logging": self.async_logging,
                    "classification_level": self.classification.default_level.value,
                    "queue_size": self._log_queue.qsize() if self.async_logging else 0
                }
    
    def validate_audit_integrity(self, audit_file: str = None) -> Dict:
        """Validate audit log integrity using cryptographic verification."""
        if not self._integrity_key:
            return {"status": "disabled", "reason": "cryptographic_integrity_disabled"}
        
        verified_events = 0
        integrity_violations = 0
        
        try:
            # Determine which file to validate
            if audit_file:
                files_to_check = [Path(audit_file)]
            else:
                # Check all audit files for current classification
                classification = self.classification.default_level.value.lower()
                files_to_check = list(self.audit_dir.glob(f"alcub3_audit_{classification}_*.log"))
            
            for file_path in files_to_check:
                if not file_path.exists():
                    continue
                    
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            audit_record = json.loads(line.strip())
                            event_data = audit_record['event']
                            stored_hash = audit_record['integrity_hash']
                            
                            if stored_hash == "integrity_disabled":
                                continue
                            
                            # Recreate event and calculate hash
                            # Convert string values back to enums for validation
                            event_data_copy = event_data.copy()
                            event_data_copy["event_type"] = AuditEventType(event_data["event_type"])
                            event_data_copy["severity"] = AuditSeverity(event_data["severity"])
                            
                            event = AuditEvent(**event_data_copy)
                            calculated_hash = self._calculate_integrity_hash(event)
                            
                            if calculated_hash == stored_hash:
                                verified_events += 1
                            else:
                                integrity_violations += 1
                                
                        except (json.JSONDecodeError, KeyError) as e:
                            integrity_violations += 1
            
            return {
                "status": "valid" if integrity_violations == 0 else "violations_detected",
                "verified_events": verified_events,
                "integrity_violations": integrity_violations,
                "files_checked": len(files_to_check)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "reason": str(e),
                "verified_events": verified_events,
                "integrity_violations": integrity_violations
            }
    
    def shutdown(self):
        """Gracefully shutdown audit logger and async components."""
        if self.async_logging and self._logging_thread:
            # Signal shutdown
            self._shutdown_event.set()
            
            # Send shutdown signal to queue
            try:
                self._log_queue.put(None, timeout=1.0)
            except queue.Full:
                pass
            
            # Wait for thread to finish
            self._logging_thread.join(timeout=5.0)
            
        self.logger.info("MAESTRO Audit Logger shutdown complete")
