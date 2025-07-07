"""
Security Classification Management System
Patent-Pending Classification-Aware Security Controls

This module implements automatic data classification and security inheritance
for air-gapped defense AI operations, supporting UNCLASSIFIED through TOP SECRET
classification levels with automatic inheritance and cross-domain validation.

Key Features:
- Automatic classification inheritance (Patent Innovation)
- Cross-domain security validation
- Real-time classification monitoring
- STIG-compliant classification handling

Classification Levels:
- UNCLASSIFIED (U): Public release authorized
- CUI: Controlled Unclassified Information  
- SECRET (S): National security information
- TOP SECRET (TS): Grave damage to national security

FISMA Compliance: SP 800-171 Information System Classification
STIG Compliance: ASD STIG V5R1 Data Classification Controls
"""

import time
import hashlib
import json
from typing import Dict, List, Optional, Set, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import re

class ClassificationLevel(Enum):
    """Security classification levels for defense operations."""
    UNCLASSIFIED = "U"
    CUI = "CUI" 
    SECRET = "S"
    TOP_SECRET = "TS"
    
    @property
    def numeric_level(self) -> int:
        """Get numeric representation for comparison."""
        levels = {
            "U": 1,
            "CUI": 2, 
            "S": 3,
            "TS": 4
        }
        return levels[self.value]
    
    def can_access(self, required_level: 'ClassificationLevel') -> bool:
        """Check if this classification can access required level."""
        return self.numeric_level >= required_level.numeric_level

@dataclass
class ClassificationMarking:
    """Classification marking with handling instructions."""
    level: ClassificationLevel
    compartments: Set[str]
    handling_instructions: List[str]
    originator: str
    classification_date: float
    declassification_date: Optional[float] = None
    
    def to_marking_string(self) -> str:
        """Generate standard classification marking string."""
        base = self.level.value
        if self.compartments:
            base += "//" + "//".join(sorted(self.compartments))
        if self.handling_instructions:
            base += "/" + "/".join(self.handling_instructions)
        return base

@dataclass 
class ClassificationValidationResult:
    """Result of classification validation."""
    is_valid: bool
    assigned_level: ClassificationLevel
    confidence_score: float
    violations: List[str]
    recommended_marking: ClassificationMarking

class SecurityClassification:
    """
    Patent-Pending Classification-Aware Security System
    
    This class implements automatic data classification and security inheritance
    for air-gapped AI operations, with patent-pending innovations for real-time
    classification validation and cross-domain security controls.
    """
    
    def __init__(self, default_level: Union[str, ClassificationLevel] = ClassificationLevel.UNCLASSIFIED):
        """Initialize classification system.
        
        Args:
            default_level: Default classification level for operations
        """
        if isinstance(default_level, str):
            # Handle string inputs like "UNCLASSIFIED", "SECRET", etc.
            level_map = {
                "UNCLASSIFIED": ClassificationLevel.UNCLASSIFIED,
                "U": ClassificationLevel.UNCLASSIFIED,
                "CUI": ClassificationLevel.CUI,
                "CONTROLLED_UNCLASSIFIED_INFORMATION": ClassificationLevel.CUI,
                "SECRET": ClassificationLevel.SECRET,
                "S": ClassificationLevel.SECRET,
                "TOP_SECRET": ClassificationLevel.TOP_SECRET,
                "TS": ClassificationLevel.TOP_SECRET,
            }
            self.default_level = level_map.get(default_level.upper(), ClassificationLevel.UNCLASSIFIED)
        else:
            self.default_level = default_level
            
        self.logger = logging.getLogger(f"alcub3.classification.{self.default_level.value}")
        
        # Initialize classification components
        self._initialize_classification_patterns()
        self._initialize_compartment_registry()
        self._initialize_handling_instructions()
        
        # Patent Innovation: Classification inheritance tracking
        self._classification_history = []
        self._cross_domain_validations = 0
        
        self.logger.info(f"Classification system initialized at {self.default_level.value}")
    
    def _initialize_classification_patterns(self):
        """Initialize patterns for automatic classification detection."""
        # Patent Innovation: AI-driven classification patterns
        self._classification_patterns = {
            ClassificationLevel.UNCLASSIFIED: {
                "keywords": ["public", "unclassified", "open source", "commercial"],
                "patterns": [r"public.{0,10}release", r"unclassified.{0,10}information"]
            },
            ClassificationLevel.CUI: {
                "keywords": ["cui", "fouo", "controlled", "sensitive", "proprietary"],
                "patterns": [r"controlled.{0,20}unclassified", r"for.{0,10}official.{0,10}use"]
            },
            ClassificationLevel.SECRET: {
                "keywords": ["secret", "classified", "national security", "defense"],
                "patterns": [r"secret.{0,10}information", r"national.{0,10}security"]
            },
            ClassificationLevel.TOP_SECRET: {
                "keywords": ["top secret", "ts", "compartmented", "codeword"],
                "patterns": [r"top.{0,10}secret", r"compartmented.{0,10}information"]
            }
        }
    
    def _initialize_compartment_registry(self):
        """Initialize compartment and special access program registry."""
        # Common defense compartments and SAPs
        self._valid_compartments = {
            "SI": "Special Intelligence",
            "TK": "Talent Keyhole", 
            "NOFORN": "Not Releasable to Foreign Nationals",
            "ORCON": "Originator Controlled",
            "PROPIN": "Proprietary Information Involved",
            "RSEN": "Releasable to Specific Foreign Nations",
        }
    
    def _initialize_handling_instructions(self):
        """Initialize handling instruction registry."""
        self._handling_instructions = {
            "FOUO": "For Official Use Only",
            "NOCON": "No Contractor Access",
            "NOFORN": "Not Releasable to Foreign Nationals", 
            "ORCON": "Originator Controlled",
            "PROPIN": "Proprietary Information Involved",
            "REL TO": "Releasable To"
        }
    
    def classify_content(self, content: str, context: Optional[Dict] = None) -> ClassificationValidationResult:
        """
        Automatically classify content using AI-driven analysis.
        
        Patent Innovation: Real-time classification with confidence scoring
        and automatic inheritance based on content and context analysis.
        
        Args:
            content: Content to classify
            context: Optional context information
            
        Returns:
            ClassificationValidationResult: Classification analysis results
        """
        start_time = time.time()
        violations = []
        confidence_scores = {}
        
        try:
            # Analyze content against classification patterns
            for level, patterns in self._classification_patterns.items():
                score = self._calculate_classification_score(content, patterns)
                confidence_scores[level] = score
            
            # Determine highest confidence classification
            best_level = max(confidence_scores.keys(), key=lambda k: confidence_scores[k])
            confidence = confidence_scores[best_level]
            
            # Apply context-based adjustments
            if context:
                best_level, confidence = self._apply_context_classification(
                    best_level, confidence, context
                )
            
            # Validate against current authorization level
            if not self.default_level.can_access(best_level):
                violations.append(f"insufficient_clearance_for_{best_level.value}")
            
            # Create classification marking
            marking = ClassificationMarking(
                level=best_level,
                compartments=self._detect_compartments(content),
                handling_instructions=self._detect_handling_instructions(content),
                originator="ALCUB3_CLASSIFIER",
                classification_date=time.time()
            )
            
            # Update classification history
            self._classification_history.append({
                "timestamp": time.time(),
                "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
                "assigned_level": best_level.value,
                "confidence": confidence,
                "processing_time_ms": (time.time() - start_time) * 1000
            })
            
            # Log classification event
            self._log_classification_event(content, best_level, confidence, violations)
            
            return ClassificationValidationResult(
                is_valid=len(violations) == 0,
                assigned_level=best_level,
                confidence_score=confidence,
                violations=violations,
                recommended_marking=marking
            )
            
        except Exception as e:
            self.logger.error(f"Classification analysis failed: {e}")
            return ClassificationValidationResult(
                is_valid=False,
                assigned_level=self.default_level,
                confidence_score=0.0,
                violations=["classification_error"],
                recommended_marking=ClassificationMarking(
                    level=self.default_level,
                    compartments=set(),
                    handling_instructions=["ERROR"],
                    originator="ALCUB3_CLASSIFIER",
                    classification_date=time.time()
                )
            )
    
    def _calculate_classification_score(self, content: str, patterns: Dict) -> float:
        """Calculate classification confidence score for given patterns."""
        score = 0.0
        content_lower = content.lower()
        
        # Keyword matching
        keyword_matches = sum(1 for keyword in patterns["keywords"] if keyword in content_lower)
        score += (keyword_matches / len(patterns["keywords"])) * 0.4
        
        # Pattern matching
        pattern_matches = 0
        for pattern in patterns["patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                pattern_matches += 1
        score += (pattern_matches / len(patterns["patterns"])) * 0.6
        
        return min(score, 1.0)
    
    def _apply_context_classification(self, base_level: ClassificationLevel, 
                                    confidence: float, context: Dict) -> tuple:
        """Apply context-based classification adjustments."""
        # Patent Innovation: Context-aware classification inheritance
        
        # Check for source classification
        if "source_classification" in context:
            source_level = ClassificationLevel(context["source_classification"])
            if source_level.numeric_level > base_level.numeric_level:
                base_level = source_level
                confidence = max(confidence, 0.8)  # High confidence for inherited classification
        
        # Check for operational context
        if context.get("operational_context") == "defense_critical":
            if base_level == ClassificationLevel.UNCLASSIFIED:
                base_level = ClassificationLevel.CUI
                confidence = max(confidence, 0.7)
        
        return base_level, confidence
    
    def _detect_compartments(self, content: str) -> Set[str]:
        """Detect compartment markings in content."""
        detected = set()
        content_upper = content.upper()
        
        for compartment in self._valid_compartments:
            if compartment in content_upper:
                detected.add(compartment)
        
        return detected
    
    def _detect_handling_instructions(self, content: str) -> List[str]:
        """Detect handling instructions in content."""
        detected = []
        content_upper = content.upper()
        
        for instruction in self._handling_instructions:
            if instruction in content_upper:
                detected.append(instruction)
        
        return detected
    
    def _log_classification_event(self, content: str, level: ClassificationLevel, 
                                confidence: float, violations: List[str]):
        """Log classification events based on security level."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        if level in [ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET]:
            # Detailed logging for classified content
            self.logger.info(f"Classification: {level.value}, confidence={confidence:.3f}, "
                           f"violations={violations}, hash={content_hash}")
        elif violations:
            # Log violations for all levels
            self.logger.warning(f"Classification violations: {violations}, level={level.value}")
        else:
            # Basic logging for unclassified
            self.logger.debug(f"Classification: {level.value}, confidence={confidence:.3f}")
    
    def validate_cross_domain_access(self, source_level: ClassificationLevel, 
                                   target_level: ClassificationLevel) -> bool:
        """
        Validate cross-domain access between classification levels.
        
        Patent Innovation: Real-time cross-domain validation for air-gapped systems.
        """
        self._cross_domain_validations += 1
        
        # Basic rule: can only access same or lower classification
        access_allowed = source_level.can_access(target_level)
        
        # Log cross-domain validation
        self.logger.info(f"Cross-domain validation: {source_level.value} -> {target_level.value} = {access_allowed}")
        
        return access_allowed
    
    def get_classification_metrics(self) -> Dict:
        """Get comprehensive classification metrics."""
        recent_classifications = [
            entry for entry in self._classification_history 
            if time.time() - entry["timestamp"] < 3600  # Last hour
        ]
        
        return {
            "default_level": self.default_level.value,
            "total_classifications": len(self._classification_history),
            "recent_classifications": len(recent_classifications),
            "cross_domain_validations": self._cross_domain_validations,
            "average_confidence": (
                sum(entry["confidence"] for entry in recent_classifications) / 
                max(1, len(recent_classifications))
            ),
            "classification_distribution": self._get_classification_distribution()
        }
    
    def _get_classification_distribution(self) -> Dict[str, int]:
        """Get distribution of classification levels assigned."""
        distribution = {}
        for entry in self._classification_history:
            level = entry["assigned_level"]
            distribution[level] = distribution.get(level, 0) + 1
        return distribution
    
    def export_classification_report(self) -> Dict:
        """Export comprehensive classification report for audit."""
        return {
            "report_timestamp": time.time(),
            "system_classification": self.default_level.value,
            "metrics": self.get_classification_metrics(),
            "recent_history": self._classification_history[-100:],  # Last 100 entries
            "compartments": list(self._valid_compartments.keys()),
            "handling_instructions": list(self._handling_instructions.keys()),
            "innovations": [
                "automatic_classification_inheritance",
                "cross_domain_validation", 
                "real_time_confidence_scoring",
                "context_aware_classification"
            ]
        }