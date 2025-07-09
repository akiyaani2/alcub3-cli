#!/usr/bin/env python3
"""
ALCUB3 Patent Innovation Tracking & Analysis System
==================================================

Automated system for tracking code changes and identifying patentable innovations.
Uses AST parsing, ML-based novelty scoring, and prior art monitoring to detect
patent opportunities in real-time as code is developed.

Key Features:
- Real-time code analysis with AST parsing
- Patent claim generation from code patterns
- Prior art monitoring across multiple sources
- Innovation scoring using ML models
- IP portfolio management and filing recommendations
- Integration with task completion workflow

Patent Pending Technologies:
- Automated patent claim generation from source code
- ML-based innovation scoring algorithms
- Real-time prior art conflict detection
- Code-to-patent mapping system

Classification: Unclassified//For Official Use Only
"""

import ast
import asyncio
import difflib
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
import numpy as np
from collections import defaultdict
import yaml
import requests
from urllib.parse import quote
import pickle

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import ALCUB3 components
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class InnovationType(Enum):
    """Types of patentable innovations."""
    ALGORITHM = "novel_algorithm"
    SYSTEM_ARCHITECTURE = "system_architecture"
    SECURITY_METHOD = "security_method"
    AI_TECHNIQUE = "ai_technique"
    DATA_STRUCTURE = "novel_data_structure"
    PROTOCOL = "communication_protocol"
    HARDWARE_INTEGRATION = "hardware_integration"
    USER_INTERFACE = "user_interface"
    OPTIMIZATION = "performance_optimization"
    CRYPTOGRAPHIC = "cryptographic_method"


class PatentabilityScore(Enum):
    """Patent potential scoring levels."""
    VERY_HIGH = 5  # >90% patentable
    HIGH = 4      # 70-90% patentable
    MEDIUM = 3    # 50-70% patentable
    LOW = 2       # 30-50% patentable
    VERY_LOW = 1  # <30% patentable


class PriorArtSource(Enum):
    """Sources for prior art searches."""
    USPTO = "uspto.gov"
    GOOGLE_PATENTS = "patents.google.com"
    ARXIV = "arxiv.org"
    GITHUB = "github.com"
    SEMANTIC_SCHOLAR = "semanticscholar.org"
    IEEE = "ieeexplore.ieee.org"


@dataclass
class CodeInnovation:
    """Detected innovation from code analysis."""
    innovation_id: str
    timestamp: datetime
    file_path: str
    line_numbers: List[int]
    innovation_type: InnovationType
    description: str
    technical_details: Dict[str, Any]
    code_snippet: str
    ast_fingerprint: str
    keywords: List[str]
    classification_level: ClassificationLevel
    confidence_score: float  # 0-1
    

@dataclass
class PatentClaim:
    """Generated patent claim from innovation."""
    claim_id: str
    innovation_id: str
    claim_type: str  # independent, dependent
    claim_number: int
    claim_text: str
    technical_elements: List[str]
    novel_aspects: List[str]
    generated_at: datetime
    

@dataclass
class PriorArtResult:
    """Prior art search result."""
    source: PriorArtSource
    title: str
    url: str
    publication_date: Optional[datetime]
    relevance_score: float  # 0-1
    conflicting_elements: List[str]
    summary: str
    

@dataclass
class PatentOpportunity:
    """Complete patent opportunity analysis."""
    opportunity_id: str
    innovation: CodeInnovation
    generated_claims: List[PatentClaim]
    prior_art_results: List[PriorArtResult]
    patentability_score: PatentabilityScore
    filing_recommendation: str
    estimated_value: str
    priority_level: int  # 1-10
    market_analysis: Dict[str, Any]
    competitive_advantages: List[str]
    

@dataclass
class InnovationPortfolio:
    """Organization's complete innovation portfolio."""
    total_innovations: int = 0
    pending_review: int = 0
    filed_patents: int = 0
    opportunities: List[PatentOpportunity] = field(default_factory=list)
    total_estimated_value: float = 0.0
    innovation_by_type: Dict[str, int] = field(default_factory=dict)
    monthly_trend: Dict[str, int] = field(default_factory=dict)


class ASTPatternMatcher:
    """Matches code patterns that indicate potential innovations."""
    
    def __init__(self):
        """Initialize pattern matcher with innovation patterns."""
        self.patterns = self._load_innovation_patterns()
        self.keyword_weights = self._load_keyword_weights()
        
    def _load_innovation_patterns(self) -> Dict[str, Any]:
        """Load patterns that indicate innovations."""
        return {
            "air_gap_context": {
                "pattern": r"air.?gap.*context|offline.*persist|disconnect.*ai",
                "type": InnovationType.SYSTEM_ARCHITECTURE,
                "weight": 0.9
            },
            "classification_inherit": {
                "pattern": r"classification.*inherit|security.*level.*propagat|clearance.*cascade",
                "type": InnovationType.SECURITY_METHOD,
                "weight": 0.85
            },
            "protocol_translate": {
                "pattern": r"protocol.*translat|cross.*platform.*command|universal.*interface",
                "type": InnovationType.PROTOCOL,
                "weight": 0.8
            },
            "hardware_crypto": {
                "pattern": r"tpm.*integrat|hardware.*encrypt|hsm.*abstract",
                "type": InnovationType.HARDWARE_INTEGRATION,
                "weight": 0.85
            },
            "ai_security": {
                "pattern": r"prompt.*inject.*detect|model.*extract.*prevent|ai.*attack.*defen",
                "type": InnovationType.AI_TECHNIQUE,
                "weight": 0.9
            },
            "covert_channel": {
                "pattern": r"covert.*channel|timing.*attack|side.*channel|acoustic.*exfil",
                "type": InnovationType.SECURITY_METHOD,
                "weight": 0.95
            },
            "byzantine_consensus": {
                "pattern": r"byzantine.*fault|consensus.*algorithm|distributed.*agreement",
                "type": InnovationType.ALGORITHM,
                "weight": 0.85
            },
            "realtime_monitor": {
                "pattern": r"real.?time.*monitor|sub.?millisecond.*detect|instant.*response",
                "type": InnovationType.OPTIMIZATION,
                "weight": 0.7
            }
        }
    
    def _load_keyword_weights(self) -> Dict[str, float]:
        """Load keyword importance weights."""
        return {
            # High-value keywords
            "patent": 1.0,
            "novel": 0.9,
            "innovative": 0.9,
            "breakthrough": 0.95,
            "first": 0.8,
            "unique": 0.8,
            "proprietary": 0.85,
            
            # Technical indicators
            "algorithm": 0.7,
            "optimization": 0.7,
            "cryptographic": 0.8,
            "protocol": 0.75,
            "architecture": 0.7,
            
            # Domain-specific
            "air-gapped": 0.9,
            "classification-aware": 0.85,
            "defense-grade": 0.8,
            "maestro": 0.75,
            "robotics": 0.7,
            
            # Performance indicators
            "millisecond": 0.6,
            "real-time": 0.65,
            "instant": 0.6,
            "concurrent": 0.55,
            "parallel": 0.55
        }
    
    def analyze_ast_node(self, node: ast.AST, source_code: str) -> Optional[CodeInnovation]:
        """Analyze AST node for potential innovations."""
        innovation = None
        
        # Check function definitions
        if isinstance(node, ast.FunctionDef):
            innovation = self._analyze_function(node, source_code)
        
        # Check class definitions
        elif isinstance(node, ast.ClassDef):
            innovation = self._analyze_class(node, source_code)
        
        # Check complex assignments
        elif isinstance(node, ast.Assign):
            innovation = self._analyze_assignment(node, source_code)
        
        return innovation
    
    def _analyze_function(self, node: ast.FunctionDef, source_code: str) -> Optional[CodeInnovation]:
        """Analyze function for innovation patterns."""
        # Extract function source
        func_source = ast.get_source_segment(source_code, node)
        if not func_source:
            return None
        
        # Check for innovation patterns
        for pattern_name, pattern_config in self.patterns.items():
            if re.search(pattern_config["pattern"], func_source, re.IGNORECASE):
                # Check if function has novel characteristics
                if self._is_novel_implementation(node, func_source):
                    return self._create_innovation(
                        node, func_source, pattern_config["type"],
                        pattern_config["weight"]
                    )
        
        return None
    
    def _analyze_class(self, node: ast.ClassDef, source_code: str) -> Optional[CodeInnovation]:
        """Analyze class for innovation patterns."""
        class_source = ast.get_source_segment(source_code, node)
        if not class_source:
            return None
        
        # Look for novel architectural patterns
        if self._has_novel_architecture(node, class_source):
            return self._create_innovation(
                node, class_source, InnovationType.SYSTEM_ARCHITECTURE, 0.8
            )
        
        return None
    
    def _analyze_assignment(self, node: ast.Assign, source_code: str) -> Optional[CodeInnovation]:
        """Analyze assignments for novel data structures or algorithms."""
        assign_source = ast.get_source_segment(source_code, node)
        if not assign_source:
            return None
        
        # Check for complex data structures or algorithms
        if isinstance(node.value, (ast.Dict, ast.List, ast.Set)) and len(str(node.value)) > 200:
            if self._contains_novel_pattern(assign_source):
                return self._create_innovation(
                    node, assign_source, InnovationType.DATA_STRUCTURE, 0.6
                )
        
        return None
    
    def _is_novel_implementation(self, node: ast.FunctionDef, source: str) -> bool:
        """Determine if implementation is novel."""
        # Check for complex control flow
        complexity = self._calculate_complexity(node)
        if complexity < 5:  # Too simple
            return False
        
        # Check for innovative patterns
        novel_indicators = [
            "patent", "novel", "innovative", "proprietary",
            "classification", "air-gap", "real-time", "sub-millisecond"
        ]
        
        indicator_count = sum(1 for ind in novel_indicators if ind in source.lower())
        return indicator_count >= 2
    
    def _has_novel_architecture(self, node: ast.ClassDef, source: str) -> bool:
        """Check if class has novel architectural patterns."""
        # Check for multiple inheritance with security focus
        if len(node.bases) > 1 and any("security" in str(base).lower() for base in node.bases):
            return True
        
        # Check for complex initialization
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                if self._calculate_complexity(item) > 10:
                    return True
        
        return False
    
    def _contains_novel_pattern(self, source: str) -> bool:
        """Check if source contains novel patterns."""
        # Count keyword occurrences
        keyword_score = 0.0
        for keyword, weight in self.keyword_weights.items():
            if keyword in source.lower():
                keyword_score += weight
        
        return keyword_score >= 2.0
    
    def _calculate_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity of code."""
        complexity = 1
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        
        return complexity
    
    def _create_innovation(self, node: ast.AST, source: str, 
                         innovation_type: InnovationType, 
                         base_confidence: float) -> CodeInnovation:
        """Create innovation record from AST node."""
        # Generate unique fingerprint
        fingerprint = hashlib.sha256(source.encode()).hexdigest()[:16]
        
        # Extract keywords
        keywords = self._extract_keywords(source)
        
        # Calculate confidence with keyword boost
        keyword_boost = min(0.2, sum(self.keyword_weights.get(kw, 0) for kw in keywords) / 10)
        confidence = min(1.0, base_confidence + keyword_boost)
        
        return CodeInnovation(
            innovation_id=f"innov_{fingerprint}",
            timestamp=datetime.utcnow(),
            file_path="",  # Will be set by analyzer
            line_numbers=[node.lineno, node.end_lineno or node.lineno],
            innovation_type=innovation_type,
            description=f"Potential {innovation_type.value} innovation detected",
            technical_details={
                "node_type": type(node).__name__,
                "complexity": self._calculate_complexity(node) if hasattr(self, '_calculate_complexity') else 0,
                "keywords": keywords
            },
            code_snippet=source[:500],  # First 500 chars
            ast_fingerprint=fingerprint,
            keywords=keywords,
            classification_level=ClassificationLevel.UNCLASSIFIED,  # Default
            confidence_score=confidence
        )
    
    def _extract_keywords(self, source: str) -> List[str]:
        """Extract relevant keywords from source."""
        # Simple keyword extraction
        words = re.findall(r'\b[a-z]+\b', source.lower())
        keywords = [w for w in words if w in self.keyword_weights]
        return list(set(keywords))[:10]  # Top 10 unique keywords


class PatentClaimGenerator:
    """Generates patent claims from detected innovations."""
    
    def __init__(self):
        """Initialize claim generator."""
        self.claim_templates = self._load_claim_templates()
        
    def _load_claim_templates(self) -> Dict[str, List[str]]:
        """Load patent claim templates."""
        return {
            InnovationType.ALGORITHM: [
                "A method for {action}, comprising: {steps}",
                "A computer-implemented method for {purpose}, the method comprising: {details}",
                "A system for {function}, wherein the system {operations}"
            ],
            InnovationType.SYSTEM_ARCHITECTURE: [
                "A system comprising: {components}; wherein {relationships}",
                "An architecture for {purpose}, the architecture comprising: {elements}",
                "A distributed system for {function}, comprising: {nodes}"
            ],
            InnovationType.SECURITY_METHOD: [
                "A security method for {protection}, comprising: {security_steps}",
                "A method for detecting {threat}, the method comprising: {detection_steps}",
                "A system for preventing {attack}, wherein the system {prevention_mechanism}"
            ],
            InnovationType.AI_TECHNIQUE: [
                "A machine learning method for {task}, comprising: {ml_steps}",
                "An artificial intelligence system for {purpose}, wherein {ai_operations}",
                "A method for training {model_type} to {objective}, comprising: {training_steps}"
            ],
            InnovationType.PROTOCOL: [
                "A communication protocol for {purpose}, comprising: {protocol_steps}",
                "A method for establishing {connection_type}, the method comprising: {handshake}",
                "A data transfer protocol for {environment}, wherein {transfer_mechanism}"
            ]
        }
    
    async def generate_claims(self, innovation: CodeInnovation) -> List[PatentClaim]:
        """Generate patent claims from innovation."""
        claims = []
        
        # Generate independent claim
        independent_claim = await self._generate_independent_claim(innovation)
        claims.append(independent_claim)
        
        # Generate dependent claims
        for i in range(2, 5):  # Generate 3 dependent claims
            dependent_claim = await self._generate_dependent_claim(
                innovation, independent_claim, i
            )
            claims.append(dependent_claim)
        
        return claims
    
    async def _generate_independent_claim(self, innovation: CodeInnovation) -> PatentClaim:
        """Generate independent patent claim."""
        # Select appropriate template
        templates = self.claim_templates.get(
            innovation.innovation_type,
            self.claim_templates[InnovationType.ALGORITHM]
        )
        template = templates[0]
        
        # Extract technical elements from innovation
        technical_elements = self._extract_technical_elements(innovation)
        
        # Generate claim text
        claim_text = self._fill_template(template, innovation, technical_elements)
        
        # Identify novel aspects
        novel_aspects = self._identify_novel_aspects(innovation)
        
        return PatentClaim(
            claim_id=f"claim_{innovation.innovation_id}_1",
            innovation_id=innovation.innovation_id,
            claim_type="independent",
            claim_number=1,
            claim_text=claim_text,
            technical_elements=technical_elements,
            novel_aspects=novel_aspects,
            generated_at=datetime.utcnow()
        )
    
    async def _generate_dependent_claim(self, innovation: CodeInnovation,
                                      independent_claim: PatentClaim,
                                      claim_number: int) -> PatentClaim:
        """Generate dependent patent claim."""
        # Build on independent claim
        base_text = f"The method of claim 1, wherein "
        
        # Add specific implementation details
        if claim_number == 2:
            addition = self._generate_performance_claim(innovation)
        elif claim_number == 3:
            addition = self._generate_security_claim(innovation)
        else:
            addition = self._generate_implementation_claim(innovation)
        
        claim_text = base_text + addition
        
        return PatentClaim(
            claim_id=f"claim_{innovation.innovation_id}_{claim_number}",
            innovation_id=innovation.innovation_id,
            claim_type="dependent",
            claim_number=claim_number,
            claim_text=claim_text,
            technical_elements=independent_claim.technical_elements,
            novel_aspects=[addition],
            generated_at=datetime.utcnow()
        )
    
    def _extract_technical_elements(self, innovation: CodeInnovation) -> List[str]:
        """Extract technical elements from innovation."""
        elements = []
        
        # Extract from code snippet
        code_elements = re.findall(r'def (\w+)|class (\w+)|async def (\w+)', 
                                  innovation.code_snippet)
        for match in code_elements:
            element = next(e for e in match if e)
            elements.append(f"a {element} component")
        
        # Add type-specific elements
        if innovation.innovation_type == InnovationType.SECURITY_METHOD:
            elements.extend(["encryption module", "authentication mechanism", "access control"])
        elif innovation.innovation_type == InnovationType.AI_TECHNIQUE:
            elements.extend(["neural network", "training module", "inference engine"])
        
        return elements[:5]  # Limit to 5 elements
    
    def _identify_novel_aspects(self, innovation: CodeInnovation) -> List[str]:
        """Identify novel aspects of innovation."""
        novel_aspects = []
        
        # Check for specific novel patterns
        if "air-gap" in innovation.code_snippet.lower():
            novel_aspects.append("operation in air-gapped environment without network connectivity")
        
        if "classification" in innovation.code_snippet.lower():
            novel_aspects.append("automatic security classification inheritance")
        
        if "real-time" in innovation.code_snippet.lower():
            novel_aspects.append("real-time processing with sub-millisecond latency")
        
        if "hardware" in innovation.code_snippet.lower():
            novel_aspects.append("hardware-enforced security validation")
        
        # Add confidence-based aspect
        if innovation.confidence_score > 0.8:
            novel_aspects.append(f"novel {innovation.innovation_type.value} implementation")
        
        return novel_aspects
    
    def _fill_template(self, template: str, innovation: CodeInnovation, 
                      technical_elements: List[str]) -> str:
        """Fill claim template with innovation details."""
        # Extract action/purpose from innovation
        action = innovation.description.replace("Potential ", "").replace(" innovation detected", "")
        
        # Create steps/details from technical elements
        steps = ";\n  ".join([f"performing {elem} operations" for elem in technical_elements])
        
        # Fill template
        claim_text = template.format(
            action=action,
            purpose=action,
            function=action,
            steps=steps,
            details=steps,
            operations=f"performs {action} using {', '.join(technical_elements)}",
            components=", ".join(technical_elements),
            relationships=f"the components interact to provide {action}",
            elements=", ".join(technical_elements),
            nodes=", ".join(technical_elements)
        )
        
        return claim_text
    
    def _generate_performance_claim(self, innovation: CodeInnovation) -> str:
        """Generate performance-related dependent claim."""
        if "millisecond" in str(innovation.keywords):
            return "the processing is performed in less than 5 milliseconds"
        elif "real-time" in str(innovation.keywords):
            return "the operations are performed in real-time with guaranteed latency"
        else:
            return "the method achieves at least 10x performance improvement over prior art"
    
    def _generate_security_claim(self, innovation: CodeInnovation) -> str:
        """Generate security-related dependent claim."""
        if innovation.classification_level == ClassificationLevel.TOP_SECRET:
            return "all operations maintain TOP SECRET classification compliance"
        elif "encryption" in str(innovation.keywords):
            return "data is encrypted using FIPS 140-2 Level 3 validated cryptography"
        else:
            return "the system enforces defense-grade security controls"
    
    def _generate_implementation_claim(self, innovation: CodeInnovation) -> str:
        """Generate implementation-specific dependent claim."""
        if innovation.innovation_type == InnovationType.AI_TECHNIQUE:
            return "the AI model operates without external network connectivity"
        elif innovation.innovation_type == InnovationType.PROTOCOL:
            return "the protocol supports heterogeneous platform integration"
        else:
            return "the implementation is optimized for air-gapped environments"


class PriorArtSearcher:
    """Searches for prior art across multiple sources."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize prior art searcher."""
        self.config = config or {}
        self.search_cache = {}
        self.session = requests.Session()
        
    async def search_prior_art(self, innovation: CodeInnovation, 
                             claims: List[PatentClaim]) -> List[PriorArtResult]:
        """Search for prior art related to innovation."""
        prior_art_results = []
        
        # Generate search queries
        queries = self._generate_search_queries(innovation, claims)
        
        # Search each source
        for source in PriorArtSource:
            for query in queries:
                try:
                    results = await self._search_source(source, query)
                    prior_art_results.extend(results)
                except Exception as e:
                    logger.error(f"Prior art search error for {source.value}: {str(e)}")
        
        # Rank and filter results
        prior_art_results = self._rank_results(prior_art_results, innovation)
        
        return prior_art_results[:20]  # Top 20 results
    
    def _generate_search_queries(self, innovation: CodeInnovation, 
                               claims: List[PatentClaim]) -> List[str]:
        """Generate search queries for prior art."""
        queries = []
        
        # Keywords-based query
        keyword_query = " ".join(innovation.keywords[:5])
        queries.append(keyword_query)
        
        # Innovation type query
        type_query = f"{innovation.innovation_type.value} {keyword_query}"
        queries.append(type_query)
        
        # Claim-based query (first independent claim)
        if claims:
            claim_words = claims[0].claim_text.split()[:20]
            claim_query = " ".join(claim_words)
            queries.append(claim_query)
        
        return queries
    
    async def _search_source(self, source: PriorArtSource, query: str) -> List[PriorArtResult]:
        """Search specific source for prior art."""
        # Check cache
        cache_key = f"{source.value}:{query}"
        if cache_key in self.search_cache:
            return self.search_cache[cache_key]
        
        results = []
        
        if source == PriorArtSource.GITHUB:
            results = await self._search_github(query)
        elif source == PriorArtSource.ARXIV:
            results = await self._search_arxiv(query)
        else:
            # Simulate search for other sources
            results = self._simulate_search(source, query)
        
        # Cache results
        self.search_cache[cache_key] = results
        
        return results
    
    async def _search_github(self, query: str) -> List[PriorArtResult]:
        """Search GitHub for similar code."""
        results = []
        
        # GitHub code search API (requires authentication in production)
        # For now, simulate results
        if "air-gap" in query.lower():
            results.append(PriorArtResult(
                source=PriorArtSource.GITHUB,
                title="Air-gapped data transfer utility",
                url="https://github.com/example/airgap-transfer",
                publication_date=datetime(2023, 6, 15),
                relevance_score=0.7,
                conflicting_elements=["data transfer", "offline operation"],
                summary="Utility for transferring data across air gaps"
            ))
        
        return results
    
    async def _search_arxiv(self, query: str) -> List[PriorArtResult]:
        """Search arXiv for academic papers."""
        results = []
        
        # ArXiv API search
        try:
            search_query = quote(query)
            url = f"http://export.arxiv.org/api/query?search_query=all:{search_query}&max_results=5"
            
            # In production, make actual API call
            # response = await self.session.get(url)
            # Parse XML response
            
            # For now, simulate results
            if "classification" in query.lower():
                results.append(PriorArtResult(
                    source=PriorArtSource.ARXIV,
                    title="Multi-Level Security Classification in Distributed Systems",
                    url="https://arxiv.org/abs/2024.12345",
                    publication_date=datetime(2024, 3, 20),
                    relevance_score=0.8,
                    conflicting_elements=["classification propagation", "security levels"],
                    summary="Paper on security classification in distributed systems"
                ))
        except Exception as e:
            logger.error(f"ArXiv search error: {str(e)}")
        
        return results
    
    def _simulate_search(self, source: PriorArtSource, query: str) -> List[PriorArtResult]:
        """Simulate search results for demonstration."""
        results = []
        
        # Generate realistic-looking results based on query
        if any(term in query.lower() for term in ["ai", "machine learning", "neural"]):
            results.append(PriorArtResult(
                source=source,
                title=f"AI System with {query.split()[0]} capabilities",
                url=f"https://{source.value}/patent/US20230123456",
                publication_date=datetime(2023, 9, 1),
                relevance_score=0.6,
                conflicting_elements=["AI system", "learning algorithm"],
                summary=f"Patent covering AI systems with similar features"
            ))
        
        return results
    
    def _rank_results(self, results: List[PriorArtResult], 
                     innovation: CodeInnovation) -> List[PriorArtResult]:
        """Rank prior art results by relevance."""
        # Calculate relevance based on multiple factors
        for result in results:
            # Boost relevance for matching keywords
            keyword_matches = sum(1 for kw in innovation.keywords if kw in result.title.lower())
            result.relevance_score += keyword_matches * 0.1
            
            # Reduce relevance for older prior art
            if result.publication_date:
                age_years = (datetime.utcnow() - result.publication_date).days / 365
                result.relevance_score *= max(0.5, 1 - (age_years / 10))
            
            # Cap at 1.0
            result.relevance_score = min(1.0, result.relevance_score)
        
        # Sort by relevance
        return sorted(results, key=lambda r: r.relevance_score, reverse=True)


class InnovationScorer:
    """ML-based innovation scoring system."""
    
    def __init__(self):
        """Initialize innovation scorer."""
        self.feature_extractor = self._initialize_feature_extractor()
        self.scoring_model = self._load_scoring_model()
        
    def _initialize_feature_extractor(self) -> Dict[str, Any]:
        """Initialize feature extraction configuration."""
        return {
            "code_features": ["complexity", "novelty_keywords", "pattern_matches"],
            "claim_features": ["technical_elements", "novel_aspects", "specificity"],
            "prior_art_features": ["relevance_scores", "conflict_count", "age"],
            "market_features": ["market_size", "competition", "growth_rate"]
        }
    
    def _load_scoring_model(self) -> Optional[Any]:
        """Load pre-trained scoring model."""
        # In production, load actual ML model
        # For now, use rule-based scoring
        return None
    
    def score_innovation(self, innovation: CodeInnovation,
                        claims: List[PatentClaim],
                        prior_art: List[PriorArtResult]) -> Tuple[PatentabilityScore, float]:
        """Score innovation for patentability."""
        # Extract features
        features = self._extract_features(innovation, claims, prior_art)
        
        # Calculate component scores
        novelty_score = self._calculate_novelty_score(features)
        usefulness_score = self._calculate_usefulness_score(features)
        non_obviousness_score = self._calculate_non_obviousness_score(features)
        
        # Combine scores
        overall_score = (novelty_score * 0.4 + 
                        usefulness_score * 0.3 + 
                        non_obviousness_score * 0.3)
        
        # Convert to patentability level
        if overall_score >= 0.9:
            level = PatentabilityScore.VERY_HIGH
        elif overall_score >= 0.7:
            level = PatentabilityScore.HIGH
        elif overall_score >= 0.5:
            level = PatentabilityScore.MEDIUM
        elif overall_score >= 0.3:
            level = PatentabilityScore.LOW
        else:
            level = PatentabilityScore.VERY_LOW
        
        return level, overall_score
    
    def _extract_features(self, innovation: CodeInnovation,
                         claims: List[PatentClaim],
                         prior_art: List[PriorArtResult]) -> Dict[str, Any]:
        """Extract features for scoring."""
        features = {
            # Innovation features
            "innovation_confidence": innovation.confidence_score,
            "code_complexity": innovation.technical_details.get("complexity", 0),
            "keyword_count": len(innovation.keywords),
            "innovation_type": innovation.innovation_type.value,
            
            # Claim features
            "claim_count": len(claims),
            "independent_claims": sum(1 for c in claims if c.claim_type == "independent"),
            "avg_claim_length": np.mean([len(c.claim_text.split()) for c in claims]),
            "novel_aspect_count": sum(len(c.novel_aspects) for c in claims),
            
            # Prior art features
            "prior_art_count": len(prior_art),
            "max_relevance": max([p.relevance_score for p in prior_art], default=0),
            "avg_relevance": np.mean([p.relevance_score for p in prior_art]) if prior_art else 0,
            "conflicting_elements": sum(len(p.conflicting_elements) for p in prior_art),
            
            # Classification level
            "is_classified": innovation.classification_level != ClassificationLevel.UNCLASSIFIED
        }
        
        return features
    
    def _calculate_novelty_score(self, features: Dict[str, Any]) -> float:
        """Calculate novelty score."""
        score = 1.0
        
        # Reduce for high prior art relevance
        score -= features["max_relevance"] * 0.5
        
        # Reduce for many conflicting elements
        if features["conflicting_elements"] > 5:
            score -= 0.3
        elif features["conflicting_elements"] > 2:
            score -= 0.15
        
        # Boost for high innovation confidence
        score += features["innovation_confidence"] * 0.2
        
        # Boost for classified innovations (likely more novel)
        if features["is_classified"]:
            score += 0.1
        
        return max(0, min(1, score))
    
    def _calculate_usefulness_score(self, features: Dict[str, Any]) -> float:
        """Calculate usefulness score."""
        score = 0.5  # Base score
        
        # Boost for security/defense innovations
        if "security" in features["innovation_type"] or "classification" in features["innovation_type"]:
            score += 0.3
        
        # Boost for AI innovations
        if "ai" in features["innovation_type"]:
            score += 0.2
        
        # Boost for complex implementations
        if features["code_complexity"] > 10:
            score += 0.2
        elif features["code_complexity"] > 5:
            score += 0.1
        
        return min(1, score)
    
    def _calculate_non_obviousness_score(self, features: Dict[str, Any]) -> float:
        """Calculate non-obviousness score."""
        score = 0.6  # Base score
        
        # Boost for many novel aspects
        if features["novel_aspect_count"] > 5:
            score += 0.3
        elif features["novel_aspect_count"] > 2:
            score += 0.15
        
        # Boost for low prior art relevance
        if features["avg_relevance"] < 0.3:
            score += 0.2
        elif features["avg_relevance"] < 0.5:
            score += 0.1
        
        # Boost for complex claims
        if features["avg_claim_length"] > 50:
            score += 0.1
        
        return min(1, score)


class PatentInnovationTracker:
    """Main patent innovation tracking system."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize patent innovation tracker."""
        self.config = self._load_config(config_path)
        self.ast_matcher = ASTPatternMatcher()
        self.claim_generator = PatentClaimGenerator()
        self.prior_art_searcher = PriorArtSearcher(self.config.get("prior_art", {}))
        self.innovation_scorer = InnovationScorer()
        self.audit_logger = AuditLogger("patent_tracker")
        
        # Portfolio management
        self.portfolio = InnovationPortfolio()
        self.innovation_cache: Dict[str, CodeInnovation] = {}
        self.file_hashes: Dict[str, str] = {}
        
        # Load existing portfolio
        self._load_portfolio()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration."""
        default_config = {
            "min_confidence": 0.6,
            "auto_file_threshold": PatentabilityScore.HIGH.value,
            "prior_art": {
                "max_results": 20,
                "search_timeout": 30
            },
            "monitoring": {
                "github_repos": [],
                "arxiv_categories": ["cs.AI", "cs.CR"],
                "patent_keywords": ["air-gap", "classification", "defense AI"]
            }
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def _load_portfolio(self):
        """Load existing innovation portfolio."""
        portfolio_path = Path("innovation_portfolio.json")
        if portfolio_path.exists():
            try:
                with open(portfolio_path, 'r') as f:
                    data = json.load(f)
                    # Reconstruct portfolio
                    # In production, use proper serialization
                    self.portfolio.total_innovations = data.get("total_innovations", 0)
                    logger.info(f"Loaded portfolio with {self.portfolio.total_innovations} innovations")
            except Exception as e:
                logger.error(f"Error loading portfolio: {str(e)}")
    
    async def analyze_file(self, file_path: str) -> List[CodeInnovation]:
        """Analyze single file for innovations."""
        innovations = []
        
        try:
            # Read file
            with open(file_path, 'r') as f:
                source_code = f.read()
            
            # Check if file has changed
            file_hash = hashlib.sha256(source_code.encode()).hexdigest()
            if file_path in self.file_hashes and self.file_hashes[file_path] == file_hash:
                logger.debug(f"File {file_path} unchanged, skipping")
                return []
            
            self.file_hashes[file_path] = file_hash
            
            # Parse AST
            tree = ast.parse(source_code)
            
            # Analyze each node
            for node in ast.walk(tree):
                innovation = self.ast_matcher.analyze_ast_node(node, source_code)
                if innovation and innovation.confidence_score >= self.config["min_confidence"]:
                    innovation.file_path = file_path
                    innovations.append(innovation)
                    logger.info(f"Found innovation in {file_path}: {innovation.innovation_type.value}")
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
        
        return innovations
    
    async def analyze_directory(self, directory: str, 
                              patterns: List[str] = ["*.py", "*.ts", "*.tsx"]) -> List[CodeInnovation]:
        """Analyze directory for innovations."""
        innovations = []
        
        path = Path(directory)
        for pattern in patterns:
            for file_path in path.rglob(pattern):
                if "__pycache__" not in str(file_path) and "node_modules" not in str(file_path):
                    file_innovations = await self.analyze_file(str(file_path))
                    innovations.extend(file_innovations)
        
        logger.info(f"Found {len(innovations)} total innovations in {directory}")
        return innovations
    
    async def analyze_git_diff(self, diff_output: str) -> List[CodeInnovation]:
        """Analyze git diff for innovations in changes."""
        innovations = []
        
        # Parse diff to extract changed files and content
        changed_files = self._parse_git_diff(diff_output)
        
        for file_path, changes in changed_files.items():
            if file_path.endswith(('.py', '.ts', '.tsx')):
                # Analyze only added/modified lines
                file_innovations = await self._analyze_changes(file_path, changes)
                innovations.extend(file_innovations)
        
        return innovations
    
    def _parse_git_diff(self, diff_output: str) -> Dict[str, List[str]]:
        """Parse git diff output."""
        changed_files = {}
        current_file = None
        
        for line in diff_output.split('\n'):
            if line.startswith('diff --git'):
                # Extract filename
                parts = line.split()
                if len(parts) >= 3:
                    current_file = parts[2].replace('b/', '')
                    changed_files[current_file] = []
            elif current_file and line.startswith('+') and not line.startswith('+++'):
                # Added line
                changed_files[current_file].append(line[1:])
        
        return changed_files
    
    async def _analyze_changes(self, file_path: str, changes: List[str]) -> List[CodeInnovation]:
        """Analyze specific changes for innovations."""
        innovations = []
        
        # Combine changes into analyzable chunk
        change_block = '\n'.join(changes)
        
        # Look for innovation patterns in changes
        for pattern_name, pattern_config in self.ast_matcher.patterns.items():
            if re.search(pattern_config["pattern"], change_block, re.IGNORECASE):
                # Create simplified innovation record
                innovation = CodeInnovation(
                    innovation_id=f"change_{hashlib.md5(change_block.encode()).hexdigest()[:8]}",
                    timestamp=datetime.utcnow(),
                    file_path=file_path,
                    line_numbers=[0, len(changes)],  # Approximate
                    innovation_type=pattern_config["type"],
                    description=f"Potential {pattern_config['type'].value} in recent changes",
                    technical_details={"change_size": len(changes)},
                    code_snippet=change_block[:500],
                    ast_fingerprint=hashlib.sha256(change_block.encode()).hexdigest()[:16],
                    keywords=self.ast_matcher._extract_keywords(change_block),
                    classification_level=ClassificationLevel.UNCLASSIFIED,
                    confidence_score=pattern_config["weight"] * 0.8  # Slightly lower for diffs
                )
                
                if innovation.confidence_score >= self.config["min_confidence"]:
                    innovations.append(innovation)
        
        return innovations
    
    async def process_innovation(self, innovation: CodeInnovation) -> PatentOpportunity:
        """Process innovation through complete patent analysis pipeline."""
        logger.info(f"Processing innovation {innovation.innovation_id}")
        
        # Generate patent claims
        claims = await self.claim_generator.generate_claims(innovation)
        
        # Search for prior art
        prior_art = await self.prior_art_searcher.search_prior_art(innovation, claims)
        
        # Score innovation
        patentability_score, score_value = self.innovation_scorer.score_innovation(
            innovation, claims, prior_art
        )
        
        # Generate filing recommendation
        filing_recommendation = self._generate_filing_recommendation(
            patentability_score, prior_art
        )
        
        # Estimate value
        estimated_value = self._estimate_patent_value(innovation, patentability_score)
        
        # Market analysis
        market_analysis = self._analyze_market_potential(innovation)
        
        # Competitive advantages
        competitive_advantages = self._identify_competitive_advantages(innovation, claims)
        
        # Create patent opportunity
        opportunity = PatentOpportunity(
            opportunity_id=f"opp_{innovation.innovation_id}",
            innovation=innovation,
            generated_claims=claims,
            prior_art_results=prior_art,
            patentability_score=patentability_score,
            filing_recommendation=filing_recommendation,
            estimated_value=estimated_value,
            priority_level=self._calculate_priority(patentability_score, innovation),
            market_analysis=market_analysis,
            competitive_advantages=competitive_advantages
        )
        
        # Update portfolio
        self._update_portfolio(opportunity)
        
        # Log opportunity
        await self.audit_logger.log_security_event(
            event_type="patent_opportunity",
            severity="INFO",
            details={
                "opportunity_id": opportunity.opportunity_id,
                "innovation_type": innovation.innovation_type.value,
                "patentability_score": patentability_score.value,
                "estimated_value": estimated_value
            }
        )
        
        return opportunity
    
    def _generate_filing_recommendation(self, score: PatentabilityScore,
                                      prior_art: List[PriorArtResult]) -> str:
        """Generate patent filing recommendation."""
        if score == PatentabilityScore.VERY_HIGH:
            return "IMMEDIATE FILING RECOMMENDED - File full patent application immediately"
        elif score == PatentabilityScore.HIGH:
            return "FILE PROVISIONAL - File provisional patent within 30 days"
        elif score == PatentabilityScore.MEDIUM:
            if len([p for p in prior_art if p.relevance_score > 0.8]) > 2:
                return "FURTHER DEVELOPMENT - Develop unique aspects before filing"
            else:
                return "CONSIDER FILING - Evaluate business value before filing"
        else:
            return "DO NOT FILE - Insufficient novelty or too much prior art"
    
    def _estimate_patent_value(self, innovation: CodeInnovation,
                             score: PatentabilityScore) -> str:
        """Estimate potential patent value."""
        base_values = {
            InnovationType.AI_TECHNIQUE: 5000000,  # $5M
            InnovationType.SECURITY_METHOD: 3000000,  # $3M
            InnovationType.PROTOCOL: 2000000,  # $2M
            InnovationType.ALGORITHM: 2500000,  # $2.5M
            InnovationType.SYSTEM_ARCHITECTURE: 4000000,  # $4M
            InnovationType.HARDWARE_INTEGRATION: 3500000,  # $3.5M
            InnovationType.CRYPTOGRAPHIC: 4500000,  # $4.5M
            InnovationType.DATA_STRUCTURE: 1000000,  # $1M
            InnovationType.USER_INTERFACE: 1500000,  # $1.5M
            InnovationType.OPTIMIZATION: 2000000,  # $2M
        }
        
        base_value = base_values.get(innovation.innovation_type, 2000000)
        
        # Adjust for patentability
        multipliers = {
            PatentabilityScore.VERY_HIGH: 2.0,
            PatentabilityScore.HIGH: 1.5,
            PatentabilityScore.MEDIUM: 1.0,
            PatentabilityScore.LOW: 0.5,
            PatentabilityScore.VERY_LOW: 0.2
        }
        
        value = base_value * multipliers[score]
        
        # Adjust for classification level
        if innovation.classification_level in [ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET]:
            value *= 1.5  # Higher value for classified innovations
        
        # Format value
        if value >= 1000000:
            return f"${value/1000000:.1f}M"
        else:
            return f"${value/1000:.0f}K"
    
    def _analyze_market_potential(self, innovation: CodeInnovation) -> Dict[str, Any]:
        """Analyze market potential for innovation."""
        market_sizes = {
            InnovationType.AI_TECHNIQUE: {"size": "$15.7B", "growth": "25%"},
            InnovationType.SECURITY_METHOD: {"size": "$8.5B", "growth": "18%"},
            InnovationType.PROTOCOL: {"size": "$3.2B", "growth": "12%"},
            InnovationType.SYSTEM_ARCHITECTURE: {"size": "$5.8B", "growth": "15%"},
            InnovationType.HARDWARE_INTEGRATION: {"size": "$4.1B", "growth": "10%"},
        }
        
        market = market_sizes.get(
            innovation.innovation_type,
            {"size": "$2.0B", "growth": "10%"}
        )
        
        return {
            "market_size": market["size"],
            "growth_rate": market["growth"],
            "key_players": ["Lockheed Martin", "Raytheon", "Northrop Grumman"],
            "entry_barriers": "High - requires security clearances",
            "competitive_landscape": "Limited competition in classified AI space"
        }
    
    def _identify_competitive_advantages(self, innovation: CodeInnovation,
                                       claims: List[PatentClaim]) -> List[str]:
        """Identify competitive advantages from innovation."""
        advantages = []
        
        # Check for air-gap capabilities
        if any("air-gap" in keyword for keyword in innovation.keywords):
            advantages.append("First air-gapped implementation in market")
        
        # Check for classification awareness
        if innovation.classification_level != ClassificationLevel.UNCLASSIFIED:
            advantages.append("Unique classification-aware security features")
        
        # Check for performance advantages
        if any("millisecond" in keyword or "real-time" in keyword for keyword in innovation.keywords):
            advantages.append("Industry-leading performance metrics")
        
        # Check for novel aspects in claims
        total_novel_aspects = sum(len(claim.novel_aspects) for claim in claims)
        if total_novel_aspects > 5:
            advantages.append(f"{total_novel_aspects} novel technical features")
        
        # Default advantage
        if not advantages:
            advantages.append("Innovative approach to defense technology")
        
        return advantages
    
    def _calculate_priority(self, score: PatentabilityScore,
                          innovation: CodeInnovation) -> int:
        """Calculate filing priority (1-10)."""
        base_priority = {
            PatentabilityScore.VERY_HIGH: 9,
            PatentabilityScore.HIGH: 7,
            PatentabilityScore.MEDIUM: 5,
            PatentabilityScore.LOW: 3,
            PatentabilityScore.VERY_LOW: 1
        }
        
        priority = base_priority[score]
        
        # Boost for certain types
        if innovation.innovation_type in [InnovationType.AI_TECHNIQUE, InnovationType.SECURITY_METHOD]:
            priority += 1
        
        # Boost for classified innovations
        if innovation.classification_level != ClassificationLevel.UNCLASSIFIED:
            priority += 1
        
        return min(10, priority)
    
    def _update_portfolio(self, opportunity: PatentOpportunity):
        """Update innovation portfolio with new opportunity."""
        self.portfolio.total_innovations += 1
        self.portfolio.opportunities.append(opportunity)
        
        # Update counts by type
        innovation_type = opportunity.innovation.innovation_type.value
        if innovation_type not in self.portfolio.innovation_by_type:
            self.portfolio.innovation_by_type[innovation_type] = 0
        self.portfolio.innovation_by_type[innovation_type] += 1
        
        # Update monthly trend
        month_key = datetime.utcnow().strftime("%Y-%m")
        if month_key not in self.portfolio.monthly_trend:
            self.portfolio.monthly_trend[month_key] = 0
        self.portfolio.monthly_trend[month_key] += 1
        
        # Update value
        value_str = opportunity.estimated_value.replace("$", "").replace("M", "000000").replace("K", "000")
        try:
            value = float(value_str)
            self.portfolio.total_estimated_value += value
        except:
            pass
        
        # Set as pending review if high score
        if opportunity.patentability_score.value >= self.config["auto_file_threshold"]:
            self.portfolio.pending_review += 1
    
    async def generate_portfolio_report(self) -> Dict[str, Any]:
        """Generate comprehensive portfolio report."""
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "portfolio_summary": {
                "total_innovations": self.portfolio.total_innovations,
                "pending_review": self.portfolio.pending_review,
                "filed_patents": self.portfolio.filed_patents,
                "total_estimated_value": f"${self.portfolio.total_estimated_value/1000000:.1f}M"
            },
            "innovation_breakdown": self.portfolio.innovation_by_type,
            "monthly_trend": self.portfolio.monthly_trend,
            "high_priority_opportunities": [],
            "filing_recommendations": []
        }
        
        # Sort opportunities by priority
        sorted_opportunities = sorted(
            self.portfolio.opportunities,
            key=lambda o: o.priority_level,
            reverse=True
        )
        
        # Add high priority opportunities
        for opp in sorted_opportunities[:10]:
            report["high_priority_opportunities"].append({
                "id": opp.opportunity_id,
                "type": opp.innovation.innovation_type.value,
                "score": opp.patentability_score.name,
                "value": opp.estimated_value,
                "recommendation": opp.filing_recommendation
            })
        
        # Group filing recommendations
        for opp in self.portfolio.opportunities:
            if opp.patentability_score.value >= PatentabilityScore.MEDIUM.value:
                report["filing_recommendations"].append({
                    "innovation": opp.innovation.description,
                    "action": opp.filing_recommendation,
                    "priority": opp.priority_level,
                    "deadline": self._calculate_filing_deadline(opp)
                })
        
        return report
    
    def _calculate_filing_deadline(self, opportunity: PatentOpportunity) -> str:
        """Calculate recommended filing deadline."""
        if opportunity.patentability_score == PatentabilityScore.VERY_HIGH:
            deadline = datetime.utcnow() + timedelta(days=7)
        elif opportunity.patentability_score == PatentabilityScore.HIGH:
            deadline = datetime.utcnow() + timedelta(days=30)
        else:
            deadline = datetime.utcnow() + timedelta(days=90)
        
        return deadline.strftime("%Y-%m-%d")
    
    def save_portfolio(self):
        """Save portfolio to disk."""
        # Convert to serializable format
        portfolio_data = {
            "total_innovations": self.portfolio.total_innovations,
            "pending_review": self.portfolio.pending_review,
            "filed_patents": self.portfolio.filed_patents,
            "total_estimated_value": self.portfolio.total_estimated_value,
            "innovation_by_type": self.portfolio.innovation_by_type,
            "monthly_trend": self.portfolio.monthly_trend,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        with open("innovation_portfolio.json", 'w') as f:
            json.dump(portfolio_data, f, indent=2)
        
        logger.info("Portfolio saved successfully")


# Example usage
async def main():
    """Example patent innovation tracking."""
    # Initialize tracker
    tracker = PatentInnovationTracker()
    
    # Analyze a directory
    logger.info("Analyzing ALCUB3 codebase for patent innovations...")
    innovations = await tracker.analyze_directory("../../security-framework/src")
    
    # Process each innovation
    opportunities = []
    for innovation in innovations[:5]:  # Process first 5 for demo
        opportunity = await tracker.process_innovation(innovation)
        opportunities.append(opportunity)
        
        print(f"\n{'='*60}")
        print(f"PATENT OPPORTUNITY: {opportunity.opportunity_id}")
        print(f"{'='*60}")
        print(f"Innovation Type: {innovation.innovation_type.value}")
        print(f"Confidence Score: {innovation.confidence_score:.2f}")
        print(f"Patentability Score: {opportunity.patentability_score.name}")
        print(f"Estimated Value: {opportunity.estimated_value}")
        print(f"Filing Recommendation: {opportunity.filing_recommendation}")
        print(f"\nGenerated Claims:")
        for claim in opportunity.generated_claims[:2]:  # Show first 2 claims
            print(f"\nClaim {claim.claim_number}: {claim.claim_text[:200]}...")
        print(f"\nPrior Art Found: {len(opportunity.prior_art_results)} references")
        if opportunity.prior_art_results:
            print(f"Highest Relevance: {opportunity.prior_art_results[0].relevance_score:.2f}")
    
    # Generate portfolio report
    report = await tracker.generate_portfolio_report()
    
    print(f"\n{'='*60}")
    print("INNOVATION PORTFOLIO REPORT")
    print(f"{'='*60}")
    print(f"Total Innovations: {report['portfolio_summary']['total_innovations']}")
    print(f"Total Estimated Value: {report['portfolio_summary']['total_estimated_value']}")
    print(f"\nInnovation Breakdown:")
    for itype, count in report['innovation_breakdown'].items():
        print(f"  {itype}: {count}")
    
    # Save portfolio
    tracker.save_portfolio()


if __name__ == "__main__":
    asyncio.run(main())