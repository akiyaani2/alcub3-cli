"""
Feature Engineering System

Advanced feature engineering for security forecasting, transforming raw
telemetry data into meaningful features for machine learning models.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import logging
from dataclasses import dataclass
from enum import Enum
import asyncio
from collections import defaultdict, deque
from scipy import stats
from scipy.stats import entropy
import warnings
warnings.filterwarnings('ignore')


class FeatureType(Enum):
    """Types of features that can be engineered."""
    TEMPORAL = "temporal"
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    CONTEXTUAL = "contextual"
    SECURITY_SPECIFIC = "security_specific"
    CLASSIFICATION_AWARE = "classification_aware"
    BYZANTINE_AWARE = "byzantine_aware"


@dataclass
class FeatureDefinition:
    """Definition of a feature with metadata."""
    name: str
    feature_type: FeatureType
    description: str
    data_type: str
    calculation_method: str
    dependencies: List[str]
    importance_weight: float


@dataclass
class FeatureVector:
    """Feature vector with metadata."""
    timestamp: datetime
    features: Dict[str, float]
    feature_definitions: List[FeatureDefinition]
    source_data_count: int
    quality_score: float


class FeatureEngineer:
    """
    Advanced feature engineering system for security forecasting.
    
    Features:
    - Temporal feature extraction
    - Statistical aggregations
    - Behavioral pattern analysis
    - Classification-aware features
    - Byzantine consensus features
    - Security-specific metrics
    """
    
    def __init__(self, 
                 window_size: int = 300,
                 feature_cache_size: int = 1000):
        """
        Initialize feature engineer.
        
        Args:
            window_size: Size of temporal window for feature calculation
            feature_cache_size: Size of feature cache
        """
        self.window_size = window_size
        self.feature_cache_size = feature_cache_size
        
        self.logger = logging.getLogger(__name__)
        
        # Feature cache
        self.feature_cache = deque(maxlen=feature_cache_size)
        self.feature_history = defaultdict(deque)
        
        # Feature definitions
        self.feature_definitions = self._initialize_feature_definitions()
        
        # Statistics for normalization
        self.feature_stats = {}
        
        # Performance tracking
        self.performance_metrics = {
            'total_feature_vectors': 0,
            'avg_processing_time': 0.0,
            'feature_quality_avg': 0.0,
            'last_processing_time': None
        }
        
        self.logger.info(f"Feature Engineer initialized with {len(self.feature_definitions)} features")
    
    def _initialize_feature_definitions(self) -> List[FeatureDefinition]:
        """Initialize feature definitions."""
        return [
            # Temporal features
            FeatureDefinition(
                name="temporal_risk_trend",
                feature_type=FeatureType.TEMPORAL,
                description="Trend in risk scores over time",
                data_type="float",
                calculation_method="linear_regression_slope",
                dependencies=["risk_score", "timestamp"],
                importance_weight=0.8
            ),
            FeatureDefinition(
                name="event_frequency_recent",
                feature_type=FeatureType.TEMPORAL,
                description="Event frequency in recent window",
                data_type="float",
                calculation_method="count_per_time_window",
                dependencies=["timestamp"],
                importance_weight=0.7
            ),
            FeatureDefinition(
                name="temporal_anomaly_score",
                feature_type=FeatureType.TEMPORAL,
                description="Anomaly score based on temporal patterns",
                data_type="float",
                calculation_method="time_series_anomaly",
                dependencies=["timestamp", "event_type"],
                importance_weight=0.6
            ),
            
            # Statistical features
            FeatureDefinition(
                name="severity_distribution_entropy",
                feature_type=FeatureType.STATISTICAL,
                description="Entropy of severity distribution",
                data_type="float",
                calculation_method="shannon_entropy",
                dependencies=["severity"],
                importance_weight=0.7
            ),
            FeatureDefinition(
                name="risk_score_variance",
                feature_type=FeatureType.STATISTICAL,
                description="Variance in risk scores",
                data_type="float",
                calculation_method="variance",
                dependencies=["risk_score"],
                importance_weight=0.6
            ),
            FeatureDefinition(
                name="event_type_diversity",
                feature_type=FeatureType.STATISTICAL,
                description="Diversity of event types",
                data_type="float",
                calculation_method="unique_count_ratio",
                dependencies=["event_type"],
                importance_weight=0.5
            ),
            
            # Behavioral features
            FeatureDefinition(
                name="source_behavior_anomaly",
                feature_type=FeatureType.BEHAVIORAL,
                description="Anomalous behavior from specific sources",
                data_type="float",
                calculation_method="source_behavior_analysis",
                dependencies=["source", "event_type", "severity"],
                importance_weight=0.8
            ),
            FeatureDefinition(
                name="user_activity_pattern",
                feature_type=FeatureType.BEHAVIORAL,
                description="Pattern in user activity",
                data_type="float",
                calculation_method="activity_pattern_analysis",
                dependencies=["user_id", "timestamp", "event_type"],
                importance_weight=0.7
            ),
            FeatureDefinition(
                name="authentication_failure_rate",
                feature_type=FeatureType.BEHAVIORAL,
                description="Rate of authentication failures",
                data_type="float",
                calculation_method="failure_rate_calculation",
                dependencies=["event_type", "severity"],
                importance_weight=0.9
            ),
            
            # Contextual features
            FeatureDefinition(
                name="system_load_correlation",
                feature_type=FeatureType.CONTEXTUAL,
                description="Correlation between events and system load",
                data_type="float",
                calculation_method="correlation_analysis",
                dependencies=["system_load", "event_count"],
                importance_weight=0.6
            ),
            FeatureDefinition(
                name="network_traffic_anomaly",
                feature_type=FeatureType.CONTEXTUAL,
                description="Anomaly in network traffic patterns",
                data_type="float",
                calculation_method="network_anomaly_detection",
                dependencies=["network_traffic", "timestamp"],
                importance_weight=0.7
            ),
            FeatureDefinition(
                name="time_of_day_factor",
                feature_type=FeatureType.CONTEXTUAL,
                description="Time of day influence factor",
                data_type="float",
                calculation_method="time_of_day_analysis",
                dependencies=["timestamp"],
                importance_weight=0.4
            ),
            
            # Security-specific features
            FeatureDefinition(
                name="threat_escalation_indicator",
                feature_type=FeatureType.SECURITY_SPECIFIC,
                description="Indicator of threat escalation",
                data_type="float",
                calculation_method="threat_escalation_analysis",
                dependencies=["threat_level", "timestamp"],
                importance_weight=0.9
            ),
            FeatureDefinition(
                name="attack_pattern_similarity",
                feature_type=FeatureType.SECURITY_SPECIFIC,
                description="Similarity to known attack patterns",
                data_type="float",
                calculation_method="pattern_matching",
                dependencies=["event_type", "severity", "source"],
                importance_weight=0.8
            ),
            FeatureDefinition(
                name="lateral_movement_indicator",
                feature_type=FeatureType.SECURITY_SPECIFIC,
                description="Indicator of lateral movement",
                data_type="float",
                calculation_method="lateral_movement_detection",
                dependencies=["source", "destination", "event_type"],
                importance_weight=0.8
            ),
            
            # Classification-aware features
            FeatureDefinition(
                name="classification_breach_risk",
                feature_type=FeatureType.CLASSIFICATION_AWARE,
                description="Risk of classification breach",
                data_type="float",
                calculation_method="classification_risk_analysis",
                dependencies=["classification", "user_clearance", "event_type"],
                importance_weight=0.9
            ),
            FeatureDefinition(
                name="compartment_violation_score",
                feature_type=FeatureType.CLASSIFICATION_AWARE,
                description="Score for compartment violations",
                data_type="float",
                calculation_method="compartment_analysis",
                dependencies=["compartment", "user_access", "event_type"],
                importance_weight=0.8
            ),
            FeatureDefinition(
                name="clearance_level_mismatch",
                feature_type=FeatureType.CLASSIFICATION_AWARE,
                description="Mismatch between clearance and access",
                data_type="float",
                calculation_method="clearance_mismatch_analysis",
                dependencies=["user_clearance", "data_classification"],
                importance_weight=0.7
            ),
            
            # Byzantine-aware features
            FeatureDefinition(
                name="byzantine_node_behavior",
                feature_type=FeatureType.BYZANTINE_AWARE,
                description="Byzantine node behavior indicator",
                data_type="float",
                calculation_method="byzantine_behavior_analysis",
                dependencies=["node_id", "consensus_vote", "timestamp"],
                importance_weight=0.8
            ),
            FeatureDefinition(
                name="consensus_disagreement_rate",
                feature_type=FeatureType.BYZANTINE_AWARE,
                description="Rate of consensus disagreements",
                data_type="float",
                calculation_method="consensus_analysis",
                dependencies=["consensus_round", "node_votes"],
                importance_weight=0.7
            ),
            FeatureDefinition(
                name="fault_tolerance_degradation",
                feature_type=FeatureType.BYZANTINE_AWARE,
                description="Degradation in fault tolerance",
                data_type="float",
                calculation_method="fault_tolerance_analysis",
                dependencies=["active_nodes", "failed_nodes", "timestamp"],
                importance_weight=0.6
            )
        ]
    
    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from raw telemetry data.
        
        Args:
            data: Raw telemetry data
            
        Returns:
            DataFrame with extracted features
        """
        try:
            if data.empty:
                return pd.DataFrame()
            
            start_time = datetime.now()
            
            # Prepare data
            processed_data = self._preprocess_data(data)
            
            # Extract features
            feature_vectors = []
            
            # Process data in windows
            for i in range(len(processed_data)):
                window_data = self._get_window_data(processed_data, i)
                
                if len(window_data) > 0:
                    features = self._extract_feature_vector(window_data)
                    feature_vectors.append(features)
            
            # Convert to DataFrame
            if feature_vectors:
                features_df = pd.DataFrame(feature_vectors)
                
                # Add timestamps
                if 'timestamp' in processed_data.columns:
                    features_df['timestamp'] = processed_data['timestamp'].iloc[-len(feature_vectors):]
                
                # Normalize features
                features_df = self._normalize_features(features_df)
                
                # Update performance metrics
                processing_time = (datetime.now() - start_time).total_seconds()
                self._update_performance_metrics(processing_time, len(feature_vectors))
                
                # Cache features
                self._cache_features(features_df)
                
                self.logger.debug(f"Extracted {len(feature_vectors)} feature vectors in {processing_time:.3f}s")
                
                return features_df
            
            return pd.DataFrame()
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return pd.DataFrame()
    
    def _preprocess_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Preprocess raw data for feature extraction."""
        try:
            processed = data.copy()
            
            # Ensure timestamp column
            if 'timestamp' not in processed.columns:
                processed['timestamp'] = datetime.now()
            
            # Convert timestamp to datetime
            if processed['timestamp'].dtype == 'object':
                processed['timestamp'] = pd.to_datetime(processed['timestamp'])
            
            # Sort by timestamp
            processed = processed.sort_values('timestamp')
            
            # Fill missing values
            numeric_columns = processed.select_dtypes(include=[np.number]).columns
            processed[numeric_columns] = processed[numeric_columns].fillna(0)
            
            categorical_columns = processed.select_dtypes(include=['object']).columns
            processed[categorical_columns] = processed[categorical_columns].fillna('unknown')
            
            return processed
            
        except Exception as e:
            self.logger.error(f"Error preprocessing data: {e}")
            return data
    
    def _get_window_data(self, data: pd.DataFrame, index: int) -> pd.DataFrame:
        """Get window of data for feature calculation."""
        try:
            start_idx = max(0, index - self.window_size + 1)
            end_idx = index + 1
            
            return data.iloc[start_idx:end_idx]
            
        except Exception as e:
            self.logger.error(f"Error getting window data: {e}")
            return pd.DataFrame()
    
    def _extract_feature_vector(self, window_data: pd.DataFrame) -> Dict[str, float]:
        """Extract feature vector from window data."""
        features = {}
        
        try:
            # Extract each feature
            for feature_def in self.feature_definitions:
                try:
                    feature_value = self._calculate_feature(feature_def, window_data)
                    features[feature_def.name] = feature_value
                except Exception as e:
                    self.logger.warning(f"Error calculating feature {feature_def.name}: {e}")
                    features[feature_def.name] = 0.0
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting feature vector: {e}")
            return {}
    
    def _calculate_feature(self, feature_def: FeatureDefinition, data: pd.DataFrame) -> float:
        """Calculate a specific feature value."""
        try:
            if data.empty:
                return 0.0
            
            if feature_def.calculation_method == "linear_regression_slope":
                return self._calculate_trend(data, 'risk_score')
            
            elif feature_def.calculation_method == "count_per_time_window":
                return self._calculate_event_frequency(data)
            
            elif feature_def.calculation_method == "time_series_anomaly":
                return self._calculate_temporal_anomaly(data)
            
            elif feature_def.calculation_method == "shannon_entropy":
                return self._calculate_entropy(data, 'severity')
            
            elif feature_def.calculation_method == "variance":
                return self._calculate_variance(data, 'risk_score')
            
            elif feature_def.calculation_method == "unique_count_ratio":
                return self._calculate_diversity(data, 'event_type')
            
            elif feature_def.calculation_method == "source_behavior_analysis":
                return self._calculate_source_behavior_anomaly(data)
            
            elif feature_def.calculation_method == "activity_pattern_analysis":
                return self._calculate_activity_pattern(data)
            
            elif feature_def.calculation_method == "failure_rate_calculation":
                return self._calculate_failure_rate(data)
            
            elif feature_def.calculation_method == "correlation_analysis":
                return self._calculate_correlation(data)
            
            elif feature_def.calculation_method == "network_anomaly_detection":
                return self._calculate_network_anomaly(data)
            
            elif feature_def.calculation_method == "time_of_day_analysis":
                return self._calculate_time_of_day_factor(data)
            
            elif feature_def.calculation_method == "threat_escalation_analysis":
                return self._calculate_threat_escalation(data)
            
            elif feature_def.calculation_method == "pattern_matching":
                return self._calculate_pattern_similarity(data)
            
            elif feature_def.calculation_method == "lateral_movement_detection":
                return self._calculate_lateral_movement(data)
            
            elif feature_def.calculation_method == "classification_risk_analysis":
                return self._calculate_classification_risk(data)
            
            elif feature_def.calculation_method == "compartment_analysis":
                return self._calculate_compartment_violation(data)
            
            elif feature_def.calculation_method == "clearance_mismatch_analysis":
                return self._calculate_clearance_mismatch(data)
            
            elif feature_def.calculation_method == "byzantine_behavior_analysis":
                return self._calculate_byzantine_behavior(data)
            
            elif feature_def.calculation_method == "consensus_analysis":
                return self._calculate_consensus_disagreement(data)
            
            elif feature_def.calculation_method == "fault_tolerance_analysis":
                return self._calculate_fault_tolerance_degradation(data)
            
            else:
                self.logger.warning(f"Unknown calculation method: {feature_def.calculation_method}")
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Error calculating feature {feature_def.name}: {e}")
            return 0.0
    
    # Feature calculation methods
    
    def _calculate_trend(self, data: pd.DataFrame, column: str) -> float:
        """Calculate trend using linear regression slope."""
        try:
            if column not in data.columns or len(data) < 2:
                return 0.0
            
            values = data[column].values
            if len(values) < 2:
                return 0.0
            
            x = np.arange(len(values))
            slope, _, _, _, _ = stats.linregress(x, values)
            
            return float(slope)
            
        except Exception as e:
            self.logger.error(f"Error calculating trend: {e}")
            return 0.0
    
    def _calculate_event_frequency(self, data: pd.DataFrame) -> float:
        """Calculate event frequency in the window."""
        try:
            if data.empty:
                return 0.0
            
            # Events per minute
            time_span = (data['timestamp'].max() - data['timestamp'].min()).total_seconds() / 60
            
            if time_span <= 0:
                return float(len(data))
            
            return float(len(data) / time_span)
            
        except Exception as e:
            self.logger.error(f"Error calculating event frequency: {e}")
            return 0.0
    
    def _calculate_temporal_anomaly(self, data: pd.DataFrame) -> float:
        """Calculate temporal anomaly score."""
        try:
            if data.empty or 'timestamp' not in data.columns:
                return 0.0
            
            # Calculate time differences
            time_diffs = data['timestamp'].diff().dt.total_seconds().dropna()
            
            if len(time_diffs) < 2:
                return 0.0
            
            # Z-score of time differences
            z_scores = np.abs(stats.zscore(time_diffs))
            
            # Return max z-score normalized to [0,1]
            return float(min(1.0, np.max(z_scores) / 3.0))
            
        except Exception as e:
            self.logger.error(f"Error calculating temporal anomaly: {e}")
            return 0.0
    
    def _calculate_entropy(self, data: pd.DataFrame, column: str) -> float:
        """Calculate Shannon entropy."""
        try:
            if column not in data.columns or data.empty:
                return 0.0
            
            values = data[column].values
            _, counts = np.unique(values, return_counts=True)
            
            if len(counts) <= 1:
                return 0.0
            
            return float(entropy(counts))
            
        except Exception as e:
            self.logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    def _calculate_variance(self, data: pd.DataFrame, column: str) -> float:
        """Calculate variance."""
        try:
            if column not in data.columns or data.empty:
                return 0.0
            
            values = data[column].values
            
            if len(values) < 2:
                return 0.0
            
            return float(np.var(values))
            
        except Exception as e:
            self.logger.error(f"Error calculating variance: {e}")
            return 0.0
    
    def _calculate_diversity(self, data: pd.DataFrame, column: str) -> float:
        """Calculate diversity as ratio of unique values."""
        try:
            if column not in data.columns or data.empty:
                return 0.0
            
            unique_count = data[column].nunique()
            total_count = len(data)
            
            return float(unique_count / total_count)
            
        except Exception as e:
            self.logger.error(f"Error calculating diversity: {e}")
            return 0.0
    
    def _calculate_source_behavior_anomaly(self, data: pd.DataFrame) -> float:
        """Calculate source behavior anomaly."""
        try:
            if 'source' not in data.columns or data.empty:
                return 0.0
            
            # Calculate behavior score per source
            source_scores = {}
            for source in data['source'].unique():
                source_data = data[data['source'] == source]
                
                # Simple behavior score based on severity and frequency
                avg_severity = source_data['severity'].mean() if 'severity' in source_data else 0
                frequency = len(source_data)
                
                source_scores[source] = avg_severity * frequency
            
            if not source_scores:
                return 0.0
            
            # Calculate anomaly as deviation from mean
            scores = list(source_scores.values())
            mean_score = np.mean(scores)
            max_deviation = np.max(np.abs(np.array(scores) - mean_score))
            
            # Normalize to [0,1]
            return float(min(1.0, max_deviation / (mean_score + 1e-6)))
            
        except Exception as e:
            self.logger.error(f"Error calculating source behavior anomaly: {e}")
            return 0.0
    
    def _calculate_activity_pattern(self, data: pd.DataFrame) -> float:
        """Calculate activity pattern score."""
        try:
            if data.empty or 'timestamp' not in data.columns:
                return 0.0
            
            # Group by hour of day
            data['hour'] = data['timestamp'].dt.hour
            hourly_counts = data.groupby('hour').size()
            
            if len(hourly_counts) < 2:
                return 0.0
            
            # Calculate coefficient of variation
            cv = hourly_counts.std() / hourly_counts.mean()
            
            return float(min(1.0, cv))
            
        except Exception as e:
            self.logger.error(f"Error calculating activity pattern: {e}")
            return 0.0
    
    def _calculate_failure_rate(self, data: pd.DataFrame) -> float:
        """Calculate authentication failure rate."""
        try:
            if data.empty or 'event_type' not in data.columns:
                return 0.0
            
            # Count failure events
            failure_events = data[data['event_type'].str.contains('fail', case=False, na=False)]
            total_events = len(data)
            
            if total_events == 0:
                return 0.0
            
            return float(len(failure_events) / total_events)
            
        except Exception as e:
            self.logger.error(f"Error calculating failure rate: {e}")
            return 0.0
    
    def _calculate_correlation(self, data: pd.DataFrame) -> float:
        """Calculate correlation between system load and events."""
        try:
            if data.empty or 'system_load' not in data.columns:
                return 0.0
            
            # Count events per time period
            data['time_bucket'] = data['timestamp'].dt.floor('5min')
            event_counts = data.groupby('time_bucket').size()
            load_avgs = data.groupby('time_bucket')['system_load'].mean()
            
            if len(event_counts) < 2:
                return 0.0
            
            # Calculate correlation
            correlation = np.corrcoef(event_counts.values, load_avgs.values)[0, 1]
            
            return float(abs(correlation) if not np.isnan(correlation) else 0.0)
            
        except Exception as e:
            self.logger.error(f"Error calculating correlation: {e}")
            return 0.0
    
    def _calculate_network_anomaly(self, data: pd.DataFrame) -> float:
        """Calculate network traffic anomaly."""
        try:
            if data.empty or 'network_traffic' not in data.columns:
                return 0.0
            
            traffic_values = data['network_traffic'].values
            
            if len(traffic_values) < 2:
                return 0.0
            
            # Calculate z-score
            z_scores = np.abs(stats.zscore(traffic_values))
            
            # Return max z-score normalized
            return float(min(1.0, np.max(z_scores) / 3.0))
            
        except Exception as e:
            self.logger.error(f"Error calculating network anomaly: {e}")
            return 0.0
    
    def _calculate_time_of_day_factor(self, data: pd.DataFrame) -> float:
        """Calculate time of day factor."""
        try:
            if data.empty or 'timestamp' not in data.columns:
                return 0.0
            
            # Get latest timestamp
            latest_time = data['timestamp'].max()
            hour = latest_time.hour
            
            # Night hours (22-06) have higher factor
            if hour >= 22 or hour <= 6:
                return 0.8
            # Business hours (08-17) have lower factor
            elif 8 <= hour <= 17:
                return 0.2
            else:
                return 0.5
                
        except Exception as e:
            self.logger.error(f"Error calculating time of day factor: {e}")
            return 0.0
    
    def _calculate_threat_escalation(self, data: pd.DataFrame) -> float:
        """Calculate threat escalation indicator."""
        try:
            if data.empty or 'threat_level' not in data.columns:
                return 0.0
            
            threat_levels = data['threat_level'].values
            
            if len(threat_levels) < 2:
                return 0.0
            
            # Calculate trend in threat levels
            x = np.arange(len(threat_levels))
            slope, _, _, _, _ = stats.linregress(x, threat_levels)
            
            # Return normalized positive slope
            return float(max(0.0, min(1.0, slope)))
            
        except Exception as e:
            self.logger.error(f"Error calculating threat escalation: {e}")
            return 0.0
    
    def _calculate_pattern_similarity(self, data: pd.DataFrame) -> float:
        """Calculate similarity to known attack patterns."""
        try:
            if data.empty:
                return 0.0
            
            # Known attack patterns (simplified)
            attack_patterns = {
                'bruteforce': ['authentication_failure', 'login_attempt'],
                'lateral_movement': ['privilege_escalation', 'file_access'],
                'data_exfiltration': ['data_access', 'network_transfer']
            }
            
            event_types = data['event_type'].value_counts().to_dict()
            
            max_similarity = 0.0
            
            for pattern_name, pattern_events in attack_patterns.items():
                similarity = 0.0
                
                for event_type in pattern_events:
                    if event_type in event_types:
                        similarity += event_types[event_type]
                
                # Normalize by total events
                similarity = similarity / len(data)
                max_similarity = max(max_similarity, similarity)
            
            return float(min(1.0, max_similarity))
            
        except Exception as e:
            self.logger.error(f"Error calculating pattern similarity: {e}")
            return 0.0
    
    def _calculate_lateral_movement(self, data: pd.DataFrame) -> float:
        """Calculate lateral movement indicator."""
        try:
            if data.empty or 'source' not in data.columns:
                return 0.0
            
            # Count unique sources
            unique_sources = data['source'].nunique()
            
            # Look for privilege escalation events
            priv_events = data[data['event_type'].str.contains('privilege', case=False, na=False)]
            
            # Score based on source diversity and privilege events
            source_score = min(1.0, unique_sources / 10.0)
            priv_score = min(1.0, len(priv_events) / len(data))
            
            return float((source_score + priv_score) / 2.0)
            
        except Exception as e:
            self.logger.error(f"Error calculating lateral movement: {e}")
            return 0.0
    
    def _calculate_classification_risk(self, data: pd.DataFrame) -> float:
        """Calculate classification breach risk."""
        try:
            if data.empty or 'classification' not in data.columns:
                return 0.0
            
            # Risk weights by classification
            risk_weights = {'U': 0.1, 'S': 0.5, 'TS': 1.0}
            
            total_risk = 0.0
            for _, row in data.iterrows():
                classification = row.get('classification', 'U')
                risk = risk_weights.get(classification, 0.1)
                
                # Increase risk for violation events
                if 'violation' in str(row.get('event_type', '')).lower():
                    risk *= 2.0
                
                total_risk += risk
            
            # Normalize
            return float(min(1.0, total_risk / len(data)))
            
        except Exception as e:
            self.logger.error(f"Error calculating classification risk: {e}")
            return 0.0
    
    def _calculate_compartment_violation(self, data: pd.DataFrame) -> float:
        """Calculate compartment violation score."""
        try:
            if data.empty:
                return 0.0
            
            # Count compartment-related events
            compartment_events = data[data['event_type'].str.contains('compartment', case=False, na=False)]
            
            if len(compartment_events) == 0:
                return 0.0
            
            # Score based on severity
            severity_score = compartment_events['severity'].mean() if 'severity' in compartment_events else 0
            
            return float(min(1.0, severity_score / 5.0))
            
        except Exception as e:
            self.logger.error(f"Error calculating compartment violation: {e}")
            return 0.0
    
    def _calculate_clearance_mismatch(self, data: pd.DataFrame) -> float:
        """Calculate clearance level mismatch."""
        try:
            if data.empty:
                return 0.0
            
            # Count clearance mismatch events
            mismatch_events = data[data['event_type'].str.contains('clearance', case=False, na=False)]
            
            return float(min(1.0, len(mismatch_events) / len(data)))
            
        except Exception as e:
            self.logger.error(f"Error calculating clearance mismatch: {e}")
            return 0.0
    
    def _calculate_byzantine_behavior(self, data: pd.DataFrame) -> float:
        """Calculate Byzantine node behavior indicator."""
        try:
            if data.empty or 'node_id' not in data.columns:
                return 0.0
            
            # Count Byzantine-related events
            byzantine_events = data[data['event_type'].str.contains('byzantine', case=False, na=False)]
            
            return float(min(1.0, len(byzantine_events) / len(data)))
            
        except Exception as e:
            self.logger.error(f"Error calculating Byzantine behavior: {e}")
            return 0.0
    
    def _calculate_consensus_disagreement(self, data: pd.DataFrame) -> float:
        """Calculate consensus disagreement rate."""
        try:
            if data.empty:
                return 0.0
            
            # Count consensus-related events
            consensus_events = data[data['event_type'].str.contains('consensus', case=False, na=False)]
            
            if len(consensus_events) == 0:
                return 0.0
            
            # Look for disagreement patterns
            disagreement_events = consensus_events[
                consensus_events['event_type'].str.contains('disagree', case=False, na=False)
            ]
            
            return float(len(disagreement_events) / len(consensus_events))
            
        except Exception as e:
            self.logger.error(f"Error calculating consensus disagreement: {e}")
            return 0.0
    
    def _calculate_fault_tolerance_degradation(self, data: pd.DataFrame) -> float:
        """Calculate fault tolerance degradation."""
        try:
            if data.empty:
                return 0.0
            
            # Count fault-related events
            fault_events = data[data['event_type'].str.contains('fault', case=False, na=False)]
            
            return float(min(1.0, len(fault_events) / len(data)))
            
        except Exception as e:
            self.logger.error(f"Error calculating fault tolerance degradation: {e}")
            return 0.0
    
    def _normalize_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Normalize feature values to [0,1] range."""
        try:
            normalized_df = features_df.copy()
            
            # Skip timestamp column
            feature_columns = [col for col in normalized_df.columns if col != 'timestamp']
            
            for column in feature_columns:
                if column in normalized_df.columns:
                    values = normalized_df[column].values
                    
                    # Calculate min-max normalization
                    min_val = np.min(values)
                    max_val = np.max(values)
                    
                    if max_val > min_val:
                        normalized_df[column] = (values - min_val) / (max_val - min_val)
                    else:
                        normalized_df[column] = 0.0
            
            return normalized_df
            
        except Exception as e:
            self.logger.error(f"Error normalizing features: {e}")
            return features_df
    
    def _cache_features(self, features_df: pd.DataFrame) -> None:
        """Cache feature vectors for future use."""
        try:
            for _, row in features_df.iterrows():
                feature_vector = FeatureVector(
                    timestamp=row.get('timestamp', datetime.now()),
                    features=row.to_dict(),
                    feature_definitions=self.feature_definitions,
                    source_data_count=1,
                    quality_score=1.0
                )
                
                self.feature_cache.append(feature_vector)
            
        except Exception as e:
            self.logger.error(f"Error caching features: {e}")
    
    def _update_performance_metrics(self, processing_time: float, vector_count: int) -> None:
        """Update performance metrics."""
        self.performance_metrics['total_feature_vectors'] += vector_count
        self.performance_metrics['last_processing_time'] = datetime.now().isoformat()
        
        # Update average processing time
        current_avg = self.performance_metrics['avg_processing_time']
        if current_avg == 0:
            self.performance_metrics['avg_processing_time'] = processing_time
        else:
            # Exponential moving average
            self.performance_metrics['avg_processing_time'] = 0.9 * current_avg + 0.1 * processing_time
    
    def get_feature_definitions(self) -> List[FeatureDefinition]:
        """Get feature definitions."""
        return self.feature_definitions
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        return self.performance_metrics.copy()
    
    def get_cached_features(self, limit: int = 100) -> List[FeatureVector]:
        """Get cached feature vectors."""
        return list(self.feature_cache)[-limit:]


# Example usage
async def demo_feature_engineer():
    """Demonstrate feature engineering capabilities."""
    
    # Initialize feature engineer
    engineer = FeatureEngineer(
        window_size=50,
        feature_cache_size=1000
    )
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 200
    
    sample_data = pd.DataFrame({
        'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='1min'),
        'event_type': np.random.choice(['login', 'logout', 'file_access', 'network_access'], n_samples),
        'source': np.random.choice(['server1', 'server2', 'server3', 'client1'], n_samples),
        'severity': np.random.randint(1, 6, n_samples),
        'classification': np.random.choice(['U', 'S', 'TS'], n_samples),
        'risk_score': np.random.random(n_samples),
        'threat_level': np.random.random(n_samples),
        'system_load': np.random.random(n_samples),
        'network_traffic': np.random.randint(1000, 10000, n_samples),
        'user_id': np.random.choice(['user1', 'user2', 'user3'], n_samples),
        'node_id': np.random.choice(['node1', 'node2', 'node3'], n_samples)
    })
    
    try:
        # Extract features
        print("Extracting features...")
        features_df = engineer.extract_features(sample_data)
        
        print(f"Original data shape: {sample_data.shape}")
        print(f"Features shape: {features_df.shape}")
        print(f"Feature columns: {list(features_df.columns)}")
        
        # Show sample features
        if not features_df.empty:
            print("\nSample features:")
            for col in features_df.columns[:5]:  # Show first 5 features
                print(f"  {col}: {features_df[col].iloc[0]:.3f}")
        
        # Get feature definitions
        definitions = engineer.get_feature_definitions()
        print(f"\nFeature definitions: {len(definitions)}")
        
        # Show performance metrics
        metrics = engineer.get_performance_metrics()
        print(f"Performance metrics: {metrics}")
        
        # Show cached features
        cached = engineer.get_cached_features(limit=5)
        print(f"Cached feature vectors: {len(cached)}")
        
    except Exception as e:
        print(f"Error in demo: {e}")


if __name__ == "__main__":
    asyncio.run(demo_feature_engineer()) 