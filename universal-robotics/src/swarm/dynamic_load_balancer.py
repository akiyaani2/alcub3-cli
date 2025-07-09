#!/usr/bin/env python3
"""
ALCUB3 Dynamic Load Balancer for Swarm Robotics
Predictive task reallocation with market-based optimization

This module implements intelligent load balancing with ML-based
prediction, market mechanisms, and emergency task migration.
"""

import asyncio
import time
import uuid
import json
import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler
import heapq

# Import security components
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))

from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger

# Import swarm components
from .distributed_task_allocator import SwarmTask, SwarmMember, TaskStatus, TaskPriority

logger = logging.getLogger(__name__)


class LoadBalancingStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    CAPABILITY_MATCH = "capability_match"
    MARKET_BASED = "market_based"
    PREDICTIVE = "predictive"
    EMERGENCY = "emergency"


class MigrationReason(Enum):
    """Reasons for task migration."""
    LOAD_IMBALANCE = "load_imbalance"
    MEMBER_FAILURE = "member_failure"
    DEADLINE_RISK = "deadline_risk"
    CAPABILITY_CHANGE = "capability_change"
    EMERGENCY_RESPONSE = "emergency_response"
    OPTIMIZATION = "optimization"


@dataclass
class TaskBid:
    """Bid for task execution in market-based allocation."""
    bidder_id: str
    task_id: str
    bid_price: float  # Lower is better (cost to execute)
    estimated_completion_time: float
    confidence_score: float  # 0.0 to 1.0
    capabilities_match: float  # 0.0 to 1.0
    timestamp: datetime
    
    def calculate_score(self, weight_price: float = 0.4, 
                       weight_time: float = 0.4, 
                       weight_confidence: float = 0.2) -> float:
        """Calculate overall bid score (lower is better)."""
        normalized_price = self.bid_price / 100.0  # Normalize to 0-1
        normalized_time = self.estimated_completion_time / 300.0  # Normalize to 5 min
        
        score = (weight_price * normalized_price + 
                weight_time * normalized_time + 
                weight_confidence * (1.0 - self.confidence_score))
        
        # Bonus for capability match
        score *= (2.0 - self.capabilities_match)
        
        return score


@dataclass
class LoadMetrics:
    """Real-time load metrics for a swarm member."""
    member_id: str
    timestamp: datetime
    cpu_usage: float  # 0.0 to 1.0
    memory_usage: float  # 0.0 to 1.0
    task_queue_length: int
    active_task_count: int
    average_task_duration: float  # seconds
    failure_rate: float  # 0.0 to 1.0
    network_latency: float  # ms
    battery_level: Optional[float] = None  # For mobile robots
    
    def calculate_load_score(self) -> float:
        """Calculate overall load score (0.0 = idle, 1.0 = overloaded)."""
        # Weighted combination of metrics
        score = (
            self.cpu_usage * 0.3 +
            self.memory_usage * 0.2 +
            min(self.task_queue_length / 10.0, 1.0) * 0.2 +
            min(self.active_task_count / 5.0, 1.0) * 0.2 +
            self.failure_rate * 0.1
        )
        
        # Penalty for low battery
        if self.battery_level is not None and self.battery_level < 0.3:
            score = min(1.0, score * (1.5 - self.battery_level))
        
        return min(1.0, score)


@dataclass
class TaskMigration:
    """Task migration record."""
    migration_id: str
    task_id: str
    from_member: str
    to_member: str
    reason: MigrationReason
    initiated_at: datetime
    completed_at: Optional[datetime] = None
    success: bool = False
    metrics_before: Optional[Dict[str, float]] = None
    metrics_after: Optional[Dict[str, float]] = None


class PredictiveLoadModel:
    """ML model for predicting future load and task completion times."""
    
    def __init__(self):
        self.completion_time_model = RandomForestRegressor(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.load_prediction_model = RandomForestRegressor(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.training_data = deque(maxlen=10000)
        self.is_trained = False
    
    def add_training_sample(
        self,
        task_features: Dict[str, float],
        member_features: Dict[str, float],
        actual_completion_time: float,
        actual_load_after: float
    ):
        """Add a training sample for model improvement."""
        sample = {
            'task_features': task_features,
            'member_features': member_features,
            'completion_time': actual_completion_time,
            'load_after': actual_load_after
        }
        self.training_data.append(sample)
        
        # Retrain periodically
        if len(self.training_data) >= 100 and len(self.training_data) % 100 == 0:
            self._retrain_models()
    
    def _retrain_models(self):
        """Retrain prediction models with accumulated data."""
        if len(self.training_data) < 50:
            return
        
        # Prepare training data
        X = []
        y_time = []
        y_load = []
        
        for sample in self.training_data:
            features = list(sample['task_features'].values()) + \
                      list(sample['member_features'].values())
            X.append(features)
            y_time.append(sample['completion_time'])
            y_load.append(sample['load_after'])
        
        X = np.array(X)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train models
        self.completion_time_model.fit(X_scaled, y_time)
        self.load_prediction_model.fit(X_scaled, y_load)
        
        self.is_trained = True
        logger.info("Retrained predictive models with %d samples", len(self.training_data))
    
    def predict_completion_time(
        self,
        task_features: Dict[str, float],
        member_features: Dict[str, float]
    ) -> Tuple[float, float]:
        """
        Predict task completion time.
        
        Returns:
            Tuple of (predicted_time, confidence_score)
        """
        if not self.is_trained:
            # Fallback to heuristic
            base_time = task_features.get('expected_duration', 60.0)
            load_factor = 1.0 + member_features.get('current_load', 0.5)
            return base_time * load_factor, 0.5
        
        # Prepare features
        features = list(task_features.values()) + list(member_features.values())
        X = np.array([features])
        X_scaled = self.scaler.transform(X)
        
        # Predict
        prediction = self.completion_time_model.predict(X_scaled)[0]
        
        # Calculate confidence based on prediction variance
        predictions = []
        for estimator in self.completion_time_model.estimators_:
            predictions.append(estimator.predict(X_scaled)[0])
        
        std_dev = np.std(predictions)
        confidence = 1.0 / (1.0 + std_dev / prediction)
        
        return prediction, confidence
    
    def predict_load_impact(
        self,
        current_load: float,
        task_features: Dict[str, float],
        member_features: Dict[str, float]
    ) -> float:
        """Predict load after task assignment."""
        if not self.is_trained:
            # Simple heuristic
            task_weight = task_features.get('resource_intensity', 0.1)
            return min(1.0, current_load + task_weight)
        
        # Prepare features
        member_features['current_load'] = current_load
        features = list(task_features.values()) + list(member_features.values())
        X = np.array([features])
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predicted_load = self.load_prediction_model.predict(X_scaled)[0]
        return min(1.0, max(0.0, predicted_load))


class MarketMechanism:
    """Market-based task allocation mechanism."""
    
    def __init__(self, reserve_price: float = 100.0):
        self.reserve_price = reserve_price
        self.market_history = deque(maxlen=1000)
        self.price_adjustments: Dict[str, float] = defaultdict(lambda: 1.0)
    
    def calculate_bid_price(
        self,
        member: SwarmMember,
        task: SwarmTask,
        load_metrics: LoadMetrics
    ) -> float:
        """Calculate bid price for a task."""
        # Base cost from load
        base_cost = load_metrics.calculate_load_score() * 50.0
        
        # Capability match discount
        capability_match = self._calculate_capability_match(member, task)
        capability_discount = (1.0 - capability_match) * 20.0
        
        # Urgency premium for critical tasks
        urgency_premium = 0.0
        if task.priority == TaskPriority.CRITICAL:
            urgency_premium = -30.0  # Negative to encourage bidding
        
        # Historical performance adjustment
        performance_adjustment = self.price_adjustments[member.member_id]
        
        # Calculate final bid
        bid_price = (base_cost + capability_discount + urgency_premium) * performance_adjustment
        
        return max(0.0, bid_price)
    
    def _calculate_capability_match(self, member: SwarmMember, task: SwarmTask) -> float:
        """Calculate how well member capabilities match task requirements."""
        if not task.required_capabilities:
            return 1.0
        
        member_caps = {cap.capability_id for cap in member.capabilities}
        matched = sum(1 for req in task.required_capabilities if req in member_caps)
        
        return matched / len(task.required_capabilities)
    
    def conduct_auction(
        self,
        task: SwarmTask,
        bids: List[TaskBid],
        min_bids: int = 1
    ) -> Optional[TaskBid]:
        """Conduct sealed-bid auction for task allocation."""
        if len(bids) < min_bids:
            return None
        
        # Filter bids below reserve price
        valid_bids = [bid for bid in bids if bid.bid_price <= self.reserve_price]
        
        if not valid_bids:
            return None
        
        # Sort by overall score
        valid_bids.sort(key=lambda b: b.calculate_score())
        
        # Select winner
        winning_bid = valid_bids[0]
        
        # Record market transaction
        self.market_history.append({
            'task_id': task.task_id,
            'winning_bid': winning_bid.bid_price,
            'bidder_id': winning_bid.bidder_id,
            'num_bids': len(bids),
            'timestamp': datetime.now()
        })
        
        return winning_bid
    
    def update_member_performance(self, member_id: str, success: bool, completion_ratio: float):
        """Update member's price adjustment based on performance."""
        current_adjustment = self.price_adjustments[member_id]
        
        if success:
            # Reduce price for good performance
            self.price_adjustments[member_id] = max(0.5, current_adjustment * 0.95)
        else:
            # Increase price for poor performance
            self.price_adjustments[member_id] = min(2.0, current_adjustment * 1.1)


class DynamicLoadBalancer:
    """
    Dynamic load balancer with:
    - Real-time load monitoring
    - Predictive task allocation
    - Market-based optimization
    - Emergency task migration
    """
    
    def __init__(
        self,
        strategy: LoadBalancingStrategy = LoadBalancingStrategy.PREDICTIVE,
        audit_logger: Optional[AuditLogger] = None
    ):
        self.strategy = strategy
        self.audit_logger = audit_logger or AuditLogger()
        
        # Components
        self.predictive_model = PredictiveLoadModel()
        self.market_mechanism = MarketMechanism()
        
        # State tracking
        self.member_loads: Dict[str, LoadMetrics] = {}
        self.task_assignments: Dict[str, str] = {}  # task_id -> member_id
        self.migration_history: deque = deque(maxlen=1000)
        self.load_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Configuration
        self.load_threshold_high = 0.8
        self.load_threshold_low = 0.3
        self.imbalance_threshold = 0.3
        self.migration_cooldown = timedelta(minutes=5)
        
        # Metrics
        self.balancing_metrics = {
            'total_migrations': 0,
            'successful_migrations': 0,
            'failed_migrations': 0,
            'average_load_variance': 0.0,
            'prediction_accuracy': deque(maxlen=100)
        }
        
        logger.info("Dynamic load balancer initialized with strategy: %s", strategy)
    
    async def update_member_load(self, member_id: str, metrics: LoadMetrics):
        """Update load metrics for a swarm member."""
        self.member_loads[member_id] = metrics
        self.load_history[member_id].append({
            'timestamp': metrics.timestamp,
            'load_score': metrics.calculate_load_score()
        })
        
        # Check for load imbalance
        if await self._detect_load_imbalance():
            asyncio.create_task(self._rebalance_load())
    
    async def allocate_task(
        self,
        task: SwarmTask,
        members: Dict[str, SwarmMember]
    ) -> Optional[str]:
        """Allocate task using configured strategy."""
        if self.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            return self._allocate_round_robin(task, members)
        
        elif self.strategy == LoadBalancingStrategy.LEAST_LOADED:
            return self._allocate_least_loaded(task, members)
        
        elif self.strategy == LoadBalancingStrategy.CAPABILITY_MATCH:
            return self._allocate_capability_match(task, members)
        
        elif self.strategy == LoadBalancingStrategy.MARKET_BASED:
            return await self._allocate_market_based(task, members)
        
        elif self.strategy == LoadBalancingStrategy.PREDICTIVE:
            return await self._allocate_predictive(task, members)
        
        elif self.strategy == LoadBalancingStrategy.EMERGENCY:
            return self._allocate_emergency(task, members)
        
        return None
    
    def _allocate_round_robin(
        self,
        task: SwarmTask,
        members: Dict[str, SwarmMember]
    ) -> Optional[str]:
        """Simple round-robin allocation."""
        eligible_members = [
            m for m in members.values()
            if m.can_execute_task(task)
        ]
        
        if not eligible_members:
            return None
        
        # Sort by last assignment to ensure fairness
        eligible_members.sort(key=lambda m: len(m.active_tasks))
        return eligible_members[0].member_id
    
    def _allocate_least_loaded(
        self,
        task: SwarmTask,
        members: Dict[str, SwarmMember]
    ) -> Optional[str]:
        """Allocate to least loaded member."""
        eligible_scores = []
        
        for member in members.values():
            if not member.can_execute_task(task):
                continue
            
            load_metrics = self.member_loads.get(member.member_id)
            if load_metrics:
                load_score = load_metrics.calculate_load_score()
                heapq.heappush(eligible_scores, (load_score, member.member_id))
        
        if eligible_scores:
            return heapq.heappop(eligible_scores)[1]
        
        return None
    
    def _allocate_capability_match(
        self,
        task: SwarmTask,
        members: Dict[str, SwarmMember]
    ) -> Optional[str]:
        """Allocate based on best capability match."""
        best_match = None
        best_score = 0.0
        
        for member in members.values():
            if not member.can_execute_task(task):
                continue
            
            # Calculate capability match score
            member_caps = {cap.capability_id for cap in member.capabilities}
            if task.required_capabilities:
                match_score = sum(
                    1 for req in task.required_capabilities 
                    if req in member_caps
                ) / len(task.required_capabilities)
            else:
                match_score = 1.0
            
            # Factor in load
            load_metrics = self.member_loads.get(member.member_id)
            if load_metrics:
                match_score *= (1.0 - load_metrics.calculate_load_score())
            
            if match_score > best_score:
                best_score = match_score
                best_match = member.member_id
        
        return best_match
    
    async def _allocate_market_based(
        self,
        task: SwarmTask,
        members: Dict[str, SwarmMember]
    ) -> Optional[str]:
        """Market-based task allocation through bidding."""
        # Collect bids
        bids = []
        
        for member in members.values():
            if not member.can_execute_task(task):
                continue
            
            load_metrics = self.member_loads.get(member.member_id)
            if not load_metrics:
                continue
            
            # Calculate bid
            bid_price = self.market_mechanism.calculate_bid_price(
                member, task, load_metrics
            )
            
            # Predict completion time
            task_features = {
                'priority': task.priority.value,
                'num_capabilities': len(task.required_capabilities),
                'has_deadline': 1.0 if task.deadline else 0.0
            }
            member_features = {
                'reliability': member.reliability_score,
                'current_load': member.current_load,
                'active_tasks': len(member.active_tasks)
            }
            
            completion_time, confidence = self.predictive_model.predict_completion_time(
                task_features, member_features
            )
            
            bid = TaskBid(
                bidder_id=member.member_id,
                task_id=task.task_id,
                bid_price=bid_price,
                estimated_completion_time=completion_time,
                confidence_score=confidence,
                capabilities_match=member.calculate_suitability_score(task) / 100.0,
                timestamp=datetime.now()
            )
            
            bids.append(bid)
        
        # Conduct auction
        winning_bid = self.market_mechanism.conduct_auction(task, bids)
        
        if winning_bid:
            # Record allocation
            self.task_assignments[task.task_id] = winning_bid.bidder_id
            
            await self.audit_logger.log_event(
                "MARKET_BASED_ALLOCATION",
                classification=task.classification,
                details={
                    'task_id': task.task_id,
                    'winner': winning_bid.bidder_id,
                    'bid_price': winning_bid.bid_price,
                    'estimated_time': winning_bid.estimated_completion_time,
                    'num_bidders': len(bids)
                }
            )
            
            return winning_bid.bidder_id
        
        return None
    
    async def _allocate_predictive(
        self,
        task: SwarmTask,
        members: Dict[str, SwarmMember]
    ) -> Optional[str]:
        """Predictive allocation using ML models."""
        best_member = None
        best_score = float('inf')
        
        task_features = {
            'priority': task.priority.value,
            'num_capabilities': len(task.required_capabilities),
            'has_deadline': 1.0 if task.deadline else 0.0,
            'urgency': task.calculate_urgency()
        }
        
        for member in members.values():
            if not member.can_execute_task(task):
                continue
            
            load_metrics = self.member_loads.get(member.member_id)
            if not load_metrics:
                continue
            
            member_features = {
                'reliability': member.reliability_score,
                'current_load': load_metrics.calculate_load_score(),
                'active_tasks': len(member.active_tasks),
                'cpu_usage': load_metrics.cpu_usage,
                'failure_rate': load_metrics.failure_rate
            }
            
            # Predict completion time
            pred_time, confidence = self.predictive_model.predict_completion_time(
                task_features, member_features
            )
            
            # Predict load impact
            pred_load = self.predictive_model.predict_load_impact(
                load_metrics.calculate_load_score(),
                task_features,
                member_features
            )
            
            # Calculate allocation score
            # Lower is better: prioritize fast completion and low load impact
            score = pred_time * (1.0 + pred_load) / confidence
            
            # Penalty for overloaded members
            if pred_load > self.load_threshold_high:
                score *= 2.0
            
            if score < best_score:
                best_score = score
                best_member = member.member_id
        
        if best_member:
            self.task_assignments[task.task_id] = best_member
        
        return best_member
    
    def _allocate_emergency(
        self,
        task: SwarmTask,
        members: Dict[str, SwarmMember]
    ) -> Optional[str]:
        """Emergency allocation for critical tasks."""
        # Find member with highest reliability and capability match
        candidates = []
        
        for member in members.values():
            if not member.can_execute_task(task):
                continue
            
            # Emergency score prioritizes reliability and capabilities
            score = member.reliability_score * member.calculate_suitability_score(task)
            
            # Boost score for less loaded members
            load_metrics = self.member_loads.get(member.member_id)
            if load_metrics:
                score *= (1.0 - load_metrics.calculate_load_score() * 0.5)
            
            candidates.append((score, member.member_id))
        
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]
        
        return None
    
    async def _detect_load_imbalance(self) -> bool:
        """Detect if load is imbalanced across swarm."""
        if len(self.member_loads) < 2:
            return False
        
        load_scores = [
            metrics.calculate_load_score() 
            for metrics in self.member_loads.values()
        ]
        
        if not load_scores:
            return False
        
        # Calculate variance
        mean_load = np.mean(load_scores)
        variance = np.var(load_scores)
        
        # Update metrics
        self.balancing_metrics['average_load_variance'] = variance
        
        # Check for imbalance
        max_load = max(load_scores)
        min_load = min(load_scores)
        
        return (max_load - min_load) > self.imbalance_threshold
    
    async def _rebalance_load(self):
        """Rebalance load through task migration."""
        # Find overloaded and underloaded members
        overloaded = []
        underloaded = []
        
        for member_id, metrics in self.member_loads.items():
            load_score = metrics.calculate_load_score()
            
            if load_score > self.load_threshold_high:
                overloaded.append((load_score, member_id))
            elif load_score < self.load_threshold_low:
                underloaded.append((load_score, member_id))
        
        if not overloaded or not underloaded:
            return
        
        # Sort for optimal pairing
        overloaded.sort(reverse=True)
        underloaded.sort()
        
        # Migrate tasks
        migrations_initiated = 0
        max_migrations = min(3, len(overloaded), len(underloaded))
        
        for i in range(max_migrations):
            source_id = overloaded[i][1]
            target_id = underloaded[i][1]
            
            # Find suitable task to migrate
            task_id = self._select_task_for_migration(source_id)
            
            if task_id:
                success = await self._migrate_task(
                    task_id,
                    source_id,
                    target_id,
                    MigrationReason.LOAD_IMBALANCE
                )
                
                if success:
                    migrations_initiated += 1
        
        logger.info("Load rebalancing: initiated %d migrations", migrations_initiated)
    
    def _select_task_for_migration(self, member_id: str) -> Optional[str]:
        """Select best task to migrate from overloaded member."""
        # Find tasks assigned to this member
        member_tasks = [
            task_id for task_id, assigned_to in self.task_assignments.items()
            if assigned_to == member_id
        ]
        
        if not member_tasks:
            return None
        
        # TODO: Implement smart selection based on task characteristics
        # For now, return first task
        return member_tasks[0]
    
    async def _migrate_task(
        self,
        task_id: str,
        from_member: str,
        to_member: str,
        reason: MigrationReason
    ) -> bool:
        """Migrate task between members."""
        migration = TaskMigration(
            migration_id=str(uuid.uuid4()),
            task_id=task_id,
            from_member=from_member,
            to_member=to_member,
            reason=reason,
            initiated_at=datetime.now()
        )
        
        # Record metrics before migration
        from_metrics = self.member_loads.get(from_member)
        to_metrics = self.member_loads.get(to_member)
        
        if from_metrics and to_metrics:
            migration.metrics_before = {
                'from_load': from_metrics.calculate_load_score(),
                'to_load': to_metrics.calculate_load_score()
            }
        
        try:
            # TODO: Implement actual task migration protocol
            # For now, just update assignment
            self.task_assignments[task_id] = to_member
            
            # Mark migration successful
            migration.completed_at = datetime.now()
            migration.success = True
            
            # Update metrics
            self.balancing_metrics['total_migrations'] += 1
            self.balancing_metrics['successful_migrations'] += 1
            
            # Audit log
            await self.audit_logger.log_event(
                "TASK_MIGRATED",
                classification=ClassificationLevel.UNCLASSIFIED,
                details={
                    'migration_id': migration.migration_id,
                    'task_id': task_id,
                    'from': from_member,
                    'to': to_member,
                    'reason': reason.value
                }
            )
            
            return True
            
        except Exception as e:
            logger.error("Task migration failed: %s", e)
            migration.success = False
            self.balancing_metrics['failed_migrations'] += 1
            return False
        
        finally:
            self.migration_history.append(migration)
    
    async def handle_member_failure(self, failed_member_id: str):
        """Handle member failure by migrating all its tasks."""
        # Find all tasks assigned to failed member
        affected_tasks = [
            task_id for task_id, member_id in self.task_assignments.items()
            if member_id == failed_member_id
        ]
        
        logger.warning("Member %s failed, migrating %d tasks", 
                      failed_member_id, len(affected_tasks))
        
        # Remove failed member from loads
        if failed_member_id in self.member_loads:
            del self.member_loads[failed_member_id]
        
        # Migrate each task
        for task_id in affected_tasks:
            # Find new member using emergency allocation
            # TODO: Get actual task and member objects
            # For now, assign to least loaded member
            target_member = self._find_least_loaded_member()
            
            if target_member:
                await self._migrate_task(
                    task_id,
                    failed_member_id,
                    target_member,
                    MigrationReason.MEMBER_FAILURE
                )
    
    def _find_least_loaded_member(self) -> Optional[str]:
        """Find member with lowest load."""
        if not self.member_loads:
            return None
        
        loads = [
            (metrics.calculate_load_score(), member_id)
            for member_id, metrics in self.member_loads.items()
        ]
        
        loads.sort()
        return loads[0][1] if loads else None
    
    def get_load_balancing_metrics(self) -> Dict[str, Any]:
        """Get load balancing performance metrics."""
        load_scores = [
            metrics.calculate_load_score()
            for metrics in self.member_loads.values()
        ]
        
        return {
            'strategy': self.strategy.value,
            'active_members': len(self.member_loads),
            'total_migrations': self.balancing_metrics['total_migrations'],
            'successful_migrations': self.balancing_metrics['successful_migrations'],
            'failed_migrations': self.balancing_metrics['failed_migrations'],
            'migration_success_rate': (
                self.balancing_metrics['successful_migrations'] / 
                max(1, self.balancing_metrics['total_migrations'])
            ),
            'average_load': np.mean(load_scores) if load_scores else 0.0,
            'load_variance': np.var(load_scores) if load_scores else 0.0,
            'max_load': max(load_scores) if load_scores else 0.0,
            'min_load': min(load_scores) if load_scores else 0.0,
            'prediction_model_trained': self.predictive_model.is_trained,
            'market_transactions': len(self.market_mechanism.market_history)
        }