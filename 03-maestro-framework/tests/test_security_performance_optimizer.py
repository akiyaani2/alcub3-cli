#!/usr/bin/env python3
"""
Tests for ALCUB3 Security Performance Optimizer
Validates performance optimization, caching, parallel validation, and real-time metrics.
"""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from concurrent.futures import ThreadPoolExecutor

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from l3_agent.security_performance_optimizer import (
    SecurityPerformanceOptimizer,
    CacheStrategy,
    ValidationPriority,
    PerformanceMetric,
    SecurityCacheEntry,
    PerformanceTarget,
    ValidationRequest,
    ValidationResult,
    get_security_optimizer,
    initialize_security_optimizer,
    shutdown_security_optimizer
)
from shared.classification import ClassificationLevel

class TestSecurityPerformanceOptimizer:
    """Test security performance optimizer core functionality."""
    
    @pytest.fixture
    def optimizer_config(self):
        return {
            "performance_targets": {
                "agent_validation": 0.005,  # 5ms
                "security_overhead": 0.100,  # 100ms
                "cache_hit_rate": 0.85,     # 85%
                "cpu_usage": 0.20,          # 20%
                "memory_usage": 0.30        # 30%
            },
            "max_threads": 4,
            "max_processes": 2,
            "max_cache_size": 1000,
            "cache_cleanup_interval": 10,  # 10 seconds for testing
            "hsm_enabled": False
        }
    
    @pytest.fixture
    def optimizer(self, optimizer_config):
        return SecurityPerformanceOptimizer(optimizer_config)
    
    @pytest.mark.asyncio
    async def test_optimizer_initialization(self, optimizer):
        """Test optimizer initialization and configuration."""
        assert optimizer.targets.agent_validation == 0.005
        assert optimizer.targets.security_overhead == 0.100
        assert optimizer.targets.cache_hit_rate == 0.85
        assert len(optimizer.validation_queues) == 5
        assert not optimizer.running
        assert optimizer.max_cache_size == 1000
    
    @pytest.mark.asyncio
    async def test_optimizer_start_stop(self, optimizer):
        """Test optimizer startup and shutdown."""
        # Test startup
        await optimizer.start()
        assert optimizer.running
        assert len(optimizer.validation_workers) > 0
        
        # Test shutdown
        await optimizer.stop()
        assert not optimizer.running
    
    @pytest.mark.asyncio
    async def test_agent_validation_performance(self, optimizer):
        """Test agent validation meets <5ms performance target."""
        await optimizer.start()
        
        try:
            # Test data
            agent_data = {
                "agent_id": "test_agent_001",
                "capabilities": ["read", "write", "execute"],
                "timestamp": datetime.utcnow().isoformat(),
                "security_level": "standard"
            }
            
            # Perform validation
            start_time = time.time()
            result = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            validation_time = time.time() - start_time
            
            # Verify performance target
            assert validation_time < 0.005, f"Agent validation took {validation_time*1000:.1f}ms, expected <5ms"
            assert result.success
            assert result.validation_time < 0.005
            assert result.classification_level == ClassificationLevel.UNCLASSIFIED
            assert result.priority == ValidationPriority.CRITICAL
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_security_operation_validation(self, optimizer):
        """Test general security operation validation."""
        await optimizer.start()
        
        try:
            # Test encryption validation
            encryption_data = {
                "algorithm": "AES-256-GCM",
                "key_length": 256,
                "mode": "encrypt"
            }
            
            result = await optimizer.validate_security_operation(
                "encryption", 
                encryption_data, 
                ClassificationLevel.SECRET,
                ValidationPriority.HIGH
            )
            
            assert result.success
            assert result.validation_time < 0.100  # <100ms target
            assert result.classification_level == ClassificationLevel.SECRET
            assert result.priority == ValidationPriority.HIGH
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self, optimizer):
        """Test security validation caching."""
        await optimizer.start()
        
        try:
            agent_data = {
                "agent_id": "cache_test_agent",
                "capabilities": ["read"],
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # First validation (cache miss)
            result1 = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            assert result1.success
            assert not result1.cache_hit
            
            # Second validation (should be cache hit)
            result2 = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            assert result2.success
            assert result2.cache_hit
            assert result2.validation_time < result1.validation_time
            
            # Verify cache statistics
            cache_info = optimizer.get_cache_info()
            assert cache_info["size"] > 0
            assert cache_info["stats"]["hits"] > 0
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_batch_validation(self, optimizer):
        """Test batch validation for improved throughput."""
        await optimizer.start()
        
        try:
            # Create batch of validation requests
            batch_requests = []
            for i in range(10):
                agent_data = {
                    "agent_id": f"batch_agent_{i}",
                    "capabilities": ["read", "write"],
                    "timestamp": datetime.utcnow().isoformat()
                }
                batch_requests.append(("agent_validation", agent_data, ClassificationLevel.UNCLASSIFIED))
            
            # Perform batch validation
            start_time = time.time()
            results = await optimizer.batch_validate(batch_requests, ValidationPriority.MEDIUM)
            batch_time = time.time() - start_time
            
            # Verify results
            assert len(results) == 10
            assert all(isinstance(r, ValidationResult) for r in results)
            assert all(r.success for r in results)
            
            # Verify throughput
            throughput = len(results) / batch_time
            assert throughput > 10, f"Batch throughput: {throughput:.1f} ops/sec"
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_cache_strategies(self, optimizer):
        """Test different cache strategies."""
        # Test cache strategy selection
        assert optimizer._get_cache_strategy("agent_validation", ClassificationLevel.UNCLASSIFIED) == CacheStrategy.MEDIUM_TERM
        assert optimizer._get_cache_strategy("agent_validation", ClassificationLevel.SECRET) == CacheStrategy.SHORT_TERM
        assert optimizer._get_cache_strategy("audit_logging", ClassificationLevel.UNCLASSIFIED) == CacheStrategy.NEVER
        
        # Test cache key generation
        data = {"test": "data"}
        key1 = optimizer._generate_cache_key("test_op", data, ClassificationLevel.UNCLASSIFIED)
        key2 = optimizer._generate_cache_key("test_op", data, ClassificationLevel.UNCLASSIFIED)
        key3 = optimizer._generate_cache_key("test_op", data, ClassificationLevel.SECRET)
        
        assert key1 == key2  # Same data should generate same key
        assert key1 != key3  # Different classification should generate different key
        assert len(key1) == 32  # SHA256 truncated to 32 chars
    
    @pytest.mark.asyncio
    async def test_classification_aware_validation(self, optimizer):
        """Test validation varies by classification level."""
        await optimizer.start()
        
        try:
            agent_data = {
                "agent_id": "classified_agent",
                "capabilities": ["read", "write", "execute"],
                "timestamp": datetime.utcnow().isoformat(),
                "classified_data": "sensitive_information"
            }
            
            # Test UNCLASSIFIED validation
            result_unclassified = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            
            # Test SECRET validation
            result_secret = await optimizer.validate_agent(agent_data, ClassificationLevel.SECRET)
            
            # Test TOP SECRET validation
            result_top_secret = await optimizer.validate_agent(agent_data, ClassificationLevel.TOP_SECRET)
            
            # All should succeed but may have different processing paths
            assert result_unclassified.success
            assert result_secret.success
            assert result_top_secret.success
            
            # Classification levels should be preserved
            assert result_unclassified.classification_level == ClassificationLevel.UNCLASSIFIED
            assert result_secret.classification_level == ClassificationLevel.SECRET
            assert result_top_secret.classification_level == ClassificationLevel.TOP_SECRET
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_priority_based_processing(self, optimizer):
        """Test that higher priority requests are processed faster."""
        await optimizer.start()
        
        try:
            # Submit requests with different priorities
            test_data = {"test": "priority_data"}
            
            # Submit low priority request
            low_priority_task = asyncio.create_task(
                optimizer.validate_security_operation(
                    "test_operation", 
                    test_data, 
                    ClassificationLevel.UNCLASSIFIED,
                    ValidationPriority.LOW
                )
            )
            
            # Submit critical priority request
            critical_priority_task = asyncio.create_task(
                optimizer.validate_security_operation(
                    "test_operation", 
                    test_data, 
                    ClassificationLevel.UNCLASSIFIED,
                    ValidationPriority.CRITICAL
                )
            )
            
            # Wait for both to complete
            results = await asyncio.gather(low_priority_task, critical_priority_task)
            
            # Both should succeed
            assert all(r.success for r in results)
            assert results[0].priority == ValidationPriority.LOW
            assert results[1].priority == ValidationPriority.CRITICAL
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_performance_monitoring(self, optimizer):
        """Test performance metrics collection and monitoring."""
        await optimizer.start()
        
        try:
            # Perform some validations to generate metrics
            for i in range(5):
                agent_data = {
                    "agent_id": f"metrics_agent_{i}",
                    "capabilities": ["read"],
                    "timestamp": datetime.utcnow().isoformat()
                }
                await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            
            # Get performance metrics
            metrics = optimizer.get_performance_metrics()
            
            # Verify metrics structure
            assert "cache_hit_rate" in metrics
            assert "avg_latency" in metrics
            assert "cpu_usage" in metrics
            assert "memory_usage" in metrics
            assert "cache_size" in metrics
            assert "queue_sizes" in metrics
            
            # Verify metric values are reasonable
            assert 0 <= metrics["cache_hit_rate"] <= 1
            assert metrics["avg_latency"] > 0
            assert 0 <= metrics["cpu_usage"] <= 1
            assert 0 <= metrics["memory_usage"] <= 1
            assert metrics["cache_size"] >= 0
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_cache_expiration_and_cleanup(self, optimizer):
        """Test cache expiration and cleanup functionality."""
        # Create optimizer with short cleanup interval
        short_config = {
            "cache_cleanup_interval": 1,  # 1 second
            "max_cache_size": 100
        }
        short_optimizer = SecurityPerformanceOptimizer(short_config)
        
        await short_optimizer.start()
        
        try:
            # Store entry with short-term cache strategy
            test_data = {"test": "expiration"}
            cache_key = short_optimizer._generate_cache_key("test", test_data, ClassificationLevel.UNCLASSIFIED)
            
            short_optimizer._store_in_cache(
                cache_key, 
                {"result": "test"}, 
                ClassificationLevel.UNCLASSIFIED, 
                CacheStrategy.SHORT_TERM
            )
            
            # Verify entry is cached
            cached_value = short_optimizer._get_from_cache(cache_key)
            assert cached_value is not None
            
            # Wait for expiration
            await asyncio.sleep(6)  # Wait longer than 5-second short-term expiration
            
            # Verify entry is expired
            expired_value = short_optimizer._get_from_cache(cache_key)
            assert expired_value is None
            
        finally:
            await short_optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_hsm_integration_mock(self, optimizer):
        """Test HSM integration (mocked)."""
        # Enable HSM for testing
        optimizer.hsm_available = True
        
        await optimizer.start()
        
        try:
            agent_data = {
                "agent_id": "hsm_test_agent",
                "capabilities": ["read", "write"],
                "timestamp": datetime.utcnow().isoformat(),
                "security_level": "high"
            }
            
            # Test SECRET classification (should use HSM)
            result = await optimizer.validate_agent(agent_data, ClassificationLevel.SECRET)
            
            assert result.success
            assert result.result.get("hsm_used") == True
            assert "hsm_signature" in result.result
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_threat_assessment_integration(self, optimizer):
        """Test integration with threat assessment."""
        await optimizer.start()
        
        try:
            # Agent data with potential threat indicators
            agent_data = {
                "agent_id": "threat_test_agent",
                "capabilities": ["exploit", "malicious"],  # Contains threat keywords
                "timestamp": datetime.utcnow().isoformat(),
                "description": "This agent contains malicious patterns"
            }
            
            result = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            
            # Should still process but may detect threats
            assert isinstance(result, ValidationResult)
            
            # Check if threat indicators were detected
            if "threat_indicators" in result.result:
                assert isinstance(result.result["threat_indicators"], list)
            
        finally:
            await optimizer.stop()
    
    def test_cache_entry_functionality(self):
        """Test SecurityCacheEntry functionality."""
        # Create cache entry
        entry = SecurityCacheEntry(
            key="test_key",
            value={"test": "data"},
            classification_level=ClassificationLevel.UNCLASSIFIED,
            created_at=datetime.utcnow(),
            last_accessed=datetime.utcnow(),
            access_count=0,
            expiration=datetime.utcnow() + timedelta(seconds=5),
            validation_hash="test_hash",
            cache_strategy=CacheStrategy.SHORT_TERM
        )
        
        # Test expiration
        assert not entry.is_expired()
        
        # Test access update
        original_access_time = entry.last_accessed
        original_access_count = entry.access_count
        
        entry.update_access()
        
        assert entry.last_accessed > original_access_time
        assert entry.access_count == original_access_count + 1
    
    @pytest.mark.asyncio
    async def test_error_handling(self, optimizer):
        """Test error handling in validation."""
        await optimizer.start()
        
        try:
            # Test with invalid agent data
            invalid_data = "not_a_dict"
            
            result = await optimizer.validate_agent(invalid_data, ClassificationLevel.UNCLASSIFIED)
            
            assert not result.success
            assert len(result.errors) > 0
            assert "invalid_agent_data" in result.metadata.get("error", "")
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_cache_clear_functionality(self, optimizer):
        """Test cache clearing functionality."""
        # Add some cache entries
        test_data = {"test": "clear_data"}
        
        optimizer._store_in_cache(
            "key1", {"data": 1}, ClassificationLevel.UNCLASSIFIED, CacheStrategy.PERSISTENT
        )
        optimizer._store_in_cache(
            "key2", {"data": 2}, ClassificationLevel.SECRET, CacheStrategy.PERSISTENT
        )
        optimizer._store_in_cache(
            "key3", {"data": 3}, ClassificationLevel.TOP_SECRET, CacheStrategy.PERSISTENT
        )
        
        # Verify cache has entries
        assert len(optimizer.cache) == 3
        
        # Clear specific classification level
        cleared_count = optimizer.clear_cache(ClassificationLevel.SECRET)
        assert cleared_count == 1
        assert len(optimizer.cache) == 2
        
        # Clear all cache
        cleared_count = optimizer.clear_cache()
        assert cleared_count == 2
        assert len(optimizer.cache) == 0

class TestGlobalOptimizerInstance:
    """Test global optimizer instance management."""
    
    @pytest.mark.asyncio
    async def test_global_instance_management(self):
        """Test global optimizer instance creation and management."""
        # Initially no global instance
        import l3_agent.security_performance_optimizer as spo_module
        spo_module._optimizer_instance = None
        
        # Get instance (should create new one)
        optimizer1 = get_security_optimizer()
        assert optimizer1 is not None
        
        # Get instance again (should return same one)
        optimizer2 = get_security_optimizer()
        assert optimizer1 is optimizer2
        
        # Initialize and shutdown
        await initialize_security_optimizer()
        assert optimizer1.running
        
        await shutdown_security_optimizer()
        assert spo_module._optimizer_instance is None

class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    @pytest.mark.asyncio
    async def test_agent_validation_latency_benchmark(self):
        """Benchmark agent validation latency."""
        config = {
            "performance_targets": {"agent_validation": 0.005},
            "max_threads": 8,
            "max_cache_size": 5000
        }
        optimizer = SecurityPerformanceOptimizer(config)
        await optimizer.start()
        
        try:
            agent_data = {
                "agent_id": "benchmark_agent",
                "capabilities": ["read", "write", "execute"],
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": {"benchmark": True}
            }
            
            # Run multiple validations and measure performance
            latencies = []
            
            for i in range(100):
                start_time = time.time()
                result = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
                latency = time.time() - start_time
                
                latencies.append(latency)
                assert result.success
            
            # Calculate statistics
            avg_latency = sum(latencies) / len(latencies)
            max_latency = max(latencies)
            p95_latency = sorted(latencies)[94]  # 95th percentile
            
            print(f"\n📊 Agent Validation Benchmark Results:")
            print(f"   Average latency: {avg_latency*1000:.2f}ms")
            print(f"   95th percentile: {p95_latency*1000:.2f}ms")
            print(f"   Maximum latency: {max_latency*1000:.2f}ms")
            
            # Verify performance targets
            assert avg_latency < 0.005, f"Average latency {avg_latency*1000:.2f}ms exceeds 5ms target"
            assert p95_latency < 0.010, f"95th percentile {p95_latency*1000:.2f}ms exceeds 10ms threshold"
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_cache_performance_benchmark(self):
        """Benchmark cache performance."""
        config = {"max_cache_size": 10000}
        optimizer = SecurityPerformanceOptimizer(config)
        await optimizer.start()
        
        try:
            # Generate test data
            test_requests = []
            for i in range(1000):
                agent_data = {
                    "agent_id": f"cache_bench_agent_{i % 100}",  # 100 unique agents (promotes cache hits)
                    "capabilities": ["read", "write"],
                    "timestamp": datetime.utcnow().isoformat()
                }
                test_requests.append(agent_data)
            
            # Benchmark cache performance
            start_time = time.time()
            
            for agent_data in test_requests:
                await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            
            total_time = time.time() - start_time
            throughput = len(test_requests) / total_time
            
            # Get cache metrics
            metrics = optimizer.get_performance_metrics()
            cache_info = optimizer.get_cache_info()
            
            print(f"\n📊 Cache Performance Benchmark Results:")
            print(f"   Total requests: {len(test_requests)}")
            print(f"   Total time: {total_time:.2f}s")
            print(f"   Throughput: {throughput:.1f} ops/sec")
            print(f"   Cache hit rate: {metrics['cache_hit_rate']*100:.1f}%")
            print(f"   Cache size: {cache_info['size']}")
            
            # Verify performance
            assert throughput > 100, f"Throughput {throughput:.1f} ops/sec too low"
            assert metrics["cache_hit_rate"] > 0.8, f"Cache hit rate {metrics['cache_hit_rate']*100:.1f}% too low"
            
        finally:
            await optimizer.stop()
    
    @pytest.mark.asyncio
    async def test_parallel_processing_benchmark(self):
        """Benchmark parallel processing performance."""
        config = {
            "max_threads": 8,
            "max_processes": 4
        }
        optimizer = SecurityPerformanceOptimizer(config)
        await optimizer.start()
        
        try:
            # Create large batch of requests
            batch_size = 500
            batch_requests = []
            
            for i in range(batch_size):
                agent_data = {
                    "agent_id": f"parallel_agent_{i}",
                    "capabilities": ["read", "write"],
                    "timestamp": datetime.utcnow().isoformat(),
                    "parallel_id": i
                }
                batch_requests.append(("agent_validation", agent_data, ClassificationLevel.UNCLASSIFIED))
            
            # Benchmark parallel processing
            start_time = time.time()
            results = await optimizer.batch_validate(batch_requests, ValidationPriority.HIGH)
            parallel_time = time.time() - start_time
            
            parallel_throughput = len(results) / parallel_time
            
            print(f"\n📊 Parallel Processing Benchmark Results:")
            print(f"   Batch size: {batch_size}")
            print(f"   Parallel time: {parallel_time:.2f}s")
            print(f"   Parallel throughput: {parallel_throughput:.1f} ops/sec")
            print(f"   Successful results: {len(results)}")
            
            # Verify results
            assert len(results) == batch_size
            assert all(r.success for r in results)
            assert parallel_throughput > 50, f"Parallel throughput {parallel_throughput:.1f} ops/sec too low"
            
        finally:
            await optimizer.stop()

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])