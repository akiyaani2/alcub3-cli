#!/usr/bin/env python3
"""
ALCUB3 Security Performance Optimizer Validation
Comprehensive validation script testing performance optimization, caching, and real-time metrics.
"""

import asyncio
import time
import json
import statistics
from datetime import datetime
from typing import Dict, List, Any

# Add path for security framework imports
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import performance optimizer components
from l3_agent.security_performance_optimizer import (
    SecurityPerformanceOptimizer,
    CacheStrategy,
    ValidationPriority,
    PerformanceTarget,
    get_security_optimizer,
    initialize_security_optimizer,
    shutdown_security_optimizer
)

# Simplified classification for validation
from enum import Enum

class ClassificationLevel(Enum):
    UNCLASSIFIED = "unclassified"
    CUI = "cui"
    SECRET = "secret"
    TOP_SECRET = "top_secret"

async def validate_agent_performance():
    """Validate agent validation performance meets <5ms target."""
    print("\n🔍 Test 1: Agent Validation Performance")
    
    config = {
        "performance_targets": {
            "agent_validation": 0.005,  # 5ms target
            "security_overhead": 0.100   # 100ms target
        },
        "max_threads": 8,
        "max_cache_size": 5000
    }
    
    optimizer = SecurityPerformanceOptimizer(config)
    await optimizer.start()
    
    try:
        # Test agent data
        agent_data = {
            "agent_id": "performance_test_agent",
            "capabilities": ["read", "write", "execute"],
            "timestamp": datetime.utcnow().isoformat(),
            "security_level": "standard",
            "metadata": {"test": "performance"}
        }
        
        # Perform 50 validations and measure performance
        latencies = []
        cache_hits = 0
        
        for i in range(50):
            start_time = time.time()
            result = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            latency = time.time() - start_time
            
            latencies.append(latency)
            if result.cache_hit:
                cache_hits += 1
            
            assert result.success, f"Validation {i} failed"
        
        # Calculate statistics
        avg_latency = statistics.mean(latencies)
        max_latency = max(latencies)
        min_latency = min(latencies)
        p95_latency = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max_latency
        cache_hit_rate = cache_hits / len(latencies)
        
        print(f"✅ Agent Validation Performance:")
        print(f"   Average latency: {avg_latency*1000:.2f}ms")
        print(f"   Minimum latency: {min_latency*1000:.2f}ms")
        print(f"   Maximum latency: {max_latency*1000:.2f}ms")
        print(f"   95th percentile: {p95_latency*1000:.2f}ms")
        print(f"   Cache hit rate: {cache_hit_rate*100:.1f}%")
        
        # Verify performance targets
        target_met = avg_latency < 0.005
        cache_effective = cache_hit_rate > 0.5  # Should have good cache hits
        
        print(f"   Performance target (<5ms): {'✅ MET' if target_met else '❌ FAILED'}")
        print(f"   Cache effectiveness (>50%): {'✅ GOOD' if cache_effective else '⚠️ LOW'}")
        
        return target_met and cache_effective
        
    finally:
        await optimizer.stop()

async def validate_cache_strategies():
    """Validate different cache strategies work correctly."""
    print("\n🗄️ Test 2: Cache Strategy Validation")
    
    optimizer = SecurityPerformanceOptimizer()
    await optimizer.start()
    
    try:
        # Test cache strategy selection
        strategies = {
            "agent_validation": {
                ClassificationLevel.UNCLASSIFIED: CacheStrategy.MEDIUM_TERM,
                ClassificationLevel.SECRET: CacheStrategy.SHORT_TERM
            },
            "encryption": {
                ClassificationLevel.UNCLASSIFIED: CacheStrategy.SHORT_TERM
            },
            "audit_logging": {
                ClassificationLevel.UNCLASSIFIED: CacheStrategy.NEVER
            }
        }
        
        print("✅ Cache Strategy Tests:")
        all_correct = True
        
        for operation, expected in strategies.items():
            for classification, expected_strategy in expected.items():
                actual_strategy = optimizer._get_cache_strategy(operation, classification)
                correct = actual_strategy == expected_strategy
                all_correct = all_correct and correct
                
                print(f"   {operation} + {classification.value}: {actual_strategy.value} {'✅' if correct else '❌'}")
        
        # Test cache key generation
        test_data = {"test": "cache_key_data"}
        key1 = optimizer._generate_cache_key("test_op", test_data, ClassificationLevel.UNCLASSIFIED)
        key2 = optimizer._generate_cache_key("test_op", test_data, ClassificationLevel.UNCLASSIFIED)
        key3 = optimizer._generate_cache_key("test_op", test_data, ClassificationLevel.SECRET)
        
        key_consistency = key1 == key2
        key_uniqueness = key1 != key3
        
        print(f"   Cache key consistency: {'✅' if key_consistency else '❌'}")
        print(f"   Cache key uniqueness: {'✅' if key_uniqueness else '❌'}")
        
        return all_correct and key_consistency and key_uniqueness
        
    finally:
        await optimizer.stop()

async def validate_parallel_processing():
    """Validate parallel processing performance."""
    print("\n⚡ Test 3: Parallel Processing Validation")
    
    config = {
        "max_threads": 8,
        "max_processes": 4
    }
    
    optimizer = SecurityPerformanceOptimizer(config)
    await optimizer.start()
    
    try:
        # Create batch of validation requests
        batch_size = 100
        batch_requests = []
        
        for i in range(batch_size):
            agent_data = {
                "agent_id": f"parallel_agent_{i}",
                "capabilities": ["read", "write"],
                "timestamp": datetime.utcnow().isoformat(),
                "batch_id": i
            }
            batch_requests.append(("agent_validation", agent_data, ClassificationLevel.UNCLASSIFIED))
        
        # Perform batch validation
        start_time = time.time()
        results = await optimizer.batch_validate(batch_requests, ValidationPriority.HIGH)
        batch_time = time.time() - start_time
        
        throughput = len(results) / batch_time
        success_rate = sum(1 for r in results if r.success) / len(results)
        
        print(f"✅ Parallel Processing Results:")
        print(f"   Batch size: {batch_size}")
        print(f"   Processing time: {batch_time:.2f}s")
        print(f"   Throughput: {throughput:.1f} ops/sec")
        print(f"   Success rate: {success_rate*100:.1f}%")
        
        # Performance targets
        throughput_target = throughput > 20  # >20 ops/sec
        success_target = success_rate > 0.95  # >95% success
        
        print(f"   Throughput target (>20 ops/sec): {'✅ MET' if throughput_target else '❌ FAILED'}")
        print(f"   Success target (>95%): {'✅ MET' if success_target else '❌ FAILED'}")
        
        return throughput_target and success_target
        
    finally:
        await optimizer.stop()

async def validate_classification_aware_processing():
    """Validate classification-aware processing."""
    print("\n🔐 Test 4: Classification-Aware Processing")
    
    optimizer = SecurityPerformanceOptimizer()
    await optimizer.start()
    
    try:
        agent_data = {
            "agent_id": "classified_test_agent",
            "capabilities": ["read", "write", "execute"],
            "timestamp": datetime.utcnow().isoformat(),
            "sensitive_data": "classified_information"
        }
        
        # Test different classification levels
        classification_results = {}
        
        for classification in [ClassificationLevel.UNCLASSIFIED, ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET]:
            result = await optimizer.validate_agent(agent_data, classification)
            classification_results[classification] = {
                "success": result.success,
                "validation_time": result.validation_time,
                "classification_preserved": result.classification_level == classification
            }
        
        print("✅ Classification Processing Results:")
        all_successful = True
        
        for classification, result in classification_results.items():
            success = result["success"]
            time_ms = result["validation_time"] * 1000
            preserved = result["classification_preserved"]
            
            all_successful = all_successful and success and preserved
            
            print(f"   {classification.value.upper()}: {time_ms:.1f}ms {'✅' if success and preserved else '❌'}")
        
        return all_successful
        
    finally:
        await optimizer.stop()

async def validate_performance_monitoring():
    """Validate performance monitoring and metrics collection."""
    print("\n📊 Test 5: Performance Monitoring")
    
    optimizer = SecurityPerformanceOptimizer()
    await optimizer.start()
    
    try:
        # Generate some validation activity
        for i in range(20):
            agent_data = {
                "agent_id": f"monitoring_agent_{i}",
                "capabilities": ["read"],
                "timestamp": datetime.utcnow().isoformat()
            }
            await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
        
        # Get performance metrics
        metrics = optimizer.get_performance_metrics()
        cache_info = optimizer.get_cache_info()
        
        print("✅ Performance Metrics:")
        
        # Check required metrics exist
        required_metrics = [
            "cache_hit_rate", "avg_latency", "cpu_usage", 
            "memory_usage", "cache_size", "queue_sizes"
        ]
        
        metrics_present = all(metric in metrics for metric in required_metrics)
        
        if metrics_present:
            print(f"   Cache hit rate: {metrics['cache_hit_rate']*100:.1f}%")
            print(f"   Average latency: {metrics['avg_latency']*1000:.2f}ms")
            print(f"   CPU usage: {metrics['cpu_usage']*100:.1f}%")
            print(f"   Memory usage: {metrics['memory_usage']*100:.1f}%")
            print(f"   Cache size: {metrics['cache_size']}")
            print(f"   Queue sizes: {sum(metrics['queue_sizes'].values())}")
            
            # Verify cache info
            print(f"   Cache entries by classification: {cache_info['entries_by_classification']}")
            print(f"   Cache entries by strategy: {cache_info['entries_by_strategy']}")
        
        print(f"   Required metrics present: {'✅' if metrics_present else '❌'}")
        
        return metrics_present
        
    finally:
        await optimizer.stop()

async def validate_security_operations():
    """Validate various security operations."""
    print("\n🛡️ Test 6: Security Operations Validation")
    
    optimizer = SecurityPerformanceOptimizer()
    await optimizer.start()
    
    try:
        # Test different security operations
        operations = {
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_length": 256,
                "mode": "encrypt"
            },
            "classification": {
                "data_type": "text",
                "content": "test classification data",
                "source": "user_input"
            },
            "access_control": {
                "user_id": "test_user",
                "resource": "classified_document",
                "action": "read"
            },
            "threat_detection": {
                "content": "normal user input data",
                "source_ip": "192.168.1.100",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        operation_results = {}
        all_successful = True
        
        for operation, test_data in operations.items():
            start_time = time.time()
            result = await optimizer.validate_security_operation(
                operation, 
                test_data, 
                ClassificationLevel.UNCLASSIFIED,
                ValidationPriority.MEDIUM
            )
            operation_time = time.time() - start_time
            
            operation_results[operation] = {
                "success": result.success,
                "time": operation_time,
                "under_100ms": operation_time < 0.100
            }
            
            all_successful = all_successful and result.success
        
        print("✅ Security Operation Results:")
        for operation, result in operation_results.items():
            success = result["success"]
            time_ms = result["time"] * 1000
            under_target = result["under_100ms"]
            
            status = "✅" if success and under_target else "❌"
            print(f"   {operation}: {time_ms:.1f}ms {status}")
        
        print(f"   All operations successful: {'✅' if all_successful else '❌'}")
        
        return all_successful
        
    finally:
        await optimizer.stop()

async def validate_global_instance():
    """Validate global optimizer instance management."""
    print("\n🌐 Test 7: Global Instance Management")
    
    try:
        # Test global instance creation
        optimizer1 = get_security_optimizer()
        optimizer2 = get_security_optimizer()
        
        singleton_test = optimizer1 is optimizer2
        print(f"   Singleton pattern: {'✅' if singleton_test else '❌'}")
        
        # Test initialization and shutdown
        await initialize_security_optimizer()
        running_test = optimizer1.running
        
        await shutdown_security_optimizer()
        
        print(f"   Initialize/shutdown: {'✅' if running_test else '❌'}")
        
        return singleton_test and running_test
        
    except Exception as e:
        print(f"   Error: {e}")
        return False

async def run_performance_benchmark():
    """Run comprehensive performance benchmark."""
    print("\n🏃 Performance Benchmark")
    
    config = {
        "performance_targets": {
            "agent_validation": 0.005,  # 5ms
            "security_overhead": 0.100  # 100ms
        },
        "max_threads": 8,
        "max_cache_size": 10000
    }
    
    optimizer = SecurityPerformanceOptimizer(config)
    await optimizer.start()
    
    try:
        # Benchmark agent validation
        print("\n📈 Agent Validation Benchmark:")
        
        agent_data = {
            "agent_id": "benchmark_agent",
            "capabilities": ["read", "write", "execute"],
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"benchmark": True}
        }
        
        # Run 200 validations
        latencies = []
        cache_hits = 0
        
        for i in range(200):
            start_time = time.time()
            result = await optimizer.validate_agent(agent_data, ClassificationLevel.UNCLASSIFIED)
            latency = time.time() - start_time
            
            latencies.append(latency)
            if result.cache_hit:
                cache_hits += 1
        
        # Calculate statistics
        avg_latency = statistics.mean(latencies)
        p50_latency = statistics.median(latencies)
        p95_latency = statistics.quantiles(latencies, n=20)[18]
        p99_latency = statistics.quantiles(latencies, n=100)[98]
        throughput = len(latencies) / sum(latencies)
        cache_hit_rate = cache_hits / len(latencies)
        
        print(f"   Requests: {len(latencies)}")
        print(f"   Average latency: {avg_latency*1000:.2f}ms")
        print(f"   Median (P50): {p50_latency*1000:.2f}ms")
        print(f"   95th percentile: {p95_latency*1000:.2f}ms")
        print(f"   99th percentile: {p99_latency*1000:.2f}ms")
        print(f"   Throughput: {throughput:.1f} ops/sec")
        print(f"   Cache hit rate: {cache_hit_rate*100:.1f}%")
        
        # Performance targets
        latency_target = avg_latency < 0.005
        throughput_target = throughput > 100
        cache_target = cache_hit_rate > 0.8
        
        print(f"\n🎯 Performance Targets:")
        print(f"   Latency (<5ms): {'✅ MET' if latency_target else '❌ FAILED'}")
        print(f"   Throughput (>100 ops/sec): {'✅ MET' if throughput_target else '❌ FAILED'}")
        print(f"   Cache hit rate (>80%): {'✅ MET' if cache_target else '❌ FAILED'}")
        
        return latency_target and throughput_target and cache_target
        
    finally:
        await optimizer.stop()

async def main():
    """Main validation function."""
    print("🔒 ALCUB3 Security Performance Optimizer Validation")
    print("=" * 60)
    
    # Run all validation tests
    tests = [
        ("Agent Performance", validate_agent_performance),
        ("Cache Strategies", validate_cache_strategies),
        ("Parallel Processing", validate_parallel_processing),
        ("Classification Processing", validate_classification_aware_processing),
        ("Performance Monitoring", validate_performance_monitoring),
        ("Security Operations", validate_security_operations),
        ("Global Instance", validate_global_instance),
        ("Performance Benchmark", run_performance_benchmark)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            print(f"\n🧪 Running {test_name}...")
            result = await test_func()
            results.append((test_name, result))
            
            if result:
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
                
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 VALIDATION SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name:<25} {status}")
    
    print(f"\n🎯 Overall Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED - Security Performance Optimizer validated!")
        print("🔒 Framework ready for production deployment.")
    else:
        print("⚠️ Some tests failed. Please review implementation.")
        print("🔧 Check configuration and system resources.")

if __name__ == "__main__":
    asyncio.run(main())