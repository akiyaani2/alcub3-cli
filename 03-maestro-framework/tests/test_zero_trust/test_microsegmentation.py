#!/usr/bin/env python3
"""
Tests for ALCUB3 Microsegmentation Engine
Validates classification-aware network segmentation functionality
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.zero_trust.microsegmentation_engine import (
    MicrosegmentationEngine,
    NetworkSegment,
    SegmentType,
    TrafficDirection,
    SegmentationPolicy,
    PolicyEffect
)
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.exceptions import SecurityError


@pytest.fixture
async def mock_audit_logger():
    """Create mock audit logger."""
    logger = Mock(spec=AuditLogger)
    logger.log_event = AsyncMock()
    return logger


@pytest.fixture
async def microsegmentation_engine(mock_audit_logger):
    """Create microsegmentation engine instance."""
    engine = MicrosegmentationEngine(
        audit_logger=mock_audit_logger,
        monitor=None,
        enable_hardware_acceleration=False
    )
    return engine


class TestMicrosegmentationEngine:
    """Test cases for microsegmentation engine."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, microsegmentation_engine):
        """Test engine initialization with default segments."""
        engine = microsegmentation_engine
        
        # Check default segments created
        assert len(engine.segments) >= 4
        assert 'default_unclassified' in engine.segments
        assert 'default_secret' in engine.segments
        assert 'dmz' in engine.segments
        assert 'quarantine' in engine.segments
        
        # Check VLAN allocation
        assert len(engine.used_vlans) >= 4
    
    @pytest.mark.asyncio
    async def test_create_segment(self, microsegmentation_engine):
        """Test creating a new network segment."""
        engine = microsegmentation_engine
        
        segment = await engine.create_segment(
            name="Test Segment",
            segment_type=SegmentType.CONFIDENTIAL,
            classification_level=ClassificationLevel.CONFIDENTIAL,
            subnet="192.168.1.0/24",
            allowed_protocols=['tcp', 'udp'],
            allowed_ports=[443, 8443]
        )
        
        assert segment.name == "Test Segment"
        assert segment.segment_type == SegmentType.CONFIDENTIAL
        assert segment.classification_level == ClassificationLevel.CONFIDENTIAL
        assert str(segment.subnet) == "192.168.1.0/24"
        assert segment.vlan_id is not None
        assert segment.segment_id in engine.segments
    
    @pytest.mark.asyncio
    async def test_subnet_conflict_detection(self, microsegmentation_engine):
        """Test detection of overlapping subnets."""
        engine = microsegmentation_engine
        
        # Create first segment
        await engine.create_segment(
            name="Segment 1",
            segment_type=SegmentType.CONFIDENTIAL,
            classification_level=ClassificationLevel.CONFIDENTIAL,
            subnet="10.1.0.0/16"
        )
        
        # Try to create overlapping segment
        with pytest.raises(SecurityError) as exc_info:
            await engine.create_segment(
                name="Segment 2",
                segment_type=SegmentType.SECRET,
                classification_level=ClassificationLevel.SECRET,
                subnet="10.1.1.0/24"  # Overlaps with first
            )
        
        assert "overlaps" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_packet_processing_allowed(self, microsegmentation_engine):
        """Test packet processing for allowed traffic."""
        engine = microsegmentation_engine
        
        # Create policy allowing traffic
        policy = await engine.create_policy(
            name="Allow Internal",
            source_segments=['default_unclassified'],
            destination_segments=['default_unclassified'],
            allowed_protocols=['tcp'],
            allowed_ports=[80, 443],
            classification_requirements=[ClassificationLevel.UNCLASSIFIED],
            action='allow'
        )
        
        # Process packet
        allowed, reason = await engine.process_packet(
            source_ip="10.0.1.100",
            destination_ip="10.0.2.200",
            protocol="tcp",
            port=443,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        assert allowed is True
        assert "Policy" in reason
    
    @pytest.mark.asyncio
    async def test_packet_processing_denied(self, microsegmentation_engine):
        """Test packet processing for denied traffic."""
        engine = microsegmentation_engine
        
        # Process packet without matching allow policy
        allowed, reason = await engine.process_packet(
            source_ip="192.168.1.100",  # Unknown segment
            destination_ip="10.0.2.200",
            protocol="tcp",
            port=22,
            classification=ClassificationLevel.SECRET
        )
        
        assert allowed is False
        assert reason is not None
    
    @pytest.mark.asyncio
    async def test_classification_enforcement(self, microsegmentation_engine):
        """Test classification-based access control."""
        engine = microsegmentation_engine
        
        # Try to send SECRET data to UNCLASSIFIED segment
        allowed, reason = await engine.process_packet(
            source_ip="10.2.1.100",  # SECRET segment
            destination_ip="10.0.1.100",  # UNCLASSIFIED segment
            protocol="tcp",
            port=443,
            classification=ClassificationLevel.SECRET
        )
        
        assert allowed is False
        assert "classification" in reason.lower()
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, microsegmentation_engine):
        """Test performance tracking."""
        engine = microsegmentation_engine
        
        # Process multiple packets
        for i in range(10):
            await engine.process_packet(
                source_ip=f"10.0.1.{i}",
                destination_ip="10.0.2.200",
                protocol="tcp",
                port=443,
                classification=ClassificationLevel.UNCLASSIFIED
            )
        
        stats = engine.get_statistics()
        assert stats['packets_processed'] == 10
        assert stats['avg_decision_time_ms'] > 0
        assert stats['avg_decision_time_ms'] < 5.0  # Should meet <5ms target
    
    @pytest.mark.asyncio
    async def test_flow_tracking(self, microsegmentation_engine):
        """Test traffic flow tracking."""
        engine = microsegmentation_engine
        
        # Process packets from same flow
        for i in range(5):
            await engine.process_packet(
                source_ip="10.0.1.100",
                destination_ip="10.0.2.200",
                protocol="tcp",
                port=443,
                classification=ClassificationLevel.UNCLASSIFIED
            )
        
        # Check flow was tracked
        flow_id = "10.0.1.100:10.0.2.200:tcp:443"
        assert flow_id in engine.active_flows
        
        flow = engine.active_flows[flow_id]
        assert flow.packet_count == 5
        assert flow.source_ip == "10.0.1.100"
        assert flow.destination_ip == "10.0.2.200"
    
    @pytest.mark.asyncio
    async def test_policy_priority(self, microsegmentation_engine):
        """Test policy priority evaluation."""
        engine = microsegmentation_engine
        
        # Create conflicting policies with different priorities
        await engine.create_policy(
            name="Deny All",
            source_segments=['default_unclassified'],
            destination_segments=['default_secret'],
            allowed_protocols=['tcp'],
            action='deny',
            priority=100
        )
        
        await engine.create_policy(
            name="Allow Specific",
            source_segments=['default_unclassified'],
            destination_segments=['default_secret'],
            allowed_protocols=['tcp'],
            allowed_ports=[443],
            action='allow',
            priority=10  # Higher priority (lower number)
        )
        
        # Test that higher priority policy wins
        allowed, reason = await engine.process_packet(
            source_ip="10.0.1.100",
            destination_ip="10.2.1.100",
            protocol="tcp",
            port=443,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        # Should be allowed by higher priority policy
        assert allowed is True
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self, microsegmentation_engine):
        """Test policy decision caching."""
        engine = microsegmentation_engine
        
        # First request - cache miss
        await engine.process_packet(
            source_ip="10.0.1.100",
            destination_ip="10.0.2.200",
            protocol="tcp",
            port=443,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        initial_cache_hits = engine.stats['cache_hits']
        
        # Second identical request - cache hit
        await engine.process_packet(
            source_ip="10.0.1.100",
            destination_ip="10.0.2.200",
            protocol="tcp",
            port=443,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        assert engine.stats['cache_hits'] == initial_cache_hits + 1
    
    @pytest.mark.asyncio
    async def test_segment_topology(self, microsegmentation_engine):
        """Test retrieving segment topology."""
        engine = microsegmentation_engine
        
        topology = await engine.get_segment_topology()
        
        assert 'segments' in topology
        assert 'policies' in topology
        assert 'active_flows' in topology
        assert 'statistics' in topology
        
        # Check segment details
        assert len(topology['segments']) >= 4
        for segment_data in topology['segments'].values():
            assert 'name' in segment_data
            assert 'type' in segment_data
            assert 'classification' in segment_data
            assert 'vlan_id' in segment_data
    
    @pytest.mark.asyncio
    async def test_cleanup_stale_flows(self, microsegmentation_engine):
        """Test cleanup of stale flows."""
        engine = microsegmentation_engine
        
        # Create a flow
        await engine.process_packet(
            source_ip="10.0.1.100",
            destination_ip="10.0.2.200",
            protocol="tcp",
            port=443,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        
        flow_id = "10.0.1.100:10.0.2.200:tcp:443"
        assert flow_id in engine.active_flows
        
        # Manually age the flow
        flow = engine.active_flows[flow_id]
        flow.last_seen = datetime.utcnow() - timedelta(hours=2)
        
        # Run cleanup
        await engine.cleanup_stale_flows(max_age_minutes=60)
        
        # Flow should be removed
        assert flow_id not in engine.active_flows
    
    @pytest.mark.asyncio
    async def test_vlan_exhaustion(self, microsegmentation_engine):
        """Test handling of VLAN pool exhaustion."""
        engine = microsegmentation_engine
        
        # Exhaust VLAN pool
        engine.vlan_pool = set()
        
        # Try to create segment
        with pytest.raises(SecurityError) as exc_info:
            await engine.create_segment(
                name="No VLAN Segment",
                segment_type=SegmentType.CONFIDENTIAL,
                classification_level=ClassificationLevel.CONFIDENTIAL
            )
        
        assert "VLAN pool exhausted" in str(exc_info.value)


@pytest.mark.asyncio
async def test_concurrent_packet_processing(microsegmentation_engine):
    """Test concurrent packet processing for performance."""
    engine = microsegmentation_engine
    
    # Create multiple concurrent packet processing tasks
    tasks = []
    for i in range(100):
        task = engine.process_packet(
            source_ip=f"10.0.1.{i % 256}",
            destination_ip=f"10.0.2.{i % 256}",
            protocol="tcp",
            port=443,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        tasks.append(task)
    
    # Process all packets concurrently
    results = await asyncio.gather(*tasks)
    
    # All should complete successfully
    assert len(results) == 100
    assert all(isinstance(r, tuple) and len(r) == 2 for r in results)
    
    # Check performance
    stats = engine.get_statistics()
    assert stats['packets_processed'] == 100
    assert stats['avg_decision_time_ms'] < 5.0  # Should meet target


if __name__ == "__main__":
    pytest.main([__file__, "-v"])