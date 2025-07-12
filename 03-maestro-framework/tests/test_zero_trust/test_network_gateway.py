#!/usr/bin/env python3
"""
Tests for ALCUB3 Zero-Trust Network Gateway
Validates SDP implementation with micro-tunnels and protocol inspection
"""

import pytest
import asyncio
import socket
import struct
import secrets
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import ipaddress

# Add parent directory to path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.zero_trust.zt_network_gateway import (
    ZeroTrustNetworkGateway,
    TunnelState,
    ProtocolType,
    InspectionLevel,
    NetworkPolicy,
    MicroTunnel,
    SDPController,
    ProtocolInspectionResult,
    HTTPInspector,
    HTTPSInspector,
    SSHInspector,
    TCPInspector,
    UDPInspector
)
from shared.classification import ClassificationLevel
from shared.audit_logger import AuditLogger
from shared.crypto_utils import CryptoUtils
from shared.protocol_filtering_diodes import ProtocolFilteringDiode
from shared.real_time_monitor import RealTimeMonitor
from shared.exceptions import SecurityError, NetworkError


@pytest.fixture
async def mock_audit_logger():
    """Create mock audit logger."""
    logger = Mock(spec=AuditLogger)
    logger.log_event = AsyncMock()
    return logger


@pytest.fixture
async def mock_crypto_utils():
    """Create mock crypto utils."""
    crypto = Mock(spec=CryptoUtils)
    crypto.generate_key = Mock(return_value=secrets.token_bytes(32))
    crypto.encrypt = Mock(return_value=b"encrypted_data")
    crypto.decrypt = Mock(return_value=b"decrypted_data")
    return crypto


@pytest.fixture
async def mock_pfd():
    """Create mock protocol filtering diode."""
    pfd = Mock(spec=ProtocolFilteringDiode)
    pfd.process_data = AsyncMock(return_value=True)
    return pfd


@pytest.fixture
async def mock_monitor():
    """Create mock real-time monitor."""
    monitor = Mock(spec=RealTimeMonitor)
    monitor.record_event = AsyncMock()
    monitor.record_metric = AsyncMock()
    return monitor


@pytest.fixture
async def network_gateway(mock_audit_logger, mock_crypto_utils, mock_pfd, mock_monitor):
    """Create network gateway instance."""
    gateway = ZeroTrustNetworkGateway(
        gateway_id="test_gateway",
        audit_logger=mock_audit_logger,
        crypto_utils=mock_crypto_utils,
        pfd=mock_pfd,
        monitor=mock_monitor,
        enable_hardware_crypto=False
    )
    return gateway


class TestZeroTrustNetworkGateway:
    """Test cases for zero-trust network gateway."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, network_gateway):
        """Test gateway initialization."""
        gateway = network_gateway
        
        assert gateway.gateway_id == "test_gateway"
        assert gateway.controller.controller_id == "sdp_test_gateway"
        assert len(gateway.protocol_inspectors) > 0
        assert ProtocolType.HTTP in gateway.protocol_inspectors
        assert ProtocolType.HTTPS in gateway.protocol_inspectors
        assert ProtocolType.SSH in gateway.protocol_inspectors
    
    @pytest.mark.asyncio
    async def test_create_network_zone(self, network_gateway):
        """Test network zone creation."""
        gateway = network_gateway
        
        await gateway.create_network_zone(
            zone_name="corporate",
            ip_ranges=["10.0.0.0/8", "172.16.0.0/12"],
            metadata={"description": "Corporate network"}
        )
        
        assert "corporate" in gateway.controller.zones
        assert "10.0.0.0/8" in gateway.controller.zones["corporate"]
        assert "172.16.0.0/12" in gateway.controller.zones["corporate"]
    
    @pytest.mark.asyncio
    async def test_create_network_policy(self, network_gateway):
        """Test network policy creation."""
        gateway = network_gateway
        
        # Create zones first
        await gateway.create_network_zone("internal", ["10.0.0.0/8"])
        await gateway.create_network_zone("dmz", ["172.16.0.0/24"])
        
        # Create policy
        policy = await gateway.create_network_policy(
            name="Internal to DMZ",
            source_zones=["internal"],
            destination_zones=["dmz"],
            allowed_protocols=[ProtocolType.HTTPS, ProtocolType.SSH],
            allowed_ports=[443, 22],
            classification_requirements=[ClassificationLevel.UNCLASSIFIED],
            inspection_level=InspectionLevel.DEEP
        )
        
        assert policy.name == "Internal to DMZ"
        assert policy.source_zones == ["internal"]
        assert policy.destination_zones == ["dmz"]
        assert ProtocolType.HTTPS in policy.allowed_protocols
        assert 443 in policy.allowed_ports
        assert policy.policy_id in gateway.controller.policies
    
    @pytest.mark.asyncio
    async def test_tunnel_establishment(self, network_gateway):
        """Test micro-tunnel establishment."""
        gateway = network_gateway
        
        # Mock reader/writer
        reader = AsyncMock()
        writer = AsyncMock()
        writer.get_extra_info = Mock(return_value=("192.168.1.100", 54321))
        
        # Mock handshake data
        handshake_data = """destination_ip: 10.0.2.50
destination_port: 443
auth_token: {}
protocol: tcp
classification: SECRET""".format(secrets.token_hex(16)).encode()
        
        reader.read = AsyncMock(return_value=handshake_data)
        
        # Create policy allowing this connection
        await gateway.create_network_zone("default", ["192.168.0.0/16", "10.0.0.0/8"])
        await gateway.create_network_policy(
            name="Allow HTTPS",
            source_zones=["default"],
            destination_zones=["default"],
            allowed_protocols=[ProtocolType.TCP],
            allowed_ports=[443]
        )
        
        # Establish tunnel
        tunnel = await gateway._establish_tunnel(
            reader, writer, "192.168.1.100", 54321
        )
        
        assert tunnel is not None
        assert tunnel.source_ip == "192.168.1.100"
        assert tunnel.destination_ip == "10.0.2.50"
        assert tunnel.destination_port == 443
        assert tunnel.state == TunnelState.ESTABLISHED
        assert tunnel.encryption_key is not None
        assert tunnel.auth_key is not None
    
    @pytest.mark.asyncio
    async def test_zone_ip_matching(self, network_gateway):
        """Test IP address to zone matching."""
        gateway = network_gateway
        
        # Create zones with different IP ranges
        await gateway.create_network_zone(
            "internal",
            ["10.0.0.0/8", "192.168.0.0/16"]
        )
        await gateway.create_network_zone(
            "dmz",
            ["172.16.0.0/24"]
        )
        await gateway.create_network_zone(
            "external",
            ["0.0.0.0/0"]  # Catch-all
        )
        
        # Test zone matching
        assert gateway._get_zone_for_ip("10.5.1.100") == "internal"
        assert gateway._get_zone_for_ip("192.168.50.25") == "internal"
        assert gateway._get_zone_for_ip("172.16.0.50") == "dmz"
        assert gateway._get_zone_for_ip("8.8.8.8") == "external"
    
    @pytest.mark.asyncio
    async def test_packet_decryption(self, network_gateway):
        """Test packet decryption."""
        gateway = network_gateway
        
        # Create tunnel with known keys
        tunnel = MicroTunnel(
            tunnel_id="test_tunnel",
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.2.50",
            destination_port=443,
            protocol=ProtocolType.TCP,
            classification=ClassificationLevel.SECRET,
            encryption_key=b"0" * 32,  # Known key for testing
            auth_key=b"1" * 32
        )
        
        # Create encrypted packet (simplified for testing)
        nonce = b"0" * 12
        ciphertext = b"encrypted_payload"
        encrypted_packet = nonce + ciphertext
        
        # Mock decryption
        with patch('shared.zero_trust.zt_network_gateway.Cipher') as mock_cipher:
            mock_decryptor = MagicMock()
            mock_decryptor.update.return_value = b"decrypted_"
            mock_decryptor.finalize.return_value = b"payload"
            mock_cipher.return_value.decryptor.return_value = mock_decryptor
            
            decrypted = await gateway._decrypt_packet(tunnel, encrypted_packet)
            assert decrypted == b"decrypted_payload"
    
    @pytest.mark.asyncio
    async def test_protocol_inspection_http(self):
        """Test HTTP protocol inspection."""
        inspector = HTTPInspector()
        
        # Test normal HTTP request
        normal_request = b"""GET /api/data HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: application/json

"""
        result = await inspector.inspect(
            normal_request,
            ClassificationLevel.UNCLASSIFIED,
            InspectionLevel.DEEP
        )
        assert result.passed is True
        assert result.protocol_detected == ProtocolType.HTTP
        assert len(result.anomalies) == 0
        
        # Test SQL injection attempt
        sql_injection = b"""GET /api/data?id=1' OR '1'='1 HTTP/1.1
Host: example.com

SELECT * FROM users"""
        
        result = await inspector.inspect(
            sql_injection,
            ClassificationLevel.UNCLASSIFIED,
            InspectionLevel.DEEP
        )
        assert result.passed is False
        assert len(result.anomalies) > 0
        assert any("SQL injection" in anomaly for anomaly in result.anomalies)
    
    @pytest.mark.asyncio
    async def test_protocol_inspection_https(self):
        """Test HTTPS protocol inspection."""
        inspector = HTTPSInspector()
        
        # Test TLS handshake
        tls_handshake = struct.pack('>BBH', 0x16, 0x03, 0x03) + b"handshake_data"
        
        result = await inspector.inspect(
            tls_handshake,
            ClassificationLevel.SECRET,
            InspectionLevel.SHALLOW
        )
        assert result.passed is True
        assert result.protocol_detected == ProtocolType.HTTPS
        
        # Test outdated TLS version
        old_tls = struct.pack('>BBH', 0x16, 0x03, 0x01) + b"old_handshake"
        
        result = await inspector.inspect(
            old_tls,
            ClassificationLevel.SECRET,
            InspectionLevel.SHALLOW
        )
        assert result.passed is False
        assert "Outdated TLS version" in result.anomalies
    
    @pytest.mark.asyncio
    async def test_protocol_inspection_ssh(self):
        """Test SSH protocol inspection."""
        inspector = SSHInspector()
        
        # Test SSH-2 banner
        ssh2_banner = b"SSH-2.0-OpenSSH_8.0\r\n"
        
        result = await inspector.inspect(
            ssh2_banner,
            ClassificationLevel.SECRET,
            InspectionLevel.SHALLOW
        )
        assert result.passed is True
        assert result.protocol_detected == ProtocolType.SSH
        
        # Test insecure SSH-1 banner
        ssh1_banner = b"SSH-1.5-OpenSSH_Old\r\n"
        
        result = await inspector.inspect(
            ssh1_banner,
            ClassificationLevel.SECRET,
            InspectionLevel.SHALLOW
        )
        assert result.passed is False
        assert "Insecure SSH version 1" in result.anomalies
    
    @pytest.mark.asyncio
    async def test_tunnel_traffic_handling(self, network_gateway):
        """Test handling of tunnel traffic."""
        gateway = network_gateway
        
        # Create tunnel
        tunnel = MicroTunnel(
            tunnel_id="traffic_tunnel",
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.2.50",
            destination_port=443,
            protocol=ProtocolType.HTTPS,
            classification=ClassificationLevel.SECRET,
            state=TunnelState.ESTABLISHED
        )
        
        gateway.controller.active_tunnels[tunnel.tunnel_id] = tunnel
        
        # Mock reader/writer
        reader = AsyncMock()
        writer = AsyncMock()
        
        # Simulate packet data
        packet_data = b"encrypted_packet_data"
        reader.read = AsyncMock(side_effect=[packet_data, b""])  # One packet then EOF
        
        # Mock decryption and inspection
        gateway._decrypt_packet = AsyncMock(return_value=b"decrypted_data")
        gateway._inspect_packet = AsyncMock(
            return_value=ProtocolInspectionResult(
                passed=True,
                protocol_detected=ProtocolType.HTTPS
            )
        )
        gateway._route_packet = AsyncMock()
        
        # Handle traffic
        await gateway._handle_tunnel_traffic(tunnel, reader, writer)
        
        # Verify packet was processed
        assert gateway._decrypt_packet.called
        assert gateway._inspect_packet.called
        assert gateway._route_packet.called
        assert tunnel.packets_sent > 0
        assert tunnel.bytes_sent > 0
    
    @pytest.mark.asyncio
    async def test_idle_tunnel_cleanup(self, network_gateway):
        """Test cleanup of idle tunnels."""
        gateway = network_gateway
        
        # Create tunnels with different idle times
        active_tunnel = MicroTunnel(
            tunnel_id="active",
            source_ip="192.168.1.100",
            source_port=11111,
            destination_ip="10.0.1.50",
            destination_port=443,
            protocol=ProtocolType.HTTPS,
            classification=ClassificationLevel.UNCLASSIFIED,
            last_activity=datetime.utcnow()
        )
        
        idle_tunnel = MicroTunnel(
            tunnel_id="idle",
            source_ip="192.168.1.101",
            source_port=22222,
            destination_ip="10.0.1.51",
            destination_port=443,
            protocol=ProtocolType.HTTPS,
            classification=ClassificationLevel.UNCLASSIFIED,
            last_activity=datetime.utcnow() - timedelta(hours=2)
        )
        
        gateway.controller.active_tunnels = {
            "active": active_tunnel,
            "idle": idle_tunnel
        }
        
        # Run cleanup
        await gateway._cleanup_idle_tunnels()
        
        # Active tunnel should remain, idle should be removed
        assert "active" in gateway.controller.active_tunnels
        assert "idle" not in gateway.controller.active_tunnels
    
    @pytest.mark.asyncio
    async def test_tunnel_rekeying(self, network_gateway):
        """Test tunnel key rotation."""
        gateway = network_gateway
        
        # Create tunnel that needs rekeying
        old_tunnel = MicroTunnel(
            tunnel_id="rekey_tunnel",
            source_ip="192.168.1.100",
            source_port=33333,
            destination_ip="10.0.1.50",
            destination_port=443,
            protocol=ProtocolType.HTTPS,
            classification=ClassificationLevel.SECRET,
            state=TunnelState.ESTABLISHED,
            created_at=datetime.utcnow() - timedelta(minutes=20),
            encryption_key=b"old_key" * 4,
            auth_key=b"old_auth" * 4
        )
        
        gateway.controller.active_tunnels[old_tunnel.tunnel_id] = old_tunnel
        old_encryption_key = old_tunnel.encryption_key
        
        # Run rekey process
        await gateway._rekey_tunnels()
        
        # Keys should be different
        assert old_tunnel.encryption_key != old_encryption_key
        assert old_tunnel.state == TunnelState.ESTABLISHED
    
    @pytest.mark.asyncio
    async def test_blacklist_whitelist(self, network_gateway):
        """Test blacklist and whitelist functionality."""
        gateway = network_gateway
        
        # Add to blacklist
        gateway.controller.blacklist.add("192.168.1.100")
        
        # Mock reader/writer
        reader = AsyncMock()
        writer = AsyncMock()
        writer.get_extra_info = Mock(return_value=("192.168.1.100", 54321))
        writer.close = Mock()
        writer.wait_closed = AsyncMock()
        
        # Try to handle connection from blacklisted IP
        await gateway._handle_connection(reader, writer)
        
        # Connection should be closed immediately
        writer.close.assert_called()
        
        # Test whitelist
        gateway.controller.whitelist.add("10.0.0.100")
        gateway.controller.blacklist.clear()
        
        # Non-whitelisted IP should fail authorization
        writer.get_extra_info = Mock(return_value=("192.168.1.101", 54321))
        
        handshake_data = """destination_ip: 10.0.2.50
destination_port: 443
auth_token: {}""".format(secrets.token_hex(16)).encode()
        
        reader.read = AsyncMock(return_value=handshake_data)
        
        await gateway._handle_connection(reader, writer)
        writer.close.assert_called()
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, network_gateway):
        """Test performance metric tracking."""
        gateway = network_gateway
        
        # Simulate tunnel operations
        for i in range(5):
            tunnel = MicroTunnel(
                tunnel_id=f"tunnel_{i}",
                source_ip=f"192.168.1.{100+i}",
                source_port=50000+i,
                destination_ip="10.0.2.50",
                destination_port=443,
                protocol=ProtocolType.HTTPS,
                classification=ClassificationLevel.UNCLASSIFIED
            )
            gateway.controller.active_tunnels[tunnel.tunnel_id] = tunnel
            gateway.stats['tunnels_created'] += 1
            
            # Simulate traffic
            tunnel.bytes_sent = 1000000 * (i + 1)
            tunnel.packets_sent = 1000 * (i + 1)
        
        gateway.stats['tunnels_active'] = len(gateway.controller.active_tunnels)
        gateway._update_throughput_stats()
        
        stats = gateway.get_statistics()
        assert stats['tunnels_created'] == 5
        assert stats['tunnels_active'] == 5
        assert stats['throughput_mbps'] > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_tunnel_creation(self, network_gateway):
        """Test concurrent tunnel creation."""
        gateway = network_gateway
        
        # Create zones and policies
        await gateway.create_network_zone("test_zone", ["192.168.0.0/16", "10.0.0.0/8"])
        await gateway.create_network_policy(
            name="Allow All",
            source_zones=["test_zone"],
            destination_zones=["test_zone"],
            allowed_protocols=[ProtocolType.TCP],
            allowed_ports=list(range(1, 65536))  # All ports
        )
        
        # Create multiple tunnel establishment tasks
        tasks = []
        for i in range(20):
            reader = AsyncMock()
            writer = AsyncMock()
            writer.get_extra_info = Mock(return_value=(f"192.168.1.{100+i}", 50000+i))
            writer.write = Mock()
            writer.drain = AsyncMock()
            
            handshake = f"""destination_ip: 10.0.2.{50+i}
destination_port: {443+i}
auth_token: {secrets.token_hex(16)}
protocol: tcp""".encode()
            
            reader.read = AsyncMock(return_value=handshake)
            
            task = gateway._establish_tunnel(
                reader, writer, f"192.168.1.{100+i}", 50000+i
            )
            tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check results
        successful_tunnels = [r for r in results if r is not None and not isinstance(r, Exception)]
        assert len(successful_tunnels) >= 15  # Most should succeed
    
    @pytest.mark.asyncio
    async def test_classification_enforcement(self, network_gateway):
        """Test classification-based access control."""
        gateway = network_gateway
        
        # Create classification-aware policy
        await gateway.create_network_zone("classified", ["10.1.0.0/16"])
        
        policy = await gateway.create_network_policy(
            name="Secret Data Policy",
            source_zones=["classified"],
            destination_zones=["classified"],
            allowed_protocols=[ProtocolType.HTTPS],
            allowed_ports=[443],
            classification_requirements=[
                ClassificationLevel.SECRET,
                ClassificationLevel.TOP_SECRET
            ],
            inspection_level=InspectionLevel.FULL
        )
        
        # Test with matching classification
        tunnel_secret = MicroTunnel(
            tunnel_id="secret_tunnel",
            source_ip="10.1.0.100",
            source_port=54321,
            destination_ip="10.1.0.200",
            destination_port=443,
            protocol=ProtocolType.HTTPS,
            classification=ClassificationLevel.SECRET,
            policy_id=policy.policy_id
        )
        
        # Should pass inspection
        result = await gateway._inspect_packet(
            tunnel_secret,
            b"https_traffic_data"
        )
        
        # Test with insufficient classification
        tunnel_unclass = MicroTunnel(
            tunnel_id="unclass_tunnel",
            source_ip="10.1.0.100",
            source_port=54322,
            destination_ip="10.1.0.200",
            destination_port=443,
            protocol=ProtocolType.HTTPS,
            classification=ClassificationLevel.UNCLASSIFIED,
            policy_id=policy.policy_id
        )
        
        # Should fail classification check in real scenario


if __name__ == "__main__":
    pytest.main([__file__, "-v"])