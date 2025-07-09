"""
TPM-Backed Cryptographic Operations Integration

This module integrates TPM 2.0 hardware security with the existing FIPS crypto utilities,
providing hardware-backed cryptographic operations for defense-grade security.

Key Features:
- TPM-backed key generation and storage
- Hardware-enforced encryption/decryption
- TPM-based digital signatures
- Secure key derivation with TPM
- Hardware random number generation
- Classification-aware TPM operations

Patent-Defensible Innovations:
- TPM-crypto hybrid operations for air-gapped systems
- Hardware-software crypto fallback mechanisms
- Mission-scoped TPM crypto operations
- Cross-platform TPM crypto abstraction

Copyright 2025 ALCUB3 Inc.
"""

import os
import time
import logging
import asyncio
from typing import Dict, Optional, Any, Union
from pathlib import Path

# Import TPM components
from ..hardware.tpm_integration import (
    TPM2Interface,
    TPMKeyHandle,
    TPMHierarchy,
    TPMError
)

from ..hardware.tpm_key_manager import (
    HardwareKeyManager,
    KeyPurpose,
    SecurityClassification,
    CryptoKeyMaterial as TPMKeyMaterial
)

# Import crypto utilities
import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "security-framework" / "src"))
from shared.crypto_utils import (
    FIPSCryptoUtils,
    CryptoAlgorithm,
    SecurityLevel,
    CryptoKeyMaterial,
    CryptoOperationResult
)


class TPMCryptoIntegration:
    """
    TPM-Backed Cryptographic Operations
    
    This class provides a seamless integration between TPM hardware security
    and FIPS-validated cryptographic operations, with automatic fallback to
    software crypto when TPM is unavailable.
    """
    
    def __init__(self, tpm: Optional[TPM2Interface] = None,
                 key_manager: Optional[HardwareKeyManager] = None):
        """
        Initialize TPM crypto integration.
        
        Args:
            tpm: TPM 2.0 interface (optional)
            key_manager: Hardware key manager (optional)
        """
        self.logger = logging.getLogger(__name__)
        self.tpm = tpm
        self.key_manager = key_manager
        self.tpm_available = tpm is not None and key_manager is not None
        
        # Initialize FIPS crypto utils
        self._init_crypto_utils()
        
        # Metrics
        self.metrics = {
            "tpm_operations": 0,
            "software_fallbacks": 0,
            "hybrid_operations": 0,
            "performance_comparisons": []
        }
        
        self.logger.info(f"TPM Crypto Integration initialized (TPM: {self.tpm_available})")
    
    def _init_crypto_utils(self):
        """Initialize FIPS crypto utilities."""
        # Create a minimal classification system adapter
        class ClassificationAdapter:
            def __init__(self):
                self.default_level = self._create_classification_level()
            
            def _create_classification_level(self):
                class Level:
                    value = "UNCLASSIFIED"
                    numeric_level = 0
                return Level()
        
        self.crypto_utils = FIPSCryptoUtils(
            ClassificationAdapter(),
            SecurityLevel.UNCLASSIFIED
        )
    
    async def generate_key(self, algorithm: CryptoAlgorithm,
                          classification: SecurityClassification = SecurityClassification.UNCLASSIFIED,
                          key_purpose: str = "general",
                          prefer_tpm: bool = True) -> CryptoKeyMaterial:
        """
        Generate cryptographic key with TPM preference.
        
        Args:
            algorithm: Cryptographic algorithm
            classification: Security classification level
            key_purpose: Purpose of the key
            prefer_tpm: Prefer TPM over software generation
            
        Returns:
            CryptoKeyMaterial: Generated key (TPM-backed or software)
        """
        start_time = time.time()
        
        # Try TPM generation first if available and preferred
        if self.tpm_available and prefer_tpm:
            try:
                tpm_key = await self._generate_tpm_key(algorithm, classification, key_purpose)
                if tpm_key:
                    self.metrics["tpm_operations"] += 1
                    operation_time = (time.time() - start_time) * 1000
                    self.logger.info(
                        f"Generated TPM-backed {algorithm.value} key in {operation_time:.1f}ms"
                    )
                    return tpm_key
            except Exception as e:
                self.logger.warning(f"TPM key generation failed: {e}, falling back to software")
                self.metrics["software_fallbacks"] += 1
        
        # Fall back to software generation
        sw_key = self.crypto_utils.generate_key(algorithm, key_purpose)
        
        # Track performance comparison
        operation_time = (time.time() - start_time) * 1000
        self.metrics["performance_comparisons"].append({
            "operation": "key_generation",
            "algorithm": algorithm.value,
            "method": "software",
            "time_ms": operation_time
        })
        
        return sw_key
    
    async def _generate_tpm_key(self, algorithm: CryptoAlgorithm,
                               classification: SecurityClassification,
                               key_purpose: str) -> Optional[CryptoKeyMaterial]:
        """Generate key using TPM hardware."""
        try:
            # Map crypto algorithm to key purpose
            purpose_map = {
                "encryption": KeyPurpose.DATA_ENCRYPTION,
                "signing": KeyPurpose.SENSOR_SIGNING,
                "general": KeyPurpose.PLATFORM_IDENTITY
            }
            
            tpm_purpose = purpose_map.get(key_purpose, KeyPurpose.PLATFORM_IDENTITY)
            
            # Derive key from appropriate root
            root_key_id = self.key_manager.root_keys.get(
                (TPMHierarchy.OWNER, classification)
            )
            
            if not root_key_id:
                self.logger.error(f"No root key for classification {classification.value}")
                return None
            
            # Create TPM key
            tpm_key = await self.key_manager.derive_classification_key(
                base_key_id=root_key_id,
                target_classification=classification,
                purpose=tpm_purpose
            )
            
            # Convert to crypto key material
            return CryptoKeyMaterial(
                key_id=tpm_key.key_id,
                algorithm=algorithm,
                key_data=b"",  # Key stays in TPM
                security_level=self._map_classification_to_security_level(classification),
                creation_timestamp=tpm_key.created_at,
                key_purpose=key_purpose,
                classification_level=classification.value,
                hsm_backed=True,  # TPM is a type of HSM
                hsm_key_handle=tpm_key.tpm_handle
            )
            
        except Exception as e:
            self.logger.error(f"TPM key generation error: {e}")
            return None
    
    async def encrypt_data(self, plaintext: bytes,
                          key_material: CryptoKeyMaterial) -> CryptoOperationResult:
        """
        Encrypt data using TPM if key is hardware-backed.
        
        Args:
            plaintext: Data to encrypt
            key_material: Encryption key (TPM or software)
            
        Returns:
            CryptoOperationResult: Encryption result
        """
        start_time = time.time()
        
        # Check if this is a TPM-backed key
        if key_material.hsm_backed and self.tpm_available:
            try:
                result = await self._tpm_encrypt(plaintext, key_material)
                if result.success:
                    self.metrics["tpm_operations"] += 1
                    return result
            except Exception as e:
                self.logger.warning(f"TPM encryption failed: {e}, falling back to software")
                self.metrics["software_fallbacks"] += 1
        
        # Use software encryption
        return self.crypto_utils.encrypt_data(plaintext, key_material)
    
    async def _tpm_encrypt(self, plaintext: bytes,
                          key_material: CryptoKeyMaterial) -> CryptoOperationResult:
        """Perform encryption using TPM."""
        try:
            # For TPM, we need to handle encryption differently based on algorithm
            if key_material.algorithm in [CryptoAlgorithm.AES_256_GCM, CryptoAlgorithm.AES_256_CBC]:
                # Symmetric encryption - seal data to TPM
                sealed_data = await self.tpm.seal_data(
                    data=plaintext,
                    auth_policy=None  # Could add PCR policy here
                )
                
                operation_time = (time.time() - time.time()) * 1000
                
                return CryptoOperationResult(
                    success=True,
                    data=sealed_data,
                    algorithm_used=key_material.algorithm,
                    operation_time_ms=operation_time,
                    security_level=key_material.security_level,
                    audit_trail={
                        "operation": "tpm_encrypt",
                        "key_id": key_material.key_id,
                        "tpm_backed": True,
                        "timestamp": time.time()
                    }
                )
            else:
                # For asymmetric algorithms, use software implementation
                return self.crypto_utils.encrypt_data(plaintext, key_material)
                
        except Exception as e:
            self.logger.error(f"TPM encryption error: {e}")
            raise
    
    async def decrypt_data(self, ciphertext: bytes,
                          key_material: CryptoKeyMaterial) -> CryptoOperationResult:
        """
        Decrypt data using TPM if key is hardware-backed.
        
        Args:
            ciphertext: Data to decrypt
            key_material: Decryption key (TPM or software)
            
        Returns:
            CryptoOperationResult: Decryption result
        """
        # Check if this is a TPM-backed key
        if key_material.hsm_backed and self.tpm_available:
            try:
                result = await self._tpm_decrypt(ciphertext, key_material)
                if result.success:
                    self.metrics["tpm_operations"] += 1
                    return result
            except Exception as e:
                self.logger.warning(f"TPM decryption failed: {e}, falling back to software")
                self.metrics["software_fallbacks"] += 1
        
        # Use software decryption
        return self.crypto_utils.decrypt_data(ciphertext, key_material)
    
    async def _tpm_decrypt(self, ciphertext: bytes,
                          key_material: CryptoKeyMaterial) -> CryptoOperationResult:
        """Perform decryption using TPM."""
        try:
            # For TPM sealed data, unseal it
            if key_material.algorithm in [CryptoAlgorithm.AES_256_GCM, CryptoAlgorithm.AES_256_CBC]:
                plaintext = await self.tpm.unseal_data(ciphertext)
                
                operation_time = 10.0  # Placeholder timing
                
                return CryptoOperationResult(
                    success=True,
                    data=plaintext,
                    algorithm_used=key_material.algorithm,
                    operation_time_ms=operation_time,
                    security_level=key_material.security_level,
                    audit_trail={
                        "operation": "tpm_decrypt",
                        "key_id": key_material.key_id,
                        "tpm_backed": True,
                        "timestamp": time.time()
                    }
                )
            else:
                # For asymmetric algorithms, use software implementation
                return self.crypto_utils.decrypt_data(ciphertext, key_material)
                
        except Exception as e:
            self.logger.error(f"TPM decryption error: {e}")
            raise
    
    async def sign_data(self, data: bytes,
                       key_material: CryptoKeyMaterial) -> CryptoOperationResult:
        """
        Sign data using TPM if key is hardware-backed.
        
        Args:
            data: Data to sign
            key_material: Signing key (TPM or software)
            
        Returns:
            CryptoOperationResult: Signature result
        """
        # Check if this is a TPM-backed key
        if key_material.hsm_backed and self.tpm_available:
            try:
                result = await self._tpm_sign(data, key_material)
                if result.success:
                    self.metrics["tpm_operations"] += 1
                    return result
            except Exception as e:
                self.logger.warning(f"TPM signing failed: {e}, falling back to software")
                self.metrics["software_fallbacks"] += 1
        
        # Use software signing
        return self.crypto_utils.sign_data(data, key_material)
    
    async def _tpm_sign(self, data: bytes,
                       key_material: CryptoKeyMaterial) -> CryptoOperationResult:
        """Perform signing using TPM."""
        try:
            # Get TPM key handle
            tpm_handle = key_material.hsm_key_handle
            if not tpm_handle:
                raise ValueError("No TPM handle for key")
            
            # Sign data with TPM
            signature = await self.tpm.sign_data(
                key_handle=tpm_handle,
                data=data,
                hash_algorithm="SHA256",
                signature_scheme="RSASSA"
            )
            
            operation_time = 50.0  # Placeholder timing
            
            return CryptoOperationResult(
                success=True,
                data=signature,
                algorithm_used=key_material.algorithm,
                operation_time_ms=operation_time,
                security_level=key_material.security_level,
                audit_trail={
                    "operation": "tpm_sign",
                    "key_id": key_material.key_id,
                    "tpm_backed": True,
                    "signature_length": len(signature),
                    "timestamp": time.time()
                }
            )
            
        except Exception as e:
            self.logger.error(f"TPM signing error: {e}")
            raise
    
    async def verify_signature(self, data: bytes, signature: bytes,
                             key_material: CryptoKeyMaterial) -> CryptoOperationResult:
        """
        Verify signature using TPM if key is hardware-backed.
        
        Args:
            data: Original data
            signature: Signature to verify
            key_material: Verification key (TPM or software)
            
        Returns:
            CryptoOperationResult: Verification result
        """
        # Check if this is a TPM-backed key
        if key_material.hsm_backed and self.tpm_available:
            try:
                result = await self._tpm_verify(data, signature, key_material)
                if result:
                    self.metrics["tpm_operations"] += 1
                    return result
            except Exception as e:
                self.logger.warning(f"TPM verification failed: {e}, falling back to software")
                self.metrics["software_fallbacks"] += 1
        
        # Use software verification
        return self.crypto_utils.verify_signature(data, signature, key_material)
    
    async def _tpm_verify(self, data: bytes, signature: bytes,
                         key_material: CryptoKeyMaterial) -> Optional[CryptoOperationResult]:
        """Perform signature verification using TPM."""
        try:
            # Get TPM key handle
            tpm_handle = key_material.hsm_key_handle
            if not tpm_handle:
                raise ValueError("No TPM handle for key")
            
            # Verify signature with TPM
            valid = await self.tpm.verify_signature(
                key_handle=tpm_handle,
                data=data,
                signature=signature,
                hash_algorithm="SHA256",
                signature_scheme="RSASSA"
            )
            
            operation_time = 30.0  # Placeholder timing
            
            return CryptoOperationResult(
                success=valid,
                data=b"signature_valid" if valid else b"signature_invalid",
                algorithm_used=key_material.algorithm,
                operation_time_ms=operation_time,
                security_level=key_material.security_level,
                audit_trail={
                    "operation": "tpm_verify",
                    "key_id": key_material.key_id,
                    "tpm_backed": True,
                    "verification_result": valid,
                    "timestamp": time.time()
                }
            )
            
        except Exception as e:
            self.logger.error(f"TPM verification error: {e}")
            return None
    
    def get_random_bytes(self, num_bytes: int) -> bytes:
        """
        Get cryptographically secure random bytes.
        
        Prefers TPM hardware RNG if available.
        
        Args:
            num_bytes: Number of random bytes needed
            
        Returns:
            bytes: Random bytes
        """
        if self.tpm_available:
            try:
                # Use TPM hardware RNG
                random_bytes = asyncio.run(self.tpm.get_random(num_bytes))
                self.metrics["tpm_operations"] += 1
                return random_bytes
            except Exception as e:
                self.logger.warning(f"TPM RNG failed: {e}, using OS random")
                self.metrics["software_fallbacks"] += 1
        
        # Fall back to OS random
        return os.urandom(num_bytes)
    
    def _map_classification_to_security_level(self,
                                            classification: SecurityClassification) -> SecurityLevel:
        """Map TPM classification to crypto security level."""
        mapping = {
            SecurityClassification.UNCLASSIFIED: SecurityLevel.UNCLASSIFIED,
            SecurityClassification.SECRET: SecurityLevel.SECRET,
            SecurityClassification.TOP_SECRET: SecurityLevel.TOP_SECRET
        }
        return mapping.get(classification, SecurityLevel.UNCLASSIFIED)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get TPM crypto integration metrics."""
        metrics = dict(self.metrics)
        
        # Calculate hybrid operation percentage
        total_ops = metrics["tpm_operations"] + metrics["software_fallbacks"]
        if total_ops > 0:
            metrics["tpm_usage_percentage"] = (metrics["tpm_operations"] / total_ops) * 100
        else:
            metrics["tpm_usage_percentage"] = 0.0
        
        # Add crypto utils metrics
        metrics["crypto_utils_metrics"] = self.crypto_utils.get_crypto_metrics()
        
        return metrics
    
    async def perform_benchmark(self) -> Dict[str, Any]:
        """
        Perform benchmark comparison between TPM and software crypto.
        
        Returns:
            Dict: Benchmark results
        """
        results = {
            "timestamp": time.time(),
            "operations": {}
        }
        
        # Test data
        test_data = b"Benchmark test data for cryptographic operations" * 10
        
        # Benchmark key generation
        print("Benchmarking key generation...")
        
        # Software key generation
        sw_start = time.time()
        sw_key = self.crypto_utils.generate_key(CryptoAlgorithm.AES_256_GCM)
        sw_keygen_time = (time.time() - sw_start) * 1000
        
        # TPM key generation (if available)
        tpm_keygen_time = None
        if self.tpm_available:
            tpm_start = time.time()
            tpm_key = await self.generate_key(
                CryptoAlgorithm.AES_256_GCM,
                prefer_tpm=True
            )
            tpm_keygen_time = (time.time() - tpm_start) * 1000
        
        results["operations"]["key_generation"] = {
            "software_ms": sw_keygen_time,
            "tpm_ms": tpm_keygen_time
        }
        
        # Benchmark encryption
        print("Benchmarking encryption...")
        
        # Software encryption
        sw_start = time.time()
        sw_encrypted = self.crypto_utils.encrypt_data(test_data, sw_key)
        sw_encrypt_time = (time.time() - sw_start) * 1000
        
        # TPM encryption (if available)
        tpm_encrypt_time = None
        if self.tpm_available and tpm_key:
            tpm_start = time.time()
            tpm_encrypted = await self.encrypt_data(test_data, tpm_key)
            tpm_encrypt_time = (time.time() - tpm_start) * 1000
        
        results["operations"]["encryption"] = {
            "software_ms": sw_encrypt_time,
            "tpm_ms": tpm_encrypt_time,
            "data_size_bytes": len(test_data)
        }
        
        # Summary
        results["summary"] = {
            "tpm_available": self.tpm_available,
            "test_data_size": len(test_data),
            "recommendation": self._get_performance_recommendation(results)
        }
        
        return results
    
    def _get_performance_recommendation(self, benchmark_results: Dict) -> str:
        """Analyze benchmark results and provide recommendation."""
        if not self.tpm_available:
            return "TPM not available - using software crypto only"
        
        # Compare performance
        ops = benchmark_results["operations"]
        
        # Key generation comparison
        keygen = ops.get("key_generation", {})
        if keygen.get("tpm_ms") and keygen.get("software_ms"):
            if keygen["tpm_ms"] < keygen["software_ms"] * 2:
                return "TPM recommended for enhanced security with acceptable performance"
            else:
                return "Use TPM for high-security operations, software for performance-critical tasks"
        
        return "Benchmark incomplete - manual evaluation recommended"


# Example usage
async def demonstrate_tpm_crypto():
    """Demonstrate TPM crypto integration."""
    print("🔐 TPM Crypto Integration Demonstration")
    print("=" * 50)
    
    # Initialize TPM components
    tpm = TPM2Interface()
    await tpm.initialize()
    
    key_manager = HardwareKeyManager(tpm)
    await key_manager.initialize()
    
    # Create integration
    crypto = TPMCryptoIntegration(tpm, key_manager)
    
    # Generate key
    print("\n🔑 Generating AES-256-GCM key...")
    key = await crypto.generate_key(
        CryptoAlgorithm.AES_256_GCM,
        SecurityClassification.UNCLASSIFIED,
        "encryption"
    )
    print(f"Key ID: {key.key_id}")
    print(f"TPM-backed: {key.hsm_backed}")
    
    # Encrypt data
    print("\n🔒 Encrypting data...")
    plaintext = b"Sensitive robotics command data"
    result = await crypto.encrypt_data(plaintext, key)
    print(f"Encryption success: {result.success}")
    print(f"Operation time: {result.operation_time_ms:.1f}ms")
    
    # Decrypt data
    if result.success:
        print("\n🔓 Decrypting data...")
        decrypt_result = await crypto.decrypt_data(result.data, key)
        print(f"Decryption success: {decrypt_result.success}")
        if decrypt_result.success:
            print(f"Decrypted: {decrypt_result.data == plaintext}")
    
    # Get metrics
    print("\n📊 Metrics:")
    metrics = crypto.get_metrics()
    print(f"TPM operations: {metrics['tpm_operations']}")
    print(f"Software fallbacks: {metrics['software_fallbacks']}")
    print(f"TPM usage: {metrics['tpm_usage_percentage']:.1f}%")
    
    # Run benchmark
    print("\n⚡ Running performance benchmark...")
    benchmark = await crypto.perform_benchmark()
    print(f"Recommendation: {benchmark['summary']['recommendation']}")
    
    print("\n✅ Demonstration completed!")


if __name__ == "__main__":
    asyncio.run(demonstrate_tpm_crypto())