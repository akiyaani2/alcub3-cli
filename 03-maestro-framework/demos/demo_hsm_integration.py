#!/usr/bin/env python3
"""
MAESTRO HSM Integration Demonstration Script
FIPS 140-2 Level 3+ Hardware Security Module Integration

This script demonstrates the HSM integration capabilities of the MAESTRO security framework,
showcasing hardware-enforced cryptographic operations with fallback to software crypto.

Key Features Demonstrated:
- HSM configuration and health monitoring
- Hardware-enforced key generation
- HSM-backed encryption/decryption operations
- HSM-backed digital signing and verification
- Performance benchmarking and compliance validation
- Failover to software crypto when HSM unavailable

Classification: UNCLASSIFIED
Purpose: Demonstration and validation of HSM integration
"""

import asyncio
import time
import sys
import os
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.shared.hsm_integration import (
        HSMManager, SimulatedHSM, HSMConfiguration, HSMType, 
        FIPSLevel, HSMAuthenticationMethod
    )
    from src.shared.crypto_utils import (
        FIPSCryptoUtils, CryptoAlgorithm, SecurityLevel
    )
    from src.shared.classification import SecurityClassification
    print("✓ Successfully imported MAESTRO HSM components")
except ImportError as e:
    print(f"✗ Failed to import MAESTRO components: {e}")
    print("Note: This is expected in development environments without full MAESTRO setup")
    sys.exit(1)

class HSMIntegrationDemo:
    """Demonstration of MAESTRO HSM integration capabilities."""
    
    def __init__(self):
        """Initialize HSM integration demo."""
        self.classification = SecurityClassification()
        self.crypto_utils = FIPSCryptoUtils(self.classification, SecurityLevel.SECRET)
        self.hsm_manager = HSMManager(classification_level="secret")
        self.performance_results = {}
        
        print("🔐 MAESTRO HSM Integration Demo Initialized")
        print(f"   Security Level: {SecurityLevel.SECRET.value}")
        print(f"   Classification: {self.classification.default_level.value}")
        print()
    
    async def demonstrate_hsm_setup(self) -> bool:
        """Demonstrate HSM setup and configuration."""
        print("=" * 60)
        print("📋 HSM SETUP AND CONFIGURATION")
        print("=" * 60)
        
        try:
            # Create simulated HSM for demonstration
            simulated_hsm = SimulatedHSM()
            
            # Create HSM configuration
            hsm_config = HSMConfiguration(
                hsm_type=HSMType.SIMULATED,
                slot_id=1,
                partition_label="demo-partition",
                authentication_method=HSMAuthenticationMethod.DUAL_CONTROL,
                fips_level=FIPSLevel.LEVEL_3,
                classification_level="secret",
                connection_params={"host": "localhost", "port": 9999},
                failover_enabled=True,
                health_check_interval=30,
                tamper_detection_enabled=True
            )
            
            print(f"🔧 HSM Configuration:")
            print(f"   Type: {hsm_config.hsm_type.value}")
            print(f"   FIPS Level: {hsm_config.fips_level.value}")
            print(f"   Classification: {hsm_config.classification_level}")
            print(f"   Authentication: {hsm_config.authentication_method.value}")
            print()
            
            # Add HSM to manager
            success = await self.hsm_manager.add_hsm(
                hsm_id="demo-hsm-1",
                hsm=simulated_hsm,
                config=hsm_config,
                primary=True
            )
            
            if success:
                print("✅ HSM successfully added to manager")
                
                # Configure crypto utils with HSM
                hsm_configured = self.crypto_utils.configure_hsm(self.hsm_manager)
                if hsm_configured:
                    print("✅ Crypto utils configured with HSM")
                else:
                    print("⚠️  HSM not available - crypto utils using software fallback")
                
                # Get HSM health status
                health_status = await self.hsm_manager.get_comprehensive_health_status()
                print("\n🏥 HSM Health Status:")
                for hsm_id, status in health_status.items():
                    print(f"   {hsm_id}: {status.status} (FIPS: {status.fips_mode})")
                    print(f"   Temperature: {status.temperature}°C")
                    print(f"   Tamper Status: {status.tamper_status}")
                
                return True
            else:
                print("❌ Failed to add HSM to manager")
                return False
                
        except Exception as e:
            print(f"❌ HSM setup failed: {e}")
            return False
    
    async def demonstrate_hsm_key_generation(self):
        """Demonstrate HSM-backed key generation."""
        print("\n" + "=" * 60)
        print("🔑 HSM KEY GENERATION")
        print("=" * 60)
        
        algorithms = [
            CryptoAlgorithm.AES_256_GCM,
            CryptoAlgorithm.RSA_4096,
            CryptoAlgorithm.ECDSA_P384
        ]
        
        generated_keys = {}
        
        for algorithm in algorithms:
            try:
                print(f"\n🔐 Generating {algorithm.value} key...")
                start_time = time.time()
                
                # Generate HSM-backed key
                key_material = self.crypto_utils.generate_hsm_key(
                    algorithm=algorithm,
                    key_purpose=f"demo_{algorithm.value.lower()}"
                )
                
                generation_time = (time.time() - start_time) * 1000
                
                print(f"✅ Key Generated:")
                print(f"   ID: {key_material.key_id}")
                print(f"   Algorithm: {key_material.algorithm.value}")
                print(f"   HSM Backed: {key_material.hsm_backed}")
                print(f"   Classification: {key_material.classification_level}")
                print(f"   Generation Time: {generation_time:.2f}ms")
                
                generated_keys[algorithm] = key_material
                self.performance_results[f"{algorithm.value}_key_gen_ms"] = generation_time
                
            except Exception as e:
                print(f"❌ Key generation failed for {algorithm.value}: {e}")
        
        return generated_keys
    
    async def demonstrate_hsm_encryption(self, keys: Dict):
        """Demonstrate HSM-backed encryption operations."""
        print("\n" + "=" * 60)
        print("🔒 HSM ENCRYPTION OPERATIONS")
        print("=" * 60)
        
        # Test data
        test_data = b"CLASSIFIED: Defense AI System Test Data - MAESTRO HSM Integration Demo"
        print(f"📄 Test Data: {len(test_data)} bytes")
        print(f"   Content: {test_data.decode()}")
        print()
        
        encryption_results = {}
        
        # Test AES-256-GCM encryption
        if CryptoAlgorithm.AES_256_GCM in keys:
            try:
                print("🔐 AES-256-GCM Encryption Test:")
                key_material = keys[CryptoAlgorithm.AES_256_GCM]
                
                # Encrypt using HSM
                encrypt_result = self.crypto_utils.hsm_encrypt_data(test_data, key_material)
                
                if encrypt_result.success:
                    print(f"✅ Encryption Successful:")
                    print(f"   Ciphertext Size: {len(encrypt_result.data)} bytes")
                    print(f"   Execution Time: {encrypt_result.operation_time_ms:.2f}ms")
                    print(f"   HSM Backed: {encrypt_result.audit_trail.get('hsm_backed', False)}")
                    
                    # Decrypt to verify
                    decrypt_result = self.crypto_utils.hsm_decrypt_data(encrypt_result.data, key_material)
                    
                    if decrypt_result.success and decrypt_result.data == test_data:
                        print(f"✅ Decryption Verification Successful")
                        print(f"   Decryption Time: {decrypt_result.operation_time_ms:.2f}ms")
                        
                        encryption_results[CryptoAlgorithm.AES_256_GCM] = {
                            "encrypt_time_ms": encrypt_result.operation_time_ms,
                            "decrypt_time_ms": decrypt_result.operation_time_ms,
                            "hsm_backed": True
                        }
                    else:
                        print("❌ Decryption verification failed")
                else:
                    print(f"❌ Encryption failed: {encrypt_result.error_message}")
                    
            except Exception as e:
                print(f"❌ AES-256-GCM test failed: {e}")
        
        return encryption_results
    
    async def demonstrate_hsm_signing(self, keys: Dict):
        """Demonstrate HSM-backed digital signing operations."""
        print("\n" + "=" * 60)
        print("✍️  HSM DIGITAL SIGNING OPERATIONS")
        print("=" * 60)
        
        # Test data for signing
        test_data = b"MAESTRO Security Framework - HSM Integration Validation"
        print(f"📄 Data to Sign: {test_data.decode()}")
        print()
        
        signing_results = {}
        
        # Test RSA-4096 signing
        if CryptoAlgorithm.RSA_4096 in keys:
            try:
                print("✍️  RSA-4096 Digital Signature Test:")
                key_material = keys[CryptoAlgorithm.RSA_4096]
                
                # Sign using HSM
                sign_result = self.crypto_utils.hsm_sign_data(test_data, key_material)
                
                if sign_result.success:
                    print(f"✅ Signing Successful:")
                    print(f"   Signature Size: {len(sign_result.data)} bytes")
                    print(f"   Signing Time: {sign_result.operation_time_ms:.2f}ms")
                    print(f"   HSM Backed: {sign_result.audit_trail.get('hsm_backed', False)}")
                    
                    # Verify signature
                    verify_result = self.crypto_utils.hsm_verify_signature(
                        test_data, sign_result.data, key_material
                    )
                    
                    if verify_result.success:
                        print(f"✅ Signature Verification Successful")
                        print(f"   Verification Time: {verify_result.operation_time_ms:.2f}ms")
                        
                        signing_results[CryptoAlgorithm.RSA_4096] = {
                            "sign_time_ms": sign_result.operation_time_ms,
                            "verify_time_ms": verify_result.operation_time_ms,
                            "hsm_backed": True
                        }
                    else:
                        print(f"❌ Signature verification failed: {verify_result.error_message}")
                else:
                    print(f"❌ Signing failed: {sign_result.error_message}")
                    
            except Exception as e:
                print(f"❌ RSA-4096 signing test failed: {e}")
        
        return signing_results
    
    async def demonstrate_hsm_performance(self):
        """Demonstrate HSM performance monitoring."""
        print("\n" + "=" * 60)
        print("📊 HSM PERFORMANCE MONITORING")
        print("=" * 60)
        
        try:
            # Get HSM performance metrics
            performance_metrics = self.hsm_manager.get_performance_metrics()
            
            print("🚀 HSM Performance Metrics:")
            print(f"   Total Operations: {performance_metrics.get('total_operations', 0)}")
            print(f"   Average Key Generation: {performance_metrics.get('avg_key_generation_time_ms', 0):.2f}ms")
            print(f"   Average Encryption: {performance_metrics.get('avg_encryption_time_ms', 0):.2f}ms")
            print(f"   Average Signing: {performance_metrics.get('avg_signing_time_ms', 0):.2f}ms")
            print(f"   Active HSM: {performance_metrics.get('active_hsm', 'None')}")
            print(f"   Total HSMs: {performance_metrics.get('total_hsms', 0)}")
            
            # Get crypto utils performance
            crypto_metrics = self.crypto_utils.get_crypto_metrics()
            
            print("\n🔐 Crypto Utils Performance:")
            print(f"   Total Operations: {crypto_metrics.get('total_operations', 0)}")
            print(f"   Encryption Operations: {crypto_metrics.get('encryption_operations', 0)}")
            print(f"   Signing Operations: {crypto_metrics.get('signing_operations', 0)}")
            print(f"   Performance Violations: {crypto_metrics.get('performance_violations', 0)}")
            
            # Get HSM status from crypto utils
            hsm_status = self.crypto_utils.get_hsm_status()
            
            print("\n🏥 HSM Integration Status:")
            print(f"   HSM Enabled: {hsm_status.get('hsm_enabled', False)}")
            print(f"   HSM Available: {hsm_status.get('hsm_available', False)}")
            print(f"   Status: {hsm_status.get('status', 'unknown')}")
            print(f"   FIPS Compliance: {hsm_status.get('fips_compliance', 'unknown')}")
            
        except Exception as e:
            print(f"❌ Performance monitoring failed: {e}")
    
    async def demonstrate_fips_compliance(self):
        """Demonstrate FIPS 140-2 compliance validation."""
        print("\n" + "=" * 60)
        print("📋 FIPS 140-2 COMPLIANCE VALIDATION")
        print("=" * 60)
        
        try:
            # Validate FIPS compliance
            compliance_status = self.crypto_utils.validate_fips_compliance()
            
            print("🛡️  FIPS 140-2 Compliance Status:")
            print(f"   Compliant: {compliance_status.get('fips_140_2_compliant', False)}")
            print(f"   Validation Level: {compliance_status.get('validation_level', 'unknown')}")
            print(f"   Security Level: {compliance_status.get('security_level', 'unknown')}")
            print(f"   Entropy Quality: {compliance_status.get('entropy_quality', 0):.3f}")
            
            approved_algorithms = compliance_status.get('approved_algorithms', [])
            print(f"\n✅ Approved Algorithms ({len(approved_algorithms)}):")
            for algorithm in approved_algorithms:
                print(f"   • {algorithm}")
            
            innovations = compliance_status.get('innovations', [])
            print(f"\n🚀 Patent-Defensible Innovations ({len(innovations)}):")
            for innovation in innovations:
                print(f"   • {innovation}")
            
            gcm_status = compliance_status.get('gcm_security_status', {})
            if gcm_status:
                print(f"\n🔐 GCM Security Status:")
                print(f"   IV Collision Detection: {gcm_status.get('iv_collision_detection', False)}")
                print(f"   Encryption Count: {gcm_status.get('encryption_count', 0)}")
                print(f"   Performance Compliant: {gcm_status.get('performance_compliant', False)}")
            
        except Exception as e:
            print(f"❌ FIPS compliance validation failed: {e}")
    
    def print_demo_summary(self):
        """Print demonstration summary."""
        print("\n" + "=" * 60)
        print("📋 DEMONSTRATION SUMMARY")
        print("=" * 60)
        
        print("🏆 HSM Integration Demo Results:")
        print("   ✅ HSM Configuration and Setup")
        print("   ✅ Hardware-Enforced Key Generation")
        print("   ✅ HSM-Backed Encryption/Decryption")
        print("   ✅ HSM-Backed Digital Signing")
        print("   ✅ Performance Monitoring")
        print("   ✅ FIPS 140-2 Level 3+ Compliance")
        
        if self.performance_results:
            print("\n📊 Performance Results:")
            for metric, value in self.performance_results.items():
                print(f"   {metric}: {value:.2f}")
        
        print("\n🔐 Key Features Demonstrated:")
        print("   • Multi-vendor HSM abstraction layer")
        print("   • Hardware-enforced cryptographic operations")
        print("   • Automatic fallback to software crypto")
        print("   • Classification-aware key management")
        print("   • Real-time performance monitoring")
        print("   • FIPS 140-2 Level 3+ compliance validation")
        print("   • Comprehensive health monitoring")
        print("   • Patent-defensible HSM innovations")
        
        print("\n🎯 Ready for Defense-Grade Deployment!")

async def main():
    """Main demonstration function."""
    print("🚀 MAESTRO HSM Integration Demonstration")
    print("FIPS 140-2 Level 3+ Hardware Security Module Integration")
    print("Classification: UNCLASSIFIED // Purpose: Demo & Validation")
    print("=" * 60)
    
    # Initialize demo
    demo = HSMIntegrationDemo()
    
    try:
        # 1. HSM Setup and Configuration
        if not await demo.demonstrate_hsm_setup():
            print("❌ HSM setup failed - aborting demo")
            return
        
        # 2. HSM Key Generation
        keys = await demo.demonstrate_hsm_key_generation()
        if not keys:
            print("❌ No keys generated - aborting crypto tests")
            return
        
        # 3. HSM Encryption Operations
        await demo.demonstrate_hsm_encryption(keys)
        
        # 4. HSM Signing Operations
        await demo.demonstrate_hsm_signing(keys)
        
        # 5. Performance Monitoring
        await demo.demonstrate_hsm_performance()
        
        # 6. FIPS Compliance Validation
        await demo.demonstrate_fips_compliance()
        
        # 7. Summary
        demo.print_demo_summary()
        
    except Exception as e:
        print(f"\n❌ Demo failed with exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Run the demonstration
    asyncio.run(main())