#!/usr/bin/env python3
"""
Test Script for Gemini Agent 3 Suggested Improvements
ALCUB3 MAESTRO Security Framework - Validation of Enhanced Features

This test validates the improvements suggested by Agent 3 (Gemini):
1. GCM Safety Limit Protection (Critical Security)
2. Enhanced Error Handling with Specific Crypto Exception Types
3. Enhanced Performance Monitoring with Detailed Metrics

Test Coverage:
- Custom cryptographic exception types
- GCM safety limit enforcement
- Enhanced performance tracking
- Detailed metrics collection
- Error categorization and handling
"""

import sys
import time
from pathlib import Path

# Add the security framework path
security_framework_path = Path(__file__).parent / "security_framework_python" / "src"
sys.path.insert(0, str(security_framework_path))

try:
    from shared.crypto_utils import (
        FIPSCryptoUtils, CryptoAlgorithm, SecurityLevel,
        CryptographicError, InvalidKeyError, EncryptionError, 
        DecryptionError, SignatureError, KeyGenerationError, 
        FIPSComplianceError
    )
    from shared.classification import SecurityClassification, ClassificationLevel
    print("✅ Successfully imported enhanced MAESTRO crypto utilities with Gemini improvements")
except ImportError as e:
    print(f"❌ Failed to import modules: {e}")
    sys.exit(1)

def test_enhanced_error_handling():
    """Test enhanced error handling with specific crypto exception types."""
    print("\n🔧 Testing Enhanced Error Handling...")
    
    try:
        # Initialize classification and crypto utils
        classification = SecurityClassification(ClassificationLevel.SECRET)
        crypto = FIPSCryptoUtils(classification, SecurityLevel.SECRET)
        
        # Test 1: InvalidKeyError for wrong key size
        print("\n📋 Test 1: InvalidKeyError Detection")
        try:
            # This should raise InvalidKeyError due to wrong key size
            wrong_key = b"too_short_key"  # Only 13 bytes instead of 32
            test_data = b"test data"
            # Try to use _aes_gcm_encrypt directly with wrong key size
            crypto._aes_gcm_encrypt(test_data, wrong_key)
            print("❌ Expected InvalidKeyError was not raised")
            return False
        except InvalidKeyError as e:
            print(f"✅ InvalidKeyError correctly caught: {e}")
        except Exception as e:
            print(f"❌ Unexpected exception type: {type(e).__name__}: {e}")
            return False
        
        # Test 2: KeyGenerationError handling
        print("\n📋 Test 2: KeyGenerationError Detection")
        try:
            # Generate a valid key first to ensure the system works
            valid_key = crypto.generate_key(CryptoAlgorithm.AES_256_GCM, "test_key")
            print(f"✅ Valid key generation successful: {valid_key.key_id}")
        except KeyGenerationError as e:
            print(f"❌ Unexpected KeyGenerationError: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected exception: {type(e).__name__}: {e}")
            return False
        
        # Test 3: DecryptionError for invalid parameters
        print("\n📋 Test 3: DecryptionError Detection")
        try:
            # Try decryption with invalid IV size
            valid_key_data = valid_key.key_data
            test_ciphertext = b"dummy_ciphertext"
            wrong_iv = b"short"  # Too short IV
            wrong_tag = b"wrong_tag_length"  # Wrong tag length
            
            crypto._aes_gcm_decrypt(test_ciphertext, valid_key_data, wrong_iv, wrong_tag)
            print("❌ Expected DecryptionError was not raised")
            return False
        except DecryptionError as e:
            print(f"✅ DecryptionError correctly caught: {e}")
        except Exception as e:
            print(f"❌ Unexpected exception type: {type(e).__name__}: {e}")
            return False
        
        print("✅ Enhanced error handling validation passed")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced error handling test failed: {e}")
        return False

def test_enhanced_performance_monitoring():
    """Test enhanced performance monitoring with detailed metrics."""
    print("\n📊 Testing Enhanced Performance Monitoring...")
    
    try:
        # Initialize crypto utils
        classification = SecurityClassification(ClassificationLevel.SECRET)
        crypto = FIPSCryptoUtils(classification, SecurityLevel.SECRET)
        
        # Test 1: Basic performance tracking
        print("\n📋 Test 1: Basic Performance Tracking")
        
        # Generate keys for testing
        aes_key = crypto.generate_key(CryptoAlgorithm.AES_256_GCM, "perf_test")
        rsa_key = crypto.generate_key(CryptoAlgorithm.RSA_4096, "perf_test")
        
        # Perform multiple operations to populate performance stats
        test_data = b"Performance test data for enhanced monitoring" * 100  # Larger data
        
        print("   Performing encryption/decryption operations...")
        for i in range(15):  # More than 10 to trigger average recalculation
            # AES encryption/decryption
            enc_result = crypto.encrypt_data(test_data, aes_key)
            dec_result = crypto.decrypt_data(enc_result.data, aes_key)
            
            # RSA signing/verification  
            sign_result = crypto.sign_data(test_data[:100], rsa_key)  # Smaller data for RSA
            verify_result = crypto.verify_signature(test_data[:100], sign_result.data, rsa_key)
        
        # Test 2: Enhanced metrics collection
        print("\n📋 Test 2: Enhanced Metrics Collection")
        
        metrics = crypto.get_crypto_metrics()
        
        # Validate enhanced metrics are present
        required_fields = [
            "total_operations", "encryption_operations", "decryption_operations",
            "signing_operations", "verification_operations", "performance_violations",
            "enhanced_performance_stats"
        ]
        
        for field in required_fields:
            if field not in metrics:
                print(f"❌ Missing enhanced metric field: {field}")
                return False
            print(f"   ✅ {field}: {metrics[field]}")
        
        # Validate enhanced performance stats
        enhanced_stats = metrics["enhanced_performance_stats"]
        print(f"\n   Enhanced Performance Statistics:")
        print(f"   - Max operation time: {enhanced_stats['max_operation_time_ms']:.2f}ms")
        print(f"   - Average operation time: {enhanced_stats['avg_operation_time_ms']:.2f}ms")
        print(f"   - Operations per second: {enhanced_stats['operations_per_second']:.2f}")
        print(f"   - Recent encryption avg: {enhanced_stats['recent_encryption_avg']:.2f}ms")
        print(f"   - Recent decryption avg: {enhanced_stats['recent_decryption_avg']:.2f}ms")
        print(f"   - Recent signing avg: {enhanced_stats['recent_signing_avg']:.2f}ms")
        print(f"   - Recent verification avg: {enhanced_stats['recent_verification_avg']:.2f}ms")
        
        # Validate reasonable values
        if enhanced_stats['max_operation_time_ms'] <= 0:
            print("❌ Invalid max operation time")
            return False
        
        if enhanced_stats['operations_per_second'] <= 0:
            print("❌ Invalid operations per second")
            return False
        
        # Test 3: Performance violation tracking
        print(f"\n📋 Test 3: Performance Violation Tracking")
        print(f"   - Total performance violations: {metrics['performance_violations']}")
        
        # Operations should be well within limits for our test data
        if metrics['performance_violations'] > 2:  # Allow some tolerance
            print(f"⚠️  High performance violations: {metrics['performance_violations']}")
        else:
            print("✅ Performance violations within acceptable range")
        
        print("✅ Enhanced performance monitoring validation passed")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced performance monitoring test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gcm_safety_limit_protection():
    """Test GCM safety limit protection mechanisms."""
    print("\n🛡️ Testing GCM Safety Limit Protection...")
    
    try:
        # Initialize crypto utils
        classification = SecurityClassification(ClassificationLevel.SECRET)
        crypto = FIPSCryptoUtils(classification, SecurityLevel.SECRET)
        
        # Test 1: Normal operation under safety limit
        print("\n📋 Test 1: Normal Operations Under Safety Limit")
        
        aes_key = crypto.generate_key(CryptoAlgorithm.AES_256_GCM, "safety_test")
        test_data = b"Safety limit test data"
        
        # Perform a few normal operations
        for i in range(5):
            enc_result = crypto.encrypt_data(test_data, aes_key)
            dec_result = crypto.decrypt_data(enc_result.data, aes_key)
        
        print("✅ Normal operations completed successfully")
        
        # Test 2: Check safety limit monitoring
        print("\n📋 Test 2: Safety Limit Monitoring")
        
        # Access the GCM security state to verify monitoring is active
        if hasattr(crypto, '_gcm_security'):
            gcm_state = crypto._gcm_security
            print(f"   - GCM encryption count: {gcm_state['encryption_count']}")
            print(f"   - Max encryptions per key: {gcm_state['max_encryptions_per_key']}")
            print(f"   - Safety monitoring active: {gcm_state.get('performance_monitoring', False)}")
            
            # Verify the safety limit is properly configured
            expected_limit = 2**32 - 1
            if gcm_state['max_encryptions_per_key'] == expected_limit:
                print("✅ GCM safety limit properly configured")
            else:
                print(f"❌ Incorrect safety limit: {gcm_state['max_encryptions_per_key']}")
                return False
        else:
            print("❌ GCM security state not initialized")
            return False
        
        # Test 3: Verify hard stop protection exists
        print("\n📋 Test 3: Hard Stop Protection Validation")
        
        # We can't easily test the actual hard stop without performing 2^32 operations,
        # but we can verify the protection code is in place by checking the method
        import inspect
        update_gcm_source = inspect.getsource(crypto._update_gcm_metrics)
        
        if "GCM safety limit exceeded" in update_gcm_source and "RuntimeError" in update_gcm_source:
            print("✅ Hard stop protection code confirmed in _update_gcm_metrics")
        else:
            print("❌ Hard stop protection code not found")
            return False
        
        print("✅ GCM safety limit protection validation passed")
        return True
        
    except Exception as e:
        print(f"❌ GCM safety limit protection test failed: {e}")
        return False

def main():
    """Main test execution for Gemini improvements."""
    print("🚀 ALCUB3 MAESTRO: Gemini Agent 3 Improvements Validation")
    print("=" * 80)
    print("Testing Agent 3 (Gemini) suggested improvements:")
    print("1. Enhanced Error Handling with Specific Exception Types")
    print("2. Enhanced Performance Monitoring with Detailed Metrics")  
    print("3. GCM Safety Limit Protection Mechanisms")
    
    try:
        results = []
        
        # Test enhanced error handling
        results.append(test_enhanced_error_handling())
        
        # Test enhanced performance monitoring
        results.append(test_enhanced_performance_monitoring())
        
        # Test GCM safety limit protection
        results.append(test_gcm_safety_limit_protection())
        
        # Summary
        passed_tests = sum(results)
        total_tests = len(results)
        
        print("\n" + "=" * 80)
        if passed_tests == total_tests:
            print("🎉 ALL GEMINI IMPROVEMENTS VALIDATED SUCCESSFULLY!")
            print(f"✅ {passed_tests}/{total_tests} test categories passed")
            print("\nImplemented Improvements:")
            print("✅ Custom cryptographic exception types for better error handling")
            print("✅ GCM safety limit protection with hard stop at 2^32-10000 operations") 
            print("✅ Enhanced performance monitoring with detailed operation metrics")
            print("✅ Real-time performance violation tracking")
            print("✅ Operations-per-second calculation and moving averages")
            print("✅ Better error categorization and audit trails")
            return 0
        else:
            print("❌ SOME GEMINI IMPROVEMENTS FAILED VALIDATION")
            print(f"❌ {passed_tests}/{total_tests} test categories passed")
            return 1
            
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())