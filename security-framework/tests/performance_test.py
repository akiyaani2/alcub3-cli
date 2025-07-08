import time
import logging
from pathlib import Path
import os
import shutil

# Ensure the security-framework src directory is in the Python path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from shared.crypto_utils import FIPSCryptoUtils, CryptoAlgorithm, SecurityLevel
from shared.key_manager import SecureKeyManager, KeyRotationPolicy, KeyStatus

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("performance_test")

# Mock ClassificationSystem for FIPSCryptoUtils and SecureKeyManager
class MockClassificationSystem:
    def __init__(self, default_level: SecurityLevel):
        self.default_level = default_level

# --- Performance Test Configuration ---
TEST_RUNS = 1000  # Number of operations for each crypto test
PAYLOAD_SIZE_BYTES = 1024 * 1024  # 1MB payload for encryption/decryption
KEY_STORE_PATH = Path("./test_keystore_perf")

# --- Performance Targets (ms) ---
TARGET_AES_ENCRYPT = 100
TARGET_AES_DECRYPT = 100
TARGET_RSA_SIGN = 500
TARGET_RSA_VERIFY = 500
TARGET_KEY_GEN_AES = 50
TARGET_KEY_GEN_RSA = 700
TARGET_KEY_ROTATION = 200

def clean_keystore():
    if KEY_STORE_PATH.exists():
        shutil.rmtree(KEY_STORE_PATH)
    KEY_STORE_PATH.mkdir(parents=True, exist_ok=True)

def run_performance_test():
    logger.info("Starting cryptographic performance tests...")
    clean_keystore()

    # Initialize crypto and key management utilities
    mock_classification = MockClassificationSystem(SecurityLevel.TOP_SECRET)
    crypto_utils = FIPSCryptoUtils(mock_classification, SecurityLevel.TOP_SECRET)
    key_manager = SecureKeyManager(mock_classification, crypto_utils, str(KEY_STORE_PATH))

    # --- Test Key Generation Performance ---
    logger.info("\n--- Testing Key Generation Performance ---")
    
    # AES Key Generation
    start_time = time.perf_counter()
    aes_key_id = key_manager.generate_managed_key(CryptoAlgorithm.AES_256_GCM, "data_encryption")
    aes_key_gen_time = (time.perf_counter() - start_time) * 1000
    logger.info(f"AES-256-GCM Key Generation: {aes_key_gen_time:.2f} ms (Target: {TARGET_KEY_GEN_AES} ms)")
    assert aes_key_gen_time <= TARGET_KEY_GEN_AES, f"AES Key Gen exceeded target: {aes_key_gen_time:.2f}ms"

    # RSA Key Generation
    start_time = time.perf_counter()
    rsa_key_id = key_manager.generate_managed_key(CryptoAlgorithm.RSA_4096, "digital_signature")
    rsa_key_gen_time = (time.perf_counter() - start_time) * 1000
    logger.info(f"RSA-4096 Key Generation: {rsa_key_gen_time:.2f} ms (Target: {TARGET_KEY_GEN_RSA} ms)")
    assert rsa_key_gen_time <= TARGET_KEY_GEN_RSA, f"RSA Key Gen exceeded target: {rsa_key_gen_time:.2f}ms"

    # --- Test AES-256-GCM Performance ---
    logger.info("\n--- Testing AES-256-GCM Encryption/Decryption Performance ---")
    plaintext = os.urandom(PAYLOAD_SIZE_BYTES)
    aes_key_material = key_manager.get_key(aes_key_id)

    encrypt_times = []
    decrypt_times = []

    for i in range(TEST_RUNS):
        # Encryption
        start_time = time.perf_counter()
        encrypt_result = crypto_utils.encrypt_data(plaintext, aes_key_material)
        encrypt_times.append((time.perf_counter() - start_time) * 1000)
        assert encrypt_result.success, f"Encryption failed: {encrypt_result.error_message}"

        # Decryption
        start_time = time.perf_counter()
        decrypt_result = crypto_utils.decrypt_data(encrypt_result.data, aes_key_material)
        decrypt_times.append((time.perf_counter() - start_time) * 1000)
        assert decrypt_result.success, f"Decryption failed: {decrypt_result.error_message}"
        assert decrypt_result.data == plaintext, "Decrypted data does not match plaintext"

    avg_encrypt_time = sum(encrypt_times) / TEST_RUNS
    avg_decrypt_time = sum(decrypt_times) / TEST_RUNS

    logger.info(f"Avg AES-256-GCM Encryption ({PAYLOAD_SIZE_BYTES} bytes): {avg_encrypt_time:.2f} ms (Target: {TARGET_AES_ENCRYPT} ms)")
    logger.info(f"Avg AES-256-GCM Decryption ({PAYLOAD_SIZE_BYTES} bytes): {avg_decrypt_time:.2f} ms (Target: {TARGET_AES_DECRYPT} ms)")
    assert avg_encrypt_time <= TARGET_AES_ENCRYPT, f"AES Encrypt exceeded target: {avg_encrypt_time:.2f}ms"
    assert avg_decrypt_time <= TARGET_AES_DECRYPT, f"AES Decrypt exceeded target: {avg_decrypt_time:.2f}ms"

    # --- Test RSA-4096 Performance ---
    logger.info("\n--- Testing RSA-4096 Signing/Verification Performance ---")
    data_to_sign = os.urandom(2048) # Smaller data for signing
    rsa_key_material = key_manager.get_key(rsa_key_id)

    sign_times = []
    verify_times = []

    for i in range(TEST_RUNS):
        # Signing
        start_time = time.perf_counter()
        sign_result = crypto_utils.sign_data(data_to_sign, rsa_key_material)
        sign_times.append((time.perf_counter() - start_time) * 1000)
        assert sign_result.success, f"Signing failed: {sign_result.error_message}"

        # Verification
        start_time = time.perf_counter()
        verify_result = crypto_utils.verify_signature(data_to_sign, sign_result.data, rsa_key_material)
        verify_times.append((time.perf_counter() - start_time) * 1000)
        assert verify_result.success, f"Verification failed: {verify_result.error_message}"

    avg_sign_time = sum(sign_times) / TEST_RUNS
    avg_verify_time = sum(verify_times) / TEST_RUNS

    logger.info(f"Avg RSA-4096 Signing: {avg_sign_time:.2f} ms (Target: {TARGET_RSA_SIGN} ms)")
    logger.info(f"Avg RSA-4096 Verification: {avg_verify_time:.2f} ms (Target: {TARGET_RSA_VERIFY} ms)")
    assert avg_sign_time <= TARGET_RSA_SIGN, f"RSA Sign exceeded target: {avg_sign_time:.2f}ms"
    assert avg_verify_time <= TARGET_RSA_VERIFY, f"RSA Verify exceeded target: {avg_verify_time:.2f}ms"

    # --- Test Key Rotation Performance ---
    logger.info("\n--- Testing Key Rotation Performance ---")
    start_time = time.perf_counter()
    new_aes_key_id = key_manager.rotate_key(aes_key_id, trigger=RotationTrigger.TIME_BASED, reason="Performance test rotation")
    key_rotation_time = (time.perf_counter() - start_time) * 1000
    logger.info(f"Key Rotation (AES): {key_rotation_time:.2f} ms (Target: {TARGET_KEY_ROTATION} ms)")
    assert new_aes_key_id is not None, "Key rotation failed"
    assert key_rotation_time <= TARGET_KEY_ROTATION, f"Key Rotation exceeded target: {key_rotation_time:.2f}ms"

    logger.info("\nCryptographic performance tests completed successfully.")
    
    # Clean up keystore
    shutil.rmtree(KEY_STORE_PATH)

if __name__ == "__main__":
    run_performance_test()
