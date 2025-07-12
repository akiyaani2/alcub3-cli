class CryptographicError(Exception):
    """Base exception for cryptographic operations."""
    pass

class InvalidKeyError(CryptographicError):
    """Raised when a cryptographic key is invalid or corrupted."""
    pass

class EncryptionError(CryptographicError):
    """Raised when encryption operation fails."""
    pass

class DecryptionError(CryptographicError):
    """Raised when decryption operation fails."""
    pass

class SignatureError(CryptographicError):
    """Raised when digital signature operation fails."""
    pass

class KeyGenerationError(CryptographicError):
    """Raised when key generation fails."""
    pass

class FIPSComplianceError(CryptographicError):
    """Raised when FIPS compliance validation fails."""
    pass
