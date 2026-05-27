"""
auth_service

Any application can import directly from here:

    from auth_service import register, start_auth, complete_auth
    from auth_service import hash_password, encrypt, decrypt
    from auth_service import generate_nonce, derive_key
"""

from auth_service.protocol import (
    register,
    start_auth,
    complete_auth,
    RegistrationResult,
    ChallengeResult,
    AuthResult,
)

from auth_service.hashing import (
    hash_password,
    verify_password,
    benchmark,
    ASCON,
    SHA256,
    BLAKE2B,
)

from auth_service.crypto import (
    encrypt,
    decrypt,
    generate_nonce,
    derive_key,
    NONCE_SIZE,
    KEY_SIZE,
    TAG_SIZE,
)

__all__ = [
    # Protocol
    "register", "start_auth", "complete_auth",
    "RegistrationResult", "ChallengeResult", "AuthResult",
    # Hashing
    "hash_password", "verify_password", "benchmark",
    "ASCON", "SHA256", "BLAKE2B",
    # Crypto
    "encrypt", "decrypt", "generate_nonce", "derive_key",
    "NONCE_SIZE", "KEY_SIZE", "TAG_SIZE",
]
