"""
auth_service/hashing.py
=======================
Unified hashing interface for the authentication protocol.

Wraps three hash algorithms behind a single API so the rest of the
auth_service (and any external app) never imports a hash library directly.
Swap the underlying algorithm here without touching protocol.py or server.py.

Algorithms
----------
  ASCON-Hash   NIST LWC standard (2023), 256-bit, 128-bit security
  SHA-256      Classic standard, 256-bit
  BLAKE2b-256  Fast modern alternative, 256-bit

Public API
----------
  hash_password(password, algo)  -> bytes   hash a plaintext password
  verify_password(password, stored_hash, algo) -> bool
  supported_algorithms()         -> list[str]
"""

import hashlib
import time
import ascon as _ascon  # the pip package — used ONLY in this file

# ── Algorithm identifiers ─────────────────────────────────────────────────────
ASCON   = "ascon"
SHA256  = "sha256"
BLAKE2B = "blake2b"

_SUPPORTED = [ASCON, SHA256, BLAKE2B]


# ══════════════════════════════════════════════════════════════════════════════
#  CORE HASH FUNCTIONS  (one per algorithm, private)
# ══════════════════════════════════════════════════════════════════════════════

def _hash_ascon(data: bytes) -> bytes:
    """
    ASCON-Hash (NIST LWC standard, 2023).
    Sponge construction, rate=64 bits, 12 rounds, 256-bit output.
    Designed for constrained environments (IoT, embedded).
    """
    return _ascon.hash(data, variant="Ascon-Hash")


def _hash_sha256(data: bytes) -> bytes:
    """
    SHA-256 (NIST FIPS 180-4).
    Merkle-Damgård construction, 256-bit output.
    Standard baseline for comparison.
    """
    return hashlib.sha256(data).digest()


def _hash_blake2b(data: bytes) -> bytes:
    """
    BLAKE2b truncated to 256 bits.
    Optimised for 64-bit platforms, faster than SHA-256 in software.
    """
    return hashlib.blake2b(data, digest_size=32).digest()


# Dispatch table — maps algorithm name → function
_HASHERS = {
    ASCON:   _hash_ascon,
    SHA256:  _hash_sha256,
    BLAKE2B: _hash_blake2b,
}


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def supported_algorithms() -> list:
    """Return the list of supported algorithm identifiers."""
    return list(_SUPPORTED)


def hash_password(password: str, algo: str = ASCON) -> bytes:
    """
    Hash a plaintext password with the chosen algorithm.

    Parameters
    ----------
    password : str   plaintext password (UTF-8 encoded internally)
    algo     : str   one of ASCON | SHA256 | BLAKE2B  (default: ASCON)

    Returns
    -------
    bytes  32-byte (256-bit) digest

    Raises
    ------
    ValueError  if algo is not supported
    """
    if algo not in _HASHERS:
        raise ValueError(
            f"Unsupported algorithm '{algo}'. "
            f"Choose from: {_SUPPORTED}"
        )
    return _HASHERS[algo](password.encode("utf-8"))


def verify_password(password: str, stored_hash: bytes, algo: str = ASCON) -> bool:
    """
    Verify a plaintext password against a previously stored hash.

    Uses a constant-time comparison to prevent timing attacks.

    Parameters
    ----------
    password    : str    candidate plaintext password
    stored_hash : bytes  the hash stored at registration time
    algo        : str    algorithm used during registration

    Returns
    -------
    bool  True if the password matches, False otherwise
    """
    candidate = hash_password(password, algo)
    # hmac.compare_digest is constant-time — prevents timing side-channels
    import hmac
    return hmac.compare_digest(candidate, stored_hash)


def benchmark(password: str = "BenchmarkPassword123!", iterations: int = 100) -> dict:
    """
    Measure average hashing time for each algorithm over `iterations` runs.

    Useful for Phase 3 comparison. Returns a dict:
      { algo_name: { "avg_us": float, "digest_hex": str, "digest_bits": int } }
    """
    results = {}
    data = password.encode("utf-8")

    for algo, fn in _HASHERS.items():
        times = []
        digest = None
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            digest = fn(data)
            times.append(time.perf_counter_ns() - t0)

        avg_ns = sum(times) / len(times)
        results[algo] = {
            "avg_us":     round(avg_ns / 1_000, 3),
            "avg_ns":     round(avg_ns, 1),
            "digest_hex": digest.hex(),
            "digest_bits": len(digest) * 8,
        }

    return results