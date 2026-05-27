"""
auth_service/protocol.py
========================
Core authentication protocol — the reusable service layer.

This module implements the two protocol phases as pure functions that
operate on data. It has NO knowledge of sockets, HTTP, or any transport.
Any application (TCP server, REST API, CLI tool) can import and use it.

Protocol summary
----------------

  PHASE 1 — Registration
  ┌─────────────────────────────────────────────────────────────┐
  │  Client                         Auth Service                │
  │  ──────                         ────────────                │
  │  password                                                   │
  │     │ H(password) via ASCON-Hash                           │
  │     ├───────────────────────────► store {id: H(password)}  │
  └─────────────────────────────────────────────────────────────┘

  PHASE 2 — Authentication
  ┌─────────────────────────────────────────────────────────────┐
  │  Client                         Auth Service                │
  │  ──────                         ────────────                │
  │  generate Nc                                                │
  │     │ ID, Nc                                                │
  │     ├───────────────────────────► generate Ns               │
  │     │                            fetch H(pwd) from DB       │
  │     │                Ns          ◄────────────              │
  │     │◄──────────────────────────┤                           │
  │  Hp = H(password)                                           │
  │  K  = derive_key(Nc, Ns)                                    │
  │  (cipher, tag) = ASCON_encrypt(K, Nonce, ID, Hp)           │
  │     │ Nonce, cipher, tag                                    │
  │     ├───────────────────────────► decrypt + verify tag      │
  │     │                            compare Hp with DB         │
  │     │             OK / FAIL                                 │
  │     │◄──────────────────────────┤                           │
  └─────────────────────────────────────────────────────────────┘

Public API
----------
  register(user_id, password)         -> RegistrationResult
  start_auth(user_id)                 -> ChallengeResult
  complete_auth(user_id, nc, nonce, ciphertext, tag) -> AuthResult
"""

import json
import time
import hmac
from pathlib import Path
from dataclasses import dataclass, field

from auth_service.hashing import hash_password, ASCON
from auth_service.crypto  import (
    generate_nonce, derive_key,
    encrypt, decrypt,
    NONCE_SIZE,
)


# ── Path to the simulated user database ──────────────────────────────────────
_DB_PATH = Path(__file__).parent.parent / "db" / "users.json"

# ── In-memory pending challenge store (keyed by user_id) ─────────────────────
# In production this would be Redis with a TTL. Here a dict is enough.
_pending_challenges: dict = {}

# Challenge TTL in seconds — a nonce exchange must complete within this window
CHALLENGE_TTL = 60


# ══════════════════════════════════════════════════════════════════════════════
#  RESULT DATACLASSES  — typed return values (no raw tuples)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RegistrationResult:
    success:   bool
    user_id:   str
    message:   str
    hash_hex:  str = ""           # H(password) as hex, for inspection


@dataclass
class ChallengeResult:
    success:   bool
    user_id:   str
    ns:        bytes = b""        # server nonce to send back to client
    message:   str  = ""


@dataclass
class AuthResult:
    success:    bool
    user_id:    str
    message:    str
    session_id: str = ""          # opaque session token on success


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE HELPERS  (private — only protocol.py talks to the DB)
# ══════════════════════════════════════════════════════════════════════════════

def _load_db() -> dict:
    if _DB_PATH.exists():
        with open(_DB_PATH, "r") as f:
            return json.load(f)
    return {}


def _save_db(db: dict) -> None:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


def _get_user(user_id: str) -> dict | None:
    """Return the stored record for user_id, or None if not found."""
    return _load_db().get(user_id)


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

def register(user_id: str, password: str) -> RegistrationResult:
    """
    Register a new user.

    CLIENT SIDE (simulated here):
      - Hashes the password with ASCON-Hash

    SERVER SIDE:
      - Validates that the user does not already exist
      - Stores only H(password) — never the plaintext

    Parameters
    ----------
    user_id  : str  unique identifier chosen by the client
    password : str  plaintext password (never stored, never logged)

    Returns
    -------
    RegistrationResult
    """
    # ── Reject duplicate registrations ───────────────────────────────────────
    if _get_user(user_id) is not None:
        return RegistrationResult(
            success=False,
            user_id=user_id,
            message=f"User '{user_id}' already exists.",
        )

    # ── CLIENT: hash the password ─────────────────────────────────────────────
    h = hash_password(password, algo=ASCON)

    # ── SERVER: store only the hash ───────────────────────────────────────────
    db = _load_db()
    db[user_id] = {
        "hash_hex":      h.hex(),
        "algo":          ASCON,
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _save_db(db)

    return RegistrationResult(
        success=True,
        user_id=user_id,
        message="Registration successful.",
        hash_hex=h.hex(),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — AUTHENTICATION  (two steps)
# ══════════════════════════════════════════════════════════════════════════════

def start_auth(user_id: str, nc: bytes) -> ChallengeResult:
    """
    Step 2.1 — Server side: receive ID + Nc, reply with Ns.

    The server:
      1. Checks the user exists
      2. Validates that Nc is the right size
      3. Generates its own nonce Ns
      4. Stores (Nc, Ns, timestamp) in the pending challenge store
      5. Returns Ns to the client

    Parameters
    ----------
    user_id : str    client's identity
    nc      : bytes  client nonce (16 bytes)

    Returns
    -------
    ChallengeResult  containing ns (the server nonce) on success
    """
    # ── User must exist ───────────────────────────────────────────────────────
    if _get_user(user_id) is None:
        return ChallengeResult(
            success=False,
            user_id=user_id,
            message=f"Unknown user '{user_id}'.",
        )

    # ── Nc must be the correct size ───────────────────────────────────────────
    if len(nc) != NONCE_SIZE:
        return ChallengeResult(
            success=False,
            user_id=user_id,
            message=f"Invalid Nc size: expected {NONCE_SIZE}, got {len(nc)}.",
        )

    # ── Generate server nonce ─────────────────────────────────────────────────
    ns = generate_nonce()

    # ── Store pending challenge ───────────────────────────────────────────────
    _pending_challenges[user_id] = {
        "nc":         nc,
        "ns":         ns,
        "created_at": time.time(),
    }

    return ChallengeResult(success=True, user_id=user_id, ns=ns, message="Challenge issued.")


def complete_auth(
    user_id:    str,
    nonce:      bytes,    # per-message nonce chosen by the client for ASCON
    ciphertext: bytes,    # ASCON-128 encrypted H(password)
    tag:        bytes,    # ASCON-128 authentication tag
) -> AuthResult:
    """
    Step 2.2 — Server side: receive (Nonce, Msg, Tag), verify, compare.

    The server:
      1. Retrieves the pending challenge (Nc, Ns)
      2. Rejects if the challenge has expired
      3. Derives the same key K = derive_key(Nc, Ns)
      4. Decrypts with ASCON-128 — returns None if tag is invalid
      5. Compares the recovered H(password) with the stored hash
      6. On success: generates a session token and clears the challenge

    Parameters
    ----------
    user_id    : str    client's identity
    nonce      : bytes  per-message ASCON nonce (16 bytes)
    ciphertext : bytes  ASCON-encrypted payload
    tag        : bytes  ASCON authentication tag (16 bytes)

    Returns
    -------
    AuthResult  with session_id on success, empty string on failure
    """
    # ── Retrieve and validate the pending challenge ───────────────────────────
    challenge = _pending_challenges.get(user_id)
    if challenge is None:
        return AuthResult(False, user_id, "No pending challenge. Call start_auth first.")

    age = time.time() - challenge["created_at"]
    if age > CHALLENGE_TTL:
        del _pending_challenges[user_id]
        return AuthResult(False, user_id, f"Challenge expired ({age:.0f}s > {CHALLENGE_TTL}s).")

    nc = challenge["nc"]
    ns = challenge["ns"]

    # ── Derive the shared key from both nonces ────────────────────────────────
    key = derive_key(nc, ns)

    # ── Decrypt and verify tag ────────────────────────────────────────────────
    # associated_data = user_id (binds the ciphertext to this specific user)
    recovered_hp = decrypt(key, nonce, user_id.encode(), ciphertext, tag)

    if recovered_hp is None:
        # Tag mismatch: message was tampered with, wrong key, or wrong nonce
        return AuthResult(False, user_id, "Authentication tag verification failed.")

    # ── Compare recovered H(password) with stored hash ────────────────────────
    record = _get_user(user_id)
    stored_hash = bytes.fromhex(record["hash_hex"])

    if not hmac.compare_digest(recovered_hp, stored_hash):
        return AuthResult(False, user_id, "Password mismatch.")

    # ── Success: issue a session token ────────────────────────────────────────
    del _pending_challenges[user_id]   # consume the challenge (anti-replay)

    import secrets
    session_id = secrets.token_hex(32)

    return AuthResult(
        success=True,
        user_id=user_id,
        message="Authentication successful.",
        session_id=session_id,
    )