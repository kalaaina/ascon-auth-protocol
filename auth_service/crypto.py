"""
auth_service/crypto.py
======================
ASCON-128 AEAD (Authenticated Encryption with Associated Data).
This is the encryption layer used in Phase 2 of the protocol.

Why ASCON-128?
--------------
  - Winner of the NIST Lightweight Cryptography competition (2023)
  - 128-bit key, 128-bit nonce, 128-bit authentication tag
  - AEAD: encrypts the payload AND authenticates it in a single pass
  - The tag ensures that any tampering with the ciphertext is detected
    before decryption — no separate MAC step needed

How it fits in the protocol
----------------------------
  Client builds:
      key        = Nc ‖ Ns          (32 bytes: client nonce + server nonce)
      nonce      = random 16 bytes  (per-message nonce, never reused)
      ad         = user_id          (associated data, authenticated but not encrypted)
      plaintext  = H(password)      (what we want to protect)

  Then calls: encrypt(key, nonce, ad, plaintext) → (ciphertext, tag)
  Sends:      (nonce, ciphertext, tag) over the wire

  Server calls: decrypt(key, nonce, ad, ciphertext, tag)
  If tag is valid → recovers H(password) and compares with DB

Public API
----------
  generate_nonce()                              -> bytes  (16 bytes)
  derive_key(nc, ns)                            -> bytes  (16 bytes)
  encrypt(key, nonce, ad, plaintext)            -> (ciphertext: bytes, tag: bytes)
  decrypt(key, nonce, ad, ciphertext, tag)      -> bytes | None
"""

import os
import hmac
import ascon as _ascon  # used ONLY in this file


# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

NONCE_SIZE  = 16   # bytes — ASCON-128 nonce
KEY_SIZE    = 16   # bytes — ASCON-128 key
TAG_SIZE    = 16   # bytes — ASCON-128 authentication tag


# ══════════════════════════════════════════════════════════════════════════════
#  KEY & NONCE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def generate_nonce() -> bytes:
    """
    Generate a cryptographically secure random 128-bit nonce.

    Uses os.urandom which reads from the OS CSPRNG (/dev/urandom on Linux).
    MUST be unique for every encryption with the same key.
    """
    return os.urandom(NONCE_SIZE)


def derive_key(nc: bytes, ns: bytes) -> bytes:
    """
    Derive the shared symmetric key from the two nonces.

    Key derivation: K = (Nc ‖ Ns)[:16]
      - Nc : client nonce (16 bytes)  — chosen by the client
      - Ns : server nonce (16 bytes)  — chosen by the server
      - Both nonces are exchanged in plaintext before encryption begins
      - Their concatenation is never repeated because both sides generate
        fresh random nonces each session

    Note: In a production system you would use a proper KDF (e.g. HKDF)
    here. For this protocol we keep it simple: XOR the two 16-byte nonces
    so neither side can fully control the key alone.

    Parameters
    ----------
    nc : bytes  client nonce (must be NONCE_SIZE bytes)
    ns : bytes  server nonce (must be NONCE_SIZE bytes)

    Returns
    -------
    bytes  16-byte derived key
    """
    assert len(nc) == NONCE_SIZE, f"Nc must be {NONCE_SIZE} bytes"
    assert len(ns) == NONCE_SIZE, f"Ns must be {NONCE_SIZE} bytes"

    # XOR the two nonces — neither party controls the result alone
    return bytes(a ^ b for a, b in zip(nc, ns))


# ══════════════════════════════════════════════════════════════════════════════
#  AEAD  —  ENCRYPT / DECRYPT
# ══════════════════════════════════════════════════════════════════════════════

def encrypt(
    key:        bytes,
    nonce:      bytes,
    associated_data: bytes,
    plaintext:  bytes,
) -> tuple:
    """
    ASCON-128 authenticated encryption.

    Parameters
    ----------
    key             : bytes  16-byte symmetric key (use derive_key)
    nonce           : bytes  16-byte per-message nonce (use generate_nonce)
    associated_data : bytes  authenticated but NOT encrypted (e.g. user_id)
    plaintext       : bytes  data to protect (e.g. H(password))

    Returns
    -------
    (ciphertext, tag) : tuple[bytes, bytes]
      ciphertext  same length as plaintext
      tag         16-byte authentication tag

    Security
    --------
    The tag guarantees that:
      (a) the ciphertext was not tampered with
      (b) the associated_data was not substituted
      (c) the same key + nonce was used on both sides
    If any of these are violated, decrypt() returns None.
    """
    assert len(key)   == KEY_SIZE,   f"Key must be {KEY_SIZE} bytes"
    assert len(nonce) == NONCE_SIZE, f"Nonce must be {NONCE_SIZE} bytes"

    # ascon.encrypt returns ciphertext ‖ tag (tag appended at the end)
    ct_and_tag = _ascon.encrypt(key, nonce, associated_data, plaintext, variant="Ascon-128")

    ciphertext = ct_and_tag[:-TAG_SIZE]
    tag        = ct_and_tag[-TAG_SIZE:]
    return ciphertext, tag


def decrypt(
    key:        bytes,
    nonce:      bytes,
    associated_data: bytes,
    ciphertext: bytes,
    tag:        bytes,
) -> bytes | None:
    """
    ASCON-128 authenticated decryption.

    Verifies the authentication tag BEFORE decrypting. If the tag is
    invalid (tampered message, wrong key, wrong nonce, wrong AD), returns
    None immediately without producing any plaintext.

    Parameters
    ----------
    key             : bytes  same 16-byte key used during encryption
    nonce           : bytes  same 16-byte nonce used during encryption
    associated_data : bytes  same associated data used during encryption
    ciphertext      : bytes  the encrypted payload
    tag             : bytes  16-byte authentication tag from encryption

    Returns
    -------
    bytes  recovered plaintext, or None if verification fails
    """
    assert len(key)   == KEY_SIZE,   f"Key must be {KEY_SIZE} bytes"
    assert len(nonce) == NONCE_SIZE, f"Nonce must be {NONCE_SIZE} bytes"
    assert len(tag)   == TAG_SIZE,   f"Tag must be {TAG_SIZE} bytes"

    # Reassemble ciphertext ‖ tag as expected by the library
    plaintext = _ascon.decrypt(key, nonce, associated_data, ciphertext + tag, variant="Ascon-128")

    # Returns None if tag verification fails (library guarantees this)
    return plaintext