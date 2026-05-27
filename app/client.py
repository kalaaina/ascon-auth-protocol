"""
app/client.py
=============
Interactive TCP client for the ASCON Authentication Protocol.

Usage
-----
  python3 app/client.py

Menu
----
  1. Register   — create a new account
  2. Login      — authenticate with existing account
  3. Exit
"""

import sys
import json
import socket
import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from auth_service import (
    hash_password, generate_nonce, derive_key, encrypt, ASCON,
)

HOST    = "127.0.0.1"
PORT    = 9999
BUFSIZE = 4096


# ══════════════════════════════════════════════════════════════════════════════
#  TRANSPORT
# ══════════════════════════════════════════════════════════════════════════════

def _send(msg: dict) -> dict:
    """Open a TCP connection, send one JSON message, return the response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"    [→ SERVER] {json.dumps(msg)}")
            s.sendall(json.dumps(msg).encode("utf-8"))
            raw = s.recv(BUFSIZE)
            response = json.loads(raw.decode("utf-8"))
            print(f"    [← SERVER] {json.dumps(response)}")
            return response
    except ConnectionRefusedError:
        print("\n  [ERROR] Cannot connect to server. Is it running?")
        print(f"          Start it with:  python3 app/server.py\n")
        return {"status": "ERR", "message": "Connection refused."}


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

def register(user_id: str, password: str) -> bool:
    print(f"\n  {'─'*50}")
    print(f"  Phase 1 — Registration")
    print(f"  {'─'*50}")

    print(f"  Computing H(password) with ASCON-Hash…")
    h = hash_password(password, algo=ASCON)
    print(f"  H(password) = {h.hex()}")
    print(f"  [plaintext password stays on your machine — only hash is sent]\n")

    response = _send({
        "cmd":      "REGISTER",
        "user_id":  user_id,
        "hash_hex": h.hex(),
    })

    ok = response.get("status") == "OK"
    if ok:
        print(f"\n  ✔  {response['message']}")
    else:
        print(f"\n  ✘  {response['message']}")
    return ok


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def authenticate(user_id: str, password: str) -> str | None:
    print(f"\n  {'─'*50}")
    print(f"  Phase 2 — Authentication")
    print(f"  {'─'*50}")

    # ── Step 1: nonce exchange ────────────────────────────────────────────────
    print(f"\n  [Step 1] Nonce exchange")
    nc = generate_nonce()
    print(f"  Generated Nc = {nc.hex()}")

    resp1 = _send({
        "cmd":     "AUTH_INIT",
        "user_id": user_id,
        "nc_hex":  nc.hex(),
    })

    if resp1.get("status") != "OK":
        print(f"\n  ✘  {resp1.get('message')}")
        return None

    ns = bytes.fromhex(resp1["ns_hex"])
    print(f"  Received  Ns = {ns.hex()}")

    # ── Step 2: encrypt and send ──────────────────────────────────────────────
    print(f"\n  [Step 2] Encrypting credential with ASCON-128")
    key = derive_key(nc, ns)
    print(f"  K = Nc XOR Ns = {key.hex()}")

    hp = hash_password(password, algo=ASCON)
    print(f"  Hp = H(password) = {hp.hex()}")

    ascon_nonce = generate_nonce()
    ciphertext, tag = encrypt(key, ascon_nonce, user_id.encode(), hp)
    print(f"  Nonce      = {ascon_nonce.hex()}")
    print(f"  Ciphertext = {ciphertext.hex()}")
    print(f"  Tag (MAC)  = {tag.hex()}\n")

    resp2 = _send({
        "cmd":            "AUTH_FINISH",
        "user_id":        user_id,
        "nonce_hex":      ascon_nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex":        tag.hex(),
    })

    if resp2.get("status") != "OK":
        print(f"\n  ✘  {resp2.get('message')}")
        return None

    session_id = resp2.get("session_id", "")
    print(f"\n  ✔  {resp2.get('message')}")
    print(f"  Session token = {session_id}")
    return session_id


# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════════════════════

def _prompt_credentials() -> tuple:
    """Ask for username and password interactively."""
    user_id  = input("  Username : ").strip()
    password = getpass.getpass("  Password : ")   # hides input while typing
    return user_id, password


def main():
    print("\n" + "═" * 55)
    print("  TP2 — ASCON Lightweight Authentication Client")
    print(f"  Server: {HOST}:{PORT}")
    print("═" * 55)

    while True:
        print("\n  ┌─────────────────────────┐")
        print("  │  1. Register            │")
        print("  │  2. Login               │")
        print("  │  3. Exit                │")
        print("  └─────────────────────────┘")

        choice = input("\n  Choose [1/2/3]: ").strip()

        if choice == "1":
            print()
            user_id, password = _prompt_credentials()
            if not user_id or not password:
                print("  [!] Username and password cannot be empty.")
                continue
            register(user_id, password)

        elif choice == "2":
            print()
            user_id, password = _prompt_credentials()
            if not user_id or not password:
                print("  [!] Username and password cannot be empty.")
                continue
            authenticate(user_id, password)

        elif choice == "3":
            print("\n  Goodbye.\n")
            break

        else:
            print("  [!] Invalid choice. Enter 1, 2 or 3.")


if __name__ == "__main__":
    main()