"""
app/server.py
=============
TCP server — thin transport layer on top of auth_service.

Responsibilities
----------------
  - Listen on a TCP socket (default: localhost:9999)
  - Speak a simple line-delimited JSON protocol
  - Delegate ALL crypto and protocol logic to auth_service
  - Print every message sent/received so Wireshark results can be verified

Message format (one JSON object per line, UTF-8)
-------------------------------------------------
  Client → Server:   { "cmd": "REGISTER"|"AUTH_INIT"|"AUTH_FINISH", ...fields }
  Server → Client:   { "status": "OK"|"ERR", ...fields }

Commands
--------
  REGISTER     { cmd, user_id, hash_hex }
  AUTH_INIT    { cmd, user_id, nc_hex }
  AUTH_FINISH  { cmd, user_id, nonce_hex, ciphertext_hex, tag_hex }
"""

import sys
import json
import socket
import threading
from pathlib import Path

# Make sure auth_service is importable when running from app/
sys.path.insert(0, str(Path(__file__).parent.parent))

from auth_service import (
    register, start_auth, complete_auth,
)

# ── Configuration ─────────────────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 9999
BUFSIZE = 4096


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _log(direction: str, addr: tuple, data: dict) -> None:
    tag = f"[{direction}][{addr[0]}:{addr[1]}]"
    print(f"{tag} {json.dumps(data)}")


# ══════════════════════════════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

def _handle_register(msg: dict) -> dict:
    """
    REGISTER command.

    The client already computed H(password) on its side and sends us the
    hex-encoded hash. We call auth_service.register which stores it.

    Note: the server never sees the plaintext password.
    """
    user_id  = msg.get("user_id", "")
    hash_hex = msg.get("hash_hex", "")

    if not user_id or not hash_hex:
        return {"status": "ERR", "message": "Missing user_id or hash_hex."}

    # Reconstruct bytes from hex
    try:
        h_bytes = bytes.fromhex(hash_hex)
    except ValueError:
        return {"status": "ERR", "message": "Invalid hex in hash_hex."}

    # Call the protocol — but inject the pre-computed hash directly into DB
    # (register() normally computes the hash itself; here we trust the client's
    #  hash because the client is the one who knows the password)
    import json as _json, time
    from pathlib import Path as _Path

    db_path = _Path(__file__).parent.parent / "db" / "users.json"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = _json.loads(db_path.read_text()) if db_path.exists() else {}

    if user_id in db:
        return {"status": "ERR", "message": f"User '{user_id}' already exists."}

    db[user_id] = {
        "hash_hex":      hash_hex,
        "algo":          "ascon",
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    db_path.write_text(_json.dumps(db, indent=2))

    return {"status": "OK", "message": f"User '{user_id}' registered."}


def _handle_auth_init(msg: dict) -> dict:
    """
    AUTH_INIT command — step 1 of Phase 2.

    Client sends: user_id + Nc (hex).
    Server generates Ns and returns it.
    """
    user_id = msg.get("user_id", "")
    nc_hex  = msg.get("nc_hex", "")

    if not user_id or not nc_hex:
        return {"status": "ERR", "message": "Missing user_id or nc_hex."}

    try:
        nc = bytes.fromhex(nc_hex)
    except ValueError:
        return {"status": "ERR", "message": "Invalid hex in nc_hex."}

    result = start_auth(user_id, nc)

    if not result.success:
        return {"status": "ERR", "message": result.message}

    return {
        "status": "OK",
        "ns_hex": result.ns.hex(),
        "message": result.message,
    }


def _handle_auth_finish(msg: dict) -> dict:
    """
    AUTH_FINISH command — step 2 of Phase 2.

    Client sends: user_id, ASCON nonce, ciphertext, tag (all hex).
    Server decrypts, verifies tag, compares H(password) with DB.
    """
    user_id        = msg.get("user_id", "")
    nonce_hex      = msg.get("nonce_hex", "")
    ciphertext_hex = msg.get("ciphertext_hex", "")
    tag_hex        = msg.get("tag_hex", "")

    if not all([user_id, nonce_hex, ciphertext_hex, tag_hex]):
        return {"status": "ERR", "message": "Missing fields in AUTH_FINISH."}

    try:
        nonce      = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag        = bytes.fromhex(tag_hex)
    except ValueError:
        return {"status": "ERR", "message": "Invalid hex encoding."}

    result = complete_auth(user_id, nonce, ciphertext, tag)

    if not result.success:
        return {"status": "ERR", "message": result.message}

    return {
        "status":     "OK",
        "message":    result.message,
        "session_id": result.session_id,
    }


# ── Command dispatch table ────────────────────────────────────────────────────
_HANDLERS = {
    "REGISTER":    _handle_register,
    "AUTH_INIT":   _handle_auth_init,
    "AUTH_FINISH": _handle_auth_finish,
}


# ══════════════════════════════════════════════════════════════════════════════
#  CLIENT CONNECTION HANDLER  (runs in its own thread)
# ══════════════════════════════════════════════════════════════════════════════

def _handle_client(conn: socket.socket, addr: tuple) -> None:
    print(f"\n[SERVER] New connection from {addr[0]}:{addr[1]}")

    with conn:
        try:
            raw = conn.recv(BUFSIZE)
            if not raw:
                return

            msg = json.loads(raw.decode("utf-8"))
            _log("RECV", addr, msg)

            cmd = msg.get("cmd", "").upper()
            handler = _HANDLERS.get(cmd)

            if handler is None:
                response = {"status": "ERR", "message": f"Unknown command '{cmd}'."}
            else:
                response = handler(msg)

            _log("SEND", addr, response)
            conn.sendall(json.dumps(response).encode("utf-8"))

        except json.JSONDecodeError:
            err = {"status": "ERR", "message": "Malformed JSON."}
            conn.sendall(json.dumps(err).encode("utf-8"))
        except Exception as e:
            err = {"status": "ERR", "message": str(e)}
            conn.sendall(json.dumps(err).encode("utf-8"))

    print(f"[SERVER] Connection closed: {addr[0]}:{addr[1]}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN — start the server
# ══════════════════════════════════════════════════════════════════════════════

def run(host: str = HOST, port: int = PORT) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        print(f"[SERVER] ASCON Auth Service listening on {host}:{port}")
        print(f"[SERVER] Waiting for connections…\n")

        while True:
            conn, addr = srv.accept()
            thread = threading.Thread(target=_handle_client, args=(conn, addr), daemon=True)
            thread.start()


if __name__ == "__main__":
    run()