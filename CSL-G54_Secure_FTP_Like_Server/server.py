import argparse
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import threading
from pathlib import Path

CHUNK = 64 * 1024
MAX_HEADER = 1024 * 1024
ROOT = Path("server_files").resolve()
USERS_FILE = Path("users.json")
LOG_FILE = Path("audit.log")


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("Connection closed unexpectedly")
        data.extend(part)
    return bytes(data)


def send_json(sock, obj):
    raw = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def recv_json(sock):
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size <= 0 or size > MAX_HEADER:
        raise ValueError("Invalid message size")
    return json.loads(recv_exact(sock, size).decode("utf-8"))


def log_event(username, action, detail):
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "username": username, "action": action, "detail": detail
        }) + "\n")


def load_users():
    if not USERS_FILE.exists():
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", b"ChangeMe123!", salt, 200_000
        ).hex()
        USERS_FILE.write_text(json.dumps({
            "student": {"salt": salt.hex(), "hash": digest}
        }, indent=2), encoding="utf-8")
        print("Created users.json: username=student, password=ChangeMe123!")
        print("Change this demo password before using the project.")
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def authenticate(username, password, users):
    record = users.get(username)
    if not record:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"),
        bytes.fromhex(record["salt"]), 200_000
    ).hex()
    return hmac.compare_digest(candidate, record["hash"])


def safe_path(filename):
    # Accept only a simple filename; block traversal and nested paths.
    name = Path(filename).name
    if not name or name in {".", ".."} or name != filename or "\x00" in name:
        raise ValueError("Only simple file names are allowed")
    target = (ROOT / name).resolve()
    if target.parent != ROOT:
        raise ValueError("Invalid file path")
    return target


def handle_client(raw_conn, address, context, users):
    username = "unknown"
    try:
        with context.wrap_socket(raw_conn, server_side=True) as conn:
            auth = recv_json(conn)
            username = str(auth.get("username", ""))[:64]
            password = str(auth.get("password", ""))
            if not authenticate(username, password, users):
                send_json(conn, {"ok": False, "message": "Authentication failed"})
                log_event(username, "LOGIN_FAILED", str(address))
                return
            send_json(conn, {"ok": True, "message": "Login successful"})
            log_event(username, "LOGIN_SUCCESS", str(address))

            while True:
                request = recv_json(conn)
                command = request.get("command", "").upper()

                if command == "LIST":
                    names = sorted(p.name for p in ROOT.iterdir() if p.is_file())
                    send_json(conn, {"ok": True, "files": names})
                    log_event(username, "LIST", f"{len(names)} files")

                elif command == "UPLOAD":
                    try:
                        target = safe_path(str(request.get("filename", "")))
                        size = int(request.get("size", -1))
                        if size < 0 or size > 100 * 1024 * 1024:
                            raise ValueError("File size must be between 0 and 100 MB")
                        temp = target.with_name(target.name + ".part")
                        remaining = size
                        with temp.open("wb") as f:
                            while remaining:
                                chunk = recv_exact(conn, min(CHUNK, remaining))
                                f.write(chunk)
                                remaining -= len(chunk)
                        os.replace(temp, target)
                        send_json(conn, {"ok": True, "message": "Upload completed"})
                        log_event(username, "UPLOAD", f"{target.name} ({size} bytes)")
                    except Exception as exc:
                        send_json(conn, {"ok": False, "message": str(exc)})
                        log_event(username, "UPLOAD_ERROR", str(exc))

                elif command == "DOWNLOAD":
                    try:
                        target = safe_path(str(request.get("filename", "")))
                        if not target.is_file():
                            raise FileNotFoundError("File not found on server")
                        size = target.stat().st_size
                        send_json(conn, {"ok": True, "size": size, "filename": target.name})
                        with target.open("rb") as f:
                            while True:
                                chunk = f.read(CHUNK)
                                if not chunk:
                                    break
                                conn.sendall(chunk)
                        log_event(username, "DOWNLOAD", f"{target.name} ({size} bytes)")
                    except Exception as exc:
                        send_json(conn, {"ok": False, "message": str(exc)})
                        log_event(username, "DOWNLOAD_ERROR", str(exc))

                elif command == "QUIT":
                    send_json(conn, {"ok": True, "message": "Goodbye"})
                    log_event(username, "QUIT", "Client disconnected")
                    break
                else:
                    send_json(conn, {"ok": False, "message": "Unknown command"})
                    log_event(username, "INVALID_COMMAND", command)
    except Exception as exc:
        log_event(username, "CONNECTION_ERROR", f"{address}: {exc}")
    finally:
        try:
            raw_conn.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Encrypted FTP-like file server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default="server.crt")
    parser.add_argument("--key", default="server.key")
    args = parser.parse_args()

    ROOT.mkdir(exist_ok=True)
    users = load_users()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)

    print(f"Secure file server listening on {args.host}:{args.port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(10)
        while True:
            conn, address = server.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, address, context, users),
                daemon=True
            ).start()


if __name__ == "__main__":
    main()
