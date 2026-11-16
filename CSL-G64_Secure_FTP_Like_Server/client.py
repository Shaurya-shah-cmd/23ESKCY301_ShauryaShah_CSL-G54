import argparse
import json
import socket
import ssl
import struct
from pathlib import Path

CHUNK = 64 * 1024
MAX_HEADER = 1024 * 1024


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


def main():
    parser = argparse.ArgumentParser(description="Encrypted FTP-like client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca", default="server.crt")
    args = parser.parse_args()

    username = input("Username: ").strip()
    password = input("Password: ")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.create_connection((args.host, args.port)) as raw:
        with context.wrap_socket(raw, server_hostname=args.host) as conn:
            send_json(conn, {"username": username, "password": password})
            result = recv_json(conn)
            print(result["message"])
            if not result.get("ok"):
                return

            print("\nCommands: LIST | UPLOAD <local_path> | DOWNLOAD <filename> | QUIT")
            while True:
                parts = input("secure-ftp> ").strip().split(maxsplit=1)
                if not parts:
                    continue
                command = parts[0].upper()

                if command == "LIST":
                    send_json(conn, {"command": "LIST"})
                    response = recv_json(conn)
                    if response.get("ok"):
                        print("Server files:")
                        for name in response["files"]:
                            print(" -", name)
                    else:
                        print(response.get("message"))

                elif command == "UPLOAD" and len(parts) == 2:
                    local = Path(parts[1]).expanduser()
                    if not local.is_file():
                        print("Local file does not exist.")
                        continue
                    filename = local.name
                    size = local.stat().st_size
                    send_json(conn, {
                        "command": "UPLOAD", "filename": filename, "size": size
                    })
                    with local.open("rb") as f:
                        while True:
                            chunk = f.read(CHUNK)
                            if not chunk:
                                break
                            conn.sendall(chunk)
                    print(recv_json(conn).get("message"))

                elif command == "DOWNLOAD" and len(parts) == 2:
                    filename = parts[1]
                    send_json(conn, {"command": "DOWNLOAD", "filename": filename})
                    response = recv_json(conn)
                    if not response.get("ok"):
                        print(response.get("message"))
                        continue
                    size = int(response["size"])
                    output = Path("downloads") / Path(filename).name
                    output.parent.mkdir(exist_ok=True)
                    remaining = size
                    with output.open("wb") as f:
                        while remaining:
                            chunk = recv_exact(conn, min(CHUNK, remaining))
                            f.write(chunk)
                            remaining -= len(chunk)
                    print(f"Downloaded to {output.resolve()} ({size} bytes)")

                elif command == "QUIT":
                    send_json(conn, {"command": "QUIT"})
                    print(recv_json(conn).get("message"))
                    break
                else:
                    print("Invalid command. Use LIST, UPLOAD <path>, DOWNLOAD <name>, or QUIT.")


if __name__ == "__main__":
    main()
