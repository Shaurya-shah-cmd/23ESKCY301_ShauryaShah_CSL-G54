# Secure FTP-like Server with Encrypted Transfer

**Project Code:** CSL-G64  
**Student:** Shaurya Shah  
**Roll No.:** 23ESKCY301  
**Batch:** CS-IOT-A-G2  
**Course:** Cyber Security Lab (7CS4-22)

## Overview
A small FTP-like client-server application written in Python. It supports login,
file listing, upload, download and audit logging. Communication is protected
with TLS (minimum TLS 1.2). Passwords are stored as PBKDF2-HMAC-SHA256 hashes
with individual random salts.

## Requirements
- Python 3.10 or later
- OpenSSL command-line tool (for creating a local self-signed certificate)
- No third-party Python packages

## Setup (local machine)
1. Extract this ZIP into a project folder.
2. Open a terminal in that folder.
3. Generate a local certificate:
   - Windows: double-click `generate_certificate_windows.bat`, or run
     `openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"`
   - Linux/macOS: run `sh generate_certificate_linux_mac.sh`
4. Start the server: `python server.py`
5. In a second terminal, start the client: `python client.py`
6. Demo login: username `student`, password `ChangeMe123!`
   Change the demo password before any real use. This is a classroom demo only.

## Commands
- `LIST` - list files stored on the server
- `UPLOAD <local_path>` - upload a local file
- `DOWNLOAD <filename>` - download a server file
- `QUIT` - close the session

## Project folders/files created at runtime
- `server_files/` - files uploaded to the server
- `downloads/` - files downloaded by the client
- `users.json` - salted password hashes (created on first server start)
- `audit.log` - JSON-lines audit trail

## Security and scope
Use only on `127.0.0.1`, your own computers, or an isolated lab network with
permission. Do not test against college Wi-Fi, public servers, or third-party
systems. This project is a teaching prototype, not a production FTP replacement.
The certificate is self-signed for a local lab demonstration. For a real
deployment, use a certificate issued by a trusted CA and add stronger account
management, rate limiting, key rotation, and backups.
