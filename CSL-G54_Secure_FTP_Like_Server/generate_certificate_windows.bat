@echo off
REM Run this only on your own project machine.
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
echo Certificate files created: server.crt and server.key
pause
