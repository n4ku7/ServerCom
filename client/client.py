#!/usr/bin/env python3
"""
Simple chat client with optional TLS.
Usage:
  python3 client.py --host 127.0.0.1 --port 5000 [--cafile cert.pem] [--insecure]

- If --cafile is provided, the client will verify server cert with this CA bundle.
- If --insecure is provided, TLS is used but server cert verification is skipped.
- If neither cafile nor insecure are provided, client connects in plaintext.
"""
import socket
import argparse
import ssl
import threading
import sys

def recv_loop(sock: socket.socket):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[Disconnected from server]")
                break
            sys.stdout.write(data.decode())
            sys.stdout.flush()
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def main(host: str, port: int, cafile: str = None, insecure: bool = False):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = raw
    if cafile or insecure:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if cafile:
            ctx.load_verify_locations(cafile)
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        # wrap socket before connect to support SNI if needed
        ssl_sock = ctx.wrap_socket(raw, server_hostname=host if not insecure else None)
    ssl_sock.connect((host, port))

    # Start recv thread
    threading.Thread(target=recv_loop, args=(ssl_sock,), daemon=True).start()

    try:
        while True:
            line = input()
            if line.strip() == "":
                continue
            ssl_sock.send((line + "\n").encode())
            if line.strip().lower() == "/quit":
                break
    except (KeyboardInterrupt, EOFError):
        try:
            ssl_sock.send(b"/quit\n")
        except:
            pass
    finally:
        try:
            ssl_sock.close()
        except:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--cafile", help="CA cert to verify server (optional)")
    parser.add_argument("--insecure", action="store_true", help="Use TLS but skip verification (insecure)")
    args = parser.parse_args()
    main(args.host, args.port, args.cafile, args.insecure)

