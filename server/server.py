#!/usr/bin/env python3
import asyncio
import aiosqlite
import bcrypt
import ssl
import argparse
import datetime
import logging
from typing import Optional, Dict, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    content TEXT NOT NULL
);
"""

class ChatServer:
    def __init__(self, db_path: str = "chat.db"):
        self.db_path = db_path
        self.clients: Dict[str, asyncio.StreamWriter] = {}
        self.lock = asyncio.Lock()

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(DB_SCHEMA)
            await db.commit()

    async def create_user(self, username: str, password: str) -> bool:
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        created = datetime.datetime.utcnow().isoformat()
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, pw_hash, created),
                )
                await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def verify_user(self, username: str, password: str) -> bool:
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            row = await cur.fetchone()
        if not row:
            return False
        stored_hash = row[0]
        return bcrypt.checkpw(password.encode(), stored_hash)

    async def save_message(self, username: str, content: str):
        ts = datetime.datetime.utcnow().isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO messages (ts, username, content) VALUES (?, ?, ?)",
                (ts, username, content),
            )
            await db.commit()

    async def get_history(self, limit: int = 50):
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "SELECT ts, username, content FROM messages ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = await cur.fetchall()
        return list(reversed(rows))

    async def broadcast(self, message: str, exclude: Tuple[str] = ()):
        async with self.lock:
            bad = []
            for uname, w in self.clients.items():
                if uname in exclude:
                    continue
                try:
                    w.write(message.encode() + b"\n")
                    await w.drain()
                except Exception as e:
                    logging.warning("Error broadcasting to %s: %s", uname, e)
                    bad.append(uname)
            for uname in bad:
                self.clients.pop(uname, None)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        logging.info("Connection from %s", peer)
        # Authentication phase
        try:
            writer.write(b"Welcome to CLI-Chat (auth required)\n")
            writer.write(b"Type: signup <username> <password>  OR  login <username> <password>\n> ")
            await writer.drain()

            line = await asyncio.wait_for(reader.readline(), timeout=120.0)
            parts = line.decode().strip().split(" ", 2)
            if len(parts) < 3:
                writer.write(b"Invalid auth command. Closing.\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            mode, username, password = parts[0].lower(), parts[1], parts[2]
            if mode == "signup":
                ok = await self.create_user(username, password)
                if not ok:
                    writer.write(b"ERROR: username already taken\n")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
                else:
                    writer.write(b"SIGNUP OK\n")
                    await writer.drain()
            elif mode == "login":
                ok = await self.verify_user(username, password)
                if not ok:
                    writer.write(b"ERROR: login failed\n")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
                else:
                    writer.write(b"LOGIN OK\n")
                    await writer.drain()
            else:
                writer.write(b"ERROR: unknown auth mode\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
        except asyncio.TimeoutError:
            writer.write(b"Auth timed out. Bye.\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # Auth succeeded. Register client
        async with self.lock:
            # If username already connected, append suffix
            base = username
            if username in self.clients:
                i = 1
                while f"{base}{i}" in self.clients:
                    i += 1
                username = f"{base}{i}"
            self.clients[username] = writer

        writer.write(f"Welcome, {username}! Type /help for commands.\n".encode())
        await writer.drain()
        await self.broadcast(f"*** {username} has joined ***", exclude=(username,))
        await self.save_message("system", f"{username} joined")

        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                text = data.decode().rstrip("\n")
                if text.startswith("/"):
                    await self.process_command(username, text, writer)
                else:
                    msg = f"[{username}] {text}"
                    await self.save_message(username, text)
                    await self.broadcast(msg)
        except Exception as e:
            logging.exception("Error on client loop %s: %s", username, e)
        finally:
            async with self.lock:
                self.clients.pop(username, None)
            await self.broadcast(f"*** {username} has left ***")
            await self.save_message("system", f"{username} left")
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            logging.info("Connection with %s closed", username)

    async def process_command(self, username: str, text: str, writer: asyncio.StreamWriter):
        cmd, *rest = text.split(" ", 1)
        arg = rest[0] if rest else ""
        cmd = cmd.lower()

        if cmd == "/help":
            writer.write(b"Commands:\n")
            writer.write(b"  /nick NEWNAME\n")
            writer.write(b"  /pm USER MESSAGE\n")
            writer.write(b"  /list\n")
            writer.write(b"  /history [N]\n")
            writer.write(b"  /quit\n")
            await writer.drain()

        elif cmd == "/nick":
            new = arg.strip()
            if not new:
                writer.write(b"Usage: /nick NEWNAME\n")
                await writer.drain()
                return
            async with self.lock:
                if new in self.clients:
                    writer.write(b"Name in use.\n")
                    await writer.drain()
                    return
                self.clients.pop(username, None)
                self.clients[new] = writer
            await self.broadcast(f"*** {username} is now known as {new} ***")
            await self.save_message("system", f"{username} renamed to {new}")
            writer.write(f"Nickname changed to {new}\n".encode())
            await writer.drain()

        elif cmd == "/pm":
            if not arg:
                writer.write(b"Usage: /pm USER MESSAGE\n")
                await writer.drain()
                return
            try:
                target, msg = arg.split(" ", 1)
            except ValueError:
                writer.write(b"Usage: /pm USER MESSAGE\n")
                await writer.drain()
                return
            async with self.lock:
                w2 = self.clients.get(target)
            if w2:
                w2.write(f"[PM from {username}] {msg}\n".encode())
                await w2.drain()
                writer.write(f"[PM to {target}] {msg}\n".encode())
                await writer.drain()
                await self.save_message(username, f"(PM to {target}) {msg}")
            else:
                writer.write(b"User not online.\n")
                await writer.drain()

        elif cmd == "/list":
            async with self.lock:
                names = ", ".join(self.clients.keys())
            writer.write(f"Users: {names}\n".encode())
            await writer.drain()

        elif cmd == "/history":
            n = 50
            if arg.strip().isdigit():
                n = int(arg.strip())
            rows = await self.get_history(n)
            writer.write(f"--- Last {len(rows)} messages ---\n".encode())
            for ts, user, content in rows:
                writer.write(f"{ts} [{user}] {content}\n".encode())
            writer.write(b"--- end ---\n")
            await writer.drain()

        elif cmd == "/quit":
            writer.write(b"Goodbye.\n")
            await writer.drain()
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

        else:
            writer.write(b"Unknown command. Type /help\n")
            await writer.drain()

    async def start(self, host: str, port: int, ssl_ctx: Optional[ssl.SSLContext] = None):
        await self.init_db()
        server = await asyncio.start_server(self.handle_client, host, port, ssl=ssl_ctx)
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        logging.info("Serving on %s", addrs)
        async with server:
            await server.serve_forever()

def create_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--certfile", help="Path to TLS certificate (PEM)")
    p.add_argument("--keyfile", help="Path to TLS private key")
    return p.parse_args()

def main():
    args = parse_args()
    ssl_ctx = None
    if args.certfile and args.keyfile:
        ssl_ctx = create_ssl_context(args.certfile, args.keyfile)
        logging.info("TLS enabled")
    server = ChatServer(db_path="chat.db")
    asyncio.run(server.start(args.host, args.port, ssl_ctx))

if __name__ == "__main__":
    main()

