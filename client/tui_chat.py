#!/usr/bin/env python3
import asyncio
import ssl
import argparse
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Static, ScrollView
from textual.containers import Vertical, Horizontal
from textual.reactive import var
from textual import events
import functools
import threading
import sys

class ChatView(ScrollView):
    def append_text(self, msg: str):
        self.update((self.renderable or "") + msg + "\n")

class ChatClientApp(App):
    CSS = """
    Screen {
      layout: vertical;
    }
    #chat_box {
      height: 1fr;
      border: heavy $accent;
    }
    #input_box {
      height: 3;
      border: heavy $accent;
    }
    """

    BINDINGS = [("ctrl+c", "quit", "Quit")]

    def __init__(self, host: str, port: int, cafile: str = None, insecure: bool = False):
        super().__init__()
        self.host = host
        self.port = port
        self.cafile = cafile
        self.insecure = insecure
        self.reader = None
        self.writer = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield ChatView(id="chat_box")
        yield Input(placeholder="Type message, or commands, then Enter", id="input_box")
        yield Footer()

    async def on_mount(self):
        chat = self.query_one("#chat_box", ChatView)
        # Start connection
        await self.connect_to_server()
        # Start reader task
        self.set_interval(0.1, lambda: None)  # keep UI alive
        asyncio.create_task(self.reader_task())

    async def connect_to_server(self):
        ssl_ctx = None
        if self.cafile or self.insecure:
            ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if self.cafile:
                ssl_ctx.load_verify_locations(self.cafile)
            if self.insecure:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(self.host, self.port, ssl=ssl_ctx)
        self.reader = reader
        self.writer = writer

        # On connect, read until prompt for auth
        # show initial lines
        line = await reader.readline()
        if line:
            self.query_one("#chat_box", ChatView).append_text(line.decode().rstrip())
        line = await reader.readline()
        if line:
            self.query_one("#chat_box", ChatView).append_text(line.decode().rstrip())

    async def reader_task(self):
        while True:
            if not self.reader:
                break
            data = await self.reader.readline()
            if not data:
                break
            msg = data.decode().rstrip()
            self.query_one("#chat_box", ChatView).append_text(msg)

    async def on_input_submitted(self, event: Input.Submitted):
        msg = event.value.strip()
        if not msg:
            return
        event.input.value = ""
        # send to server
        try:
            self.writer.write((msg + "\n").encode())
            await self.writer.drain()
        except Exception as e:
            self.query_one("#chat_box", ChatView).append_text(f"[Error sending] {e}")

    def action_quit(self):
        self.exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--cafile", help="CA certificate file (optional)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    app = ChatClientApp(args.host, args.port, args.cafile, args.insecure)
    app.run()

