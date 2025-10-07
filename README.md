# CLI ChatApp — Full Version (TUI + TLS + Auth + Docker + systemd)

## Features

- Asynchronous server (asyncio) 
- SQLite database for users & chat history 
- Passwords hashed with bcrypt 
- TLS support (optional) 
- TUI client using `textual` 
- Docker + docker-compose setup 
- systemd unit for server 
- Commands: `/help`, `/nick`, `/pm`, `/list`, `/history`, `/quit`

## Setup (server)

```bash
cd server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

