FROM python:3.11-slim

WORKDIR /app

COPY server/ /app/

RUN pip install --no-cache-dir aiosqlite bcrypt

EXPOSE 5000

CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "5000"]

