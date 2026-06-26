# ─── Build stage (resolves and installs deps) ───────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies into an isolated prefix so we can copy them cleanly
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ─── Runtime stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from the builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Non-root user for security
RUN adduser --disabled-password --gecos "" scanner
USER scanner

EXPOSE 5000

# Use a production-grade WSGI server when available; fall back to Flask dev server
CMD ["python", "app.py"]
