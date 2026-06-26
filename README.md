# 🛰 NetScan Pro

> **A multi-threaded TCP port scanner with real-time results, banner grabbing, and a dark cyberpunk dashboard — built with Python & Flask.**

![CI](https://github.com/<YOUR_USERNAME>/Portscanner_flask/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/flask-2.3%2B-lightgrey?logo=flask)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

| Category | Details |
|---|---|
| **Scanning** | Concurrent TCP-connect scan via `ThreadPoolExecutor` (up to 150 workers) |
| **Banner Grabbing** | Reads service banners (SSH, HTTP, FTP, SMTP, Redis, MySQL…) and fingerprints versions |
| **Risk Classification** | Auto-labels open ports as `HIGH` / `MEDIUM` / `LOW` risk based on service type |
| **Real-time UI** | Async scan + JS polling — results stream into the table live as ports are scanned |
| **Filtering** | Toggle between All / Open / Closed views instantly |
| **Export** | Download full reports as **CSV** or **JSON** |
| **Scan History** | Last 15 scans stored in-memory with host, open count, and duration |
| **Rate Limiting** | 5 scans / minute per IP — prevents abuse |
| **Dark Theme** | Cyberpunk aesthetic with glassmorphism cards, neon accents, and micro-animations |

---

## 🖥 Architecture

```
Browser (JS polling)
    │
    ├── POST /scan/async  ──►  Flask  ──►  ThreadPoolExecutor  ──►  TCP sockets
    │                              │
    ├── GET  /scan/progress/<id>  ◄─┘  (shared progress dict, thread-safe)
    │
    ├── GET  /export/csv/<id>
    └── GET  /export/json/<id>
```

**Stack:** Python 3.12 · Flask 2.3 · `concurrent.futures` · Vanilla JS · CSS3

---

## 🚀 Quickstart

### Option 1 — Docker (recommended)

```bash
docker build -t netscan-pro .
docker run -p 5000:5000 netscan-pro
```

Then open **http://localhost:5000** in your browser.

### Option 2 — Local venv

```bash
# 1. Clone and enter the project
git clone https://github.com/<YOUR_USERNAME>/Portscanner_flask.git
cd Portscanner_flask

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows:
.\.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server
python app.py
```

Open **http://127.0.0.1:5000**.

---

## ⚙️ Configuration

All options are set via environment variables — no config file needed.

| Variable | Default | Description |
|---|---|---|
| `FLASK_SECRET` | `dev-secret-change-in-prod` | Flask session secret key |
| `PORTSCANNER_ALLOWED_NETWORKS` | `127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16` | Comma-separated CIDRs that scan silently (no warning) |
| `PORTSCANNER_BLOCKED_NETWORKS` | *(empty)* | Comma-separated CIDRs that are always hard-rejected |

> **Note:** Targets outside the allowed list still scan successfully but the UI displays an advisory warning reminding you to only scan hosts you own or have permission to test.

---

## 🧪 Running Tests

```bash
python -m unittest discover -s tests/ -v
```

The test suite uses `unittest.mock` — no real network connections are made.

---

## 📂 Project Structure

```
Portscanner_flask/
├── app.py              # Flask routes, rate limiting, scan history
├── scanner.py          # TCP scanner, banner grabbing, fingerprinting
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── static/
│   ├── scanner.js      # Async polling, live results, export, presets
│   └── style.css       # Dark cyberpunk theme
├── templates/
│   └── index.html      # Single-page dashboard
└── tests/
    └── test_scanner.py # Unit tests (mock-based)
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes and authorised testing only**.  
Only scan systems you own or have explicit written permission to test.  
Unauthorised port scanning may be illegal in your jurisdiction.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
