"""Flask web app for a TCP-connect port scanner dashboard.

Features
--------
- Async scan:       POST /scan/async  (returns scan_id JSON)
- Progress poll:    GET  /scan/progress/<scan_id>  (JSON)
- Report export:    GET  /export/csv/<scan_id>  |  /export/json/<scan_id>
- Scan history:     kept in-memory (last 15 scans)
- Rate limiting:    5 scans/minute per IP via Flask-Limiter
"""
import csv
import io
import json
import os
import socket
import threading
import time
import uuid
import ipaddress
from typing import List

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    stream_with_context,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import scanner as sc

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-in-prod")

# ---------------------------------------------------------------------------
# Rate limiting — 5 scan requests per minute per IP
# ---------------------------------------------------------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],           # no blanket limit; only decorate specific routes
    storage_uri="memory://",
)


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Rate limit exceeded — maximum 5 scans per minute. Please wait and try again."), 429

# ---------------------------------------------------------------------------
# Network allow / block lists
# ---------------------------------------------------------------------------
# By default allow localhost + private RFC-1918 ranges so the demo works.
# Override via PORTSCANNER_ALLOWED_NETWORKS (comma-separated CIDRs) to tighten.
_ENV_ALLOWED = os.environ.get("PORTSCANNER_ALLOWED_NETWORKS")
if _ENV_ALLOWED:
    try:
        ALLOWED_NETWORKS = [
            ipaddress.ip_network(x.strip())
            for x in _ENV_ALLOWED.split(",")
            if x.strip()
        ]
    except Exception:
        ALLOWED_NETWORKS = []
else:
    ALLOWED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

_BLOCK_ENV = os.environ.get("PORTSCANNER_BLOCKED_NETWORKS")
if _BLOCK_ENV:
    try:
        BLOCKED_NETWORKS = [
            ipaddress.ip_network(x.strip())
            for x in _BLOCK_ENV.split(",")
            if x.strip()
        ]
    except Exception:
        BLOCKED_NETWORKS = []
else:
    BLOCKED_NETWORKS = []


def _check_host(host: str):
    """Resolve host and validate against allow/block lists.

    Returns (resolved_ip_set, error_or_None, warning_or_None).

    - Blocked networks  → hard error (scan denied).
    - Allowed networks  → no error, no warning.
    - Everything else   → scan proceeds with an advisory warning so the
      UI can display a yellow notice. This lets public demo targets like
      scanme.nmap.org work while still being transparent about intent.
    """
    try:
        resolved = {res[4][0] for res in socket.getaddrinfo(host, None)}
    except Exception:
        return None, f"Unable to resolve host: {host}", None

    ips = []
    for addr in resolved:
        try:
            ips.append(ipaddress.ip_address(addr))
        except ValueError:
            pass

    # Hard block — always enforced
    if BLOCKED_NETWORKS:
        for ip in ips:
            if any(ip in net for net in BLOCKED_NETWORKS):
                return None, "Scanning denied — target is in a blocked network.", None

    # Outside private/allow list → soft warning, scan still proceeds
    in_allowed = any(ip in net for ip in ips for net in ALLOWED_NETWORKS)
    warning = None
    if not in_allowed:
        warning = (
            "Target is outside private networks. "
            "Only scan hosts you own or have explicit permission to test."
        )

    return resolved, None, warning


# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------
QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
COMMON_PORTS = list(range(1, 1025))


def parse_ports(text: str) -> List[int]:
    """Parse comma/range port expression. Returns sorted unique list."""
    if not text or text.strip().lower() == "quick":
        return QUICK_PORTS
    if text.strip().lower() == "common":
        return COMMON_PORTS

    ports: set = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a_i, b_i = int(a), int(b)
                if a_i > b_i:
                    a_i, b_i = b_i, a_i
                ports.update(range(max(1, a_i), min(65535, b_i) + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


# ---------------------------------------------------------------------------
# In-memory scan history
# ---------------------------------------------------------------------------
_history: list = []
_history_lock = threading.Lock()
HISTORY_LIMIT = 15


def _record_history(host: str, scan_id: str, open_count: int, total: int,
                    elapsed: float) -> None:
    entry = {
        "id": scan_id,
        "host": host,
        "open": open_count,
        "total": total,
        "elapsed": round(elapsed, 2),
        "ts": time.strftime("%H:%M:%S"),
    }
    with _history_lock:
        _history.insert(0, entry)
        if len(_history) > HISTORY_LIMIT:
            _history.pop()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    with _history_lock:
        history = list(_history)
    return render_template("index.html", history=history)


@app.route("/scan/async", methods=["POST"])
@limiter.limit("5 per minute")
def scan_async():
    """Start a scan in a background thread; return scan_id immediately."""
    data = request.get_json(silent=True) or request.form
    host = (data.get("host") or "").strip()
    ports_text = (data.get("ports") or "").strip()
    timeout_raw = data.get("timeout", "0.8")
    grab_banner = str(data.get("grab_banner", "true")).lower() != "false"

    if not host:
        return jsonify(error="Host is required"), 400

    _, err, warning = _check_host(host)
    if err:
        return jsonify(error=err), 403

    try:
        timeout_f = float(timeout_raw)
    except ValueError:
        timeout_f = 0.8

    ports = parse_ports(ports_text)
    if not ports:
        return jsonify(error="No valid ports specified"), 400

    scan_id = str(uuid.uuid4())

    def _run():
        results = sc.scan_ports(
            host, ports,
            timeout=timeout_f,
            max_workers=150,
            grab_banner=grab_banner,
            scan_id=scan_id,
        )
        open_count = sum(1 for r in results.values() if r["open"])
        state = sc.get_scan_state(scan_id)
        elapsed = state["elapsed"] if state else 0.0
        _record_history(host, scan_id, open_count, len(ports), elapsed)
        sc.cleanup_old_scans()

    threading.Thread(target=_run, daemon=True).start()
    resp: dict = {"scan_id": scan_id, "total": len(ports)}
    if warning:
        resp["warning"] = warning
    return jsonify(**resp)


@app.route("/scan/progress/<scan_id>")
def scan_progress(scan_id):
    """Return JSON progress snapshot for a running or finished scan."""
    state = sc.get_scan_state(scan_id)
    if state is None:
        return jsonify(error="Scan not found"), 404

    results_sorted = dict(sorted(state["results"].items()))
    return jsonify(
        status=state["status"],
        done=state["done"],
        total=state["total"],
        elapsed=round(state["elapsed"], 2),
        results=results_sorted,
    )


@app.route("/export/csv/<scan_id>")
def export_csv(scan_id):
    """Stream a CSV report for the given scan."""
    state = sc.get_scan_state(scan_id)
    if not state:
        return "Scan not found", 404

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Port", "Status", "Service", "Version", "Risk", "Banner"])
        for port, r in sorted(state["results"].items()):
            writer.writerow([
                port,
                "open" if r["open"] else "closed",
                r.get("service", ""),
                r.get("version", ""),
                r.get("risk", ""),
                r.get("banner", "").replace("\n", " ")[:200],
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    headers = {
        "Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.csv"',
        "Content-Type": "text/csv",
    }
    return Response(stream_with_context(generate()), headers=headers)


@app.route("/export/json/<scan_id>")
def export_json(scan_id):
    """Return a JSON report for the given scan."""
    state = sc.get_scan_state(scan_id)
    if not state:
        return "Scan not found", 404

    payload = {
        "scan_id": scan_id,
        "elapsed": round(state["elapsed"], 2),
        "total": state["total"],
        "results": {str(p): r for p, r in sorted(state["results"].items())},
    }
    resp = Response(
        json.dumps(payload, indent=2),
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.json"'
        },
    )
    return resp


@app.route("/history")
def history():
    with _history_lock:
        return jsonify(_history)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
