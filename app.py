"""Flask web app for the Port Scanner Dashboard.

Routes:
- GET / : show form
- POST /scan : perform scan and show results

This file wires the web UI (templates) to the scanner utilities.
"""
from flask import Flask, render_template, request, redirect, url_for, flash
import socket
import scanner
import ipaddress
import os
from typing import List

app = Flask(__name__)
# NOTE: For real deployments move this to an env var and keep secret.
app.secret_key = "dev-secret"

# Restrict scanning to these IPs/hostnames or networks only. You can add
# single IPs as /32 networks or full CIDRs. If BLOCKED_NETWORKS is set
# (see below) the app will use the blocklist mode which allows all hosts
# except those in BLOCKED_NETWORKS.
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.1/32"),
    ipaddress.ip_network("10.22.163.177/32"),
]

# Optional blocklist mode: if you set the environment variable
# PORTSCANNER_BLOCKED_NETWORKS to a comma-separated list of CIDRs, the
# app will deny scans for any target resolving into those CIDRs. Example:
# PORTSCANNER_BLOCKED_NETWORKS='8.8.8.8/32,203.0.113.0/24'
_BLOCK_ENV = os.environ.get("PORTSCANNER_BLOCKED_NETWORKS")
if _BLOCK_ENV:
    try:
        BLOCKED_NETWORKS = [
            ipaddress.ip_network(x.strip())
            for x in _BLOCK_ENV.split(',')
            if x.strip()
        ]
    except Exception:
        BLOCKED_NETWORKS = []
else:
    BLOCKED_NETWORKS = []


def parse_ports(ports_text: str) -> List[int]:
    """Parse user input for ports.

    Accepts formats like:
      - "22,80,443"
      - "20-1024"
      - mix of both: "22,80,1000-1010"

    Returns a list of unique integer ports filtered to 1..65535
    """
    if not ports_text:
        # default common ports
        return [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            139,
            143,
            443,
            445,
            3306,
            3389,
            8080,
        ]

    ports = set()
    parts = [p.strip() for p in ports_text.split(',') if p.strip()]
    for part in parts:
        if '-' in part:
            try:
                a, b = part.split('-', 1)
                a_i = int(a)
                b_i = int(b)
                if a_i > b_i:
                    a_i, b_i = b_i, a_i
                for i in range(max(1, a_i), min(65535, b_i) + 1):
                    ports.add(i)
            except ValueError:
                continue
        else:
            try:
                p_i = int(part)
                if 1 <= p_i <= 65535:
                    ports.add(p_i)
            except ValueError:
                continue
    return sorted(ports)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    host = request.form.get('host', '').strip()
    ports_text = request.form.get('ports', '').strip()
    timeout = request.form.get('timeout', '0.8')

    if not host:
        flash('Please enter a hostname or IP address', 'warning')
        return redirect(url_for('index'))

    # Resolve host early
    try:
        resolved = {res[4][0] for res in socket.getaddrinfo(host, None)}
    except Exception:
        flash('Unable to resolve host: %s' % host, 'danger')
        return redirect(url_for('index'))

    # If a blocklist is configured, deny if any resolved IP is inside it.
    if BLOCKED_NETWORKS:
        blocked = False
        for addr in resolved:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if any(ip in net for net in BLOCKED_NETWORKS):
                blocked = True
                break
        if blocked:
            blocked_list = ", ".join(str(n) for n in BLOCKED_NETWORKS)
            flash(
                f'Scanning denied. Target resolves into blocked networks: '
                f'{blocked_list}',
                'danger',
            )
            return redirect(url_for('index'))

    else:
        # No blocklist configured — fall back to allowlist behavior
        allowed = False
        for addr in resolved:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if any(ip in net for net in ALLOWED_NETWORKS):
                allowed = True
                break
        if not allowed:
            allowed_list = ", ".join(str(n) for n in ALLOWED_NETWORKS)
            message = (
                'Scanning is restricted. Allowed networks: '
                f'{allowed_list}'
            )
            flash(message, 'danger')
            return redirect(url_for('index'))

    try:
        timeout_f = float(timeout)
    except ValueError:
        timeout_f = 0.8

    ports = parse_ports(ports_text)
    if not ports:
        flash('No valid ports to scan', 'warning')
        return redirect(url_for('index'))

    # Run the scanner (fast, concurrent)
    results = scanner.scan_ports(
        host, ports, timeout=timeout_f, max_workers=200
    )

    return render_template(
        'index.html', host=host, results=results, timeout=timeout_f
    )


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
