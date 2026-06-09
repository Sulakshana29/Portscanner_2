from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
import socket
import scanner
import io
import csv

app = Flask(__name__)
app.secret_key = "dev-secret"

LAST_RESULTS = {}

def parse_ports(ports_text):
    if not ports_text:
        return list(range(1,1025))

    ports = set()
    for part in ports_text.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    host = request.form.get("host", "").strip()
    ports = parse_ports(request.form.get("ports", ""))

    results = scanner.scan_ports(host, ports)

    LAST_RESULTS.clear()
    LAST_RESULTS.update(results)

    return jsonify(results)

@app.route("/report")
def report():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Port", "Status", "Service", "Banner"])

    for port, data in LAST_RESULTS.items():
        writer.writerow([
            port,
            "Open" if data["open"] else "Closed",
            data.get("service", ""),
            data.get("banner", "")
        ])

    mem = io.BytesIO(output.getvalue().encode())
    return send_file(mem, as_attachment=True,
                     download_name="scan_report.csv",
                     mimetype="text/csv")

if __name__ == "__main__":
    app.run(debug=True)
