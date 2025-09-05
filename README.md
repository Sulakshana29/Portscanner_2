# Flask Port Scanner Dashboard

Simple educational project: a Flask web UI to run TCP-connect style port scans against a host and display open ports and the best-guess service name.

Quickstart (local):

1. Create a virtualenv and install dependencies:

   python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt

2. Run the server:

   python app.py

3. Open http://127.0.0.1:5000 in your browser.

Notes:
- Use only on systems you own or have permission to test.
- The scanner uses plain TCP connect so it does not require raw sockets or special privileges.
