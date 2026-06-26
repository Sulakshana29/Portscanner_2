"""Lightweight TCP-connect port scanner with banner grabbing and fingerprinting.

Uses blocking TCP connect calls (no raw sockets) and a thread pool for
concurrency. Intended for local/lab testing on authorised targets only.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import re
import threading
import time
from typing import List, Dict, Tuple, Optional

# ---------------------------------------------------------------------------
# Service name lookup table
# ---------------------------------------------------------------------------
COMMON_SERVICES: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    194: "irc",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    4369: "epmd",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "k8s-api",
    8080: "http-alt",
    8443: "https-alt",
    8888: "jupyter",
    9000: "php-fpm",
    9090: "prometheus",
    9200: "elasticsearch",
    9300: "elasticsearch-cluster",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    27018: "mongodb",
    50070: "hadoop",
}

# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------
HIGH_RISK_PORTS = {23, 21, 135, 137, 138, 139, 445, 1433, 2375, 3306, 3389,
                   5432, 5900, 6379, 11211, 27017}
MEDIUM_RISK_PORTS = {22, 25, 53, 80, 110, 143, 389, 636, 1521, 5984, 8080, 9200}

def risk_level(port: int, is_open: bool) -> str:
    """Return 'high', 'medium', 'low', or 'closed'."""
    if not is_open:
        return "closed"
    if port in HIGH_RISK_PORTS:
        return "high"
    if port in MEDIUM_RISK_PORTS:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Banner fingerprinting patterns
# ---------------------------------------------------------------------------
_FINGERPRINTS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-(\d+\.\d+)-(.+)", re.I),       "SSH"),
    (re.compile(r"HTTP/\d\S*\s+\d+.*Server:\s*(\S+)", re.I | re.S), "HTTP"),
    (re.compile(r"220[- ].*FTP",             re.I),  "FTP"),
    (re.compile(r"220[- ].*SMTP|Postfix|Exim|sendmail", re.I), "SMTP"),
    (re.compile(r"220[- ].*ESMTP",           re.I),  "SMTP"),
    (re.compile(r"\+OK",                     re.I),  "POP3"),
    (re.compile(r"\* OK.*IMAP",              re.I),  "IMAP"),
    (re.compile(r"Redis",                    re.I),  "Redis"),
    (re.compile(r"MongoDB",                  re.I),  "MongoDB"),
    (re.compile(r"mysql|MariaDB",            re.I),  "MySQL/MariaDB"),
    (re.compile(r"PostgreSQL",               re.I),  "PostgreSQL"),
    (re.compile(r"Elasticsearch",            re.I),  "Elasticsearch"),
    (re.compile(r"memcache",                 re.I),  "Memcached"),
    (re.compile(r"RFB \d+\.\d+",            re.I),  "VNC"),
    (re.compile(r"220.*Telnet|login:",       re.I),  "Telnet"),
]

# ---------------------------------------------------------------------------
# OS hint patterns — ordered most-specific first
# Derived from banners only (no raw-socket fingerprinting required).
# ---------------------------------------------------------------------------
_OS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # SSH banner suffixes: "OpenSSH_9.3p2 Ubuntu-3ubuntu0.6"
    (re.compile(r"OpenSSH[_\s]\S+\s+Ubuntu",   re.I), "\U0001f427 Linux (Ubuntu)"),
    (re.compile(r"OpenSSH[_\s]\S+\s+Debian",   re.I), "\U0001f427 Linux (Debian)"),
    (re.compile(r"OpenSSH[_\s]\S+\s+Raspbian", re.I), "\U0001f427 Linux (Raspbian)"),
    (re.compile(r"OpenSSH[_\s]\S+\s+Fedora",   re.I), "\U0001f427 Linux (Fedora)"),
    (re.compile(r"OpenSSH[_\s]\S+\s+CentOS",   re.I), "\U0001f427 Linux (CentOS)"),
    (re.compile(r"OpenSSH[_\s]\S+\s+Red.Hat",  re.I), "\U0001f427 Linux (RHEL)"),
    (re.compile(r"OpenSSH[_\s]\S+\s+Alpine",   re.I), "\U0001f427 Linux (Alpine)"),
    (re.compile(r"OpenSSH_for_Windows",         re.I), "\U0001fa9f Windows"),
    (re.compile(r"OpenSSH",                     re.I), "\U0001f427 Linux"),
    # HTTP Server header patterns
    (re.compile(r"Server:\s*\S+.*\(Ubuntu\)",  re.I | re.S), "\U0001f427 Linux (Ubuntu)"),
    (re.compile(r"Server:\s*\S+.*\(Debian\)",  re.I | re.S), "\U0001f427 Linux (Debian)"),
    (re.compile(r"Server:\s*\S+.*\(CentOS\)",  re.I | re.S), "\U0001f427 Linux (CentOS)"),
    (re.compile(r"Server:\s*\S+.*\(Fedora\)",  re.I | re.S), "\U0001f427 Linux (Fedora)"),
    (re.compile(r"Server:\s*\S+.*\(Win",       re.I | re.S), "\U0001fa9f Windows"),
    (re.compile(r"Server:\s*Microsoft-IIS",     re.I),        "\U0001fa9f Windows (IIS)"),
    # Generic keyword fallbacks
    (re.compile(r"ubuntu",   re.I), "\U0001f427 Linux (Ubuntu)"),
    (re.compile(r"debian",   re.I), "\U0001f427 Linux (Debian)"),
    (re.compile(r"raspbian", re.I), "\U0001f427 Linux (Raspbian)"),
    (re.compile(r"centos",   re.I), "\U0001f427 Linux (CentOS)"),
    (re.compile(r"fedora",   re.I), "\U0001f427 Linux (Fedora)"),
    (re.compile(r"freebsd",  re.I), "\U0001f608 FreeBSD"),
    (re.compile(r"openbsd",  re.I), "\U0001f608 OpenBSD"),
    (re.compile(r"netbsd",   re.I), "\U0001f608 NetBSD"),
    (re.compile(r"darwin|mac.?os", re.I), "\U0001f34e macOS"),
    (re.compile(r"windows|microsoft|win32|win64", re.I), "\U0001fa9f Windows"),
]


def _os_hint(banner: str) -> str:
    """Return a short OS guess derived from the service banner, or empty string."""
    if not banner:
        return ""
    for pattern, label in _OS_PATTERNS:
        if pattern.search(banner):
            return label
    return ""


def _grab_banner(sock: socket.socket, timeout: float) -> str:
    """Attempt to read a banner from an already-connected socket."""
    try:
        sock.settimeout(timeout)
        # Try HTTP probe first for web servers that don't send first
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n")
        except Exception:
            pass
        raw = sock.recv(1024)
        return raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _fingerprint(banner: str) -> str:
    """Return a short version string extracted from the banner."""
    if not banner:
        return ""
    for pattern, label in _FINGERPRINTS:
        m = pattern.search(banner)
        if m:
            # If there's a group with version detail, include it
            groups = [g for g in m.groups() if g]
            if groups:
                return f"{label} ({groups[0].strip()[:60]})"
            return label
    # Fallback: first non-empty line, truncated
    first_line = banner.splitlines()[0].strip()
    return first_line[:80] if first_line else ""


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------
_scans: Dict[str, dict] = {}   # scan_id -> state dict
_scans_lock = threading.Lock()


def _new_scan_state(scan_id: str, total: int) -> None:
    with _scans_lock:
        _scans[scan_id] = {
            "total": total,
            "done": 0,
            "results": {},
            "status": "running",
            "start_time": time.time(),
            "elapsed": 0.0,
        }


def get_scan_state(scan_id: str) -> Optional[dict]:
    with _scans_lock:
        return _scans.get(scan_id)


def _update_scan_result(scan_id: str, port: int, result: dict) -> None:
    with _scans_lock:
        state = _scans.get(scan_id)
        if state:
            state["results"][port] = result
            state["done"] += 1
            state["elapsed"] = time.time() - state["start_time"]


def _finish_scan(scan_id: str) -> None:
    with _scans_lock:
        state = _scans.get(scan_id)
        if state:
            state["status"] = "done"
            state["elapsed"] = time.time() - state["start_time"]


def cleanup_old_scans(keep: int = 20) -> None:
    """Remove oldest scans beyond `keep` to prevent unbounded growth."""
    with _scans_lock:
        if len(_scans) > keep:
            oldest = sorted(_scans.keys())[: len(_scans) - keep]
            for k in oldest:
                del _scans[k]


# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------
def scan_port(
    host: str, port: int, timeout: float = 1.0, grab_banner: bool = True
) -> Dict[str, object]:
    """Try a TCP connect to (host, port). Returns a result dict."""
    result = {
        "port": port,
        "open": False,
        "service": COMMON_SERVICES.get(port, ""),
        "banner": "",
        "version": "",
        "os_hint": "",
        "risk": "closed",
    }
    try:
        # Resolve once and use first address
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return result

    result["open"] = True
    result["risk"] = risk_level(port, True)

    if grab_banner:
        banner = _grab_banner(sock, min(timeout, 1.5))
        result["banner"]  = banner
        result["version"] = _fingerprint(banner)
        result["os_hint"] = _os_hint(banner)

    sock.close()

    # Fallback service name
    if not result["service"]:
        try:
            result["service"] = socket.getservbyport(port)
        except OSError:
            pass

    return result


def scan_ports(
    host: str,
    ports: List[int],
    timeout: float = 1.0,
    max_workers: int = 150,
    grab_banner: bool = True,
    scan_id: Optional[str] = None,
) -> Dict[int, Dict[str, object]]:
    """Concurrently scan a list of ports on host.

    Returns a mapping: port -> result_dict
    If scan_id is provided, updates the shared progress state in real time.
    """
    if not ports:
        return {}

    if scan_id:
        _new_scan_state(scan_id, len(ports))

    workers = min(max_workers, len(ports))
    results: Dict[int, Dict[str, object]] = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, p, timeout, grab_banner): p
            for p in ports
        }
        for future in as_completed(future_to_port):
            port_result = future.result()
            port = port_result["port"]
            results[port] = port_result
            if scan_id:
                _update_scan_result(scan_id, port, port_result)

    if scan_id:
        _finish_scan(scan_id)

    return dict(sorted(results.items()))
