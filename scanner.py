"""scanner.py
Small, reusable port-scanning utilities.

Functions:
- scan_port(host, port, timeout): attempts a TCP connect and returns
    (port, is_open, service)
- scan_ports(host, ports, timeout, max_workers): concurrently scans a
    list of ports and returns a dict of results

This module intentionally avoids raw packet manipulation and uses plain
TCP connect calls so it works without elevated privileges.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import List, Dict, Tuple
import os
import ipaddress

# A short list of common services to fall back to when getservbyport fails.
COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "ms-wbt-server",
    8080: "http-proxy",
}

# Optional enforcement: if PORTSCANNER_ALLOWED_NETWORKS env var is set to a
# comma-separated list of CIDRs (e.g. "127.0.0.1/32,10.22.163.177/32"), then
# the scanner will refuse to connect to hosts that don't resolve into those
# networks. Leave unset to disable this protection.
_ENV_ALLOWED = os.environ.get("PORTSCANNER_ALLOWED_NETWORKS")
if _ENV_ALLOWED:
    try:
        ALLOWED_NETWORKS = [
            ipaddress.ip_network(x.strip())
            for x in _ENV_ALLOWED.split(',')
            if x.strip()
        ]
    except Exception:
        ALLOWED_NETWORKS = []
else:
    ALLOWED_NETWORKS = []


def _host_allowed(host: str) -> bool:
    """Return True if all resolved IPs for `host` are inside ALLOWED_NETWORKS.

    If ALLOWED_NETWORKS is empty, enforcement is disabled and the function
    returns True.
    """
    if not ALLOWED_NETWORKS:
        return True
    try:
        resolved = {res[4][0] for res in socket.getaddrinfo(host, None)}
    except Exception:
        return False
    for addr in resolved:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if not any(ip in net for net in ALLOWED_NETWORKS):
            return False
    return True


def scan_port(
    host: str, port: int, timeout: float = 1.0
) -> Tuple[int, bool, str]:
    """Try a TCP connect to (host, port).

        Returns (port, is_open, service_name). service_name will be an empty
        string if unknown.

        Notes:
        - Uses blocking connect with a timeout. This is cross-platform and
            doesn't require raw sockets.
        - Caller should handle exceptions if they want to treat them
            differently.
    """
    # Enforce host allowlist at scanner layer if configured via env var.
    if not _host_allowed(host):
        raise PermissionError(f"Host {host} is not inside allowed networks")

    try:
        # create_connection attempts to connect; on success we immediately
        # close the socket.
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = COMMON_SERVICES.get(port, "")
        return port, True, service
    except Exception:
        return port, False, ""


def scan_ports(
    host: str,
    ports: List[int],
    timeout: float = 1.0,
    max_workers: int = 100,
) -> Dict[int, Dict[str, object]]:
    """Concurrently scan a list of ports on host.

    Returns a mapping: port -> {"open": bool, "service": str}

    Parameters:
    - host: hostname or IP to scan (string)
    - ports: list of integer ports to check
    - timeout: per-port socket timeout in seconds
    - max_workers: max threads to use for concurrency
    """
    results: Dict[int, Dict[str, object]] = {}

    if not ports:
        return results

    workers = min(max_workers, len(ports))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, p, timeout): p
            for p in ports
        }
        for future in as_completed(future_to_port):
            port, is_open, service = future.result()
            results[port] = {"open": is_open, "service": service}

    # Return results sorted by port for determinism
    return dict(sorted(results.items()))
