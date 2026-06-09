from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

def grab_banner(sock):
    try:
        sock.settimeout(2)
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return ""

def scan_port(host, port, timeout=1):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        try:
            service = socket.getservbyport(port)
        except:
            service = COMMON_SERVICES.get(port, "Unknown")

        banner = grab_banner(sock)
        sock.close()

        return port, {
            "open": True,
            "service": service,
            "banner": banner
        }

    except:
        return port, {
            "open": False,
            "service": "",
            "banner": ""
        }

def scan_ports(host, ports, timeout=1, max_workers=200):
    results = {}

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
        futures = [
            executor.submit(scan_port, host, port, timeout)
            for port in ports
        ]

        for future in as_completed(futures):
            port, result = future.result()
            results[port] = result

    return dict(sorted(results.items()))
