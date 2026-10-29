"""Risky services that should not be reachable from the internet."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..models import Finding


_RISKY_PORTS = {
    21: ("FTP", "high"), 23: ("Telnet", "high"), 3389: ("Remote Desktop (RDP)", "high"),
    3306: ("MySQL database", "high"), 5432: ("PostgreSQL database", "high"),
    6379: ("Redis", "high"), 27017: ("MongoDB", "high"), 445: ("SMB file sharing", "high"),
}


def check_open_ports(host: str, ips: list[str]) -> list[Finding]:
    ip = ips[0]
    open_ports: list[str] = []

    def probe(port):
        try:
            with socket.create_connection((ip, port), timeout=2.0):
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for port in pool.map(probe, _RISKY_PORTS):
            if port:
                open_ports.append(f"{port} ({_RISKY_PORTS[port][0]})")
    if open_ports:
        return [Finding("risky_ports", "Network", "Risky services are open to the internet", "high", False,
                        f"Open: {', '.join(open_ports)}.",
                        "Close these ports in your firewall or allow only trusted IP addresses. "
                        "Databases and remote-access services should never be public.")]
    return [Finding("risky_ports_ok", "Network", "No risky database or remote-access ports open", "info", True,
                    f"Checked {len(_RISKY_PORTS)} common risky ports.")]
