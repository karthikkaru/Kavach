"""TLS certificate and protocol checks."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..constants import HTTP_TIMEOUT
from ..models import Finding


def check_tls(host: str) -> list[Finding]:
    out: list[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version() or "unknown"
    except ssl.SSLCertVerificationError as e:
        return [Finding(
            "tls_invalid", "SSL/TLS", "SSL certificate is not valid", "high", False,
            f"Browsers will show a security warning. Reason: {e.verify_message}.",
            "Install a valid certificate from a trusted authority (for example Let's Encrypt) "
            "that matches your domain name, and renew it before it expires.",
        )]
    except (ConnectionRefusedError, socket.timeout, OSError):
        return [Finding(
            "tls_missing", "SSL/TLS", "HTTPS is not available", "high", False,
            "We could not make a secure (HTTPS) connection on port 443.",
            "Enable HTTPS on your web server and install an SSL certificate.",
        )]

    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    if days_left < 0:
        out.append(Finding("tls_expired", "SSL/TLS", "SSL certificate has expired", "high", False,
                           f"Expired {abs(days_left)} days ago.", "Renew the certificate immediately."))
    elif days_left < 15:
        out.append(Finding("tls_expiring", "SSL/TLS", "SSL certificate expires very soon", "medium", False,
                           f"Expires in {days_left} days.", "Renew now and set up automatic renewal."))
    else:
        out.append(Finding("tls_valid", "SSL/TLS", "SSL certificate is valid", "info", True,
                           f"Valid for another {days_left} days."))

    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding("tls_old_version", "SSL/TLS", "Outdated TLS version in use", "medium", False,
                           f"Connection negotiated {version}.", "Allow only TLS 1.2 and TLS 1.3."))
    else:
        out.append(Finding("tls_version_ok", "SSL/TLS", "Modern TLS version in use", "info", True,
                           f"Connection negotiated {version}."))
    return out
