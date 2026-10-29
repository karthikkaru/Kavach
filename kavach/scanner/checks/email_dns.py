"""Email spoofing protection: SPF, DKIM and DMARC records."""
from __future__ import annotations

import re

import dns.exception
import dns.resolver

from ..models import Finding


def _txt_records(name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 3.0
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return ["".join(s.decode() for s in r.strings) for r in answers]


def check_email_dns(host: str) -> list[Finding]:
    out: list[Finding] = []
    # Check the registrable-looking domain: use host as given (user should enter root domain).
    try:
        txt = _txt_records(host)
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if not spf:
            out.append(Finding("spf", "Email security", "SPF record missing", "medium", False,
                               "Anyone can more easily send fake emails that appear to come from your domain.",
                               "Publish an SPF TXT record listing the servers allowed to send your email."))
        else:
            tokens = spf[0].lower().split()
            if any(t in ("+all", "all", "?all") for t in tokens):
                out.append(Finding("spf", "Email security", "SPF record is too permissive", "medium", False,
                                   "The record allows any server to send as your domain.",
                                   "End your SPF record with -all (or ~all while testing)."))
            else:
                out.append(Finding("spf", "Email security", "SPF record present", "info", True, spf[0][:120]))

        dmarc = [t for t in _txt_records(f"_dmarc.{host}") if t.lower().startswith("v=dmarc1")]
        if not dmarc:
            out.append(Finding("dmarc", "Email security", "DMARC record missing", "medium", False,
                               "Receivers have no policy for handling fake email sent in your name.",
                               "Publish a DMARC record at _dmarc.yourdomain, starting with p=none and moving to quarantine/reject."))
        else:
            policy = re.search(r"p=(\w+)", dmarc[0].lower())
            pol = policy.group(1) if policy else "none"
            if pol == "none":
                out.append(Finding("dmarc", "Email security", "DMARC is in monitoring mode only", "low", False,
                                   "DMARC is set to p=none, so fake emails are reported but not blocked.",
                                   "After reviewing reports, move the policy to p=quarantine and then p=reject."))
            else:
                out.append(Finding("dmarc", "Email security", "DMARC record present", "info", True, f"Policy: p={pol}."))

        selectors = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim")
        found = [s for s in selectors if _txt_records(f"{s}._domainkey.{host}")]
        if found:
            out.append(Finding("dkim", "Email security", "DKIM record found", "info", True,
                               f"Found selector: {found[0]}."))
        else:
            out.append(Finding("dkim", "Email security", "DKIM record not found for common selectors", "info", False,
                               "We only test common selector names, so this may be a false alarm if you use a custom one.",
                               "Make sure your email provider signs outgoing mail with DKIM."))
    except dns.exception.DNSException:
        out.append(Finding("email_dns_error", "Email security", "Email DNS records could not be checked", "info", False,
                           "DNS lookup timed out or failed."))
    return out


# (path, label, validator over (status_code, body_bytes))
