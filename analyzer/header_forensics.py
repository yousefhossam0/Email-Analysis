"""
SOC Mail Analysis Tool — Header Forensics
===========================================
Received hop tracing, timestamp validation, sender header cross-comparison,
Message-ID validation, X-Mailer detection, and header injection checks.
"""
import re
import logging
from datetime import datetime
from typing import Optional
from email.utils import parsedate_to_datetime

from analyzer.domain_intel import Finding
from utils.ip_utils import extract_ips_from_text, is_private_ip, extract_first_public_ip
import config

logger = logging.getLogger(__name__)


def parse_received_hops(email_obj) -> list[dict]:
    """Parse all Received headers into structured hop data."""
    received_headers = email_obj.get_all('Received', [])
    hops = []
    for i, header in enumerate(received_headers):
        hop = {'raw': header, 'index': i}
        # Extract 'from' server
        from_match = re.search(r'from\s+([\w.\-]+)', header, re.IGNORECASE)
        hop['from_server'] = from_match.group(1) if from_match else None
        # Extract 'by' server
        by_match = re.search(r'by\s+([\w.\-]+)', header, re.IGNORECASE)
        hop['by_server'] = by_match.group(1) if by_match else None
        # Extract IPs
        hop['ips'] = extract_ips_from_text(header)
        # Extract timestamp
        date_match = re.search(r';\s*(.+)$', header.strip())
        if date_match:
            try:
                hop['timestamp'] = parsedate_to_datetime(date_match.group(1).strip())
            except Exception:
                hop['timestamp'] = None
        else:
            hop['timestamp'] = None
        # Extract 'with' protocol
        with_match = re.search(r'with\s+(\w+)', header, re.IGNORECASE)
        hop['protocol'] = with_match.group(1) if with_match else None
        hops.append(hop)
    return hops


def analyze_received_hops(email_obj) -> list[Finding]:
    """Trace the full relay chain and analyze each hop."""
    findings = []
    hops = parse_received_hops(email_obj)
    if not hops:
        findings.append(Finding("Received Headers", "No Received headers found",
                                Finding.SEVERITY_HIGH, "Missing Received headers is highly unusual."))
        return findings

    findings.append(Finding("Relay Chain", f"Email traversed {len(hops)} hop(s)",
                            Finding.SEVERITY_INFO))

    for hop in hops:
        from_s = hop['from_server'] or 'unknown'
        by_s = hop['by_server'] or 'unknown'
        ips = hop['ips']
        ts = hop['timestamp'].strftime('%Y-%m-%d %H:%M:%S %Z') if hop['timestamp'] else 'no timestamp'
        findings.append(Finding("Hop Detail",
            f"Hop {hop['index']}: from={from_s} by={by_s} IPs={ips} [{ts}]",
            Finding.SEVERITY_INFO))

        # Flag genuinely suspicious patterns (not just presence of the word 'unknown')
        raw_lower = hop['raw'].lower()
        # Only flag when the hop origin is explicitly "from unknown" — this means
        # the server couldn't identify the source, which is more concerning than
        # just having 'unknown' appear anywhere in the header.
        if re.search(r'from\s+unknown', raw_lower):
            findings.append(Finding("Suspicious Hop",
                f"Hop {hop['index']}: 'from unknown' host in relay chain",
                Finding.SEVERITY_MEDIUM, "Legitimate servers usually identify themselves."))
        if 'localhost' in raw_lower and hop['index'] != len(hops) - 1:
            findings.append(Finding("Suspicious Hop",
                f"Hop {hop['index']}: 'localhost' in relay chain",
                Finding.SEVERITY_MEDIUM, "Localhost in intermediate hops is unusual."))

    return findings


def analyze_timestamps(email_obj) -> list[Finding]:
    """Check if Received header timestamps are in logical order."""
    findings = []
    hops = parse_received_hops(email_obj)
    timestamps = [(h['index'], h['timestamp']) for h in hops if h['timestamp']]

    if len(timestamps) < 2:
        findings.append(Finding("Timestamp Validation",
            "Not enough timestamps to validate ordering", Finding.SEVERITY_INFO))
        return findings

    # Received headers: index 0 is newest, last is oldest
    for i in range(len(timestamps) - 1):
        idx1, ts1 = timestamps[i]
        idx2, ts2 = timestamps[i + 1]
        if ts1 < ts2:
            findings.append(Finding("Timestamp Order",
                f"Timestamps out of order between hop {idx1} and {idx2}",
                Finding.SEVERITY_HIGH,
                f"Hop {idx1}: {ts1} < Hop {idx2}: {ts2}. "
                "This may indicate header forgery."))

    # Check for large time gaps
    for i in range(len(timestamps) - 1):
        idx1, ts1 = timestamps[i]
        idx2, ts2 = timestamps[i + 1]
        try:
            diff = abs((ts1 - ts2).total_seconds())
            if diff > 3600:
                findings.append(Finding("Timestamp Gap",
                    f"Large time gap ({int(diff/60)} min) between hop {idx1} and {idx2}",
                    Finding.SEVERITY_LOW,
                    "Large time gaps may indicate processing delays or time manipulation."))
        except Exception:
            pass

    # Check for future-dated timestamps
    now = datetime.now(timestamps[0][1].tzinfo) if timestamps[0][1].tzinfo else datetime.now()
    for idx, ts in timestamps:
        try:
            if ts > now:
                findings.append(Finding("Future Timestamp",
                    f"Hop {idx} has a future timestamp: {ts}",
                    Finding.SEVERITY_HIGH, "Future timestamps strongly indicate header forgery."))
        except Exception:
            pass

    if not any(f.severity in (Finding.SEVERITY_HIGH, Finding.SEVERITY_CRITICAL) for f in findings):
        findings.append(Finding("Timestamp Validation",
            "Timestamps are in logical order", Finding.SEVERITY_INFO))

    return findings


def analyze_sender_headers(email_obj) -> list[Finding]:
    """Cross-compare From, Return-Path, Reply-To, and Envelope-From."""
    findings = []
    from_header = email_obj.get('From', '').lower()
    return_path = email_obj.get('Return-Path', '').lower()
    reply_to = email_obj.get('Reply-To', '').lower()
    envelope_from = email_obj.get('X-Envelope-From', email_obj.get('Envelope-From', '')).lower()

    def extract_domain(text):
        match = re.search(r'@([\w.\-]+\.\w+)', text)
        return match.group(1) if match else None

    from_domain = extract_domain(from_header)
    rp_domain = extract_domain(return_path)
    rt_domain = extract_domain(reply_to)
    env_domain = extract_domain(envelope_from)

    if from_domain and rp_domain:
        if from_domain == rp_domain:
            findings.append(Finding("From/Return-Path", "Domains match", Finding.SEVERITY_INFO))
        else:
            findings.append(Finding("From/Return-Path",
                f"Domain mismatch: From={from_domain}, Return-Path={rp_domain}",
                Finding.SEVERITY_HIGH,
                "Mismatched From and Return-Path domains is a strong spoofing indicator."))

    if reply_to and from_domain:
        if rt_domain and rt_domain != from_domain:
            # Reply-To mismatches are common for mailing lists, support systems,
            # and no-reply addresses. Only flag as LOW by default.
            findings.append(Finding("From/Reply-To",
                f"Domain mismatch: From={from_domain}, Reply-To={rt_domain}",
                Finding.SEVERITY_LOW,
                "Replies go to a different domain than the sender claims. "
                "This is common for mailing lists and support systems."))

    if envelope_from and from_domain:
        if env_domain and env_domain != from_domain:
            findings.append(Finding("From/Envelope-From",
                f"Domain mismatch: From={from_domain}, Envelope-From={env_domain}",
                Finding.SEVERITY_HIGH, "Envelope-From doesn't match displayed From."))

    if not from_domain:
        findings.append(Finding("From Header", "Could not extract domain from From header",
                                Finding.SEVERITY_MEDIUM))

    return findings


def analyze_message_id(email_obj) -> list[Finding]:
    """Validate Message-ID domain alignment."""
    findings = []
    message_id = email_obj.get('Message-ID', '')
    from_header = email_obj.get('From', '')

    if not message_id:
        findings.append(Finding("Message-ID", "Missing Message-ID header",
                                Finding.SEVERITY_MEDIUM, "All legitimate emails should have a Message-ID."))
        return findings

    mid_domain = re.search(r'@([\w.\-]+)', message_id)
    from_domain = re.search(r'@([\w.\-]+\.\w+)', from_header)

    if mid_domain and from_domain:
        mid_d = mid_domain.group(1).lower().rstrip('>')
        from_d = from_domain.group(1).lower()
        if mid_d == from_d or from_d in mid_d or mid_d in from_d:
            findings.append(Finding("Message-ID", f"Domain aligns with From ({mid_d})", Finding.SEVERITY_INFO))
        else:
            # Check if Message-ID domain is a known trusted relay
            if any(mid_d.endswith(td) for td in config.TRUSTED_RELAY_DOMAINS):
                findings.append(Finding("Message-ID",
                    f"Message-ID domain ({mid_d}) is a trusted relay for From={from_d}",
                    Finding.SEVERITY_INFO,
                    "Third-party email services generate Message-IDs with their own domain."))
            else:
                findings.append(Finding("Message-ID",
                    f"Domain mismatch: Message-ID={mid_d}, From={from_d}",
                    Finding.SEVERITY_MEDIUM, "May be legitimate (e.g., sent via third-party service) or spoofed."))

    return findings


def analyze_xmailer(email_obj) -> list[Finding]:
    """Detect suspicious X-Mailer or User-Agent headers."""
    findings = []
    xmailer = email_obj.get('X-Mailer', '') or email_obj.get('User-Agent', '')
    if xmailer:
        findings.append(Finding("X-Mailer", f"Mail client: {xmailer}", Finding.SEVERITY_INFO))
        for tool in config.SUSPICIOUS_MAILERS:
            if tool.lower() in xmailer.lower():
                findings.append(Finding("Suspicious Mailer",
                    f"Known mass-mailing tool detected: {tool}",
                    Finding.SEVERITY_HIGH, f"X-Mailer header: {xmailer}"))
                break
    return findings


def analyze_header_injection(email_obj) -> list[Finding]:
    """Detect duplicate or injected critical headers."""
    findings = []
    critical_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID']
    for h in critical_headers:
        values = email_obj.get_all(h, [])
        if len(values) > 1:
            findings.append(Finding("Header Injection",
                f"Duplicate '{h}' header detected ({len(values)} occurrences)",
                Finding.SEVERITY_HIGH,
                "Multiple instances of critical headers can indicate header injection attacks."))
    return findings


def run_header_forensics(email_obj) -> list[Finding]:
    """Run all header forensics checks."""
    all_findings = []
    all_findings.extend(analyze_received_hops(email_obj))
    all_findings.extend(analyze_timestamps(email_obj))
    all_findings.extend(analyze_sender_headers(email_obj))
    all_findings.extend(analyze_message_id(email_obj))
    all_findings.extend(analyze_xmailer(email_obj))
    all_findings.extend(analyze_header_injection(email_obj))
    return all_findings
