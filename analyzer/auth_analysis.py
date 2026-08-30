"""
SOC Mail Analysis Tool — Authentication Deep Analysis
=======================================================
Full SPF, DKIM, DMARC, and ARC analysis with alignment checks.
"""
import re
import logging
from analyzer.domain_intel import Finding
from utils.dns_utils import get_spf_record, get_dmarc_record
import config

logger = logging.getLogger(__name__)


def parse_auth_results(email_obj) -> dict:
    """Parse all Authentication-Results headers into structured data."""
    results = {
        'spf': {'result': None, 'details': ''},
        'dkim': {'result': None, 'details': '', 'd_domain': None, 's_selector': None},
        'dmarc': {'result': None, 'details': ''},
        'compauth': {'result': None, 'details': ''},
    }
    auth_headers = email_obj.get_all('Authentication-Results', [])
    for header in auth_headers:
        h = header.lower()
        # SPF
        spf_match = re.search(r'spf\s*=\s*(\w+)', h)
        if spf_match:
            results['spf']['result'] = spf_match.group(1)
            results['spf']['details'] = header.strip()
        # DKIM
        dkim_match = re.search(r'dkim\s*=\s*(\w+)', h)
        if dkim_match:
            results['dkim']['result'] = dkim_match.group(1)
            results['dkim']['details'] = header.strip()
            d_match = re.search(r'header\.d\s*=\s*([\w.\-]+)', h)
            if d_match:
                results['dkim']['d_domain'] = d_match.group(1)
            s_match = re.search(r'header\.s\s*=\s*([\w.\-]+)', h)
            if s_match:
                results['dkim']['s_selector'] = s_match.group(1)
        # DMARC
        dmarc_match = re.search(r'dmarc\s*=\s*(\w+)', h)
        if dmarc_match:
            results['dmarc']['result'] = dmarc_match.group(1)
            results['dmarc']['details'] = header.strip()
        # compauth / composite auth
        compauth_match = re.search(r'compauth\s*=\s*(\w+)', h)
        if compauth_match:
            results['compauth']['result'] = compauth_match.group(1)
            results['compauth']['details'] = header.strip()

    # Also check Received-SPF header
    received_spf = email_obj.get('Received-SPF', '')
    if received_spf and not results['spf']['result']:
        spf_match = re.search(r'^(pass|fail|softfail|neutral|none|temperror|permerror)', received_spf.lower())
        if spf_match:
            results['spf']['result'] = spf_match.group(1)
            results['spf']['details'] = received_spf.strip()

    return results


def analyze_spf(email_obj, sender_domain: str) -> list[Finding]:
    """Deep SPF analysis."""
    findings = []
    auth = parse_auth_results(email_obj)
    spf_result = auth['spf']['result']

    if spf_result:
        if spf_result == 'pass':
            findings.append(Finding("SPF Result", "SPF: PASS", Finding.SEVERITY_INFO,
                                    auth['spf']['details']))
        elif spf_result in ('fail', 'hardfail'):
            findings.append(Finding("SPF Result", "SPF: FAIL — sender IP not authorized",
                                    Finding.SEVERITY_CRITICAL,
                                    "The sending server's IP is NOT in the domain's SPF record. "
                                    "This is a strong spoofing indicator. " + auth['spf']['details']))
        elif spf_result == 'softfail':
            findings.append(Finding("SPF Result", "SPF: SOFTFAIL — sender IP not fully authorized",
                                    Finding.SEVERITY_HIGH,
                                    "Softfail means the IP is probably not authorized. " + auth['spf']['details']))
        elif spf_result == 'neutral':
            findings.append(Finding("SPF Result", "SPF: NEUTRAL — no assertion",
                                    Finding.SEVERITY_MEDIUM, auth['spf']['details']))
        elif spf_result == 'none':
            findings.append(Finding("SPF Result", "SPF: NONE — no SPF record published",
                                    Finding.SEVERITY_MEDIUM, auth['spf']['details']))
        elif spf_result in ('temperror', 'permerror'):
            findings.append(Finding("SPF Result", f"SPF: {spf_result.upper()} — DNS error",
                                    Finding.SEVERITY_MEDIUM, auth['spf']['details']))
    else:
        findings.append(Finding("SPF Result", "No SPF result found in headers",
                                Finding.SEVERITY_LOW, "No Received-SPF or Authentication-Results with SPF data."))

    # Verify against published SPF record
    published_spf = get_spf_record(sender_domain)
    if published_spf:
        findings.append(Finding("Published SPF", f"Domain SPF: {published_spf[:100]}",
                                Finding.SEVERITY_INFO))
    else:
        findings.append(Finding("Published SPF", f"No SPF record published for {sender_domain}",
                                Finding.SEVERITY_MEDIUM, "Domain has no SPF — anyone can send as this domain."))

    return findings


def analyze_dkim(email_obj, sender_domain: str) -> list[Finding]:
    """Deep DKIM analysis."""
    findings = []
    auth = parse_auth_results(email_obj)
    dkim_result = auth['dkim']['result']
    dkim_sig = email_obj.get('DKIM-Signature', '')

    if dkim_result:
        if dkim_result == 'pass':
            findings.append(Finding("DKIM Result", "DKIM: PASS", Finding.SEVERITY_INFO,
                                    auth['dkim']['details']))
        elif dkim_result == 'fail':
            findings.append(Finding("DKIM Result", "DKIM: FAIL — signature invalid",
                                    Finding.SEVERITY_HIGH,
                                    "DKIM signature verification failed. Message may have been "
                                    "tampered with or forged. " + auth['dkim']['details']))
        elif dkim_result == 'none':
            findings.append(Finding("DKIM Result", "DKIM: NONE — no signature",
                                    Finding.SEVERITY_MEDIUM, auth['dkim']['details']))
        else:
            findings.append(Finding("DKIM Result", f"DKIM: {dkim_result.upper()}",
                                    Finding.SEVERITY_MEDIUM, auth['dkim']['details']))
    elif dkim_sig:
        findings.append(Finding("DKIM Signature", "DKIM-Signature header present but no verification result",
                                Finding.SEVERITY_LOW))
    else:
        findings.append(Finding("DKIM Result", "No DKIM signature or result found",
                                Finding.SEVERITY_LOW, "Email was not signed with DKIM."))

    # DKIM alignment check
    if auth['dkim']['d_domain']:
        d_domain = auth['dkim']['d_domain']
        if d_domain == sender_domain or sender_domain.endswith('.' + d_domain):
            findings.append(Finding("DKIM Alignment", f"DKIM d={d_domain} aligns with From domain",
                                    Finding.SEVERITY_INFO))
        else:
            # Check if the DKIM domain is a known trusted relay provider
            if any(d_domain.endswith(td) for td in config.TRUSTED_RELAY_DOMAINS):
                findings.append(Finding("DKIM Alignment",
                    f"DKIM d={d_domain} is a trusted relay (From={sender_domain})",
                    Finding.SEVERITY_INFO,
                    f"DKIM domain '{d_domain}' is a known legitimate email relay/provider. "
                    "Third-party email services sign with their own domain — this is normal."))
            else:
                findings.append(Finding("DKIM Alignment",
                    f"DKIM d={d_domain} does NOT align with From={sender_domain}",
                    Finding.SEVERITY_HIGH,
                    "DKIM domain doesn't match the From domain and is not a known "
                    "trusted relay. The signature may be from an attacker."))

    # Parse DKIM-Signature header for d= if not in auth results
    if dkim_sig and not auth['dkim']['d_domain']:
        d_match = re.search(r'd\s*=\s*([\w.\-]+)', dkim_sig)
        if d_match:
            d_domain = d_match.group(1)
            if d_domain != sender_domain and not sender_domain.endswith('.' + d_domain):
                # Check trusted relays before flagging
                if any(d_domain.endswith(td) for td in config.TRUSTED_RELAY_DOMAINS):
                    findings.append(Finding("DKIM Alignment",
                        f"DKIM-Signature d={d_domain} via trusted relay (From={sender_domain})",
                        Finding.SEVERITY_INFO))
                else:
                    findings.append(Finding("DKIM Alignment",
                        f"DKIM-Signature d={d_domain} misaligns with From={sender_domain}",
                        Finding.SEVERITY_HIGH))

    return findings


def analyze_dmarc(email_obj, sender_domain: str) -> list[Finding]:
    """Deep DMARC analysis."""
    findings = []
    auth = parse_auth_results(email_obj)
    dmarc_result = auth['dmarc']['result']

    if dmarc_result:
        if dmarc_result == 'pass':
            findings.append(Finding("DMARC Result", "DMARC: PASS", Finding.SEVERITY_INFO,
                                    auth['dmarc']['details']))
        elif dmarc_result == 'fail':
            findings.append(Finding("DMARC Result", "DMARC: FAIL",
                                    Finding.SEVERITY_CRITICAL,
                                    "DMARC failed — neither SPF nor DKIM passed with alignment. "
                                    "This is a very strong indicator of spoofing. " + auth['dmarc']['details']))
        elif dmarc_result == 'none':
            findings.append(Finding("DMARC Result", "DMARC: NONE — no policy published",
                                    Finding.SEVERITY_MEDIUM, auth['dmarc']['details']))
        else:
            findings.append(Finding("DMARC Result", f"DMARC: {dmarc_result.upper()}",
                                    Finding.SEVERITY_MEDIUM, auth['dmarc']['details']))
    else:
        findings.append(Finding("DMARC Result", "No DMARC result in headers",
                                Finding.SEVERITY_LOW))

    # Check published DMARC policy
    published = get_dmarc_record(sender_domain)
    if published:
        findings.append(Finding("Published DMARC", f"Domain DMARC: {published[:100]}",
                                Finding.SEVERITY_INFO))
        if 'p=reject' in published:
            if dmarc_result == 'fail':
                findings.append(Finding("DMARC Enforcement",
                    "DMARC failed but domain has p=reject — email should have been blocked",
                    Finding.SEVERITY_CRITICAL,
                    "The receiving server accepted this email despite DMARC failure and reject policy."))
    else:
        findings.append(Finding("Published DMARC", f"No DMARC record for {sender_domain}",
                                Finding.SEVERITY_MEDIUM))

    return findings


def analyze_arc(email_obj) -> list[Finding]:
    """Analyze ARC (Authenticated Received Chain) headers if present."""
    findings = []
    arc_auth = email_obj.get_all('ARC-Authentication-Results', [])
    arc_seal = email_obj.get_all('ARC-Seal', [])
    arc_msg_sig = email_obj.get_all('ARC-Message-Signature', [])

    if arc_auth or arc_seal or arc_msg_sig:
        findings.append(Finding("ARC Chain", f"ARC headers present ({len(arc_seal)} seal(s))",
                                Finding.SEVERITY_INFO))
        for arc in arc_auth:
            arc_lower = arc.lower()
            if 'arc=pass' in arc_lower:
                findings.append(Finding("ARC Result", "ARC: PASS", Finding.SEVERITY_INFO))
            elif 'arc=fail' in arc_lower:
                findings.append(Finding("ARC Result", "ARC: FAIL", Finding.SEVERITY_MEDIUM,
                                        "ARC chain validation failed."))
    else:
        findings.append(Finding("ARC Chain", "No ARC headers (not all servers use ARC)",
                                Finding.SEVERITY_INFO))

    return findings


def run_auth_analysis(email_obj, sender_domain: str) -> list[Finding]:
    """Run all authentication checks."""
    all_findings = []
    all_findings.extend(analyze_spf(email_obj, sender_domain))
    all_findings.extend(analyze_dkim(email_obj, sender_domain))
    all_findings.extend(analyze_dmarc(email_obj, sender_domain))
    all_findings.extend(analyze_arc(email_obj))
    return all_findings
