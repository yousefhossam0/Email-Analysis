"""
SOC Mail Analysis Tool — Domain Intelligence
==============================================
Domain age (WHOIS), ASCII/IDN validation, DNS records verification,
domain reputation, and registrar analysis.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import whois

from utils.dns_utils import (
    get_mx_records, get_a_records, get_txt_records,
    get_spf_record, get_dmarc_record, domain_exists,
)
from utils.text_utils import (
    is_ascii_domain, is_punycode_domain, decode_punycode,
    detect_homoglyphs, detect_mixed_scripts, detect_domain_tricks,
    normalize_domain,
)
import config

logger = logging.getLogger(__name__)


class Finding:
    """Represents a single analysis finding."""
    SEVERITY_INFO = "INFO"
    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(self, check: str, description: str, severity: str, details: str = ""):
        self.check = check
        self.description = description
        self.severity = severity
        self.details = details

    def __repr__(self):
        return f"[{self.severity}] {self.check}: {self.description}"


def analyze_domain_age(domain: str) -> list[Finding]:
    """
    Perform WHOIS lookup to determine domain age and registrar info.
    Flags domains younger than the configured threshold.
    """
    findings = []

    try:
        w = whois.whois(domain)

        # Extract creation date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if isinstance(creation_date, str):
                try:
                    from dateutil import parser as dateutil_parser
                    creation_date = dateutil_parser.parse(creation_date)
                except Exception:
                    findings.append(Finding(
                        "Domain Age", f"Could not parse creation date: {creation_date}",
                        Finding.SEVERITY_LOW
                    ))
                    return findings

            # Make timezone-aware if needed
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days

            if age_days < config.DOMAIN_AGE_THRESHOLD_DAYS:
                findings.append(Finding(
                    "Domain Age",
                    f"Domain is only {age_days} days old (created {creation_date.strftime('%Y-%m-%d')})",
                    Finding.SEVERITY_HIGH,
                    f"Domains younger than {config.DOMAIN_AGE_THRESHOLD_DAYS} days are commonly "
                    f"used in phishing campaigns. Threshold: {config.DOMAIN_AGE_THRESHOLD_DAYS} days."
                ))
            elif age_days < 90:
                findings.append(Finding(
                    "Domain Age",
                    f"Domain is {age_days} days old (created {creation_date.strftime('%Y-%m-%d')})",
                    Finding.SEVERITY_LOW,
                    "Relatively new domain but past the high-risk threshold. Exercise caution."
                ))
            else:
                findings.append(Finding(
                    "Domain Age",
                    f"Domain is {age_days} days old (created {creation_date.strftime('%Y-%m-%d')})",
                    Finding.SEVERITY_INFO,
                    "Domain age appears normal."
                ))
        else:
            findings.append(Finding(
                "Domain Age", "Creation date not available in WHOIS data",
                Finding.SEVERITY_LOW,
                "Some domains use privacy protection that hides registration details."
            ))

        # Check registrar
        registrar = w.registrar
        if registrar:
            findings.append(Finding(
                "Registrar", f"Registered via: {registrar}",
                Finding.SEVERITY_INFO
            ))

        # Check for privacy protection
        name = str(w.name or '').lower()
        org = str(w.org or '').lower()
        privacy_indicators = ['privacy', 'redacted', 'whoisguard', 'domains by proxy', 'contact privacy']
        if any(p in name or p in org for p in privacy_indicators):
            findings.append(Finding(
                "WHOIS Privacy",
                "Domain uses WHOIS privacy protection",
                Finding.SEVERITY_LOW,
                f"Registrant: {w.name or 'N/A'}, Org: {w.org or 'N/A'}. "
                "Privacy protection hides the true owner — common for both legitimate "
                "and malicious domains."
            ))

        # Check expiration date
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date:
            if isinstance(expiration_date, str):
                try:
                    from dateutil import parser as dateutil_parser
                    expiration_date = dateutil_parser.parse(expiration_date)
                except Exception:
                    pass
            if isinstance(expiration_date, datetime):
                if expiration_date.tzinfo is None:
                    expiration_date = expiration_date.replace(tzinfo=timezone.utc)
                days_until_expiry = (expiration_date - datetime.now(timezone.utc)).days
                if days_until_expiry < 30:
                    findings.append(Finding(
                        "Domain Expiry",
                        f"Domain expires in {days_until_expiry} days",
                        Finding.SEVERITY_MEDIUM,
                        "Short-lived domains are sometimes used in disposable phishing campaigns."
                    ))

    except Exception as e:
        findings.append(Finding(
            "Domain Age", f"WHOIS lookup failed: {str(e)}",
            Finding.SEVERITY_LOW,
            "Could not retrieve WHOIS data. The domain may use a TLD that "
            "doesn't support WHOIS or the server may be unreachable."
        ))

    return findings


def analyze_domain_ascii_idn(domain: str) -> list[Finding]:
    """
    Check for ASCII/IDN attacks:
    - Punycode domains (xn--)
    - Unicode homoglyphs (Cyrillic/Greek chars mimicking Latin)
    - Mixed-script attacks
    - Brand impersonation via subdomains
    """
    findings = []

    # Punycode check
    if is_punycode_domain(domain):
        decoded = decode_punycode(domain)
        findings.append(Finding(
            "IDN/Punycode",
            f"Punycode domain detected: {domain} → {decoded}",
            Finding.SEVERITY_HIGH,
            "Punycode domains can be used in IDN homoglyph attacks where "
            "the domain looks identical to a legitimate one but uses different "
            "Unicode characters. This is a well-known phishing technique."
        ))

    # Non-ASCII / homoglyph check
    if not is_ascii_domain(domain):
        homoglyphs = detect_homoglyphs(domain)
        if homoglyphs:
            details_parts = []
            for h in homoglyphs:
                details_parts.append(
                    f"'{h['character']}' ({h['codepoint']} {h['unicode_name']}) mimics '{h['mimics']}'"
                )
            findings.append(Finding(
                "Homoglyph Attack",
                f"Found {len(homoglyphs)} homoglyph character(s) in domain",
                Finding.SEVERITY_CRITICAL,
                "Characters found: " + "; ".join(details_parts) + ". "
                "These characters look identical to Latin letters but are from "
                "different Unicode blocks (e.g., Cyrillic, Greek). This is a "
                "strong indicator of a homoglyph phishing attack."
            ))
        else:
            findings.append(Finding(
                "Non-ASCII Domain",
                f"Domain contains non-ASCII characters: {domain}",
                Finding.SEVERITY_MEDIUM,
                "While internationalized domain names are legitimate, they "
                "can also be used for spoofing. Verify the domain carefully."
            ))

    # Mixed script check
    mixed = detect_mixed_scripts(domain)
    if mixed['is_mixed']:
        findings.append(Finding(
            "Mixed Scripts",
            f"Domain uses characters from multiple scripts: {', '.join(mixed['scripts_found'])}",
            Finding.SEVERITY_HIGH,
            "Mixing characters from different writing systems (e.g., Latin + Cyrillic) "
            "is a strong indicator of a homoglyph attack."
        ))

    # Domain tricks (brand impersonation, etc.)
    tricks = detect_domain_tricks(domain)
    for trick in tricks:
        if 'Brand impersonation' in trick:
            findings.append(Finding(
                "Brand Impersonation", trick,
                Finding.SEVERITY_HIGH,
                "A well-known brand name appears in the subdomain but the "
                "actual domain is different. This is a common phishing technique."
            ))

    # If no issues found
    if not findings:
        findings.append(Finding(
            "Domain ASCII/IDN",
            "Domain uses standard ASCII characters — no IDN attacks detected",
            Finding.SEVERITY_INFO
        ))

    return findings


def analyze_domain_dns(domain: str) -> list[Finding]:
    """
    Verify DNS records for the sender's domain:
    - A records (domain resolves)
    - MX records (can receive mail)
    - SPF record exists
    - DMARC record exists
    """
    findings = []

    # Check if domain exists
    if not domain_exists(domain):
        findings.append(Finding(
            "Domain DNS",
            f"Domain {domain} does not resolve (no A or MX records)",
            Finding.SEVERITY_CRITICAL,
            "The sender's domain has no DNS records. This strongly suggests "
            "the email is spoofed — legitimate organizations always have "
            "resolvable domains."
        ))
        return findings

    # A records
    a_records = get_a_records(domain)
    if a_records:
        findings.append(Finding(
            "A Records", f"Domain resolves to: {', '.join(a_records)}",
            Finding.SEVERITY_INFO
        ))
    else:
        findings.append(Finding(
            "A Records", f"No A records found for {domain}",
            Finding.SEVERITY_LOW,
            "Some domains may only have MX records for mail-only setups."
        ))

    # MX records
    mx_records = get_mx_records(domain)
    if mx_records:
        findings.append(Finding(
            "MX Records", f"Mail servers: {', '.join(mx_records)}",
            Finding.SEVERITY_INFO
        ))
    else:
        findings.append(Finding(
            "MX Records", f"No MX records found for {domain}",
            Finding.SEVERITY_MEDIUM,
            "The domain has no mail exchange servers configured. "
            "This is unusual for a domain sending emails."
        ))

    # SPF record
    spf = get_spf_record(domain)
    if spf:
        findings.append(Finding(
            "SPF Record", f"SPF record found: {spf[:80]}{'...' if len(spf) > 80 else ''}",
            Finding.SEVERITY_INFO,
            f"Full record: {spf}"
        ))
        # Check for overly permissive SPF
        if '+all' in spf:
            findings.append(Finding(
                "SPF Permissive",
                "SPF record uses '+all' — allows ANY server to send as this domain",
                Finding.SEVERITY_HIGH,
                "A '+all' SPF mechanism means the domain's SPF policy accepts "
                "mail from all sources. This effectively disables SPF protection."
            ))
        elif '~all' in spf:
            findings.append(Finding(
                "SPF Softfail",
                "SPF record uses '~all' (softfail) — weak enforcement",
                Finding.SEVERITY_LOW,
                "Softfail means unauthorized senders are flagged but not rejected. "
                "This is common during SPF rollout but provides weaker protection than '-all'."
            ))
        elif '?all' in spf:
            findings.append(Finding(
                "SPF Neutral",
                "SPF record uses '?all' (neutral) — no enforcement",
                Finding.SEVERITY_MEDIUM,
                "Neutral means no assertion about unauthorized senders. "
                "This provides essentially no SPF protection."
            ))
    else:
        findings.append(Finding(
            "SPF Record", f"No SPF record found for {domain}",
            Finding.SEVERITY_MEDIUM,
            "The domain does not publish an SPF record. Without SPF, "
            "anyone can send email claiming to be from this domain."
        ))

    # DMARC record
    dmarc = get_dmarc_record(domain)
    if dmarc:
        findings.append(Finding(
            "DMARC Record", f"DMARC record found: {dmarc[:80]}{'...' if len(dmarc) > 80 else ''}",
            Finding.SEVERITY_INFO,
            f"Full record: {dmarc}"
        ))
        # Check DMARC policy
        if 'p=none' in dmarc:
            findings.append(Finding(
                "DMARC Policy",
                "DMARC policy is 'none' — monitoring only, no enforcement",
                Finding.SEVERITY_MEDIUM,
                "The domain is monitoring DMARC failures but not rejecting "
                "or quarantining spoofed emails. Spoofing is still possible."
            ))
        elif 'p=quarantine' in dmarc:
            findings.append(Finding(
                "DMARC Policy",
                "DMARC policy is 'quarantine' — moderate enforcement",
                Finding.SEVERITY_INFO,
                "Failed emails will be quarantined (sent to spam). Good but "
                "not as strong as p=reject."
            ))
        elif 'p=reject' in dmarc:
            findings.append(Finding(
                "DMARC Policy",
                "DMARC policy is 'reject' — strong enforcement",
                Finding.SEVERITY_INFO,
                "The domain has the strongest DMARC policy. Spoofed emails "
                "should be rejected by compliant mail servers."
            ))
    else:
        findings.append(Finding(
            "DMARC Record", f"No DMARC record found for {domain}",
            Finding.SEVERITY_MEDIUM,
            "The domain does not publish a DMARC record. Without DMARC, "
            "there is no policy to handle SPF/DKIM failures."
        ))

    return findings


def run_domain_intelligence(domain: str) -> list[Finding]:
    """
    Run all domain intelligence checks and return consolidated findings.
    """
    all_findings = []

    logger.info(f"[Domain Intel] Analyzing domain: {domain}")

    # 1. Domain age & WHOIS
    logger.info("[Domain Intel] Checking WHOIS / domain age...")
    all_findings.extend(analyze_domain_age(domain))

    # 2. ASCII / IDN / Homoglyph
    logger.info("[Domain Intel] Checking ASCII/IDN/homoglyphs...")
    all_findings.extend(analyze_domain_ascii_idn(domain))

    # 3. DNS records verification
    logger.info("[Domain Intel] Verifying DNS records...")
    all_findings.extend(analyze_domain_dns(domain))

    return all_findings
