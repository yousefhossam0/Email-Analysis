"""
SOC Mail Analysis Tool — Sender Reputation
============================================
IP reputation checks via AbuseIPDB, DNS blocklists, reverse DNS,
VirusTotal IP scanning, and free email provider detection.
"""
import re
import logging
import time
from typing import Optional
import requests

from analyzer.domain_intel import Finding
from utils.dns_utils import get_ptr_record, check_ip_in_dnsbl
from utils.ip_utils import (
    extract_first_public_ip, is_private_ip, is_valid_ip,
    get_ip_geolocation, extract_ips_from_text,
)
import config

logger = logging.getLogger(__name__)
_last_vt_request_time = 0


def _rate_limit_vt():
    global _last_vt_request_time
    current = time.time()
    wait = (60 / config.VIRUSTOTAL_RATE_LIMIT) - (current - _last_vt_request_time)
    if wait > 0:
        time.sleep(wait)
    _last_vt_request_time = time.time()


def extract_sender_ip(email_obj) -> Optional[str]:
    """Extract originating sender IP from email headers."""
    received_headers = email_obj.get_all('Received', [])
    if not received_headers:
        return None
    for header in reversed(received_headers):
        ip = extract_first_public_ip(header)
        if ip:
            return ip
    x_orig = email_obj.get('X-Originating-IP', '')
    if x_orig:
        ip = x_orig.strip('[]').strip()
        if is_valid_ip(ip) and not is_private_ip(ip):
            return ip
    return None


def check_abuseipdb(ip_address: str) -> list[Finding]:
    findings = []
    if config.ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_KEY_HERE":
        findings.append(Finding("AbuseIPDB", "API key not configured — skipping", Finding.SEVERITY_INFO))
        return findings
    try:
        headers = {'Key': config.ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': 90, 'verbose': True}
        resp = requests.get(config.ABUSEIPDB_CHECK_ENDPOINT, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get('data', {})
        confidence = data.get('abuseConfidenceScore', 0)
        total_reports = data.get('totalReports', 0)
        is_tor = data.get('isTor', False)
        detail = f"IP: {ip_address} | Country: {data.get('countryCode','?')} | ISP: {data.get('isp','?')} | Reports: {total_reports}"
        if is_tor:
            findings.append(Finding("Tor Exit Node", f"IP {ip_address} is a Tor exit node", Finding.SEVERITY_HIGH,
                                    "Tor exit nodes commonly anonymize malicious email traffic."))
        if confidence >= config.ABUSEIPDB_CONFIDENCE_THRESHOLD:
            findings.append(Finding("AbuseIPDB", f"IP abuse confidence: {confidence}% ({total_reports} reports)", Finding.SEVERITY_HIGH, detail))
        elif confidence > 0:
            findings.append(Finding("AbuseIPDB", f"IP has some reports: {confidence}% ({total_reports})", Finding.SEVERITY_MEDIUM, detail))
        else:
            findings.append(Finding("AbuseIPDB", f"IP {ip_address} has no abuse reports", Finding.SEVERITY_INFO, detail))
    except requests.RequestException as e:
        findings.append(Finding("AbuseIPDB", f"API request failed: {e}", Finding.SEVERITY_LOW))
    return findings


def check_dns_blocklists(ip_address: str) -> list[Finding]:
    findings = []
    listed_on = []
    for bl in config.DNS_BLOCKLISTS:
        try:
            if check_ip_in_dnsbl(ip_address, bl):
                listed_on.append(bl)
        except Exception:
            pass
    if listed_on:
        findings.append(Finding("DNS Blocklist", f"IP listed on {len(listed_on)} blocklist(s)", Finding.SEVERITY_HIGH,
                                f"Listed on: {', '.join(listed_on)}"))
    else:
        findings.append(Finding("DNS Blocklist", f"IP not on any checked blocklists", Finding.SEVERITY_INFO))
    return findings


def check_reverse_dns(ip_address: str, expected_domain: str) -> list[Finding]:
    findings = []
    ptr = get_ptr_record(ip_address)
    if ptr:
        if expected_domain.lower() in ptr.lower():
            findings.append(Finding("Reverse DNS", f"PTR {ip_address} → {ptr} (matches)", Finding.SEVERITY_INFO))
        else:
            # Check if PTR resolves to a known trusted relay domain
            # (e.g., email sent via Google Workspace will have PTR like
            #  mail-sor-f41.google.com, not the customer's domain)
            is_trusted = any(ptr.lower().endswith(td) for td in config.TRUSTED_RELAY_DOMAINS)
            if is_trusted:
                findings.append(Finding("Reverse DNS",
                    f"PTR {ip_address} → {ptr} (trusted relay for '{expected_domain}')",
                    Finding.SEVERITY_INFO,
                    f"PTR resolves to a known trusted email provider/relay."))
            else:
                findings.append(Finding("Reverse DNS",
                    f"PTR {ip_address} → {ptr} (mismatch with '{expected_domain}')",
                    Finding.SEVERITY_MEDIUM, "Reverse DNS doesn't match sender domain."))
    else:
        findings.append(Finding("Reverse DNS", f"No PTR record for {ip_address}", Finding.SEVERITY_MEDIUM,
                                "Legitimate mail servers typically have PTR records."))
    return findings


def check_virustotal_ip(ip_address: str) -> list[Finding]:
    findings = []
    if config.VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        findings.append(Finding("VT IP Rep", "VirusTotal API key not configured — skipping", Finding.SEVERITY_INFO))
        return findings
    try:
        _rate_limit_vt()
        params = {'apikey': config.VIRUSTOTAL_API_KEY, 'ip': ip_address}
        resp = requests.get(config.VIRUSTOTAL_IP_REPORT_ENDPOINT, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        det_urls = len(data.get('detected_urls', []))
        det_samples = len(data.get('detected_communicating_samples', []))
        total = det_urls + det_samples
        if total:
            findings.append(Finding("VT IP Rep", f"IP has {total} detections on VT", 
                                    Finding.SEVERITY_HIGH if total > 5 else Finding.SEVERITY_MEDIUM))
        else:
            findings.append(Finding("VT IP Rep", f"IP clean on VirusTotal", Finding.SEVERITY_INFO))
    except requests.RequestException as e:
        findings.append(Finding("VT IP Rep", f"VT API failed: {e}", Finding.SEVERITY_LOW))
    return findings


def check_free_email_provider(domain: str, display_name: str = "") -> list[Finding]:
    findings = []
    if domain.lower() in config.FREE_EMAIL_PROVIDERS:
        biz = ['inc', 'corp', 'llc', 'bank', 'support', 'billing', 'admin', 'helpdesk', 'official', 'security']
        if any(b in display_name.lower() for b in biz):
            findings.append(Finding("Free Email + Biz", f"Free provider '{domain}' with business display name",
                                    Finding.SEVERITY_HIGH, "Legitimate businesses don't use free email for official comms."))
        else:
            findings.append(Finding("Free Email", f"Sender uses free provider: {domain}", Finding.SEVERITY_LOW))
    return findings


def run_sender_reputation(email_obj, sender_domain: str, display_name: str = "") -> list[Finding]:
    all_findings = []
    sender_ip = extract_sender_ip(email_obj)
    if sender_ip:
        all_findings.append(Finding("Sender IP", f"Originating IP: {sender_ip}", Finding.SEVERITY_INFO))
        geo = get_ip_geolocation(sender_ip)
        all_findings.append(Finding("IP Geolocation",
            f"{sender_ip}: {geo['city']}, {geo['country']} | ISP: {geo['isp']}", Finding.SEVERITY_INFO))
        all_findings.extend(check_abuseipdb(sender_ip))
        all_findings.extend(check_dns_blocklists(sender_ip))
        all_findings.extend(check_reverse_dns(sender_ip, sender_domain))
        all_findings.extend(check_virustotal_ip(sender_ip))
    else:
        all_findings.append(Finding("Sender IP", "Could not extract sender IP", Finding.SEVERITY_LOW,
                                    "Some email formats or local deliveries may not include sender IP."))
    all_findings.extend(check_free_email_provider(sender_domain, display_name))
    return all_findings
