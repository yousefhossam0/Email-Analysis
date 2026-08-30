"""
SOC Mail Analysis Tool — Body & Content Analysis
==================================================
URL extraction/detonation, attachment scanning, phishing heuristics,
display-vs-actual URL comparison, base64 payload detection.
"""
import re
import hashlib
import base64
import logging
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from analyzer.domain_intel import Finding
from utils.text_utils import count_phishing_keywords
import config

logger = logging.getLogger(__name__)
_last_vt_time = 0

# Known legitimate unsubscribe/tracking domains to ignore in URL count
_TRACKING_DOMAINS = [
    'list-manage.com', 'mailchimp.com', 'sendgrid.net',
    'tracking.', 'click.', 'links.',
]


def _rate_limit():
    global _last_vt_time
    wait = (60 / config.VIRUSTOTAL_RATE_LIMIT) - (time.time() - _last_vt_time)
    if wait > 0:
        time.sleep(wait)
    _last_vt_time = time.time()


def get_email_body(email_obj) -> tuple[str, str]:
    """Extract plain text and HTML body from email."""
    plain_body = ""
    html_body = ""
    try:
        body_part = email_obj.get_body(preferencelist=('plain',))
        if body_part:
            content = body_part.get_content()
            plain_body = content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
    except Exception:
        pass
    try:
        body_part = email_obj.get_body(preferencelist=('html',))
        if body_part:
            content = body_part.get_content()
            html_body = content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
    except Exception:
        pass
    # Fallback: walk all parts
    if not plain_body and not html_body:
        for part in email_obj.walk():
            ct = part.get_content_type()
            try:
                payload = part.get_content()
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='ignore')
                if ct == 'text/plain' and not plain_body:
                    plain_body = payload
                elif ct == 'text/html' and not html_body:
                    html_body = payload
            except Exception:
                pass
    return plain_body, html_body


def extract_urls(plain_body: str, html_body: str) -> list[dict]:
    """Extract URLs with display text comparison for HTML emails."""
    urls = []
    seen = set()
    # From plain text
    for url in re.findall(r'https?://\S+', plain_body):
        url = url.rstrip('.,;:>)]}\'\"')
        if url not in seen:
            urls.append({'url': url, 'display_text': None, 'source': 'plain'})
            seen.add(url)
    # From HTML — compare href with display text
    if html_body:
        try:
            soup = BeautifulSoup(html_body, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                display = a.get_text(strip=True)
                if href.startswith(('http://', 'https://')) and href not in seen:
                    urls.append({'url': href, 'display_text': display, 'source': 'html'})
                    seen.add(href)
        except Exception:
            pass
    return urls


def analyze_urls(plain_body: str, html_body: str) -> list[Finding]:
    """Analyze all extracted URLs."""
    findings = []
    urls = extract_urls(plain_body, html_body)
    if not urls:
        findings.append(Finding("URLs", "No URLs found in email body", Finding.SEVERITY_INFO))
        return findings

    findings.append(Finding("URLs", f"Found {len(urls)} URL(s) in email", Finding.SEVERITY_INFO))

    for url_data in urls:
        url = url_data['url']
        display = url_data['display_text']
        parsed = urlparse(url)
        domain = parsed.hostname or ''

        # Check URL shorteners
        if domain.lower() in config.URL_SHORTENERS:
            findings.append(Finding("URL Shortener",
                f"Shortened URL: {url}", Finding.SEVERITY_MEDIUM,
                "URL shorteners hide the true destination. Often used in phishing."))

        # Display vs actual URL mismatch
        if display and display.startswith(('http://', 'https://')):
            display_parsed = urlparse(display)
            display_domain = display_parsed.hostname or ''
            if display_domain and domain and display_domain.lower() != domain.lower():
                findings.append(Finding("URL Display Mismatch",
                    f"Display: {display_domain} → Actual: {domain}",
                    Finding.SEVERITY_CRITICAL,
                    f"Hyperlink text shows '{display}' but actually links to '{url}'. "
                    "This is a classic phishing technique."))

        # Check for IP-based URLs
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            findings.append(Finding("IP-based URL",
                f"URL uses IP address instead of domain: {url}",
                Finding.SEVERITY_HIGH, "Legitimate services rarely use IP addresses in URLs."))

        # VirusTotal scan
        if config.VIRUSTOTAL_API_KEY != "YOUR_VT_API_KEY_HERE":
            try:
                _rate_limit()
                params = {'apikey': config.VIRUSTOTAL_API_KEY, 'resource': url}
                resp = requests.get(config.VIRUSTOTAL_URL_REPORT_ENDPOINT, params=params, timeout=15)
                resp.raise_for_status()
                result = resp.json()
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                if positives >= config.URL_SCAN_THRESHOLD:
                    findings.append(Finding("VT URL Scan",
                        f"MALICIOUS URL: {url} ({positives}/{total} detections)",
                        Finding.SEVERITY_CRITICAL))
                elif positives > 0:
                    findings.append(Finding("VT URL Scan",
                        f"Suspicious URL: {url} ({positives}/{total} detections)",
                        Finding.SEVERITY_MEDIUM))
                else:
                    findings.append(Finding("VT URL Scan",
                        f"URL clean: {url}", Finding.SEVERITY_INFO))
            except Exception as e:
                findings.append(Finding("VT URL Scan", f"Scan failed for {url}: {e}",
                                        Finding.SEVERITY_LOW))

    return findings


def extract_attachments(email_obj) -> list[dict]:
    """Extract attachment metadata and hashes."""
    attachments = []
    for part in email_obj.walk():
        disp = part.get("Content-Disposition", "")
        if "attachment" in disp:
            filename = part.get_filename() or "unknown"
            payload = part.get_payload(decode=True)
            size = len(payload) if isinstance(payload, bytes) else 0
            sha256 = hashlib.sha256(payload).hexdigest() if isinstance(payload, bytes) else None
            attachments.append({
                'filename': filename,
                'size': size,
                'sha256': sha256,
                'content_type': part.get_content_type(),
            })
    return attachments


def analyze_attachments(email_obj) -> list[Finding]:
    """Analyze all attachments."""
    findings = []
    attachments = extract_attachments(email_obj)
    if not attachments:
        findings.append(Finding("Attachments", "No attachments found", Finding.SEVERITY_INFO))
        return findings

    findings.append(Finding("Attachments", f"Found {len(attachments)} attachment(s)", Finding.SEVERITY_INFO))

    for att in attachments:
        fn = att['filename']
        findings.append(Finding("Attachment", f"{fn} ({att['content_type']}, {att['size']} bytes)",
                                Finding.SEVERITY_INFO))

        # Suspicious extension
        if any(fn.lower().endswith(ext) for ext in config.SUSPICIOUS_EXTENSIONS):
            findings.append(Finding("Suspicious Extension",
                f"Dangerous file type: {fn}", Finding.SEVERITY_HIGH))

        # Double extension (e.g., invoice.pdf.exe)
        parts = fn.rsplit('.', 2)
        if len(parts) >= 3:
            findings.append(Finding("Double Extension",
                f"Double extension detected: {fn}", Finding.SEVERITY_CRITICAL,
                "Double extensions like 'file.pdf.exe' are used to trick users."))

        # Size check
        if att['size'] > config.MAX_ATTACHMENT_SIZE:
            findings.append(Finding("Large Attachment",
                f"Attachment too large: {fn} ({att['size']} bytes)", Finding.SEVERITY_LOW))

        # VT hash scan
        if att['sha256'] and config.VIRUSTOTAL_API_KEY != "YOUR_VT_API_KEY_HERE":
            try:
                _rate_limit()
                params = {'apikey': config.VIRUSTOTAL_API_KEY, 'resource': att['sha256']}
                resp = requests.get(config.VIRUSTOTAL_FILE_REPORT_ENDPOINT, params=params, timeout=15)
                resp.raise_for_status()
                result = resp.json()
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                if positives >= config.ATTACHMENT_SCAN_THRESHOLD:
                    findings.append(Finding("VT Attachment",
                        f"MALICIOUS: {fn} ({positives}/{total} detections)",
                        Finding.SEVERITY_CRITICAL,
                        f"SHA256: {att['sha256']}"))
                elif positives > 0:
                    findings.append(Finding("VT Attachment",
                        f"Suspicious: {fn} ({positives}/{total})",
                        Finding.SEVERITY_MEDIUM, f"SHA256: {att['sha256']}"))
                else:
                    findings.append(Finding("VT Attachment",
                        f"Clean: {fn}", Finding.SEVERITY_INFO, f"SHA256: {att['sha256']}"))
            except Exception as e:
                findings.append(Finding("VT Attachment", f"Scan failed: {e}", Finding.SEVERITY_LOW))

    return findings


def analyze_phishing_heuristics(plain_body: str, html_body: str) -> list[Finding]:
    """Detect phishing indicators in email content."""
    findings = []
    combined = plain_body + " " + html_body

    # ─── Strong phishing phrases (high specificity) ──────────────────
    strong_found = count_phishing_keywords(combined, config.STRONG_PHISHING_KEYWORDS)
    if strong_found:
        findings.append(Finding("Strong Phishing Signal",
            f"Found {len(strong_found)} high-confidence phishing phrase(s)",
            Finding.SEVERITY_HIGH,
            f"Phrases: {', '.join(strong_found[:5])}"))

    # ─── Generic keyword detection (lower specificity) ───────────────
    found_keywords = count_phishing_keywords(combined, config.PHISHING_KEYWORDS)
    if len(found_keywords) >= config.PHISHING_KEYWORDS_HIGH_THRESHOLD:
        findings.append(Finding("Phishing Keywords",
            f"Found {len(found_keywords)} phishing keywords/phrases",
            Finding.SEVERITY_HIGH,
            f"Keywords: {', '.join(found_keywords[:10])}"))
    elif len(found_keywords) >= config.PHISHING_KEYWORDS_LOW_THRESHOLD:
        findings.append(Finding("Phishing Keywords",
            f"Found {len(found_keywords)} phishing keyword(s)",
            Finding.SEVERITY_LOW,
            f"Keywords: {', '.join(found_keywords)}"))
    # 0-1 generic keywords: no finding at all (very common in legit mail)

    # HTML form detection
    if html_body:
        try:
            soup = BeautifulSoup(html_body, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                findings.append(Finding("HTML Form",
                    f"Email contains {len(forms)} HTML form(s)",
                    Finding.SEVERITY_HIGH,
                    "HTML forms in emails are a strong phishing indicator — "
                    "they can capture credentials directly."))
            # Password input fields
            pwd_inputs = soup.find_all('input', {'type': 'password'})
            if pwd_inputs:
                findings.append(Finding("Password Field",
                    "Email contains password input field(s)", Finding.SEVERITY_CRITICAL,
                    "A password input in an email is almost certainly phishing."))
            # Hidden iframes
            iframes = soup.find_all('iframe')
            if iframes:
                findings.append(Finding("Hidden Iframe",
                    f"Email contains {len(iframes)} iframe(s)", Finding.SEVERITY_HIGH,
                    "Iframes can load external malicious content."))
            # JavaScript
            scripts = soup.find_all('script')
            if scripts:
                findings.append(Finding("Embedded Script",
                    f"Email contains {len(scripts)} script tag(s)", Finding.SEVERITY_HIGH,
                    "JavaScript in emails can be used for malicious purposes."))
        except Exception:
            pass

    # Base64 encoded content in plain text (potential payload)
    # Only flag base64 blobs that appear in plain text body, NOT in HTML
    # (HTML emails commonly contain base64-encoded inline images which are benign).
    if plain_body:
        b64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'  # Raised from 50 to 100 chars
        b64_matches = re.findall(b64_pattern, plain_body)
        if b64_matches:
            findings.append(Finding("Base64 Content",
                f"Found {len(b64_matches)} large base64-encoded blob(s) in plain text body",
                Finding.SEVERITY_MEDIUM,
                "Large base64 strings in plain text email body may contain hidden payloads."))

    return findings


def run_body_analysis(email_obj) -> list[Finding]:
    """Run all body/content analysis checks."""
    all_findings = []
    plain_body, html_body = get_email_body(email_obj)
    if not plain_body and not html_body:
        all_findings.append(Finding("Email Body", "Could not extract email body",
                                    Finding.SEVERITY_LOW))
        return all_findings

    all_findings.extend(analyze_urls(plain_body, html_body))
    all_findings.extend(analyze_attachments(email_obj))
    all_findings.extend(analyze_phishing_heuristics(plain_body, html_body))
    return all_findings
