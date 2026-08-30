"""
SOC Mail Analysis Tool — Report Generator
============================================
Rich console output + detailed file/JSON report generation with IOC extraction.
"""
import json
import os
import sys
import re
import logging
from datetime import datetime
from typing import Optional

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from analyzer.domain_intel import Finding
import config

logger = logging.getLogger(__name__)
console = Console(force_terminal=True)

# Severity color mapping
SEVERITY_COLORS = {
    Finding.SEVERITY_INFO: "cyan",
    Finding.SEVERITY_LOW: "green",
    Finding.SEVERITY_MEDIUM: "yellow",
    Finding.SEVERITY_HIGH: "red",
    Finding.SEVERITY_CRITICAL: "bold red on white",
}

SEVERITY_ICONS = {
    Finding.SEVERITY_INFO: "[i]",
    Finding.SEVERITY_LOW: "[+]",
    Finding.SEVERITY_MEDIUM: "[!]",
    Finding.SEVERITY_HIGH: "[!!]",
    Finding.SEVERITY_CRITICAL: "[!!!]",
}


def print_banner():
    """Print the tool banner."""
    banner = Text()
    banner.append("+--------------------------------------------------------------+\n", style="bold cyan")
    banner.append("|        SOC Mail Spoof & Phishing Analysis Tool               |\n", style="bold cyan")
    banner.append("|        Comprehensive Email Forensic Analyzer                 |\n", style="bold cyan")
    banner.append("|        v2.0 -- Built for Security Operations Center          |\n", style="bold cyan")
    banner.append("+--------------------------------------------------------------+", style="bold cyan")
    console.print(banner)
    console.print()


def print_email_summary(email_obj):
    """Print email metadata summary."""
    table = Table(title="[Email Summary]", box=box.ASCII, border_style="blue")
    table.add_column("Field", style="bold", width=15)
    table.add_column("Value", overflow="fold")

    table.add_row("From", email_obj.get('From', 'Unknown'))
    table.add_row("To", email_obj.get('To', 'Unknown'))
    table.add_row("Subject", email_obj.get('Subject', '(no subject)'))
    table.add_row("Date", email_obj.get('Date', 'Unknown'))
    table.add_row("Message-ID", email_obj.get('Message-ID', 'None'))
    table.add_row("Return-Path", email_obj.get('Return-Path', 'None'))
    table.add_row("Reply-To", email_obj.get('Reply-To', 'None'))

    console.print(table)
    console.print()


def print_section(title: str, findings: list[Finding]):
    """Print a section of findings with color-coded severity."""
    if not findings:
        return

    table = Table(title=title, box=box.ASCII2, border_style="blue",
                  show_lines=True, pad_edge=True)
    table.add_column("Sev", width=5, justify="center")
    table.add_column("Check", style="bold", width=22, overflow="fold")
    table.add_column("Description", overflow="fold")

    for f in findings:
        icon = SEVERITY_ICONS.get(f.severity, "?")
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            Text(icon, style=color),
            Text(f.check, style=color),
            Text(f.description, style=color),
        )

    console.print(table)
    console.print()


def print_score_card(score_data: dict):
    """Print the final risk score card."""
    # Category scores table
    table = Table(title="[Risk Score Breakdown]", box=box.ASCII2, border_style="magenta")
    table.add_column("Category", style="bold", width=35)
    table.add_column("Score", justify="center", width=10)
    table.add_column("Bar", width=20)

    for cat, data in score_data['category_scores'].items():
        score = data['score']
        max_score = data['max']
        pct = (score / max_score * 100) if max_score > 0 else 0
        bar_filled = int(pct / 5)
        bar = "#" * bar_filled + "-" * (20 - bar_filled)
        if pct >= 60:
            color = "red"
        elif pct >= 30:
            color = "yellow"
        else:
            color = "green"
        table.add_row(cat, f"[{color}]{score}/{max_score}[/{color}]", f"[{color}]{bar}[/{color}]")

    console.print(table)
    console.print()

    # Verdict panel
    verdict = score_data['verdict']
    emoji = score_data['verdict_emoji']
    total = score_data['total_score']
    confidence = score_data['confidence']

    if "LEGITIMATE" in verdict:
        style = "bold green"
    elif "SUSPICIOUS" in verdict:
        style = "bold yellow"
    elif "PHISHING" in verdict:
        style = "bold red"
    else:
        style = "bold white on red"

    verdict_text = Text()
    verdict_text.append(f"\n  [{emoji}]  VERDICT: {verdict}  [{emoji}]\n\n", style=style)
    verdict_text.append(f"  Risk Score: {total}/100\n", style="bold")
    verdict_text.append(f"  Confidence: {confidence}%\n", style="bold")
    verdict_text.append(f"  Total Findings: {score_data['total_findings']}\n", style="dim")

    panel = Panel(verdict_text, title="[Final Assessment]", border_style=style.replace("bold ", ""),
                  box=box.ASCII)
    console.print(panel)
    console.print()

    # Key findings
    if score_data['key_findings']:
        console.print("[bold red]Key Findings (High/Critical):[/bold red]")
        for i, f in enumerate(score_data['key_findings'], 1):
            icon = SEVERITY_ICONS.get(f.severity, "?")
            console.print(f"  {i}. {icon} [{f.severity}] {f.check}: {f.description}")
            if f.details:
                console.print(f"     |- {f.details[:120]}{'...' if len(f.details) > 120 else ''}", style="dim")
        console.print()


def print_recommendations(score_data: dict):
    """Print actionable recommendations based on verdict."""
    total = score_data['total_score']
    console.print("[bold]Recommendations:[/bold]")

    if total > config.VERDICT_LIKELY_PHISHING_MAX:
        recs = [
            "[-] DO NOT click any links or open attachments",
            "[-] Create a security incident ticket immediately",
            "[-] Quarantine or delete the email",
            "[-] Alert the impersonated sender's organization",
            "[-] Check if other users received similar emails",
            "[-] Add sender IP/domain to blocklist",
            "[-] Extract IOCs and update threat intelligence feeds",
        ]
    elif total > config.VERDICT_SUSPICIOUS_MAX:
        recs = [
            "[-] Exercise extreme caution with this email",
            "[-] Manually verify sender identity through a separate channel",
            "[-] Do NOT click links or open attachments until verified",
            "[-] Document and escalate to Tier 2 if needed",
            "[-] Check email gateway logs for similar patterns",
        ]
    elif total > config.VERDICT_LEGITIMATE_MAX:
        recs = [
            "[-] Review the flagged items before proceeding",
            "[-] Likely safe but verify sender if unexpected",
            "[-] No immediate action required",
        ]
    else:
        recs = [
            "[-] Email appears legitimate",
            "[-] No significant threats detected",
            "[-] Safe to proceed with normal handling",
        ]

    for r in recs:
        console.print(f"  {r}")
    console.print()


def extract_iocs(email_obj, all_findings: list[Finding]) -> dict:
    """Extract Indicators of Compromise from the analysis."""
    iocs = {'ips': set(), 'domains': set(), 'urls': set(), 'hashes': set(), 'emails': set()}

    # From findings
    for f in all_findings:
        text = f"{f.description} {f.details}"
        # IPs
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
            iocs['ips'].add(ip)
        # Domains
        for domain in re.findall(r'[\w.-]+\.\w{2,}', text):
            if not re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                iocs['domains'].add(domain)
        # URLs
        for url in re.findall(r'https?://\S+', text):
            iocs['urls'].add(url.rstrip('.,;:)'))
        # Hashes (SHA256)
        for h in re.findall(r'\b[a-f0-9]{64}\b', text):
            iocs['hashes'].add(h)

    # From headers
    from_addr = re.search(r'[\w.\-+]+@[\w.\-]+', email_obj.get('From', ''))
    if from_addr:
        iocs['emails'].add(from_addr.group())
    rp_addr = re.search(r'[\w.\-+]+@[\w.\-]+', email_obj.get('Return-Path', ''))
    if rp_addr:
        iocs['emails'].add(rp_addr.group())

    return {k: sorted(v) for k, v in iocs.items()}


def save_report(email_obj, score_data: dict, all_findings: list[Finding],
                category_findings: dict, iocs: dict) -> str:
    """Save a detailed report to file."""
    os.makedirs(config.REPORT_OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(config.REPORT_OUTPUT_DIR, f"email_analysis_{timestamp}.txt")

    lines = []
    lines.append("=" * 70)
    lines.append("SOC MAIL SPOOF & PHISHING ANALYSIS REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append("")

    # Email summary
    lines.append("--- EMAIL SUMMARY ---")
    for h in ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Return-Path', 'Reply-To']:
        lines.append(f"  {h}: {email_obj.get(h, 'N/A')}")
    lines.append("")

    # Verdict
    lines.append("--- VERDICT ---")
    lines.append(f"  {score_data['verdict_emoji']} {score_data['verdict']}")
    lines.append(f"  Risk Score: {score_data['total_score']}/100")
    lines.append(f"  Confidence: {score_data['confidence']}%")
    lines.append("")

    # Category scores
    lines.append("--- CATEGORY SCORES ---")
    for cat, data in score_data['category_scores'].items():
        lines.append(f"  {cat}: {data['score']}/{data['max']}")
    lines.append("")

    # All findings by category
    for cat_name, findings in category_findings.items():
        lines.append(f"--- {cat_name.upper()} ---")
        for f in findings:
            lines.append(f"  [{f.severity}] {f.check}: {f.description}")
            if f.details:
                lines.append(f"    Detail: {f.details}")
        lines.append("")

    # IOCs
    lines.append("--- INDICATORS OF COMPROMISE (IOCs) ---")
    for ioc_type, values in iocs.items():
        if values:
            lines.append(f"  {ioc_type.upper()}:")
            for v in values:
                lines.append(f"    - {v}")
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    # Also save JSON version
    json_filename = filename.replace('.txt', '.json')
    json_data = {
        'timestamp': datetime.now().isoformat(),
        'email': {
            'from': email_obj.get('From', ''),
            'to': email_obj.get('To', ''),
            'subject': email_obj.get('Subject', ''),
            'date': email_obj.get('Date', ''),
            'message_id': email_obj.get('Message-ID', ''),
        },
        'verdict': score_data['verdict'],
        'risk_score': score_data['total_score'],
        'confidence': score_data['confidence'],
        'category_scores': score_data['category_scores'],
        'findings': [
            {'severity': f.severity, 'check': f.check, 'description': f.description, 'details': f.details}
            for f in all_findings
        ],
        'iocs': iocs,
    }
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, default=str)

    return filename
