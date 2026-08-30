"""
SOC Mail Spoof & Phishing Analysis Tool
=========================================
Comprehensive email forensic analysis for Security Operations Center analysts.

Usage:
    python main.py <email_file.eml>
    python main.py                     (interactive mode)

Features:
    - Domain Intelligence (WHOIS age, ASCII/IDN/homoglyph detection, DNS records)
    - Sender Reputation (AbuseIPDB, DNS blocklists, reverse DNS, VirusTotal IP)
    - Header Forensics (hop tracing, timestamps, sender cross-comparison, injection)
    - Authentication Analysis (SPF, DKIM, DMARC, ARC with alignment checks)
    - Body/Content Analysis (URL detonation, attachment scanning, phishing heuristics)
    - Weighted Risk Scoring with final verdict
    - IOC extraction and detailed report generation
"""
import re
import sys
import os
import logging
from email.parser import BytesParser
from email.policy import default

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from analyzer.domain_intel import run_domain_intelligence
from analyzer.sender_reputation import run_sender_reputation
from analyzer.header_forensics import run_header_forensics
from analyzer.auth_analysis import run_auth_analysis
from analyzer.body_analysis import run_body_analysis
from analyzer.scoring_engine import calculate_risk_score
from analyzer.report_generator import (
    console, print_banner, print_email_summary,
    print_section, print_score_card, print_recommendations,
    extract_iocs, save_report,
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT,
)
logger = logging.getLogger(__name__)


def extract_sender_domain(email_obj) -> tuple[str, str]:
    """Extract sender domain and display name from the From header."""
    from_header = email_obj.get('From', '')
    # Extract email address
    email_match = re.search(r'[\w.\-+]+@([\w.\-]+\.\w+)', from_header)
    domain = email_match.group(1) if email_match else ''

    # Extract display name
    display_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    display_name = display_match.group(1).strip() if display_match else ''

    return domain, display_name


def analyze_email(email_path: str):
    """Run the full analysis pipeline on an email file."""
    print_banner()

    # Parse the email
    console.print(f"[bold]Loading email:[/bold] {email_path}")
    console.print()

    try:
        with open(email_path, 'rb') as f:
            email_obj = BytesParser(policy=default).parse(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error: File not found: {email_path}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error parsing email: {e}[/bold red]")
        sys.exit(1)

    # Print email summary
    print_email_summary(email_obj)

    # Extract sender info
    sender_domain, display_name = extract_sender_domain(email_obj)
    if not sender_domain:
        console.print("[bold red]Could not extract sender domain from From header[/bold red]")
        sys.exit(1)

    console.print(f"[bold]Analyzing sender domain:[/bold] {sender_domain}")
    if display_name:
        console.print(f"[bold]Display name:[/bold] {display_name}")
    console.print()

    # ===============================================================
    # PHASE 1: Domain Intelligence
    # ===============================================================
    console.print("[bold magenta]=== PHASE 1: Domain Intelligence ===[/bold magenta]")
    domain_findings = run_domain_intelligence(sender_domain)
    print_section("Domain Intelligence", domain_findings)

    # ===============================================================
    # PHASE 2: Sender Reputation
    # ===============================================================
    console.print("[bold magenta]=== PHASE 2: Sender Reputation ===[/bold magenta]")
    reputation_findings = run_sender_reputation(email_obj, sender_domain, display_name)
    print_section("Sender Reputation", reputation_findings)

    # ===============================================================
    # PHASE 3: Header Forensics
    # ===============================================================
    console.print("[bold magenta]=== PHASE 3: Header Forensics ===[/bold magenta]")
    header_findings = run_header_forensics(email_obj)
    print_section("Header Forensics", header_findings)

    # ===============================================================
    # PHASE 4: Authentication Analysis
    # ===============================================================
    console.print("[bold magenta]=== PHASE 4: Authentication Analysis ===[/bold magenta]")
    auth_findings = run_auth_analysis(email_obj, sender_domain)
    print_section("Authentication (SPF/DKIM/DMARC/ARC)", auth_findings)

    # ===============================================================
    # PHASE 5: Body & Content Analysis
    # ===============================================================
    console.print("[bold magenta]=== PHASE 5: Body & Content Analysis ===[/bold magenta]")
    body_findings = run_body_analysis(email_obj)
    print_section("Body & Content Analysis", body_findings)

    # ===============================================================
    # FINAL: Risk Scoring & Verdict
    # ===============================================================
    console.print("[bold magenta]=== FINAL ASSESSMENT ===[/bold magenta]")
    score_data = calculate_risk_score(
        auth_findings, domain_findings, header_findings,
        reputation_findings, body_findings,
    )
    print_score_card(score_data)
    print_recommendations(score_data)

    # ===============================================================
    # IOC Extraction & Report
    # ===============================================================
    all_findings = (domain_findings + reputation_findings + header_findings +
                    auth_findings + body_findings)
    iocs = extract_iocs(email_obj, all_findings)

    # Print IOCs
    has_iocs = any(v for v in iocs.values())
    if has_iocs:
        console.print("[bold]Extracted IOCs:[/bold]")
        for ioc_type, values in iocs.items():
            if values:
                console.print(f"  [bold]{ioc_type.upper()}:[/bold]")
                for v in values:
                    console.print(f"    - {v}")
        console.print()

    # Save report
    category_findings = {
        'Domain Intelligence': domain_findings,
        'Sender Reputation': reputation_findings,
        'Header Forensics': header_findings,
        'Authentication': auth_findings,
        'Body Analysis': body_findings,
    }
    report_path = save_report(email_obj, score_data, all_findings, category_findings, iocs)
    console.print(f"[bold green]Report saved:[/bold green] {report_path}")
    console.print(f"[bold green]JSON report:[/bold green] {report_path.replace('.txt', '.json')}")
    console.print()

    return score_data


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        email_path = sys.argv[1]
    else:
        print_banner()
        console.print("[bold]SOC Mail Analysis Tool — Interactive Mode[/bold]")
        console.print()
        email_path = input("Enter the path to the email file (.eml / .msg / .txt): ").strip()
        if not email_path:
            console.print("[bold red]No file provided. Exiting.[/bold red]")
            sys.exit(1)

    # Remove quotes if present
    email_path = email_path.strip('"').strip("'")

    if not os.path.exists(email_path):
        console.print(f"[bold red]❌ File not found: {email_path}[/bold red]")
        sys.exit(1)

    analyze_email(email_path)


if __name__ == "__main__":
    main()
