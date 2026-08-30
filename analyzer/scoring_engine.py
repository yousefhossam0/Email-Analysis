"""
SOC Mail Analysis Tool — Scoring Engine
=========================================
Weighted risk scoring with configurable weights per category.
Produces final verdict with confidence percentage.

v2.1: Reduced false positives by introducing trust credits for strong
positive signals (auth passes, known-good relays) and using a two-pass
scoring model: raw penalties are first reduced by trust credits before
normalization.
"""
import logging
from analyzer.domain_intel import Finding
import config

logger = logging.getLogger(__name__)

# Severity to numeric score mapping — penalties for suspicious/bad signals
SEVERITY_SCORES = {
    Finding.SEVERITY_INFO: 0,
    Finding.SEVERITY_LOW: 1,
    Finding.SEVERITY_MEDIUM: 2,   # Reduced from 3 to avoid accumulation of benign gaps
    Finding.SEVERITY_HIGH: 7,
    Finding.SEVERITY_CRITICAL: 12,
}

# ─── Trust Credit Tags ──────────────────────────────────────────────────
# Findings can carry trust_credit attribute to subtract from raw scores.
# These are set by analysis modules when strong positive evidence is found.

TRUST_CREDIT_KEYWORDS = {
    # Finding description substrings that earn trust credit
    'SPF: PASS': 4,
    'DKIM: PASS': 4,
    'DMARC: PASS': 5,
    'ARC: PASS': 2,
    'Timestamps are in logical order': 1,
    'Domains match': 2,                     # From/Return-Path match
    'Domain uses standard ASCII': 1,
    'IP not on any checked blocklists': 1,
    'has no abuse reports': 1,
    'IP clean on VirusTotal': 1,
    'Domain resolves to': 1,
    'Mail servers:': 1,
    'aligns with From domain': 2,           # DKIM alignment
}


def _calculate_trust_credits(findings: list[Finding]) -> float:
    """
    Calculate trust credits from positive signals in findings.
    Returns a positive number to subtract from raw penalty score.
    """
    credits = 0.0
    for f in findings:
        if f.severity != Finding.SEVERITY_INFO:
            continue
        desc = f.description
        for keyword, credit in TRUST_CREDIT_KEYWORDS.items():
            if keyword in desc:
                credits += credit
                break
    return credits


def calculate_category_score(findings: list[Finding], max_points: int) -> tuple[float, list[Finding]]:
    """
    Calculate score for a category based on its findings.
    Returns (score, critical_findings).

    Two-pass model:
      1. Sum raw penalty points from non-INFO findings.
      2. Subtract trust credits from strong positive signals.
      3. Normalize to max_points with diminishing returns.
    """
    if not findings:
        return 0.0, []

    raw_score = 0
    critical = []
    for f in findings:
        s = SEVERITY_SCORES.get(f.severity, 0)
        raw_score += s
        if f.severity in (Finding.SEVERITY_HIGH, Finding.SEVERITY_CRITICAL):
            critical.append(f)

    # Subtract trust credits
    trust = _calculate_trust_credits(findings)
    adjusted = max(0, raw_score - trust)

    if adjusted == 0:
        return 0.0, critical

    # Normalize with a gentler curve (divisor 15 instead of 10)
    # This means you need more penalty evidence to reach the max
    normalized = min(max_points, max_points * (1 - (1 / (1 + adjusted / 15))))
    return round(normalized, 1), critical


def calculate_risk_score(
    auth_findings: list[Finding],
    domain_findings: list[Finding],
    header_findings: list[Finding],
    reputation_findings: list[Finding],
    body_findings: list[Finding],
) -> dict:
    """
    Calculate the overall risk score from all analysis categories.
    Returns dict with scores, verdict, confidence, and key findings.
    """
    auth_score, auth_critical = calculate_category_score(auth_findings, config.WEIGHT_AUTH)
    domain_score, domain_critical = calculate_category_score(domain_findings, config.WEIGHT_DOMAIN)
    header_score, header_critical = calculate_category_score(header_findings, config.WEIGHT_HEADER)
    rep_score, rep_critical = calculate_category_score(reputation_findings, config.WEIGHT_REPUTATION)
    body_score, body_critical = calculate_category_score(body_findings, config.WEIGHT_BODY)

    total_score = auth_score + domain_score + header_score + rep_score + body_score
    total_score = min(round(total_score, 1), 100)

    # ─── Cross-category trust boost ──────────────────────────────────
    # If all three core auth mechanisms pass, apply a global trust reduction.
    all_findings = auth_findings + domain_findings + header_findings + reputation_findings + body_findings
    auth_descriptions = ' '.join(f.description for f in auth_findings)
    core_auth_pass = (
        'SPF: PASS' in auth_descriptions and
        'DKIM: PASS' in auth_descriptions and
        'DMARC: PASS' in auth_descriptions
    )
    if core_auth_pass:
        # Full auth pass is very strong — discount the total by 30%
        total_score = round(total_score * 0.7, 1)
        logger.info(f"Triple auth pass detected — applied 30% score reduction → {total_score}")

    total_score = min(round(total_score, 1), 100)

    # Determine verdict
    if total_score <= config.VERDICT_LEGITIMATE_MAX:
        verdict = "LEGITIMATE"
        verdict_emoji = "✅"
    elif total_score <= config.VERDICT_SUSPICIOUS_MAX:
        verdict = "SUSPICIOUS"
        verdict_emoji = "⚠️"
    elif total_score <= config.VERDICT_LIKELY_PHISHING_MAX:
        verdict = "LIKELY PHISHING"
        verdict_emoji = "🔶"
    else:
        verdict = "CONFIRMED SPOOFED/MALICIOUS"
        verdict_emoji = "🚨"

    # Confidence is based on how many checks ran successfully
    total_checks = len(all_findings)
    info_only = sum(1 for f in all_findings if f.severity == Finding.SEVERITY_INFO)
    actionable = total_checks - info_only
    confidence = min(100, int((total_checks / max(total_checks, 20)) * 100))

    # Key findings (most impactful)
    all_critical = auth_critical + domain_critical + header_critical + rep_critical + body_critical
    all_critical.sort(key=lambda f: SEVERITY_SCORES.get(f.severity, 0), reverse=True)

    return {
        'total_score': total_score,
        'verdict': verdict,
        'verdict_emoji': verdict_emoji,
        'confidence': confidence,
        'category_scores': {
            'Authentication (SPF/DKIM/DMARC)': {'score': auth_score, 'max': config.WEIGHT_AUTH},
            'Domain Intelligence': {'score': domain_score, 'max': config.WEIGHT_DOMAIN},
            'Header Forensics': {'score': header_score, 'max': config.WEIGHT_HEADER},
            'Sender Reputation': {'score': rep_score, 'max': config.WEIGHT_REPUTATION},
            'Body/Content Analysis': {'score': body_score, 'max': config.WEIGHT_BODY},
        },
        'key_findings': all_critical[:10],
        'total_findings': total_checks,
    }
