"""
SOC Mail Analysis Tool — Text Utilities
=========================================
Unicode/IDN normalization, homoglyph detection, and text analysis helpers.
"""
import re
import unicodedata
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Common Homoglyph Mappings (Cyrillic/Greek → Latin) ─────────────────
# These are characters that look identical or very similar to Latin characters
# but are actually from different Unicode blocks — commonly used in IDN homoglyph attacks.
HOMOGLYPH_MAP = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у (looks like y)
    '\u0445': 'x',  # Cyrillic х
    '\u04bb': 'h',  # Cyrillic һ
    '\u0456': 'i',  # Cyrillic і
    '\u0458': 'j',  # Cyrillic ј
    '\u043A': 'k',  # Cyrillic к
    '\u043B': 'l',  # Cyrillic л (partial)
    '\u043C': 'm',  # Cyrillic м (partial)
    '\u043D': 'h',  # Cyrillic н (looks like h)
    '\u0442': 't',  # Cyrillic т (partial)
    '\u0437': '3',  # Cyrillic з (looks like 3)
    '\u0432': 'b',  # Cyrillic в (partial)
    '\u03B1': 'a',  # Greek α
    '\u03B5': 'e',  # Greek ε (partial)
    '\u03BF': 'o',  # Greek ο
    '\u03C1': 'p',  # Greek ρ
    '\u03B9': 'i',  # Greek ι
    '\u03BA': 'k',  # Greek κ
    '\u03BD': 'v',  # Greek ν
    '\u03C4': 't',  # Greek τ (partial)
    '\u0261': 'g',  # Latin small letter script g
    '\u01C3': '!',  # Latin letter retroflex click
    '\u2024': '.',  # One dot leader
    '\uFF0E': '.',  # Fullwidth full stop
    '\u2027': '·',  # Hyphenation point
}


def is_ascii_domain(domain: str) -> bool:
    """Check if a domain contains only ASCII characters."""
    try:
        domain.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False


def is_punycode_domain(domain: str) -> bool:
    """Check if a domain uses punycode encoding (xn-- prefix)."""
    return any(label.startswith('xn--') for label in domain.split('.'))


def decode_punycode(domain: str) -> str:
    """Decode a punycode domain to its Unicode representation."""
    try:
        return domain.encode('ascii').decode('idna')
    except (UnicodeError, UnicodeDecodeError):
        # Try label-by-label
        labels = []
        for label in domain.split('.'):
            try:
                if label.startswith('xn--'):
                    labels.append(label.encode('ascii').decode('idna'))
                else:
                    labels.append(label)
            except (UnicodeError, UnicodeDecodeError):
                labels.append(label)
        return '.'.join(labels)


def detect_homoglyphs(text: str) -> list[dict]:
    """
    Detect homoglyph characters in text.
    Returns list of dicts with position, character, and what it mimics.
    """
    findings = []
    for i, char in enumerate(text):
        if char in HOMOGLYPH_MAP:
            findings.append({
                'position': i,
                'character': char,
                'unicode_name': unicodedata.name(char, 'UNKNOWN'),
                'mimics': HOMOGLYPH_MAP[char],
                'codepoint': f'U+{ord(char):04X}',
            })
    return findings


def detect_mixed_scripts(text: str) -> dict:
    """
    Detect if text uses characters from multiple Unicode scripts.
    This is a strong indicator of homoglyph attacks.
    """
    scripts = set()
    script_chars = {}

    for char in text:
        if char in '.@-_':
            continue
        try:
            # Get the script of the character using its Unicode category and name
            name = unicodedata.name(char, '')
            if 'CYRILLIC' in name:
                script = 'Cyrillic'
            elif 'GREEK' in name:
                script = 'Greek'
            elif 'LATIN' in name or char.isascii():
                script = 'Latin'
            elif 'ARABIC' in name:
                script = 'Arabic'
            elif 'CJK' in name:
                script = 'CJK'
            else:
                script = 'Other'

            scripts.add(script)
            if script not in script_chars:
                script_chars[script] = []
            script_chars[script].append(char)
        except Exception:
            pass

    return {
        'is_mixed': len(scripts) > 1,
        'scripts_found': list(scripts),
        'script_chars': {k: ''.join(set(v)) for k, v in script_chars.items()},
    }


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain by:
    1. Converting to lowercase
    2. Decoding punycode
    3. Replacing homoglyphs with their Latin equivalents
    """
    domain = domain.lower().strip()

    # Decode punycode if present
    if is_punycode_domain(domain):
        domain = decode_punycode(domain)

    # Replace known homoglyphs
    normalized = []
    for char in domain:
        normalized.append(HOMOGLYPH_MAP.get(char, char))
    return ''.join(normalized)


def detect_domain_tricks(domain: str) -> list[str]:
    """
    Detect various domain spoofing tricks:
    - Homoglyph substitution
    - Punycode abuse
    - Mixed scripts
    - Unusual TLDs
    - Subdomain abuse (e.g., google.com.evil.com)
    """
    tricks = []

    # Check for punycode
    if is_punycode_domain(domain):
        decoded = decode_punycode(domain)
        tricks.append(f"Punycode domain detected: {domain} decodes to {decoded}")

    # Check for non-ASCII (homoglyph)
    if not is_ascii_domain(domain):
        tricks.append(f"Non-ASCII characters in domain: {domain}")
        homoglyphs = detect_homoglyphs(domain)
        if homoglyphs:
            for h in homoglyphs:
                tricks.append(
                    f"  Homoglyph: '{h['character']}' ({h['codepoint']} {h['unicode_name']}) "
                    f"mimics '{h['mimics']}'"
                )

    # Check for mixed scripts
    mixed = detect_mixed_scripts(domain)
    if mixed['is_mixed']:
        tricks.append(
            f"Mixed Unicode scripts detected: {', '.join(mixed['scripts_found'])}"
        )

    # Check for brand impersonation via subdomain
    well_known_brands = [
        'google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal',
        'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'chase',
        'wellsfargo', 'bankofamerica', 'citibank', 'adobe', 'docusign',
    ]
    domain_parts = domain.split('.')
    if len(domain_parts) > 2:
        for brand in well_known_brands:
            # Check if a brand appears in subdomain but not as the actual domain
            subdomains = '.'.join(domain_parts[:-2])
            actual_domain = domain_parts[-2]
            if brand in subdomains.lower() and brand not in actual_domain.lower():
                tricks.append(
                    f"Brand impersonation: '{brand}' in subdomain but domain is '{actual_domain}'"
                )

    return tricks


def count_phishing_keywords(text: str, keywords: list[str]) -> list[str]:
    """
    Count occurrences of phishing keywords in text.
    Returns list of found keywords.
    """
    text_lower = text.lower()
    found = []
    for keyword in keywords:
        if keyword.lower() in text_lower:
            found.append(keyword)
    return found
