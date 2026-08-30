"""
SOC Mail Analysis Tool — IP Utilities
=======================================
IP validation, geolocation, PTR lookups, and IP reputation helpers.
"""
import re
import socket
import logging
from typing import Optional
from ipaddress import ip_address, IPv4Address, IPv6Address

logger = logging.getLogger(__name__)


def is_valid_ip(ip_str: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ip_address(ip_str)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        return False


def extract_ips_from_text(text: str) -> list[str]:
    """Extract all IPv4 addresses from a text string."""
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = re.findall(ipv4_pattern, text)
    return [ip for ip in candidates if is_valid_ip(ip)]


def extract_first_public_ip(text: str) -> Optional[str]:
    """Extract the first public (non-private) IPv4 address from text."""
    ips = extract_ips_from_text(text)
    for ip in ips:
        if not is_private_ip(ip):
            return ip
    return None


def get_ip_geolocation(ip_str: str) -> dict:
    """
    Get geolocation info for an IP using ip-api.com (free, no key needed).
    Returns dict with country, city, isp, org, etc.
    """
    import requests
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_str}",
            params={'fields': 'status,message,country,countryCode,region,city,isp,org,as,query'},
            timeout=5
        )
        data = response.json()
        if data.get('status') == 'success':
            return {
                'ip': ip_str,
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', '??'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'asn': data.get('as', 'Unknown'),
            }
    except Exception as e:
        logger.debug(f"IP geolocation failed for {ip_str}: {e}")

    return {
        'ip': ip_str,
        'country': 'Unknown',
        'country_code': '??',
        'city': 'Unknown',
        'isp': 'Unknown',
        'org': 'Unknown',
        'asn': 'Unknown',
    }


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve a hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
