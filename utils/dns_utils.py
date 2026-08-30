"""
SOC Mail Analysis Tool — DNS Utilities
=======================================
Helper functions for DNS queries: MX, TXT (SPF/DMARC), A, AAAA, PTR records.
"""
import dns.resolver
import dns.reversename
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def query_dns(domain: str, record_type: str, timeout: float = 5.0) -> list[str]:
    """
    Query DNS for a given domain and record type.
    Returns a list of record strings, or empty list on failure.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        logger.debug(f"No {record_type} records for {domain}")
        return []
    except dns.resolver.NXDOMAIN:
        logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
        return []
    except dns.resolver.NoNameservers:
        logger.debug(f"No nameservers available for {domain}")
        return []
    except dns.exception.Timeout:
        logger.debug(f"DNS timeout querying {record_type} for {domain}")
        return []
    except Exception as e:
        logger.debug(f"DNS query error for {domain}/{record_type}: {e}")
        return []


def get_mx_records(domain: str) -> list[str]:
    """Get MX records for a domain."""
    return query_dns(domain, 'MX')


def get_a_records(domain: str) -> list[str]:
    """Get A records for a domain."""
    return query_dns(domain, 'A')


def get_aaaa_records(domain: str) -> list[str]:
    """Get AAAA records for a domain."""
    return query_dns(domain, 'AAAA')


def get_txt_records(domain: str) -> list[str]:
    """Get TXT records for a domain."""
    return query_dns(domain, 'TXT')


def get_spf_record(domain: str) -> Optional[str]:
    """Extract the SPF TXT record for a domain, if present."""
    txt_records = get_txt_records(domain)
    for record in txt_records:
        # Remove surrounding quotes
        clean = record.strip('"').strip("'")
        if clean.startswith('v=spf1'):
            return clean
    return None


def get_dmarc_record(domain: str) -> Optional[str]:
    """Query _dmarc.<domain> for the DMARC policy record."""
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = get_txt_records(dmarc_domain)
    for record in txt_records:
        clean = record.strip('"').strip("'")
        if clean.startswith('v=DMARC1'):
            return clean
    return None


def get_ptr_record(ip_address: str) -> Optional[str]:
    """Perform a reverse DNS lookup for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        return str(answers[0]).rstrip('.')
    except Exception as e:
        logger.debug(f"PTR lookup failed for {ip_address}: {e}")
        return None


def check_ip_in_dnsbl(ip_address: str, blocklist: str) -> bool:
    """
    Check if an IP is listed in a DNS blocklist.
    Returns True if listed (bad), False if not.
    """
    try:
        # Reverse the IP octets and append the blocklist domain
        reversed_ip = '.'.join(reversed(ip_address.split('.')))
        query_name = f"{reversed_ip}.{blocklist}"
        dns.resolver.resolve(query_name, 'A')
        return True  # Listed in blocklist
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False  # Not listed
    except Exception:
        return False  # Assume not listed on error


def domain_exists(domain: str) -> bool:
    """Check if a domain has any DNS records (A or MX)."""
    return bool(get_a_records(domain) or get_mx_records(domain))
