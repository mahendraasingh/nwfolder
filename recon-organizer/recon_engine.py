"""
recon_engine.py - Core Reconnaissance Engine for Reconnaissance Information Organizer

Contains functions to clean user inputs, resolve IP addresses, query DNS records,
and extract WHOIS domain registration details.
Designed to be modular, robust, and beginner-friendly for cybersecurity students.
"""

import socket
import re
import urllib.parse
import warnings
from datetime import datetime

# Suppress minor urllib3 LibreSSL warning on macOS
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

import dns.resolver
import whois
import requests


def clean_domain(raw_input):
    """
    Sanitizes user input to extract a clean domain name.
    Handles URLs with http/https, trailing slashes, port numbers, and subpaths.
    Example: 'https://www.example.com:8080/path' -> 'www.example.com'
    """
    if not raw_input:
        return None

    cleaned = raw_input.strip()
    if not cleaned:
        return None

    # Prepend http:// if missing scheme so urllib can parse reliably
    if not cleaned.startswith(('http://', 'https://')):
        cleaned = 'http://' + cleaned

    parsed = urllib.parse.urlparse(cleaned)
    domain = parsed.netloc or parsed.path

    # Strip port number if user specified (e.g., example.com:8080)
    if ':' in domain:
        domain = domain.split(':')[0]

    # Clean domain from leading/trailing dots or spaces
    domain = domain.strip().strip('.')

    # Basic regex validation for domain names
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, domain):
        # Also allow valid IPv4 addresses
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if not re.match(ipv4_pattern, domain):
            return None

    return domain.lower()


def lookup_ip(domain):
    """
    Performs IP address resolution and basic network location identification.
    Returns:
        dict: Primary IP, list of all resolved IPs, reverse DNS (PTR),
              and basic geolocation/ISP details.
    """
    result = {
        'status': 'success',
        'primary_ip': 'N/A',
        'all_ips': [],
        'canonical_hostname': 'N/A',
        'reverse_dns': 'N/A',
        'geo': {},
        'error': None
    }

    try:
        # Resolve primary IPv4
        primary_ip = socket.gethostbyname(domain)
        result['primary_ip'] = primary_ip

        # Resolve all available IPv4 addresses and canonical host
        try:
            host_info = socket.gethostbyname_ex(domain)
            result['canonical_hostname'] = host_info[0]
            # Deduplicate IP list while preserving order
            all_ips = list(dict.fromkeys(host_info[2]))
            result['all_ips'] = all_ips
        except Exception:
            result['all_ips'] = [primary_ip]

        # Reverse DNS lookup (PTR Record)
        try:
            rev_host = socket.gethostbyaddr(primary_ip)
            result['reverse_dns'] = rev_host[0]
        except Exception:
            result['reverse_dns'] = 'No PTR record found'

        # Optional: Geolocation & ASN lookup via free ip-api.com
        try:
            # Short 2-second timeout to ensure the application stays fast
            geo_response = requests.get(
                f"http://ip-api.com/json/{primary_ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query",
                timeout=2.0
            )
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                if geo_data.get('status') == 'success':
                    result['geo'] = {
                        'country': geo_data.get('country', 'N/A'),
                        'region': geo_data.get('regionName', 'N/A'),
                        'city': geo_data.get('city', 'N/A'),
                        'isp': geo_data.get('isp', 'N/A'),
                        'org': geo_data.get('org', 'N/A'),
                        'asn': geo_data.get('as', 'N/A')
                    }
        except Exception:
            # Fallback gracefully if network/offline
            result['geo'] = {'country': 'Lookup unavailable', 'isp': 'N/A'}

    except socket.gaierror as e:
        result['status'] = 'error'
        result['error'] = f"Could not resolve domain '{domain}': Host not found."
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)

    return result


def lookup_dns(domain):
    """
    Queries common DNS record types for the target domain:
    A, AAAA, MX, NS, TXT, CNAME, SOA.
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    records_list = []
    records_by_type = {rtype: [] for rtype in record_types}

    resolver = dns.resolver.Resolver()
    # Configure reasonable timeouts so queries don't hang
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    success_count = 0
    errors = []

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                val = rdata.to_text()

                # Clean up formatting for display
                if rtype == 'MX':
                    clean_val = f"Priority {rdata.preference} -> {rdata.exchange.to_text()}"
                elif rtype == 'TXT':
                    clean_val = val.strip('"')
                else:
                    clean_val = val

                record_item = {
                    'type': rtype,
                    'name': domain,
                    'ttl': answers.rrset.ttl if hasattr(answers, 'rrset') else 'N/A',
                    'value': clean_val
                }
                records_list.append(record_item)
                records_by_type[rtype].append(clean_val)
                success_count += 1
        except dns.resolver.NoAnswer:
            # Record type doesn't exist for this domain (normal behavior)
            pass
        except dns.resolver.NXDOMAIN:
            errors.append(f"Domain '{domain}' does not exist (NXDOMAIN).")
            break
        except dns.resolver.Timeout:
            errors.append(f"Timeout querying DNS {rtype} records.")
        except Exception as e:
            # Suppress individual record query exceptions
            pass

    return {
        'status': 'success' if success_count > 0 else ('error' if errors else 'no_records'),
        'total_found': success_count,
        'records': records_list,
        'records_by_type': records_by_type,
        'errors': errors
    }


