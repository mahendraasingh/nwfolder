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


