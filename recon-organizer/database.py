"""
database.py - SQLite Database Management for Reconnaissance Information Organizer

This module manages all database operations using Python's built-in sqlite3 library.
It stores reconnaissance results (IP, DNS, and WHOIS information) as JSON strings,
allowing college students to easily query, review, and persist scan histories.
"""

import sqlite3
import json
import os
from datetime import datetime

# Path to the SQLite database file in the project directory
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'recon_data.db')


def get_db_connection():
    """Establishes and returns a connection to the SQLite database with row factory enabled."""
    conn = sqlite3.connect(DB_FILE)
    # Allows accessing columns by name like dictionary keys: row['domain']
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the necessary tables if they do not already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            primary_ip TEXT,
            status TEXT DEFAULT 'Success',
            ip_data TEXT NOT NULL,
            dns_data TEXT NOT NULL,
            whois_data TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()


def save_scan(domain, ip_data, dns_data, whois_data, status='Success', primary_ip=None):
    """
    Saves a completed reconnaissance scan into the SQLite database.
    Serializes the dictionary data into JSON strings for clean storage.
    Returns the newly created scan ID.
    """
    if primary_ip is None and isinstance(ip_data, dict):
        primary_ip = ip_data.get('primary_ip', 'N/A')

    # Format timestamp nicely (e.g. 2026-11-02 23:15:00)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO scans (domain, scan_date, primary_ip, status, ip_data, dns_data, whois_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        domain,
        current_time,
        str(primary_ip),
        status,
        json.dumps(ip_data),
        json.dumps(dns_data),
        json.dumps(whois_data)
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans():
    """Retrieves all scans ordered by most recent first."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, domain, scan_date, primary_ip, status
        FROM scans
        ORDER BY id DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    # Convert to list of standard dictionaries
    return [dict(row) for row in rows]


def get_recent_scans(limit=5):
    """Retrieves the most recent scans up to the given limit."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, domain, scan_date, primary_ip, status
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    """
    Retrieves full details for a single scan by its primary key ID.
    Parses stored JSON strings back into Python dictionaries for template rendering.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    scan_dict = dict(row)

    # Safely deserialize the stored JSON structures
    try:
        scan_dict['ip_data'] = json.loads(scan_dict.get('ip_data', '{}'))
    except Exception:
        scan_dict['ip_data'] = {}

    try:
        scan_dict['dns_data'] = json.loads(scan_dict.get('dns_data', '{}'))
    except Exception:
        scan_dict['dns_data'] = {}

    try:
        scan_dict['whois_data'] = json.loads(scan_dict.get('whois_data', '{}'))
    except Exception:
        scan_dict['whois_data'] = {}

    return scan_dict


def delete_scan(scan_id):
    """Deletes a specific scan record by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def get_dashboard_stats():
    """Calculates overall statistics for the dashboard/homepage."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM scans')
    total_scans = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(DISTINCT domain) FROM scans')
    unique_domains = cursor.fetchone()[0]

    cursor.execute('SELECT scan_date FROM scans ORDER BY id DESC LIMIT 1')
    last_row = cursor.fetchone()
    last_scan = last_row[0] if last_row else 'None'

    conn.close()

    return {
        'total_scans': total_scans,
        'unique_domains': unique_domains,
        'last_scan': last_scan
    }


# Auto-initialize database on import if it doesn't exist
if not os.path.exists(DB_FILE):
    init_db()
