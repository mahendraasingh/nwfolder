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


