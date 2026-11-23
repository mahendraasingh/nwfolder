"""
app.py - Main Flask Web Application for Reconnaissance Information Organizer

A beginner-friendly Cyber Security Reconnaissance web application.
Provides domain reconnaissance (IP, DNS, WHOIS), SQLite history storage,
and an interactive cybersecurity-themed UI.
"""

import warnings
warnings.filterwarnings("ignore")

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import database
import recon_engine

app = Flask(__name__)
app.secret_key = 'recon-organizer-secret-key-college-demo'

# Initialize SQLite database schema
database.init_db()


@app.route('/')
def index():
    """
    Homepage: Displays the domain search form, project statistics,
    and a preview of the most recent reconnaissance scans.
    """
    stats = database.get_dashboard_stats()
    recent_scans = database.get_recent_scans(limit=5)
    return render_template('index.html', stats=stats, recent_scans=recent_scans)


