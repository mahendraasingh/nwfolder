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


@app.route('/scan', methods=['POST'])
def scan():
    """
    Form submission handler:
    Accepts domain name from form, conducts reconnaissance,
    saves the results to SQLite, and redirects to the results dashboard.
    """
    target = request.form.get('domain', '').strip()

    if not target:
        flash('Please enter a valid domain name or IP address.', 'danger')
        return redirect(url_for('index'))

    # Run full reconnaissance engine
    result = recon_engine.perform_full_recon(target)

    if not result.get('success'):
        flash(result.get('error', 'Reconnaissance failed.'), 'danger')
        return redirect(url_for('index'))

    # Save to SQLite database
    scan_id = database.save_scan(
        domain=result['domain'],
        ip_data=result['ip_data'],
        dns_data=result['dns_data'],
        whois_data=result['whois_data'],
        status=result['status'],
        primary_ip=result['ip_data'].get('primary_ip', 'N/A')
    )

    flash(f"Reconnaissance completed for {result['domain']}", 'success')
    return redirect(url_for('results', scan_id=scan_id))


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    REST API endpoint for domain reconnaissance.
    Used by frontend JavaScript to show interactive terminal animation
    and progress before redirecting to the organized results view.
    """
    data = request.get_json() or {}
    target = data.get('domain', '').strip()

    if not target:
        return jsonify({'success': False, 'error': 'No domain provided.'}), 400

    result = recon_engine.perform_full_recon(target)

    if not result.get('success'):
        return jsonify({'success': False, 'error': result.get('error')}), 400

    # Save result to SQLite
    scan_id = database.save_scan(
        domain=result['domain'],
        ip_data=result['ip_data'],
        dns_data=result['dns_data'],
        whois_data=result['whois_data'],
        status=result['status'],
        primary_ip=result['ip_data'].get('primary_ip', 'N/A')
    )

    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'domain': result['domain'],
        'redirect_url': url_for('results', scan_id=scan_id)
    })


@app.route('/results/<int:scan_id>')
def results(scan_id):
    """
    Results Dashboard: Displays organized tables for IP Information,
    DNS Records, and WHOIS details for a specific scan.
    """
    scan_data = database.get_scan_by_id(scan_id)
    if not scan_data:
        flash(f"Scan record #{scan_id} was not found.", 'warning')
        return redirect(url_for('index'))

    return render_template('results.html', scan=scan_data)


