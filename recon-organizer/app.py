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


@app.route('/history')
def history():
    """
    History Dashboard: Lists all saved reconnaissance searches from SQLite
    with options to inspect results or delete records.
    """
    all_scans = database.get_all_scans()
    stats = database.get_dashboard_stats()
    return render_template('history.html', scans=all_scans, stats=stats)


@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_record(scan_id):
    """
    Deletes a scan entry from the SQLite database.
    """
    deleted = database.delete_scan(scan_id)
    if deleted:
        flash(f"Scan #{scan_id} deleted successfully.", 'info')
    else:
        flash(f"Failed to delete scan #{scan_id}.", 'danger')

    return redirect(url_for('history'))


@app.route('/export/<int:scan_id>')
def export_scan(scan_id):
    """
    Exports the stored scan data in raw JSON format for reporting or verification.
    """
    scan_data = database.get_scan_by_id(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404

    return jsonify(scan_data)


@app.route('/quick-lookup')
def quick_lookup():
    """
    Quick Lookup feature page: Allows testing individual tools (IP only, DNS only, WHOIS only).
    """
    return render_template('quick_lookup.html')


@app.route('/api/quick-lookup', methods=['POST'])
def api_quick_lookup():
    """
    API endpoint for individual quick lookups (IP, DNS, or WHOIS).
    """
    data = request.get_json() or {}
    lookup_type = data.get('type')
    raw_domain = data.get('domain', '').strip()

    clean = recon_engine.clean_domain(raw_domain)
    if not clean:
        return jsonify({'success': False, 'error': 'Invalid domain format.'}), 400

    if lookup_type == 'ip':
        res = recon_engine.lookup_ip(clean)
        return jsonify({'success': True, 'domain': clean, 'type': 'ip', 'data': res})
    elif lookup_type == 'dns':
        res = recon_engine.lookup_dns(clean)
        return jsonify({'success': True, 'domain': clean, 'type': 'dns', 'data': res})
    elif lookup_type == 'whois':
        res = recon_engine.lookup_whois(clean)
        return jsonify({'success': True, 'domain': clean, 'type': 'whois', 'data': res})
    else:
        return jsonify({'success': False, 'error': 'Invalid lookup type requested.'}), 400


if __name__ == '__main__':
    # Running locally in debug mode on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
