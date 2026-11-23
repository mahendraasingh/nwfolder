"""
test_app.py - Automated Unit & Integration Tests for Reconnaissance Information Organizer

Tests:
1. Domain sanitization logic
2. IP address lookup
3. DNS records lookup
4. WHOIS lookup
5. SQLite database operations (create, read, list, delete)
6. Flask web routes and API endpoints (GET /, POST /scan, GET /results, GET /history, GET /export)
"""

import unittest
import json
import os
import warnings

# Suppress minor urllib3 warning on macOS
warnings.filterwarnings("ignore")

import database
import recon_engine
from app import app


class TestReconOrganizer(unittest.TestCase):

    def setUp(self):
        """Set up Flask test client and ensure test database connection."""
        self.client = app.test_client()
        app.config['TESTING'] = True
        database.init_db()

    def test_domain_sanitization(self):
        """Verify URL sanitization strips schemes, slashes, ports and paths."""
        self.assertEqual(recon_engine.clean_domain('https://example.com/'), 'example.com')
        self.assertEqual(recon_engine.clean_domain('http://sub.domain.org/path?q=1'), 'sub.domain.org')
        self.assertEqual(recon_engine.clean_domain('  example.com:8080  '), 'example.com')
        self.assertEqual(recon_engine.clean_domain('google.com'), 'google.com')
        # Invalid inputs
        self.assertIsNone(recon_engine.clean_domain('invalid..domain'))
        self.assertIsNone(recon_engine.clean_domain(''))

    def test_database_crud(self):
        """Verify SQLite insertion, retrieval, and deletion."""
        test_domain = 'test-suite-example.com'
        ip_sample = {'primary_ip': '192.0.2.1', 'all_ips': ['192.0.2.1'], 'status': 'success'}
        dns_sample = {'total_found': 2, 'records': [{'type': 'A', 'value': '192.0.2.1'}]}
        whois_sample = {'registrar': 'Test Registrar', 'status': 'success'}

        scan_id = database.save_scan(
            domain=test_domain,
            ip_data=ip_sample,
            dns_data=dns_sample,
            whois_data=whois_sample,
            status='Success',
            primary_ip='192.0.2.1'
        )
        self.assertIsNotNone(scan_id)

        # Retrieve by ID
        record = database.get_scan_by_id(scan_id)
        self.assertIsNotNone(record)
        self.assertEqual(record['domain'], test_domain)
        self.assertEqual(record['primary_ip'], '192.0.2.1')
        self.assertEqual(record['ip_data']['primary_ip'], '192.0.2.1')
        self.assertEqual(record['dns_data']['total_found'], 2)

        # Retrieve all
        all_scans = database.get_all_scans()
        self.assertTrue(any(s['id'] == scan_id for s in all_scans))

        # Delete
        deleted = database.delete_scan(scan_id)
        self.assertTrue(deleted)
        self.assertIsNone(database.get_scan_by_id(scan_id))

    def test_route_index(self):
        """Verify homepage loads with HTTP 200 and cybersecurity branding."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Reconnaissance Information Organizer', response.data)
        self.assertIn(b'Initiate Recon', response.data)

    def test_route_history(self):
        """Verify history page loads with HTTP 200."""
        response = self.client.get('/history')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Reconnaissance Audit Log', response.data)

    def test_route_quick_lookup(self):
        """Verify quick lookup page loads with HTTP 200."""
        response = self.client.get('/quick-lookup')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Modular Reconnaissance Tools', response.data)

    def test_api_scan_and_results(self):
        """Verify full scan flow via API and results view."""
        # Query example.com
        res = self.client.post('/api/scan', json={'domain': 'example.com'})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data.get('success'))
        scan_id = data.get('scan_id')
        self.assertIsNotNone(scan_id)

        # Verify results page for this scan
        res_page = self.client.get(f'/results/{scan_id}')
        self.assertEqual(res_page.status_code, 200)
        self.assertIn(b'example.com', res_page.data)
        self.assertIn(b'IP Address & Network Intelligence', res_page.data)
        self.assertIn(b'DNS Records Lookup', res_page.data)
        self.assertIn(b'WHOIS Registration Intelligence', res_page.data)

        # Verify export JSON route
        export_res = self.client.get(f'/export/{scan_id}')
        self.assertEqual(export_res.status_code, 200)
        export_data = json.loads(export_res.data)
        self.assertEqual(export_data['domain'], 'example.com')


if __name__ == '__main__':
    unittest.main()
