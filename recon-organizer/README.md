# Reconnaissance Information Organizer

> **Academic Cyber Security Project** &bull; Passive Intelligence & OSINT Reconnaissance Suite  
> Built with **Python 3**, **Flask**, **SQLite**, **HTML5**, **CSS3**, and **JavaScript**.

---

## 📌 Project Overview

In cybersecurity and ethical hacking, **Reconnaissance (Information Gathering)** is the foundational first phase of any security assessment. It involves collecting publicly available information about a target domain to map its infrastructure, identify hosting providers, discover mail exchangers, and evaluate registration timelines.

The **Reconnaissance Information Organizer** is a simple, professional, and beginner-friendly web application designed for students and educators. It automates passive domain reconnaissance by querying DNS, IP, and WHOIS registries, organizing the intelligence into readable cyber-themed dashboards and persisting the audit trail in a local SQLite database.

---

## 🚀 Key Features

1. **Homepage & Interactive Domain Search**
   - Clean cybersecurity terminal theme with glowing blue (`#38bdf8`) and neon green (`#00ff9d`) highlights.
   - Live terminal animation simulating real-time discovery steps (`[*] Resolving IP...`, `[*] Interrogating DNS...`, `[*] Querying WHOIS...`).
   - Quick target suggestion chips for fast testing.

2. **IP Address & Network Lookup**
   - Resolves target domains to primary and multi-homed IPv4 addresses.
   - Reverse DNS resolution (PTR records) via `in-addr.arpa`.
   - Discovers canonical hostnames, Autonomous System Numbers (ASN), and ISP / Geolocation routing metadata.

3. **DNS Records Lookup**
   - Authoritative zone queries for standard DNS record types:
     - `A` (IPv4 address mapping)
     - `AAAA` (IPv6 address mapping)
     - `MX` (Mail Exchange servers with priority values)
     - `NS` (Delegated authoritative nameservers)
     - `TXT` (SPF, DKIM, and DMARC verification records)
     - `CNAME` (Canonical alias records)
     - `SOA` (Start of Authority records)
   - Reports record Time-To-Live (TTL) values with one-click copy buttons.

4. **WHOIS Domain Intelligence**
   - Queries global domain registries for:
     - Sponsoring Registrar and WHOIS server
     - Creation date, expiration date, and last updated date
     - Delegated name servers
     - Domain status codes (e.g. `clientTransferProhibited`)
     - Registrant country, organization, and public abuse contact emails.

5. **Organized Results Dashboard**
   - Displays all gathered information organized in structured tabular views.
   - Status classifications and quick metrics cards.
   - Includes one-click **Export to JSON** for lab reports and API integration.

6. **SQLite Persistent Database & Audit Trail**
   - Saves all scan records locally in `recon_data.db`.
   - Real-time client-side search filter by domain or IP address.
   - Detailed dossier inspection, record deletion, and quick stats (Total Scans, Unique Targets).

7. **Modular Quick Lookup Tools**
   - Dedicated tabbed utility page (`/quick-lookup`) to test individual reconnaissance capabilities (IP only, DNS only, or WHOIS only) without saving to the database.

---

## 📁 Project Structure

```text
recon-organizer/
├── app.py                  # Flask web application & API routing
├── database.py             # SQLite helper functions & schema setup
├── recon_engine.py         # Modular recon functions (IP, DNS, WHOIS)
├── recon_data.db           # SQLite database (auto-generated)
├── requirements.txt        # Python library dependencies
├── test_app.py             # Automated test suite (6 unit & route tests)
├── README.md               # Project documentation & setup instructions
├── static/
│   ├── css/
│   │   └── style.css       # Dark cybersecurity theme (CSS variables, glow effects)
│   └── js/
│       └── main.js         # Asynchronous search, terminal logs, copy-to-clipboard
└── templates/
    ├── base.html           # Master layout with cyber navigation & footer
    ├── index.html          # Homepage with domain input & stats
    ├── results.html        # Comprehensive tabular results dashboard
    ├── history.html        # SQLite database history & filterable audit log
    └── quick_lookup.html   # Standalone tools for single-module testing
```

---

## 🛠️ Prerequisites & Installation

### Step 1: Open a Terminal & Navigate to the Project

```bash
cd recon-organizer
```

### Step 2: Create a Virtual Environment

```bash
python3 -m venv venv
```

Activate the virtual environment:
- **macOS / Linux:**
  ```bash
  source venv/bin/activate
  ```
- **Windows (Command Prompt / PowerShell):**
  ```cmd
  venv\Scripts\activate
  ```

### Step 3: Install Required Dependencies

```bash
pip install -r requirements.txt
```

The application relies on:
- **`Flask`**: Lightweight Python web framework.
- **`dnspython`**: Python DNS toolkit for resolving standard DNS records (A, MX, NS, TXT, etc.).
- **`python-whois`**: WHOIS query client to parse domain registration timelines.
- **`requests`**: Safe, non-intrusive HTTP requests for network geolocation.

---

## ⚡ How to Run the Application

With the virtual environment activated, run:

```bash
python3 app.py
```

Open your browser and navigate to:
👉 **http://127.0.0.1:5000**

---

## 📊 Database Schema

The application uses a single clean SQLite table named `scans` in `recon_data.db`:

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY AUTOINCREMENT` | Unique identifier for each reconnaissance run |
| `domain` | `TEXT NOT NULL` | Sanitized target domain (e.g. `example.com`) |
| `scan_date` | `TEXT NOT NULL` | Timestamp of query execution (`YYYY-MM-DD HH:MM:SS`) |
| `primary_ip` | `TEXT` | Primary IPv4 address resolved |
| `status` | `TEXT` | Overall scan health (`Success`, `Partial`, or `Failed`) |
| `ip_data` | `TEXT NOT NULL` | JSON-serialized dictionary of IP & routing details |
| `dns_data` | `TEXT NOT NULL` | JSON-serialized dictionary of DNS records |
| `whois_data` | `TEXT NOT NULL` | JSON-serialized dictionary of WHOIS registry data |
