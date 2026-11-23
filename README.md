# Cybersecurity Web Applications & Tools Suite

Welcome to the **nwfolder** repository. This repository contains web applications and cybersecurity utilities designed for security assessment, authentication demonstration, and passive reconnaissance.

---

## 📁 Repository Modules

### 1. 🔐 JWT Authentication & RBAC Portal (/)
A responsive web interface demonstrating JSON Web Token (JWT) based authentication and Role-Based Access Control (RBAC).
- **Core Files:** index.html, dashboard.html, dmin.html, js/auth.js, js/rbac.js, css/style.css
- **Features:**
  - Token generation and verification
  - Role-based UI gating (Admin, Editor, Viewer)
  - Protected views and session management

### 2. 🛡️ Reconnaissance Information Organizer (/recon-organizer)
An academic and practical OSINT suite built with Python, Flask, and SQLite for passive network and domain intelligence gathering.
- **Core Files:** pp.py, database.py, econ_engine.py, 	emplates/, static/
- **Features:**
  - **IP & Network Resolution:** IPv4 resolution, canonical hostname, reverse DNS (PTR), ISP and geolocation mapping
  - **DNS Zone Interrogation:** Lookups for A, AAAA, MX, NS, TXT, CNAME, and SOA records
  - **WHOIS Intelligence:** Registration dates, registrar information, domain status codes, abuse contact emails
  - **Persistent Audit Trail:** Local SQLite storage with historical query search, inspect, and JSON export

---

## 🚀 Quick Start

### Running JWT Auth Portal
Open index.html in any modern web browser or serve locally using any HTTP server:
`ash
python -m http.server 8000
`

### Running Reconnaissance Information Organizer
`ash
cd recon-organizer
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python app.py
`
Access the application at http://127.0.0.1:5000.

---

## 📄 License
Academic & Educational Use.