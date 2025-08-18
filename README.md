Web Recon Visualizer

A small web app that, given a domain, performs:
- WHOIS lookup
- Subdomain enumeration (prefers Amass or Sublist3r if installed; falls back to crt.sh)
- DNS resolution to map subdomains to IPs
- Reverse IP lookup to find co-hosted domains on the same IPs (best-effort, public API)
- Interactive graph visualization (domain → subdomains → IPs → co-hosted domains)

Stack
- Backend: Python 3.10+, FastAPI, uvicorn
- Frontend: HTML/JS with Cytoscape.js

Subdomain enumeration
- Preferred: Amass (recommended) or Sublist3r available on PATH.
  - Amass example install (Linux/macOS): see https://github.com/owasp-amass/amass#installation
  - Sublist3r example install: `pip install sublist3r` (also provides `sublist3r` CLI)
- Fallback: crt.sh passive enumeration if neither tool is available.

Amass/Sublist3r installation
- Sublist3r (Python package & CLI):
  - pip install sublist3r
  - CLI will be available as `sublist3r`
- Amass (recommended breadth):
  - macOS: brew install amass (or use setup.sh)
  - Linux: use setup.sh to download the release from https://github.com/owasp-amass/amass/releases and place `amass` on PATH
  - Debian/Ubuntu repo packages may be outdated; prefer the official releases over apt


Reverse IP lookup
- Uses Hackertarget public API by default (rate-limited, best-effort).
- You can optionally plug your own provider in `app/services/reverse_ip.py`.

Quick start
1) Create and activate a virtual environment
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\\Scripts\\activate

2) Install dependencies
   pip install -r requirements.txt

3) (Optional) Install Amass or Sublist3r so the app can use them for better coverage (or just run bash setup.sh)
   # Amass (one option)
   brew install amass             # macOS (Homebrew)
   sudo apt-get install amass     # Debian/Ubuntu (may be outdated)
   # Or download from releases: https://github.com/owasp-amass/amass/releases

   # Sublist3r
   pip install sublist3r

4) Run the app
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

5) Open the UI
   http://localhost:8000

Docker
- Build: docker build -t web-recon .
- Run:   docker run --rm -p 8000:8000 web-recon
  Then visit http://localhost:8000
- Includes Amass installed from the official release by default.

Setup script (recommended)
- Run: bash setup.sh
  - Installs system tools (where possible), creates venv, installs Python deps, and installs Amass from official releases when apt/brew is unavailable or outdated.
  - If Amass can’t be installed system-wide, it is placed under ./bin; add it to PATH when running the app.

Settings
- Click Settings in the toolbar to choose:
  - Mode: Passive or Aggressive (affects Amass)
  - Providers: Amass, Sublist3r, crt.sh (Subfinder supported if installed; toggle coming soon)
  - Timeouts per provider
  - Nmap: enable probing, top ports, timing (T3/T4/T5), -Pn, UDP, timeout/host, concurrency

Health check
- GET /api/status returns JSON with status and whether amass/sublist3r are available on PATH.

Notes
- WHOIS may rely on system `whois` availability for some TLDs. If results are sparse, install a system whois client.
- Reverse IP via public endpoints can be slow and rate-limited; consider using a commercial API in production.
- This tool is for legitimate security/reconnaissance on domains you own or are authorized to assess. Respect ToS and laws.

Project structure
- app/
  - main.py (FastAPI app and static file serving)
  - models/schema.py (Pydantic schemas)
  - services/
    - whois_lookup.py
    - subdomain_enum.py
    - dns_utils.py
    - reverse_ip.py
- frontend/
  - index.html
  - app.js
  - style.css
- requirements.txt
- README.md
