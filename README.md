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

Environment and providers
- Create a .env file (or set env vars) to enable additional providers:
  - SECURITYTRAILS_API_KEY=<your_key>
  - SHODAN_API_KEY=<your_key>
  - CENSYS_API_ID=<your_id>
  - CENSYS_API_SECRET=<your_secret>

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
- Build (auto-arch):
  - docker buildx build --platform linux/amd64,linux/arm64 -t web-recon .
  - Or single-arch: docker build -t web-recon .
- Run:
  - docker run --rm -p 8000:8000 web-recon
  - Then visit http://localhost:8000

Docker Compose (with Tor proxy) — Recommended
- docker compose up --build -d
- Services on a shared network:
  - tor: Tor SOCKS5 proxy, available at hostname tor:9050 to other containers (not exposed to host by default).
  - web: the app, configured to prefer socks5://tor:9050 automatically.
- Check status:
  - docker compose ps
  - docker compose logs -f tor  # wait for "Bootstrapped 100%"
  - docker compose logs -f web  # wait for "Uvicorn running on 0.0.0.0:8000"
- Open UI:
  - http://localhost:8000  (or http://<server-ip>:8000)

Tor routing in app
- The app detects a SOCKS proxy in this order:
  1) TOR_SOCKS_URL env
  2) socks5://tor:9050 (compose service)
  3) socks5://127.0.0.1:9050 (local)
- In Settings > Nmap & Tor:
  - Toggle "Route HTTP via Tor (SOCKS)" to route HTTP providers via Tor (crt.sh, RDAP, reverse IP, Shodan, Censys).
  - Toggle "Require Tor" to fail analyze when Tor is unavailable.
  - Toggle "Route Nmap via Tor (proxychains)" to run Nmap through proxychains (slower, best-effort).
- The header shows Tor availability and whether routing is enabled, plus exit IP/country when available.

Troubleshooting Tor
- If you see "Tor: not detected":
  - Ensure tor container is up (docker compose logs -f tor; wait for Bootstrapped 100%)
  - Refresh the page; status is polled periodically.
- If you run another Tor on the host (e.g., Tor Browser on 9150), set SOCKS URL in Settings to socks5://127.0.0.1:9150
- If you need tor exposed to the host, uncomment the ports mapping in docker-compose.yml for tor (9050:9050), but ensure 9050 is free.

PDF Report
- Click "Create PDF Report" to generate a styled PDF with:
  - WHOIS, Subdomains, DNS A/CNAME, Reverse IP, IP Info (RDAP), Open Ports (Nmap)
  - Tor routing status and Tor exit IP/country
  - Embedded graph PNG screenshot

Notes
- WHOIS parsing is best-effort and normalizes CRLF banners; raw WHOIS is included at the end of the report.
- Reverse IP via public endpoints is rate-limited; consider using a commercial provider in production.

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
