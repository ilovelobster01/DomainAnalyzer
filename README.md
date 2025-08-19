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
- Build (auto-arch): docker buildx build --platform linux/amd64,linux/arm64 -t web-recon .
  - If you are on Apple Silicon (arm64) and want a single-arch image: docker buildx build --platform linux/arm64 -t web-recon .
  - If you are on x86_64: docker build -t web-recon .
- Run:   docker run --rm -p 8000:8000 web-recon
  Then visit http://localhost:8000
- Includes Amass and Nmap installed from official sources by default.

Docker Compose (with Tor proxy)
- A docker-compose.yml is provided to run a dedicated Tor SOCKS5 proxy alongside the web app.
- Quick start:
  - docker compose up --build
  - This brings up two services on a shared network:
    - tor: SOCKS5 proxy exposed as host:9050 and available to other containers at hostname tor:9050
    - web: the app, configured by default to prefer socks5://tor:9050 if reachable
- The app will attempt to detect a SOCKS proxy in this order:
  1) TOR_SOCKS_URL env (if set)
  2) socks5://tor:9050 (Docker Compose service)
  3) socks5://127.0.0.1:9050 (local Tor)
- In Settings, you can toggle “Route HTTP via Tor (SOCKS)”. When enabled, HTTP-based providers (crt.sh, RDAP, reverse IP, Shodan, Censys) route via the detected proxy. You can also set “Require Tor” to fail requests when Tor isn’t available.
- Nmap routing: optionally enable “Route Nmap via Tor (proxychains)” in Settings if you configure proxychains in your environment. This is advanced, slower, and may give incomplete results.

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
