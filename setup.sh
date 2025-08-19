#!/usr/bin/env bash
set -euo pipefail

# Setup script for Web Recon Visualizer
# - Installs system dependencies (whois, curl, unzip when possible)
# - Creates Python venv and installs requirements
# - Installs Amass from official releases if not found on PATH
# - Sublist3r is installed via pip from requirements.txt

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$PROJECT_DIR/bin"
AMASS_VERSION="v3.25.1"   # Change to desired version if needed

mkdir -p "$BIN_DIR"

has_cmd() { command -v "$1" >/dev/null 2>&1; }

install_system_deps() {
  echo "==> Installing system dependencies (whois, curl, unzip) if possible"
  if has_cmd apt-get; then
    sudo apt-get update -y
    sudo apt-get install -y whois curl unzip nmap
  elif has_cmd yum; then
    sudo yum install -y whois curl unzip nmap
  elif has_cmd brew; then
    brew update
    brew install whois unzip nmap || true
  else
    echo "-> No known package manager found. Please ensure whois, curl, unzip, and nmap are installed. Continuing..."
  fi
}

setup_venv() {
  echo "==> Setting up Python virtual environment"
  if ! has_cmd python3; then
    echo "ERROR: python3 is required but not found. Please install Python 3.10+ and re-run." >&2
    exit 1
  fi
  python3 -m venv "$PROJECT_DIR/.venv"
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.venv/bin/activate"
  python -m pip install -U pip setuptools wheel
  python -m pip install -r "$PROJECT_DIR/requirements.txt"
}

install_amass() {
  if has_cmd amass; then
    echo "==> Amass already installed at $(command -v amass)"
    return 0
  fi

  echo "==> Installing Amass $AMASS_VERSION from releases"
  UNAME_S="$(uname -s)"
  UNAME_M="$(uname -m)"

  case "$UNAME_S" in
    Linux) AMASS_OS="Linux" ;;
    Darwin) AMASS_OS="macOS" ;;
    *) echo "Unsupported OS for automatic Amass install: $UNAME_S"; return 0 ;;
  esac

  case "$UNAME_M" in
    x86_64|amd64) AMASS_ARCH="amd64" ;;
    aarch64|arm64) AMASS_ARCH="arm64" ;;
    *) echo "Unsupported arch for automatic Amass install: $UNAME_M"; return 0 ;;
  esac

  ASSET="amass_${AMASS_OS}_${AMASS_ARCH}.zip"
  URL="https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/${ASSET}"
  TMP_ZIP="/tmp/${ASSET}"
  TMP_DIR="/tmp/amass_${AMASS_OS}_${AMASS_ARCH}"

  echo "-> Downloading $URL"
  rm -f "$TMP_ZIP" && rm -rf "$TMP_DIR"
  mkdir -p "$TMP_DIR"
  if ! curl -fsSL -o "$TMP_ZIP" "$URL"; then
    echo "Failed to download $URL. You may need to update AMASS_VERSION or install manually."
    return 0
  fi
  echo "-> Extracting"
  unzip -q "$TMP_ZIP" -d "$TMP_DIR"

  # Find the binary; typically in a folder named after the asset
  AMASS_BIN="$(find "$TMP_DIR" -type f -name amass -perm -111 | head -n1 || true)"
  if [ -z "$AMASS_BIN" ]; then
    # Sometimes binary may not be marked executable
    AMASS_BIN="$(find "$TMP_DIR" -type f -name amass | head -n1 || true)"
    if [ -n "$AMASS_BIN" ]; then chmod +x "$AMASS_BIN"; fi
  fi
  if [ -z "$AMASS_BIN" ]; then
    echo "Amass binary not located in archive. Please install manually."
    return 0
  fi

  echo "-> Installing amass to $BIN_DIR and attempting to copy to /usr/local/bin"
  cp "$AMASS_BIN" "$BIN_DIR/amass"
  chmod +x "$BIN_DIR/amass"
  if has_cmd sudo; then
    sudo cp "$AMASS_BIN" /usr/local/bin/amass || true
  fi
  echo "Amass installed. Ensure $BIN_DIR is on your PATH if /usr/local/bin copy failed."
}

main() {
  install_system_deps
  setup_venv
  install_amass

  echo "\n==> Done"
  echo "Run the app:"
  echo "  source .venv/bin/activate"
  echo "  uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
  echo "Open http://localhost:8000"
}

main "$@"
