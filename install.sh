#!/usr/bin/env bash
# Installs wafscan as a system command on Kali (or any Debian-based distro).
# Run with: sudo ./install.sh

set -e

INSTALL_DIR="/opt/wafscan"
BIN_LINK="/usr/local/bin/wafscan"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Run as root: sudo ./install.sh"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "[*] curl not found — installing..."
  apt-get update && apt-get install -y curl
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[x] python3 not found. Kali ships with it by default — check your install."
  exit 1
fi

echo "[*] Installing to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -r ./* "$INSTALL_DIR"/

cat > "$BIN_LINK" << 'WRAPPER'
#!/usr/bin/env bash
exec python3 /opt/wafscan/main.py "$@"
WRAPPER
chmod +x "$BIN_LINK"

echo "[+] Installed. Run it from anywhere with:  wafscan <url>"
echo "[+] Try:  wafscan --help"
