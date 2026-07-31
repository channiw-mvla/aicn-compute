#!/usr/bin/env sh
# Quick Cloudflare Tunnel for the AICN gateway — an instant public wss:// URL
# with NO Cloudflare account and NO domain. Perfect for testing auto-join end to
# end. For a stable production hostname, use a NAMED tunnel instead (see
# cloudflared-config.yml.template and the README).
#
# Run this ON THE GATEWAY BOX, with the gateway already listening on :8765.
# The gateway MUST be started with --trusted-proxy (so the LAN-only control gate
# reads the real client IP from Cloudflare's header, not cloudflared's 127.0.0.1).
set -eu

PORT="${AICN_WS_PORT:-8765}"

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "Installing cloudflared..."
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; esac
  url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-${os}-${arch}"
  sudo curl -fsSL "$url" -o /usr/local/bin/cloudflared
  sudo chmod +x /usr/local/bin/cloudflared
fi

echo
echo "Starting a quick tunnel to http://localhost:$PORT"
echo "Cloudflare prints a  https://<random>.trycloudflare.com  URL below."
echo "  -> your gateway URL for nodes is that URL with https:// changed to wss://"
echo "  -> put it in join.sh (AICN_GATEWAY) so new nodes connect to it"
echo "REMINDER: the gateway must be running with --trusted-proxy."
echo
exec cloudflared tunnel --url "http://localhost:$PORT"
