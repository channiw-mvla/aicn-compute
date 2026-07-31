#!/usr/bin/env sh
# AICN — one-command node join (Linux / macOS).
#
#   curl -fsSL https://YOUR-HOST/join.sh | sh
#
# Installs the node agent and connects this machine to the network. The gateway
# runs with open enrollment (--auto-approve-nodes), so this node is admitted
# automatically on first connect — no manual approval. It still gets a unique
# identity, so the operator can revoke it and reputation tracks it.
#
# Override the defaults with env vars:
#   AICN_GATEWAY=wss://gateway.example.com  AICN_NODE_ID=my-box  sh join.sh
set -eu

# --- EDIT THIS to your public gateway before sharing the script --------------
GATEWAY="${AICN_GATEWAY:-wss://YOUR-GATEWAY-HOST}"
PKG="${AICN_PKG:-git+https://github.com/channiw-mvla/aicn-compute}"
# -----------------------------------------------------------------------------

rand="$(head -c3 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo $$)"
NODE_ID="${AICN_NODE_ID:-$(hostname 2>/dev/null || echo node)-$rand}"

echo "AICN node join"
echo "  gateway : $GATEWAY"
echo "  node id : $NODE_ID"

case "$GATEWAY" in
  *YOUR-GATEWAY-HOST*)
    echo "ERROR: set your gateway first — AICN_GATEWAY=wss://your-gateway sh join.sh" >&2
    exit 1 ;;
esac

# 1. Python 3
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: Python 3 is required. Install it and re-run." >&2
  exit 1
fi

# 2. pipx (isolated install of the agent)
if ! command -v pipx >/dev/null 2>&1; then
  echo "Installing pipx..."
  python3 -m pip install --user pipx >/dev/null
  python3 -m pipx ensurepath >/dev/null 2>&1 || true
fi
export PATH="$HOME/.local/bin:$PATH"

# 3. Install / update the agent
echo "Installing the AICN agent..."
pipx install --force "$PKG" >/dev/null
export PATH="$HOME/.local/bin:$PATH"

# 4. Pick the safest sandbox available. A node runs OTHER PEOPLE'S code, so the
#    hardened (Docker) sandbox is strongly preferred; fall back with a warning.
SANDBOX="subprocess"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  SANDBOX="hardened"
else
  echo
  echo "WARNING: Docker isn't available, so the 'subprocess' sandbox will be used."
  echo "         That is NOT a hard security boundary and this node will run code"
  echo "         submitted by others. Install Docker and re-run for the hardened"
  echo "         sandbox before joining an untrusted/public network."
  echo
fi

# 5. Connect. --secure auto-creates this node's identity (~/.aicn/identity.key);
#    the gateway auto-enrolls it. Runs in the foreground (Ctrl-C to stop).
echo "Connecting as a node using the '$SANDBOX' sandbox (Ctrl-C to stop)..."
echo "To keep it running after you log out, see the nohup/systemd note in the README."
exec aicn-agent --gateway "$GATEWAY" --secure --sandbox "$SANDBOX" --node-id "$NODE_ID"
