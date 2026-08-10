#!/usr/bin/env bash
# One-command AICN gateway setup.
#
# Registers this machine as your organization's gateway: installs the code and
# its dependencies, writes the config, installs a systemd service (so it starts
# on boot), and brings it up.
#
#   curl -fsSL https://raw.githubusercontent.com/channiw-mvla/aicn-compute/main/setup-gateway.sh \
#     | bash -s -- --token aicngw_YOUR_TOKEN
#
# Get the token from your org's page in the portal → "Register gateway".
#
# Options:
#   --token   <tok>   gateway token from the portal            (required)
#   --portal  <url>   portal URL      (default https://app.aicn.dev)
#   --dir     <path>  install dir     (default ~/aicn-gateway)
#   --port    <n>     WebSocket port  (default 8765)
#   --no-service      don't install systemd; run with nohup instead
set -euo pipefail

PORTAL="https://app.aicn.dev"
TOKEN=""
DIR="$HOME/aicn-gateway"
PORT="8765"
REPO="https://github.com/channiw-mvla/aicn-compute"
USE_SERVICE=1

while [ $# -gt 0 ]; do
  case "$1" in
    --token)      TOKEN="$2"; shift 2 ;;
    --portal)     PORTAL="${2%/}"; shift 2 ;;
    --dir)        DIR="$2"; shift 2 ;;
    --port)       PORT="$2"; shift 2 ;;
    --no-service) USE_SERVICE=0; shift ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mx\033[0m %s\n' "$*" >&2; exit 1; }

[ -n "$TOKEN" ] || die "missing --token (get one from your org page in the portal → Register gateway)"

# ---- 1. prerequisites ------------------------------------------------------
command -v python3 >/dev/null || die "python3 is required (try: sudo apt install -y python3 python3-venv git)"
command -v git     >/dev/null || die "git is required (try: sudo apt install -y git)"
python3 -c 'import venv' 2>/dev/null || die "python3-venv is required (try: sudo apt install -y python3-venv)"

# ---- 2. code ---------------------------------------------------------------
if [ -d "$DIR/.git" ]; then
  say "updating $DIR"
  git -C "$DIR" pull --ff-only || warn "could not update — using the existing checkout"
else
  say "cloning into $DIR"
  git clone --depth 1 "$REPO" "$DIR"
fi
cd "$DIR"

# ---- 3. dependencies -------------------------------------------------------
say "installing dependencies"
[ -d venv ] || python3 -m venv venv
./venv/bin/pip install --quiet --upgrade pip
./venv/bin/pip install --quiet -r requirements.txt

# ---- 4. config -------------------------------------------------------------
ADMIN_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
umask 077
cat > "$DIR/gateway.env" <<EOF
AICN_PORTAL_URL=$PORTAL
AICN_GATEWAY_TOKEN=$TOKEN
AICN_ADMIN_TOKEN=$ADMIN_TOKEN
EOF
say "wrote $DIR/gateway.env (keeps your tokens — chmod 600)"

# ---- 5. verify the portal accepts this token -------------------------------
say "checking in with the portal"
ORG="$(curl -fsS -X POST "$PORTAL/api/gw/heartbeat" \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}' \
        2>/dev/null | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("org_name") or "")
except Exception: print("")' || true)"
if [ -n "$ORG" ]; then
  say "authenticated — this gateway serves organization: $ORG"
else
  warn "could not confirm the token against $PORTAL (it will keep retrying once running)"
fi

# ---- 6. run ----------------------------------------------------------------
ARGS="--host 0.0.0.0 --port $PORT --authorized-keys $DIR/authorized_keys.json --auto-approve-nodes --trusted-proxy"

CAN_SERVICE=0
if [ "$USE_SERVICE" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
  # need root, or sudo (passwordless or an already-valid timestamp)
  if [ "$(id -u)" -eq 0 ] || sudo -v 2>/dev/null; then
    CAN_SERVICE=1
  else
    warn "no sudo available — falling back to nohup (won't start on boot)"
  fi
fi

if [ "$CAN_SERVICE" -eq 1 ]; then
  say "installing systemd service (starts on boot)"
  sudo tee /etc/systemd/system/aicn-gateway.service >/dev/null <<EOF
[Unit]
Description=AICN gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$DIR
EnvironmentFile=$DIR/gateway.env
ExecStart=$DIR/venv/bin/python gateway.py $ARGS
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now aicn-gateway
  sleep 2
  systemctl is-active --quiet aicn-gateway && say "gateway is running" || warn "check: journalctl -u aicn-gateway -n 40"
  RUNHINT="systemctl status aicn-gateway   ·   journalctl -u aicn-gateway -f"
else
  say "starting gateway (nohup)"
  set -a; . "$DIR/gateway.env"; set +a
  nohup "$DIR/venv/bin/python" gateway.py $ARGS > "$DIR/gateway.log" 2>&1 &
  sleep 2
  RUNHINT="tail -f $DIR/gateway.log   ·   stop: pkill -f gateway.py"
fi

cat <<EOF

──────────────────────────────────────────────────────────────
 AICN gateway is set up${ORG:+ for "$ORG"}.

 Next:
   1. Make it reachable — expose port $PORT (a Cloudflare tunnel is easiest):
        cloudflared tunnel --url http://localhost:$PORT
      then put that wss:// URL on your org's page in the portal.
   2. Add servers in the portal (org page → Add server) and run the
      claim command it shows on each machine.

 Manage:  $RUNHINT
 Config:  $DIR/gateway.env
 Admin token (for node controls): $ADMIN_TOKEN
──────────────────────────────────────────────────────────────
EOF
