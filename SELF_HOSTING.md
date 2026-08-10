# Self-host an AICN gateway

Stand up your own independent AICN instance — gateway + portal + your nodes —
so your organization runs its own hub with nothing shared with anyone else. This
is the same stack the hosted service runs; you just own it.

You'll have:

```
  app.<your-domain>      → the portal (accounts, orgs, servers, run jobs)
  gateway.<your-domain>  → where your nodes connect
  status.<your-domain>   → optional public read-only pool status
                     │
              portal.db (shared) ── gateway ── your nodes
```

The portal and gateway run on **one box** and share a single SQLite file; nodes
run anywhere and dial in.

---

## 0. Prerequisites

- A Linux box for the **gateway box** (a small VPS or a machine that stays on).
- **Python 3.10+**.
- **Docker** on any node that will run untrusted code (for the hardened sandbox).
- One of: a **domain** (recommended, for a stable public URL), a **Tailscale**
  tailnet (private group), or just a **LAN** (local only). See step 4.

Clone the repo on the gateway box:

```bash
git clone https://github.com/channiw-mvla/aicn-compute ~/aicn
cd ~/aicn
```

---

## 1. Pick a data directory + secrets

Everything shares one `portal.db`. Decide its absolute path — here we use
`~/aicn/portal/portal.db`. Choose a strong admin token (used to control nodes):

```bash
export AICN_PORTAL_DB="$HOME/aicn/portal/portal.db"
export AICN_ADMIN_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
echo "admin token: $AICN_ADMIN_TOKEN"   # save this
```

---

## 2. Start the portal (web app)

```bash
cd ~/aicn/portal
python3 -m venv venv
venv/bin/pip install -r requirements.txt

AICN_PORTAL_DB="$AICN_PORTAL_DB" \
AICN_GATEWAY_URL="wss://gateway.YOURDOMAIN.com" \
AICN_PORTAL_SECURE_COOKIES=1 \
venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```

- `AICN_GATEWAY_URL` is the address shown in the portal's "add a server" command —
  set it to how your nodes will reach the gateway (see step 4).
- `AICN_PORTAL_SECURE_COOKIES=1` **only** when served over HTTPS (the tunnel). For a
  plain-`http://` LAN test, leave it **off** or logins won't stick.

---

## 3. Start the gateway (same box, linked to the portal DB)

```bash
cd ~/aicn
AICN_PORTAL_DB="$AICN_PORTAL_DB" AICN_ADMIN_TOKEN="$AICN_ADMIN_TOKEN" \
python3 gateway.py --host 0.0.0.0 \
  --authorized-keys ~/aicn/authorized_keys.json \
  --auto-approve-nodes \
  --trusted-proxy
```

What each flag does:

| Flag | Why |
|------|-----|
| `AICN_PORTAL_DB` | links the gateway to the portal → org routing + web jobs. **Same path as the portal.** |
| `--authorized-keys` | secure mode (keypair auth). Nodes claim/connect with keys. |
| `--auto-approve-nodes` | nodes join with one command (still revocable, still identity-tracked). |
| `--admin-token` (env) | enables node control (pause/schedule) — LAN-only. |
| `--trusted-proxy` | **only if behind a local reverse proxy/tunnel** (cloudflared). Reads the real client IP so LAN-only control isn't fooled. Omit for LAN/Tailscale-direct. |

---

## 4. Make it reachable — pick ONE

**A. Public, with a domain (recommended — free TLS, stable URL).**
Use Cloudflare Tunnel. Add your domain to Cloudflare, then:
```bash
cloudflared tunnel login
cloudflared tunnel create aicn-gateway
cp cloudflared-config.yml.template ~/.cloudflared/config.yml   # fill in TUNNEL-ID + YOURDOMAIN
cloudflared tunnel route dns aicn-gateway app.YOURDOMAIN.com
cloudflared tunnel route dns aicn-gateway gateway.YOURDOMAIN.com
cloudflared tunnel route dns aicn-gateway status.YOURDOMAIN.com
cloudflared tunnel run aicn-gateway
```
The template already maps `app.` → portal (8000), `gateway.` → gateway WS (8765),
`status.` → the read-only dashboard. Keep `--trusted-proxy` **on**.

**B. Public, no domain (testing only).** Quick tunnel — URL changes each restart:
```bash
sh cloudflare-tunnel.sh    # prints https://<random>.trycloudflare.com  (use wss:// of it)
```

**C. Private group (Tailscale).** Everyone installs Tailscale + joins your tailnet.
Nodes use `ws://<gateway-tailscale-ip>:8765`. **Drop `--trusted-proxy`** (no proxy).

**D. LAN only.** Nodes use `ws://<gateway-lan-ip>:8765`. Drop `--trusted-proxy`.
Set the portal's `AICN_GATEWAY_URL` to match whichever you pick.

---

## 5. Add your first node

1. Open the portal (`https://app.YOURDOMAIN.com` or `http://localhost:8000`) → **Sign up**.
2. **Create an organization.**
3. **Servers → Add server** → copy the shown command and run it on the machine:
   ```bash
   pipx install git+https://github.com/channiw-mvla/aicn-compute
   aicn-agent --gateway wss://gateway.YOURDOMAIN.com --secure --claim-token <TOKEN> --sandbox hardened
   ```
   (drop `--sandbox hardened` for a trusted machine without Docker)
4. Back in the portal, the server flips to **claimed** → **Share** it into your org.
5. On the org page, **Run a job**.

Invite teammates from **Organizations → invite link**.

---

## 6. Run it persistently (survives reboots)

Use the systemd units in [`systemd/`](systemd/) — see [`systemd/README.md`](systemd/README.md).
In short: fill in `~/aicn/aicn.env`, then:
```bash
sudo cp systemd/aicn-gateway.service systemd/aicn-portal.service systemd/aicn-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aicn-gateway aicn-portal aicn-tunnel
```

---

## 7. Security checklist

- [ ] Gateway runs with **`--authorized-keys`** (secure mode) — not open mode on a public URL.
- [ ] **`--admin-token`** set, and kept secret (it grants node control).
- [ ] **`--trusted-proxy`** set **iff** behind a local tunnel/proxy (so control stays LAN-only).
- [ ] `AICN_PORTAL_SECURE_COOKIES=1` in production (HTTPS).
- [ ] `authorized_keys.json`, `portal.db`, and `aicn.env` are **git-ignored** (they are by default).
- [ ] Public nodes use **`--sandbox hardened`** (they run others' code).
- [ ] Revoke a bad node any time: `python3 authctl.py --keys authorized_keys.json revoke <fingerprint>`.

Security is enforced by the **gateway**, not by hiding the client — anyone can have
the code; only the LAN + admin token + approved keys grant control.

---

## Ports at a glance

| Port | Service | Exposure |
|------|---------|----------|
| 8000 | portal (web app) | via tunnel as `app.` |
| 8765 | gateway WebSocket (nodes/jobs) | via tunnel as `gateway.` |
| 8766 | gateway dashboard (operator) | LAN only (or `status.` read-only) |
| 8770 | per-node local panel | loopback on each node |

That's a full independent instance. It shares nothing with any other deployment —
your gateway, your portal, your database, your nodes.
