# Running AICN under systemd (survives logout + reboot)

Three services: **gateway** and **tunnel** on the gateway box, **agent** on each node.
All read `/home/wchanning/aicn/aicn.env`. Adjust the `User=`, paths, and the
`venv/bin/python` location in the `.service` files to match your machine.

## 1. Config file (both boxes)

```bash
cp systemd/aicn.env.example ~/aicn/aicn.env
nano ~/aicn/aicn.env          # set the admin token, gateway URL, node id
chmod 600 ~/aicn/aicn.env     # it holds the admin token
```

## 2. Gateway box — gateway + portal + tunnel

The gateway and portal run on the same box and share `portal.db`. Set up the
portal's venv once:
```bash
cd ~/aicn/portal
python3 -m venv venv && venv/bin/pip install -r requirements.txt
```
Then install the services:
```bash
sudo cp systemd/aicn-gateway.service systemd/aicn-portal.service systemd/aicn-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aicn-gateway     # reads AICN_PORTAL_DB from aicn.env -> org routing on
sudo systemctl enable --now aicn-portal      # the web app on localhost:8000
sudo systemctl enable --now aicn-tunnel      # quick tunnel; see note below (use a NAMED tunnel for a stable URL)
```
With a **named tunnel** (recommended), the portal is served at `app.YOURDOMAIN.com`
— add that hostname to `~/.cloudflared/config.yml` and route its DNS:
```bash
cloudflared tunnel route dns aicn-gateway app.YOURDOMAIN.com
```

Get the current quick-tunnel URL from its log (it rotates on restart):
```bash
journalctl -u aicn-tunnel --no-pager | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | tail -1
```

**For a stable URL, skip `aicn-tunnel` and use a named tunnel instead:** set up
`~/.cloudflared/config.yml` (see `cloudflared-config.yml.template`) and run
`sudo cloudflared service install` — cloudflared installs its own persistent
service with your domain, so the address never changes.

## 3. Each node box — agent

Make sure your user is in the `docker` group first (`sudo usermod -aG docker $USER`, then re-login):
```bash
sudo cp systemd/aicn-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aicn-agent
```

## Managing them

```bash
systemctl status aicn-gateway aicn-tunnel aicn-agent   # health
journalctl -u aicn-agent -f                            # live logs
sudo systemctl restart aicn-agent                      # restart after editing aicn.env
sudo systemctl disable --now aicn-agent                # stop + don't start on boot
```

`Restart=always` means they come back after a crash, and `enable` means they start
on boot — so the network stays up unattended.
