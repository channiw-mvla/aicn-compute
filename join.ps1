# AICN — one-command node join (Windows PowerShell).
#
#   irm https://YOUR-HOST/join.ps1 | iex
#
# Installs the node agent and connects this machine to the network. The gateway
# runs with open enrollment (--auto-approve-nodes), so this node is admitted
# automatically on first connect. It still gets a unique identity, so the
# operator can revoke it and reputation tracks it.
#
# Override the defaults with env vars:
#   $env:AICN_GATEWAY="wss://gateway.example.com"; irm .../join.ps1 | iex
$ErrorActionPreference = "Stop"

# --- EDIT THIS to your public gateway before sharing the script --------------
$Gateway = if ($env:AICN_GATEWAY) { $env:AICN_GATEWAY } else { "wss://YOUR-GATEWAY-HOST" }
$Pkg     = if ($env:AICN_PKG) { $env:AICN_PKG } else { "git+https://github.com/channiw-mvla/aicn-compute" }
# -----------------------------------------------------------------------------

$NodeId = if ($env:AICN_NODE_ID) { $env:AICN_NODE_ID } else { "$env:COMPUTERNAME-$(Get-Random -Maximum 9999)" }

Write-Host "AICN node join"
Write-Host "  gateway : $Gateway"
Write-Host "  node id : $NodeId"

if ($Gateway -like "*YOUR-GATEWAY-HOST*") {
  Write-Error "Set your gateway first: `$env:AICN_GATEWAY='wss://your-gateway'; then re-run."
  exit 1
}

# 1. Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Error "Python 3 is required. Install it from python.org and re-run."
  exit 1
}

# 2. pipx
if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
  Write-Host "Installing pipx..."
  python -m pip install --user pipx | Out-Null
  python -m pipx ensurepath | Out-Null
}

# 3. Install / update the agent
Write-Host "Installing the AICN agent..."
pipx install --force $Pkg | Out-Null

# 4. Safest sandbox available (hardened needs Docker Desktop; a node runs others' code)
$Sandbox = "subprocess"
if (Get-Command docker -ErrorAction SilentlyContinue) {
  try { docker info | Out-Null; $Sandbox = "hardened" } catch {}
}
if ($Sandbox -eq "subprocess") {
  Write-Warning ("Docker isn't available, so the 'subprocess' sandbox will be used. That is NOT a " +
                 "hard security boundary and this node will run code submitted by others. Install " +
                 "Docker Desktop and re-run for the hardened sandbox before joining an untrusted network.")
}

# 5. Connect. --secure auto-creates this node's identity; the gateway auto-enrolls it.
Write-Host "Connecting as a node using the '$Sandbox' sandbox (Ctrl-C to stop)..."
aicn-agent --gateway $Gateway --secure --sandbox $Sandbox --node-id $NodeId
