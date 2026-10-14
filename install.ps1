# Vite Shop Terminal Script — Windows PowerShell installer for the NetScope capture agent.
#
# Usage (PowerShell, as Administrator):
#   irm https://raw.githubusercontent.com/mummuzumill-ops/wiresharp-terminal-script/main/install.ps1 | iex
#
# Or with a room code:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/mummuzumill-ops/wiresharp-terminal-script/main/install.ps1))) -Room NET-XXXXX-XXXXX
#
# There is no `sudo` on Windows. Run PowerShell as Administrator instead.
param(
    [string]$Room = "",
    [string]$Iface = "",
    [int]$Port = 9000,
    [switch]$Test
)

$ErrorActionPreference = "Stop"

$repoUrl = if ($env:NETSCOPE_REPO_URL) { $env:NETSCOPE_REPO_URL } else { "https://github.com/mummuzumill-ops/wiresharp-terminal-script.git" }
$workDir = if ($env:NETSCOPE_DIR) { $env:NETSCOPE_DIR } else { Join-Path $HOME ".wiresharp-terminal-script" }

# --- admin check (Windows equivalent of `sudo`) -------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Not running as Administrator." -ForegroundColor Yellow
    Write-Host "    Packet capture needs elevation. Close this window, open" -ForegroundColor Yellow
    Write-Host "    'Windows PowerShell' with 'Run as administrator', then re-run this command." -ForegroundColor Yellow
    exit 1
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "[!] git is required. Install it from https://git-scm.com/download/win" -ForegroundColor Red
    exit 1
}

$python = $null
foreach ($candidate in @("python", "py", "python3")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $python = $candidate; break }
}
if (-not $python) {
    Write-Host "[!] Python 3 is required. Install it from https://www.python.org/downloads/" -ForegroundColor Red
    exit 1
}

# --- fetch / update the agent -------------------------------------------------
Write-Host "==> Fetching the capture agent into $workDir" -ForegroundColor Cyan
if (Test-Path (Join-Path $workDir ".git")) {
    & git -C $workDir pull --ff-only --quiet
} else {
    & git clone --depth 1 --quiet $repoUrl $workDir
}

Set-Location $workDir

# --- Scapy is required on Windows --------------------------------------------
$hasScapy = $false
try {
    & $python -c "import scapy" 2>$null
    $hasScapy = ($LASTEXITCODE -eq 0)
} catch { $hasScapy = $false }

if (-not $hasScapy) {
    Write-Host "==> Installing Scapy (required on Windows)" -ForegroundColor Cyan
    & $python -m pip install --quiet --upgrade pip
    & $python -m pip install --quiet scapy
}

Write-Host ""
Write-Host "NOTE: Windows capture also needs the Npcap driver." -ForegroundColor Yellow
Write-Host "      If packets stay empty, install it from https://npcap.com/#download" -ForegroundColor Yellow
Write-Host "      (the regular graphical installer; it cannot be installed silently)." -ForegroundColor Yellow
Write-Host ""

# --- run ----------------------------------------------------------------------
$args = @("capture_agent.py", "--port", "$Port")
if ($Room)   { $args += @("--room", $Room) }
if ($Iface)  { $args += @("--iface", $Iface) }
if ($Test)   { $args += "--test" }

Write-Host "==> Starting: $python $($args -join ' ')" -ForegroundColor Cyan
& $python @args
