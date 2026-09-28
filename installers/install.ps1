<#
ThreatScan installer for Windows 10/11 (PowerShell 5.1+).
  irm https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.ps1 | iex
Environment options:
  $env:THREATSCAN_REF      git ref / tag (default main)
  $env:THREATSCAN_WEBHOOK  alert webhook URL
  $env:THREATSCAN_ROOTS    semicolon-separated project dirs to watch
  $env:THREATSCAN_NO_INSTALL=1   only install the CLI
  $env:THREATSCAN_BLOCK_C2=1     also add firewall rules (needs an elevated shell)
#>
$ErrorActionPreference = 'Stop'
$Repo   = if ($env:THREATSCAN_REPO) { $env:THREATSCAN_REPO } else { 'https://github.com/FaheemRafiq/threatscan' }
$Ref    = if ($env:THREATSCAN_REF)  { $env:THREATSCAN_REF }  else { 'main' }
$Prefix = if ($env:THREATSCAN_PREFIX) { $env:THREATSCAN_PREFIX } else { Join-Path $HOME '.threatscan' }
$Venv   = Join-Path $Prefix 'venv'
$BinDir = Join-Path $env:LOCALAPPDATA 'Programs\threatscan'

function Say($m)  { Write-Host "[threatscan] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[threatscan] $m" -ForegroundColor Red; exit 1 }

# ── 1. Python 3.8+ ───────────────────────────────────────────────────────────
function Find-Python {
  foreach ($c in @('py -3', 'python3', 'python')) {
    try {
      $v = & cmd /c "$c -c ""import sys;print(sys.version_info>=(3,8))""" 2>$null
      if ($v -match 'True') { return $c }
    } catch {}
  }
  return $null
}
$Py = Find-Python
if (-not $Py) {
  Say 'Python 3.8+ not found; installing via winget (Python.Python.3.12)...'
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements --silent | Out-Null
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path','User') + ';' + [System.Environment]::GetEnvironmentVariable('Path','Machine')
    $Py = Find-Python
  }
  if (-not $Py) { Fail 'Install Python 3 from https://www.python.org/downloads/ (tick "Add to PATH") and re-run.' }
}
Say "Using $(& cmd /c "$Py --version" 2>&1)"

# ── 2. Virtualenv ────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $Prefix, $BinDir | Out-Null
$VenvPy = Join-Path $Venv 'Scripts\python.exe'
if (-not (Test-Path $VenvPy)) {
  Say "Creating virtualenv in $Venv"
  & cmd /c "$Py -m venv ""$Venv"""
  if (-not (Test-Path $VenvPy)) { Fail 'Could not create virtualenv.' }
}
& $VenvPy -m pip install -q --upgrade pip 2>$null | Out-Null

# ── 3. Install / upgrade ─────────────────────────────────────────────────────
Say "Installing threatscan ($Ref) from $Repo"
$local = Join-Path $PSScriptRoot '..\pyproject.toml'
if ($PSScriptRoot -and (Test-Path $local) -and -not $env:THREATSCAN_FORCE_REMOTE) {
  & $VenvPy -m pip install -q --upgrade (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
} else {
  try { & $VenvPy -m pip install -q --upgrade "git+$Repo.git@$Ref" }
  catch {
    Say 'git not available; falling back to tarball'
    $tgz = Join-Path $env:TEMP 'threatscan.tar.gz'
    Invoke-WebRequest -Uri "$Repo/archive/$Ref.tar.gz" -OutFile $tgz -UseBasicParsing
    & $VenvPy -m pip install -q --upgrade $tgz
    Remove-Item $tgz -ErrorAction SilentlyContinue
  }
}
# Launcher on PATH (a .cmd shim so it works from cmd, PowerShell and Explorer)
$shim = Join-Path $BinDir 'threatscan.cmd'
"@echo off`r`n""$Venv\Scripts\threatscan.exe"" %*" | Set-Content -Path $shim -Encoding ASCII
$userPath = [Environment]::GetEnvironmentVariable('Path','User')
if ($userPath -notlike "*$BinDir*") {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$BinDir", 'User')
  $env:Path += ";$BinDir"
  Say "Added $BinDir to your user PATH (open a new terminal to use 'threatscan')"
}
Say "Installed: $(& "$Venv\Scripts\threatscan.exe" --version)"

# ── 4. Harden + guard + first scan ──────────────────────────────────────────
if (-not $env:THREATSCAN_NO_INSTALL) {
  $args = @('install')
  if ($env:THREATSCAN_WEBHOOK) { $args += @('--webhook', $env:THREATSCAN_WEBHOOK) }
  if ($env:THREATSCAN_ROOTS)   { $args += @('--roots') + ($env:THREATSCAN_ROOTS -split ';') }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if ($env:THREATSCAN_BLOCK_C2 -and $isAdmin) { $args += '--block-c2' }
  & "$Venv\Scripts\threatscan.exe" @args
  if ($env:THREATSCAN_BLOCK_C2 -and -not $isAdmin) { Say 'Firewall step skipped: re-run in an elevated PowerShell:  threatscan protect --block-c2' }
}
Say 'Done.  Try:  threatscan status'
