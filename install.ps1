Write-Host "======================================="
Write-Host " SilentEye DFIR Installer"
Write-Host "======================================="

$ErrorActionPreference = "Stop"

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Refresh-Path {
    $machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}

# --- Python ---
Write-Host "[*] Checking Python..."
if (-not (Test-Command "python")) {
    Write-Host "[!] Python not found. Installing..."

    $url = "https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe"
    $out = "$env:TEMP\python_installer.exe"

    Invoke-WebRequest $url -OutFile $out
    Start-Process $out -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait

    Refresh-Path
    Write-Host "[+] Python installed"
} else {
    Write-Host "[+] Python detected"
}

# --- Pip ---
Write-Host "[*] Upgrading pip..."
python -m pip install --upgrade pip

# --- Dependencies ---
Write-Host "[*] Installing dependencies..."
if (Test-Path ".\requirements.txt") {
    pip install -r requirements.txt
} else {
    pip install textual
}

# --- osquery ---
Write-Host "[*] Checking osquery..."
if (-not (Test-Command "osqueryi")) {
    Write-Host "[!] osquery not found."
    Write-Host "Install manually: https://osquery.io/downloads"
} else {
    Write-Host "[+] osquery detected"
}

# --- Exports folder ---
if (-not (Test-Path ".\exports")) {
    New-Item -ItemType Directory -Path ".\exports" | Out-Null
    Write-Host "[+] Created exports folder"
}

Write-Host ""
Write-Host "======================================="
Write-Host " Installation Complete"
Write-Host "======================================="
Write-Host "Run with: python silenteye.py"
