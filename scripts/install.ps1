#requires -Version 5.1

<#
.SYNOPSIS
    SilentEye DFIR Console installer for Windows.

.DESCRIPTION
    Prepares a local SilentEye environment by:

      - Validating Windows
      - Detecting Python 3.10+
      - Creating an isolated Python virtual environment
      - Installing dependencies from requirements.txt
      - Locating and validating osquery
      - Creating the exports directory
      - Compiling silenteye.py as a basic integrity/syntax check
      - Validating the Textual dependency

    The installer intentionally does NOT silently download and execute
    Python or osquery installers.

.EXAMPLE
    .\install.ps1

.EXAMPLE
    .\install.ps1 -RebuildVenv

.EXAMPLE
    .\install.ps1 -SkipOsqueryCheck
#>

[CmdletBinding()]
param(
    [switch]$RebuildVenv,
    [switch]$SkipOsqueryCheck
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------
# Project Paths
# ---------------------------------------------------------------------

$ProjectRoot       = $PSScriptRoot
$SilentEyeFile     = Join-Path $ProjectRoot "silenteye.py"
$RequirementsFile  = Join-Path $ProjectRoot "requirements.txt"
$VenvPath          = Join-Path $ProjectRoot ".venv"
$VenvPython        = Join-Path $VenvPath "Scripts\python.exe"
$ExportsPath       = Join-Path $ProjectRoot "exports"

# ---------------------------------------------------------------------
# Console Helpers
# ---------------------------------------------------------------------

function Write-Step {
    param([string]$Message)

    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)

    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-WarningMessage {
    param([string]$Message)

    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Stop-Install {
    param([string]$Message)

    Write-Host "[-] $Message" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------
# Platform Validation
# ---------------------------------------------------------------------

function Test-WindowsPlatform {

    Write-Step "Validating operating system..."

    if ($env:OS -ne "Windows_NT") {
        Stop-Install "SilentEye is currently designed for Windows DFIR analysis."
    }

    Write-Success "Windows detected."
}

# ---------------------------------------------------------------------
# Project Validation
# ---------------------------------------------------------------------

function Test-ProjectFiles {

    Write-Step "Validating SilentEye project files..."

    if (-not (Test-Path -LiteralPath $SilentEyeFile)) {
        Stop-Install "silenteye.py was not found in: $ProjectRoot"
    }

    if (-not (Test-Path -LiteralPath $RequirementsFile)) {
        Stop-Install "requirements.txt was not found in: $ProjectRoot"
    }

    Write-Success "Required project files found."
}

# ---------------------------------------------------------------------
# Python Discovery
# ---------------------------------------------------------------------

function Get-SupportedPython {

    $Candidates = @()

    $PythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if ($PythonCommand) {
        $Candidates += [PSCustomObject]@{
            Executable = $PythonCommand.Source
            Args       = @()
        }
    }

    $PyLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if ($PyLauncher) {
        $Candidates += [PSCustomObject]@{
            Executable = $PyLauncher.Source
            Args       = @("-3")
        }
    }

    foreach ($Candidate in $Candidates) {

        try {
            $VersionOutput = & $Candidate.Executable `
                @($Candidate.Args) `
                -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"

            if ($LASTEXITCODE -ne 0) {
                continue
            }

            $Version = [version]$VersionOutput.Trim()

            if ($Version -ge [version]"3.10") {
                return [PSCustomObject]@{
                    Executable = $Candidate.Executable
                    Args       = $Candidate.Args
                    Version    = $Version
                }
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Initialize-Python {

    Write-Step "Checking for Python 3.10 or newer..."

    $Python = Get-SupportedPython

    if (-not $Python) {

        Write-Host ""
        Write-WarningMessage "Python 3.10+ was not detected."
        Write-Host ""
        Write-Host "Install Python from the official Python website:"
        Write-Host "  https://www.python.org/downloads/"
        Write-Host ""
        Write-Host "During installation, enable:"
        Write-Host "  Add Python to PATH"
        Write-Host ""

        Stop-Install "Install Python and run install.ps1 again."
    }

    Write-Success "Python $($Python.Version) detected."

    return $Python
}

# ---------------------------------------------------------------------
# Virtual Environment
# ---------------------------------------------------------------------

function Initialize-VirtualEnvironment {

    param(
        [Parameter(Mandatory)]
        $Python
    )

    if ($RebuildVenv -and (Test-Path -LiteralPath $VenvPath)) {

        Write-Step "Removing existing virtual environment..."

        Remove-Item `
            -LiteralPath $VenvPath `
            -Recurse `
            -Force

        Write-Success "Existing virtual environment removed."
    }

    if (-not (Test-Path -LiteralPath $VenvPython)) {

        Write-Step "Creating SilentEye virtual environment..."

        & $Python.Executable `
            @($Python.Args) `
            -m venv `
            $VenvPath

        if ($LASTEXITCODE -ne 0) {
            Stop-Install "Python failed to create the virtual environment."
        }

        Write-Success "Virtual environment created."
    }
    else {
        Write-Success "Existing SilentEye virtual environment detected."
    }

    if (-not (Test-Path -LiteralPath $VenvPython)) {
        Stop-Install "Virtual-environment Python executable was not created."
    }
}

# ---------------------------------------------------------------------
# Python Dependencies
# ---------------------------------------------------------------------

function Install-PythonDependencies {

    Write-Step "Upgrading pip inside the SilentEye virtual environment..."

    & $VenvPython `
        -m pip `
        install `
        --upgrade `
        pip

    if ($LASTEXITCODE -ne 0) {
        Stop-Install "Unable to upgrade pip."
    }

    Write-Step "Installing dependencies from requirements.txt..."

    & $VenvPython `
        -m pip `
        install `
        -r $RequirementsFile

    if ($LASTEXITCODE -ne 0) {
        Stop-Install "Python dependency installation failed."
    }

    Write-Success "Python dependencies installed."
}

# ---------------------------------------------------------------------
# osquery Discovery
# ---------------------------------------------------------------------

function Find-Osquery {

    $Commands = @(
        "osqueryi.exe",
        "osqueryi"
    )

    foreach ($CommandName in $Commands) {

        $Command = Get-Command `
            $CommandName `
            -ErrorAction SilentlyContinue

        if ($Command) {
            return $Command.Source
        }
    }

    $CandidatePaths = @(
        "C:\Program Files\osquery\osqueryi.exe",
        "C:\ProgramData\chocolatey\bin\osqueryi.exe"
    )

    foreach ($Candidate in $CandidatePaths) {

        if (Test-Path -LiteralPath $Candidate) {
            return $Candidate
        }
    }

    return $null
}

function Test-Osquery {

    Write-Step "Checking for osquery..."

    $OsqueryPath = Find-Osquery

    if (-not $OsqueryPath) {

        if ($SkipOsqueryCheck) {

            Write-WarningMessage `
                "osquery was not detected. Continuing because -SkipOsqueryCheck was supplied."

            return $null
        }

        Write-Host ""
        Write-WarningMessage "osquery was not detected."
        Write-Host ""
        Write-Host "SilentEye requires osquery for endpoint telemetry."
        Write-Host ""
        Write-Host "Install osquery from:"
        Write-Host "  https://osquery.io/downloads/"
        Write-Host ""
        Write-Host "SilentEye checks:"
        Write-Host "  PATH"
        Write-Host "  C:\Program Files\osquery\osqueryi.exe"
        Write-Host "  C:\ProgramData\chocolatey\bin\osqueryi.exe"
        Write-Host ""

        Stop-Install "Install osquery and run install.ps1 again."
    }

    try {

        $VersionOutput = & $OsqueryPath "--version"

        if ($LASTEXITCODE -ne 0) {
            Stop-Install "osquery was found but could not be executed."
        }

        Write-Success "osquery detected."
        Write-Host "    Path: $OsqueryPath"
        Write-Host "    $VersionOutput"
    }
    catch {
        Stop-Install "osquery was located but execution failed: $($_.Exception.Message)"
    }

    return $OsqueryPath
}

# ---------------------------------------------------------------------
# Working Directories
# ---------------------------------------------------------------------

function Initialize-ProjectDirectories {

    Write-Step "Preparing SilentEye working directories..."

    if (-not (Test-Path -LiteralPath $ExportsPath)) {

        New-Item `
            -ItemType Directory `
            -Path $ExportsPath `
            -Force `
            | Out-Null

        Write-Success "Created exports directory."
    }
    else {
        Write-Success "Exports directory already exists."
    }
}

# ---------------------------------------------------------------------
# Application Validation
# ---------------------------------------------------------------------

function Test-SilentEyeSyntax {

    Write-Step "Checking silenteye.py syntax..."

    & $VenvPython `
        -m py_compile `
        $SilentEyeFile

    if ($LASTEXITCODE -ne 0) {
        Stop-Install "silenteye.py failed Python syntax validation."
    }

    Write-Success "silenteye.py syntax validation passed."
}

function Test-PythonDependencies {

    Write-Step "Validating Textual dependency..."

    & $VenvPython `
        -c "import textual; print('Textual version:', getattr(textual, '__version__', 'installed'))"

    if ($LASTEXITCODE -ne 0) {
        Stop-Install "Textual could not be imported."
    }

    Write-Success "Python dependency validation passed."
}

function Test-OsqueryQuery {

    param(
        [string]$OsqueryPath
    )

    if (-not $OsqueryPath) {
        return
    }

    Write-Step "Running basic osquery validation query..."

    try {

        $Output = & $OsqueryPath `
            "--json" `
            "SELECT version FROM osquery_info;"

        if ($LASTEXITCODE -ne 0) {
            Stop-Install "osquery validation query failed."
        }

        if (-not $Output) {
            Stop-Install "osquery returned no output during validation."
        }

        Write-Success "osquery validation query passed."
    }
    catch {
        Stop-Install "osquery validation query failed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------

function Show-InstallationSummary {

    param(
        $Python,
        $OsqueryPath
    )

    Write-Host ""
    Write-Host "========================================================="
    Write-Host " SilentEye DFIR Console Installation Complete"
    Write-Host "========================================================="
    Write-Host ""

    Write-Host "Project:"
    Write-Host "  $ProjectRoot"
    Write-Host ""

    Write-Host "Python:"
    Write-Host "  $($Python.Version)"
    Write-Host ""

    Write-Host "Virtual environment:"
    Write-Host "  $VenvPath"
    Write-Host ""

    if ($OsqueryPath) {
        Write-Host "osquery:"
        Write-Host "  $OsqueryPath"
        Write-Host ""
    }
    else {
        Write-Host "osquery:"
        Write-Host "  Not validated"
        Write-Host ""
    }

    Write-Host "Exports:"
    Write-Host "  $ExportsPath"
    Write-Host ""

    Write-Host "Run SilentEye:"
    Write-Host ""
    Write-Host "  .\.venv\Scripts\python.exe .\silenteye.py" `
        -ForegroundColor Green

    Write-Host ""
    Write-Host "Or activate the virtual environment:"
    Write-Host ""
    Write-Host "  .\.venv\Scripts\Activate.ps1"
    Write-Host "  python .\silenteye.py"
    Write-Host ""

    Write-Host "For the most complete Windows DFIR visibility,"
    Write-Host "run PowerShell as Administrator before launching SilentEye."
    Write-Host ""
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

try {

    Write-Host ""
    Write-Host "========================================================="
    Write-Host " SilentEye DFIR Console Installer"
    Write-Host "========================================================="
    Write-Host ""

    Set-Location $ProjectRoot

    Test-WindowsPlatform

    Test-ProjectFiles

    $Python = Initialize-Python

    Initialize-VirtualEnvironment `
        -Python $Python

    Install-PythonDependencies

    $OsqueryPath = Test-Osquery

    Initialize-ProjectDirectories

    Test-SilentEyeSyntax

    Test-PythonDependencies

    Test-OsqueryQuery `
        -OsqueryPath $OsqueryPath

    Show-InstallationSummary `
        -Python $Python `
        -OsqueryPath $OsqueryPath
}
catch {

    Write-Host ""
    Write-Host "========================================================="
    Write-Host " Installation Failed"
    Write-Host "========================================================="
    Write-Host ""

    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""

    exit 1
}
