function Write-Colored {
    param(
        [string]$Text,
        [ConsoleColor]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

function Write-IndentedOutput {
    param(
        [string[]]$Lines
    )
    foreach ($line in $Lines) {
        Write-Host "    $line" -ForegroundColor DarkGray
    }
}


# Check if running as Administrator
Write-Host ""
Write-Colored "=== Checking Admin Rights ===" Cyan

$adminCheck = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()))
if (-not $adminCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Colored "Requesting admin access..." Yellow
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
} else {
    Write-Colored "Running as Administrator." Green
}

# -------- Rust Check --------
Write-Host ""
Write-Colored "=== Checking Rust Installation ===" Cyan

$rustupPath = (Get-Command rustup -ErrorAction SilentlyContinue).Path
if (-not $rustupPath) {
    Write-Colored "Rust not found. Installing Rust..." Red
    Invoke-WebRequest -Uri https://sh.rustup.rs -OutFile rustup-init.exe -UseBasicParsing
    Start-Process -FilePath .\rustup-init.exe -ArgumentList "-y" -Wait
    Remove-Item rustup-init.exe
    Write-Colored "Rust installed." Green
} else {
    Write-Colored "Rust is installed. Checking for updates..." Green
    $rustupSelfUpdate = rustup self update 2>&1
    Write-IndentedOutput $rustupSelfUpdate
    $rustupUpdate = rustup update 2>&1
    Write-IndentedOutput $rustupUpdate
}

# -------- Python 3.13 Check --------
Write-Host ""
Write-Colored "=== Checking Python 3.13 Installation ===" Cyan

$pythonVersionOk = $false
$pythonVersionOutput = & python --version 2>&1

if ($pythonVersionOutput -and $pythonVersionOutput -match 'Python (\d+)\.(\d+)\.(\d+)') {
    $major = [int]$matches[1]
    $minor = [int]$matches[2]
    $patch = [int]$matches[3]
    Write-Colored "Detected Python version: $major.$minor.$patch" White
    if ($major -eq 3 -and $minor -eq 13) {
        $pythonVersionOk = $true
    }
} else {
    Write-Colored "Python not found." Red
}

if (-not $pythonVersionOk) {
    Write-Colored "Python 3.13 not found. Installing..." Red
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe -OutFile python_installer.exe -UseBasicParsing
    Start-Process -FilePath .\python_installer.exe -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait
    Remove-Item python_installer.exe
    Write-Colored "Python 3.13 installed." Green
} else {
    Write-Colored "Python 3.13 is already installed." Green
}

# -------- Python Virtual Environment Check --------
Write-Host ""
Write-Colored "=== Checking Python Virtual Environment ===" Cyan

$venvDir = ".venv"
if (-not (Test-Path "$venvDir\Scripts\Activate.ps1")) {
    Write-Colored "Virtual environment not found. Creating..." Red
    python -m venv $venvDir
    Write-Colored "Virtual environment created." Green
} else {
    Write-Colored "Virtual environment already exists." Green
}

Write-Colored "Activating virtual environment..." White
& "$venvDir\Scripts\Activate.ps1"

# -------- Install Requirements --------
if (Test-Path "requirements.txt") {
    Write-Host ""
    Write-Colored "=== Installing Python Requirements ===" Cyan
    $pipOutput = pip install -r requirements.txt 2>&1
    Write-IndentedOutput $pipOutput
} else {
    Write-Colored "No requirements.txt found - skipping dependency installation." Yellow
}

# -------- Run Application --------
# Uncomment below lines to run your app
# Write-Host ""
# Write-Colored "=== Starting Application ===" Cyan
# python main.py

Write-Host ""
Write-Colored "Done." Green
