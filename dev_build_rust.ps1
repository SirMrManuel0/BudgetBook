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

function Ask-YesNo($message) {
    while ($true) {
        $answer = Read-Host "$message [Y/N]"
        switch ($answer.ToUpper()) {
            "Y" { return $true }
            "N" { return $false }
            default { Write-Colored "Please answer Y or N." Yellow }
        }
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

# -------- MSVC Build Tools Check --------
Write-Host ""
Write-Colored "=== MSVC Build Tools Check ===" Cyan
Write-Colored "Automatic MSVC detection is disabled." Yellow
Write-Colored "Please ensure that MSVC Build Tools with C++ workload are installed on your machine." Yellow
Write-Colored "If you don't have it installed, you can download it from:" Yellow
Write-Colored "https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022" Yellow
Read-Host -Prompt "Press Enter once you have verified or installed MSVC Build Tools"


# -------- Rust target toolchain check --------
Write-Host ""
Write-Colored "=== Checking Rust Target and Toolchain ===" Cyan

# Get default rust target triple
$rustTarget = rustc -vV | Select-String "host:" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }

Write-Colored "Detected Rust host target: $rustTarget" White

if ($rustTarget -match "gnu") {
    Write-Colored "Rust is using GNU toolchain, checking for mingw-w64 gcc..." Cyan
    $gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if (-not $gcc) {
        Write-Colored "gcc.exe (mingw-w64) not found in PATH." Red
        Write-Colored "Please install mingw-w64 (e.g. from https://winlibs.com/) and add to PATH." Yellow
        if (Ask-YesNo "Do you want to open mingw-w64 download page now?") {
            Start-Process "https://winlibs.com/"
        }
    } else {
        Write-Colored "mingw-w64 gcc detected." Green
    }
} elseif ($rustTarget -match "msvc") {
    Write-Colored "Rust is using MSVC toolchain, MSVC Build Tools check done earlier." Green
} else {
    Write-Colored "Rust target is neither GNU nor MSVC (detected: $rustTarget). Please verify your toolchain manually." Yellow
}

# -------- LLVM (libclang) Check --------
Write-Host ""
Write-Colored "=== Checking LLVM (libclang.dll) Installation ===" Cyan

function Test-LibClang {
    try {
        # Try finding libclang.dll in PATH
        $null = (Get-Command libclang.dll -ErrorAction Stop)
        return $true
    } catch {
        # Also check common LLVM install locations
        $commonPaths = @(
            "$env:ProgramFiles\LLVM\bin\libclang.dll",
            "$env:ProgramFiles(x86)\LLVM\bin\libclang.dll",
            "$env:LocalAppData\Programs\LLVM\bin\libclang.dll"
        )
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                # Add directory to PATH env var for current session
                $dir = Split-Path $path
                $env:PATH = "$dir;$env:PATH"
                Write-Colored "Found libclang.dll at $path" Green
                return $true
            }
        }
        return $false
    }
}

if (-not (Test-LibClang)) {
    Write-Colored "libclang.dll not found on PATH." Red
    if (Ask-YesNo "Do you want to install LLVM now?") {
        Write-Colored "Installing LLVM..." Yellow

        $llvmVersion = "15.0.7"
        $llvmInstallerUrl = "https://github.com/llvm/llvm-project/releases/download/llvmorg-$llvmVersion/LLVM-$llvmVersion-win64.exe"
        $installerPath = "LLVM-installer.exe"

        Invoke-WebRequest -Uri $llvmInstallerUrl -OutFile $installerPath -UseBasicParsing
        Write-Colored "Downloaded LLVM installer." White

        # Run installer silently - adjust args if you want interactive or custom install location
        Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
        Remove-Item $installerPath

        # After install, try to find libclang.dll again
        if (Test-LibClang) {
            Write-Colored "LLVM installed and libclang.dll found." Green
        } else {
            Write-Colored "LLVM installation completed but libclang.dll still not found. Please check manually." Yellow
        }
    } else {
        Write-Colored "Skipping LLVM installation." Yellow
    }
} else {
    Write-Colored "LLVM (libclang.dll) is already installed." Green
}

# -------- Environment variable refresh advice --------
Write-Host ""
Write-Colored "=== Environment Variables Refresh ===" Cyan
Write-Colored "If you just installed MSVC Build Tools or mingw-w64, you might need to restart your terminal or log out/in" Yellow
Write-Colored "to ensure environment variables and PATH changes take effect." Yellow
Read-Host -Prompt "Press Enter to continue..."

# -------- Rust Check --------
Write-Host ""
Write-Colored "=== Checking Rust Installation ===" Cyan

$rustupPath = (Get-Command rustup -ErrorAction SilentlyContinue).Path
if (-not $rustupPath) {
    Write-Colored "Rust not found." Red
    if (Ask-YesNo "Do you want to install Rust now?") {
        Write-Colored "Installing Rust..." Yellow
        Invoke-WebRequest -Uri https://sh.rustup.rs -OutFile rustup-init.exe -UseBasicParsing
        Start-Process -FilePath .\rustup-init.exe -ArgumentList "-y" -Wait
        Remove-Item rustup-init.exe
        Write-Colored "Rust installed." Green
    } else {
        Write-Colored "Skipping Rust installation." Yellow
    }
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
    if (Ask-YesNo "Python 3.13 not found. Do you want to install it now?") {
        Write-Colored "Installing Python 3.13..." Yellow
        Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe -OutFile python_installer.exe -UseBasicParsing
        Start-Process -FilePath .\python_installer.exe -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait
        Remove-Item python_installer.exe
        Write-Colored "Python 3.13 installed." Green
    } else {
        Write-Colored "Skipping Python 3.13 installation." Yellow
    }
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
    Write-Colored "=== Checking Python Requirements ===" Cyan

    # Run pip check to see if all requirements are met
    $pipCheckOutput = pip check 2>&1
    if ($pipCheckOutput -match "No broken requirements found") {
        Write-Colored "All Python requirements are already satisfied." Green
    } else {
        Write-Colored "Installing/updating Python requirements..." Cyan
        $pipOutput = pip install -r requirements.txt 2>&1
        Write-IndentedOutput $pipOutput
    }
} else {
    Write-Colored "No requirements.txt found - skipping dependency installation." Yellow
}

# -------- Install Maturin & Develop --------
Write-Host ""
Write-Colored "=== Installing Maturin and Running 'maturin develop --release' ===" Cyan

# Install maturin
$pipMaturinOutput = pip install maturin 2>&1
Write-IndentedOutput $pipMaturinOutput

# Run maturin and capture unified output
$maturinOutput = & maturin develop --release 2>&1
$exitCode = $LASTEXITCODE

# Split into lines for inspection
$lines = $maturinOutput -split "`r?`n"

# Regex patterns
$installedPattern = 'Installed\s+([\w\-.]+-\d+\.\d+\.\d+)'
$warningPattern   = '\bwarning\b'          # case-insensitive
$errorPattern     = '\b(error|failed|exception)\b'  # case-insensitive

$successFound = $false
$warningFound = $false
$errorFound   = $false

foreach ($line in $lines) {
    $lower = $line.ToLower()

    if ($line -match $installedPattern) {
        Write-Colored $line Green
        $successFound = $true
    }
    elseif ($lower -match $warningPattern -and -not ($lower -match $errorPattern)) {
        Write-Colored $line Yellow
        $warningFound = $true
    }
    elseif ($lower -match $errorPattern) {
        Write-Colored $line Red
        $errorFound = $true
    }
    else {
        Write-Host $line
    }
}

# Summaries
if (-not $successFound) {
    Write-Colored "'maturin develop --release' finished but no 'Installed ...' line was detected." Yellow
}

if ($exitCode -ne 0) {
    Write-Colored "maturin exited with non-zero exit code ($exitCode)." Red
    $errorFound = $true
}

if ($errorFound) {
    Write-Colored "There were errors during 'maturin develop --release'." Red
} elseif ($warningFound) {
    Write-Colored "'maturin develop --release' completed with warnings." Yellow
} elseif ($successFound) {
    Write-Colored "'maturin develop --release' completed successfully." Green
} else {
    # Fallback if nothing matched but exit code was zero
    Write-Colored "Finished 'maturin develop --release' (no explicit success/error line detected)." Cyan
}


# -------- Run Application --------
# Uncomment below lines to run your app
# Write-Host ""
# Write-Colored "=== Starting Application ===" Cyan
# python main.py

Write-Host ""
Write-Colored "Done." Green
Read-Host -Prompt "Press Enter to continue..."
