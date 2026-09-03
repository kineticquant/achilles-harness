##############################################################################
# goose CLI Install Script for Windows PowerShell
#
# This script downloads the latest stable 'goose' CLI binary from GitHub releases
# and installs it to your system.
#
# Supported OS: Windows
# Supported Architectures: x86_64
#
# Usage:
#   Invoke-WebRequest -Uri "https://github.com/kineticquant/achilles-harness/releases/download/stable/download_cli.ps1" -OutFile "download_cli.ps1"; .\download_cli.ps1
#   Or simply: .\download_cli.ps1
#
# Environment variables:
#   $env:GOOSE_BIN_DIR  - Directory to which goose will be installed (default: $env:USERPROFILE\.local\bin)
#   $env:GOOSE_VERSION  - Optional: specific version to install (e.g., "v1.0.25"). Can be in the format vX.Y.Z, vX.Y.Z-suffix, or X.Y.Z
#   $env:GOOSE_PROVIDER - Optional: provider for goose
#   $env:GOOSE_MODEL    - Optional: model for goose
#   $env:GOOSE_WINDOWS_VARIANT - Optional: Windows package variant to install ("standard" or "cuda")
#   $env:CANARY         - Optional: if set to "true", downloads from canary release instead of stable
#   $env:CONFIGURE      - Optional: if set to "false", disables running goose configure interactively
##############################################################################

# Set error action preference to stop on errors
$ErrorActionPreference = "Stop"

# --- 1) Variables ---
$REPO = "kineticquant/achilles-harness"
$OUT_FILE = "achilles.exe"

# Set default bin directory if not specified
if (-not $env:GOOSE_BIN_DIR) {
    $env:GOOSE_BIN_DIR = Join-Path $env:USERPROFILE ".local\bin"
}

# Determine release type
$RELEASE = if ($env:CANARY -eq "true") { "true" } else { "false" }
$CONFIGURE = if ($env:CONFIGURE -eq "false") { "false" } else { "true" }
$WINDOWS_VARIANT = if ($env:GOOSE_WINDOWS_VARIANT) { $env:GOOSE_WINDOWS_VARIANT.ToLowerInvariant() } else { "standard" }

# Determine release tag
if ($env:GOOSE_VERSION) {
    # Validate version format
    if ($env:GOOSE_VERSION -notmatch '^v?[0-9]+\.[0-9]+\.[0-9]+(-.*)?$') {
        Write-Error "Invalid version '$env:GOOSE_VERSION'. Expected: semver format vX.Y.Z, vX.Y.Z-suffix, or X.Y.Z"
        exit 1
    }
    # Ensure version starts with 'v'
    $RELEASE_TAG = if ($env:GOOSE_VERSION.StartsWith("v")) { $env:GOOSE_VERSION } else { "v$env:GOOSE_VERSION" }
} else {
    # Use canary or stable based on RELEASE variable
    $RELEASE_TAG = if ($RELEASE -eq "true") { "canary" } else { "stable" }
}

# --- 2) Detect Architecture ---
$ARCH = $env:PROCESSOR_ARCHITECTURE
if ($ARCH -eq "AMD64") {
    $ARCH = "x86_64"
} elseif ($ARCH -eq "ARM64") {
    Write-Error "Windows ARM64 is not currently supported."
    exit 1
} else {
    Write-Error "Unsupported architecture '$ARCH'. Only x86_64 is supported on Windows."
    exit 1
}

if ($WINDOWS_VARIANT -ne "standard" -and $WINDOWS_VARIANT -ne "cuda") {
    Write-Error "Unsupported GOOSE_WINDOWS_VARIANT '$WINDOWS_VARIANT'. Expected 'standard' or 'cuda'."
    exit 1
}

# --- 3) Build download URL ---
$FILE = if ($WINDOWS_VARIANT -eq "cuda") { "achilles-$ARCH-pc-windows-msvc-cuda.zip" } else { "achilles-$ARCH-pc-windows-msvc.zip" }
$DOWNLOAD_URL = "https://github.com/$REPO/releases/download/$RELEASE_TAG/$FILE"

Write-Host "Downloading $RELEASE_TAG release: $FILE..." -ForegroundColor Green

# --- 4) Download the file (fall back to legacy goose asset name) ---
try {
    Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile $FILE -UseBasicParsing
    Write-Host "Download completed successfully." -ForegroundColor Green
} catch {
    $LEGACY_FILE = $FILE -replace '^achilles-', 'goose-'
    $LEGACY_URL = $DOWNLOAD_URL -replace 'achilles-', 'goose-'
    Write-Host "Achilles asset not found, trying legacy name: $LEGACY_FILE..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $LEGACY_URL -OutFile $FILE -UseBasicParsing
        Write-Host "Download completed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to download $DOWNLOAD_URL. Error: $($_.Exception.Message)"
        exit 1
    }
}

# --- 5) Create temporary directory for extraction ---
$TMP_DIR = Join-Path $env:TEMP "goose_install_$(Get-Random)"
try {
    New-Item -ItemType Directory -Path $TMP_DIR -Force | Out-Null
    Write-Host "Created temporary directory: $TMP_DIR" -ForegroundColor Yellow
} catch {
    Write-Error "Could not create temporary extraction directory: $TMP_DIR"
    exit 1
}

# --- 6) Extract the archive ---
Write-Host "Extracting $FILE to temporary directory..." -ForegroundColor Green
try {
    Expand-Archive -Path $FILE -DestinationPath $TMP_DIR -Force
    Write-Host "Extraction completed successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to extract $FILE. Error: $($_.Exception.Message)"
    Remove-Item -Path $TMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# Clean up the downloaded archive
Remove-Item -Path $FILE -Force

# --- 7) Determine extraction directory ---
$EXTRACT_DIR = $TMP_DIR
if (Test-Path (Join-Path $TMP_DIR "achilles-package")) {
    Write-Host "Found achilles-package subdirectory, using that as extraction directory" -ForegroundColor Yellow
    $EXTRACT_DIR = Join-Path $TMP_DIR "achilles-package"
} elseif (Test-Path (Join-Path $TMP_DIR "goose-package")) {
    Write-Host "Found goose-package subdirectory, using that as extraction directory" -ForegroundColor Yellow
    $EXTRACT_DIR = Join-Path $TMP_DIR "goose-package"
}

# --- 8) Create bin directory if it doesn't exist ---
if (-not (Test-Path $env:GOOSE_BIN_DIR)) {
    Write-Host "Creating directory: $env:GOOSE_BIN_DIR" -ForegroundColor Yellow
    try {
        New-Item -ItemType Directory -Path $env:GOOSE_BIN_DIR -Force | Out-Null
    } catch {
        Write-Error "Could not create directory: $env:GOOSE_BIN_DIR"
        Remove-Item -Path $TMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# --- 9) Install achilles binary (fall back to legacy goose binary) ---
$SOURCE_ACHILLES = Join-Path $EXTRACT_DIR "achilles.exe"
$SOURCE_GOOSE = Join-Path $EXTRACT_DIR "goose.exe"
$SOURCE_BIN = if (Test-Path $SOURCE_ACHILLES) { $SOURCE_ACHILLES } else { $SOURCE_GOOSE }
$DEST_BIN = Join-Path $env:GOOSE_BIN_DIR $OUT_FILE

if (Test-Path $SOURCE_BIN) {
    Write-Host "Moving achilles to $DEST_BIN" -ForegroundColor Green
    try {
        # Remove existing file if it exists to avoid conflicts
        if (Test-Path $DEST_BIN) {
            Remove-Item -Path $DEST_BIN -Force
        }
        Move-Item -Path $SOURCE_BIN -Destination $DEST_BIN -Force
    } catch {
        Write-Error "Failed to move achilles.exe to $DEST_BIN. Error: $($_.Exception.Message)"
        Remove-Item -Path $TMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
} else {
    Write-Error "achilles.exe not found in extracted files"
    Remove-Item -Path $TMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# --- 10) Copy Windows runtime DLLs if they exist ---
$DLL_FILES = Get-ChildItem -Path $EXTRACT_DIR -Filter "*.dll" -ErrorAction SilentlyContinue
foreach ($dll in $DLL_FILES) {
    $DEST_DLL = Join-Path $env:GOOSE_BIN_DIR $dll.Name
    Write-Host "Moving Windows runtime DLL: $($dll.Name)" -ForegroundColor Green
    try {
        # Remove existing file if it exists to avoid conflicts
        if (Test-Path $DEST_DLL) {
            Remove-Item -Path $DEST_DLL -Force
        }
        Move-Item -Path $dll.FullName -Destination $DEST_DLL -Force
    } catch {
        Write-Warning "Failed to move $($dll.Name): $($_.Exception.Message)"
    }
}

# --- 11) Clean up temporary directory ---
try {
    Remove-Item -Path $TMP_DIR -Recurse -Force
    Write-Host "Cleaned up temporary directory." -ForegroundColor Yellow
} catch {
    Write-Warning "Could not clean up temporary directory: $TMP_DIR"
}

# --- 12) Configure achilles (Optional) ---
if ($CONFIGURE -eq "true") {
    Write-Host ""
    Write-Host "Configuring achilles" -ForegroundColor Green
    Write-Host ""
    try {
        & $DEST_BIN configure
    } catch {
        Write-Warning "Failed to run achilles configure. You may need to run it manually later."
    }
} else {
    Write-Host "Skipping 'achilles configure', you may need to run this manually later" -ForegroundColor Yellow
}

# --- 13) Check PATH and give instructions if needed ---
$CURRENT_PATH = $env:PATH
if ($CURRENT_PATH -notlike "*$env:GOOSE_BIN_DIR*") {
    Write-Host ""
    Write-Host "Warning: achilles installed, but $env:GOOSE_BIN_DIR is not in your PATH." -ForegroundColor Yellow
    Write-Host "To add it to your PATH permanently, run the following command as Administrator:" -ForegroundColor Yellow
    Write-Host "    [Environment]::SetEnvironmentVariable('PATH', `$env:PATH + ';$env:GOOSE_BIN_DIR', 'Machine')" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Or add it to your user PATH (no admin required):" -ForegroundColor Yellow
    Write-Host "    [Environment]::SetEnvironmentVariable('PATH', `$env:PATH + ';$env:GOOSE_BIN_DIR', 'User')" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "For this session only, you can run:" -ForegroundColor Yellow
    Write-Host "    `$env:PATH += ';$env:GOOSE_BIN_DIR'" -ForegroundColor Cyan
    Write-Host ""
}

Write-Host "achilles CLI installation completed successfully!" -ForegroundColor Green
Write-Host "achilles is installed at: $DEST_BIN" -ForegroundColor Green
