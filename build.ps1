#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for EvasionEngine.

.PARAMETER Config
    Debug or Release (default: Release)

.PARAMETER Arch
    x64 or x86 (default: x64)

.PARAMETER Clean
    Wipe the build directory before configuring.

.PARAMETER VS
    Visual Studio year: 2022 or 2019 (default: 2022)

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Config Debug -Clean
    .\build.ps1 -Config Release -Test
#>
[CmdletBinding()]
param(
    [ValidateSet("Debug","Release")]
    [string]$Config       = "Release",

    [ValidateSet("x64","x86")]
    [string]$Arch         = "x64",

    [switch]$Clean,

    [ValidateSet("2022","2019")]
    [string]$VS           = "2022"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Paths ------------------------------------------------------------------
$Root     = $PSScriptRoot
$BuildDir = Join-Path $Root "build\$Arch-$Config"
$BinDir   = Join-Path $Root "bin"
$Harness  = Join-Path $Root "tools\test-harness.py"

# -- Helpers ----------------------------------------------------------------
function Write-Step { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan   }
function Write-OK   { param($msg) Write-Host "[+] $msg" -ForegroundColor Green  }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "[-] $msg" -ForegroundColor Red    }

function Assert-Exit {
    param([int]$Code, [string]$Step)
    if ($Code -ne 0) { Write-Fail "$Step failed (exit $Code)."; exit $Code }
}

# -- Banner -----------------------------------------------------------------
Write-Host ""
Write-Host "  EvasionEngine Build" -ForegroundColor Magenta
Write-Host "  Config: $Config  |  Arch: $Arch" -ForegroundColor DarkGray
Write-Host ""

# -- Prereq: cmake ----------------------------------------------------------
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Write-Fail "cmake not found in PATH. Install CMake and retry."
    exit 1
}

# -- Clean ------------------------------------------------------------------
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Step "Cleaning $BuildDir ..."
    Remove-Item $BuildDir -Recurse -Force
    Write-OK "Clean complete."
}

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# -- Generator selection ----------------------------------------------------
$Generator = @{ "2022" = "Visual Studio 17 2022"; "2019" = "Visual Studio 16 2019" }[$VS]
$Platform  = if ($Arch -eq "x64") { "x64" } else { "Win32" }

# -- Configure --------------------------------------------------------------
Write-Step "Configuring ($Generator / $Platform / $Config)..."

& cmake `
    -S $Root `
    -B $BuildDir `
    -G $Generator `
    -A $Platform `
    "-DCMAKE_BUILD_TYPE=$Config" `

Assert-Exit $LASTEXITCODE "Configure"

# -- Build ------------------------------------------------------------------
Write-Step "Building..."

$BuildArgs = @("--build", $BuildDir, "--config", $Config, "--parallel")
if ($PSBoundParameters.ContainsKey("Verbose")) { $BuildArgs += "--verbose" }

& cmake @BuildArgs
Assert-Exit $LASTEXITCODE "Build"

# -- Locate binary ----------------------------------------------------------
$Binary = Join-Path $BinDir "EvasionEngine.exe"

if (-not (Test-Path $Binary)) {
    Write-Warn "Binary not found at $Binary -- check POST_BUILD output above."
} else {
    $sizeKB = [math]::Round((Get-Item $Binary).Length / 1024, 1)
    Write-OK "Binary ready: $Binary  ($sizeKB KB)"
}

Write-Host ""
Write-OK "Done. Artifacts in: $BinDir\"
Write-Host ""