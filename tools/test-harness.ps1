param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [string]$LogFile = "qa_test_harness.log"
)

# ------------------------------------------------------------
# Utility: Write telemetry entry
# ------------------------------------------------------------
function Write-Telemetry {
    param(
        [string]$LogFile,
        [string]$DstDir,
        [string]$DstFilename,
        [string]$Parameters,
        [string]$ExitCode,
        [bool]$FileStillPresent
    )

    $entry = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        dstDir = $DstDir
        dstFilename = $DstFilename
        parameters = $Parameters
        exit_code = $ExitCode
        file_still_present_after_run = $FileStillPresent
    }

    $json = $entry | ConvertTo-Json -Compress
    Add-Content -Path $LogFile -Value $json
}

# ------------------------------------------------------------
# Staging Actions
# ------------------------------------------------------------

function Stage-Copy {
    param($Stage)

    $src = Join-Path $Stage.src_dir $Stage.src_filename
    $dst = Join-Path $Stage.dst_dir $Stage.dst_filename

    if (-not (Test-Path $src)) {
        Write-Host "[-] Source missing: $src"
        return $null
    }

    if (-not (Test-Path $Stage.dst_dir)) {
        New-Item -ItemType Directory -Path $Stage.dst_dir -Force | Out-Null
    }

    if (Test-Path $dst) {
        $resp = Read-Host "[?] '$dst' exists. Overwrite? (y/n)"
        if ($resp -ne 'y') {
            Write-Host "[*] Skipping copy for $dst"
            return $null
        }
    }

    Copy-Item -Path $src -Destination $dst -Force
    Write-Host "[+] Staged file: $src -> $dst"
    return $dst
}

function Stage-Mkdir {
    param($Stage)
    New-Item -ItemType Directory -Path $Stage.dst_dir -Force | Out-Null
    Write-Host "[+] Created directory: $($Stage.dst_dir)"
}

function Stage-Delete {
    param($Stage)
    $dst = Join-Path $Stage.dst_dir $Stage.dst_filename

    if (Test-Path $dst) {
        Remove-Item $dst -Force
        Write-Host "[+] Deleted file: $dst"
    } else {
        Write-Host "[!] delete skipped; file not found: $dst"
    }
}

function Stage-Command {
    param($Stage)
    Write-Host "[*] Running command: $($Stage.cmd)"
    Invoke-Expression $Stage.cmd
}

function Stage-Env {
    param($Stage)

    if (-not $Stage.vars) {
        Write-Host "[!] env stage has no variables - skipping"
        return @{}
    }

    $scope = $Stage.scope
    if (-not $scope) { $scope = "process" }

    Write-Host "[+] Staging environment variables ($scope scope):"

    $envVars = @{}

    foreach ($kv in $Stage.vars.PSObject.Properties) {
        $name = $kv.Name
        $value = $kv.Value

        Write-Host "    $name = $value"

        if ($scope -eq "global") {
            # Global environment variable
            setx $name $value | Out-Null
        }

        # Process-level env vars (injected into Start-Process)
        $envVars[$name] = $value
    }

    return $envVars
}

# ------------------------------------------------------------
# Run all staging commands
# ------------------------------------------------------------
function Run-Staging {
    param($StagingList)

    $stagedFiles = @()
    $stagedEnv = @{}
    $firstExe = $null

    foreach ($stage in $StagingList) {
        switch ($stage.type) {
            "copy"    { $dst = Stage-Copy $stage; if ($dst) { if (-not $firstExe) { $firstExe = $dst } $stagedFiles += $dst } }
            "mkdir"   { Stage-Mkdir $stage }
            "delete"  { Stage-Delete $stage }
            "command" { Stage-Command $stage }
            "env"     { $vars = Stage-Env $stage; $stagedEnv += $vars }
            default   { Write-Host "[!] Unknown staging type '$($stage.type)' - skipping" }
        }
    }

    return @{ files = $stagedFiles; env = $stagedEnv; exe = $firstExe }
}

# ------------------------------------------------------------
# Execute a single test case
# ------------------------------------------------------------
function Process-TestCase {
    param($TestCase, $LogFile)

    $staging = $TestCase.staging
    $parameters = $TestCase.parameters

    Write-Host "[*] Running staging commands..."
    $result = Run-Staging $staging

    $stagedFiles = $result.files
    $stagedEnv   = $result.env

    if ($stagedFiles.Count -eq 0) {
        Write-Host "[-] No staged executable found. Skipping."
        return
    }

    $exe = $result.exe
    Write-Host "[+] Selected executable: $exe"

    $args = $parameters

    Write-Host "[*] Executing: $exe $args"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = $args
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    foreach ($kv in $stagedEnv.GetEnumerator()) {
        $psi.EnvironmentVariables[$kv.Key] = $kv.Value
    }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null

    #$timeoutMs = 300000  # 5 minutes
    $timeoutMs = 120000  # 2 minutes
    if (-not $proc.WaitForExit($timeoutMs)) {
        Write-Host "[!] Timeout exceeded - killing process"
        $proc.Kill()
        $exitCode = "KILLED_TIMEOUT"
    } else {
        $exitCode = $proc.ExitCode
        Write-Host "[+] Process terminated with exit code $exitCode"
    }

    Start-Sleep -Milliseconds 750

    # initialize to false
    $fileStillPresent = $false
    # Cleanup
    foreach ($f in $stagedFiles) {
        if (Test-Path $f) {
            if ($f -eq $exe) {
                $fileStillPresent = $true    
            }
            Remove-Item $f -Force
            Write-Host "[+] Deleted staged file: $f"
        }
    }

    $dstDir = Split-Path $exe -Parent
    $dstFilename = Split-Path $exe -Leaf

    Write-Telemetry -LogFile $LogFile `
                    -DstDir $dstDir `
                    -DstFilename $dstFilename `
                    -Parameters $parameters `
                    -ExitCode $exitCode `
                    -FileStillPresent $fileStillPresent

    Write-Host "[+] Telemetry captured."
    Write-Host "--------------------------------------------------"
}

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

if (-not (Test-Path $InputFile)) {
    Write-Host "[-] Input file not found: $InputFile"
    exit 1
}

$configRaw = Get-Content $InputFile -Raw
$config = $configRaw | ConvertFrom-Json

Write-Host "[*] Starting test suite..."
Write-Host "=================================================="

if ($config -is [System.Collections.IEnumerable]) {
    foreach ($tc in $config) {
        Process-TestCase -TestCase $tc -LogFile $LogFile
    }
} else {
    Process-TestCase -TestCase $config -LogFile $LogFile
}

Write-Host "[*] Test suite complete."
