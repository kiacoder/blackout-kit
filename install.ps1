$ErrorActionPreference = "Stop"

Write-Host "Installing Blackout Kit..." -ForegroundColor Cyan

# 1. Define installation directory
$InstallDir = "$env:LOCALAPPDATA\BlackoutKit"
if (-Not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ExePath = Join-Path -Path $InstallDir -ChildPath "blackout.exe"
# The binary is staged beside the install target and moved into place only after
# its SHA-256 matches the release checksum. An unverified file therefore never
# replaces a working install and is never executed.
$StagedPath = Join-Path -Path $InstallDir -ChildPath "blackout.exe.download"
$ChecksumPath = Join-Path -Path $InstallDir -ChildPath "release-checksums.download"

function Stop-Install {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    Remove-Item -LiteralPath $StagedPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ChecksumPath -Force -ErrorAction SilentlyContinue
    exit 1
}

# Returns the single lowercase SHA-256 published for $FileName, or $null when the
# checksum text has no entry, several conflicting entries, or a malformed hash.
# Accepts sha256sum lines ("<hash>  <name>" or "<hash> *<name>") and bare-hash files.
function Get-ExpectedSha256 {
    param([string]$Text, [string]$FileName)
    $Hashes = @()
    foreach ($Line in ($Text -split '\r?\n')) {
        $Trimmed = $Line.TrimStart([char]0xFEFF).Trim()
        if ($Trimmed -eq "") { continue }
        $Parts = $Trimmed -split "\s+", 2
        if ($Parts.Count -eq 2) {
            $Name = $Parts[1].TrimStart("*").Trim()
        } else {
            $Name = $FileName
        }
        if ($Name -ieq $FileName) {
            $Hashes += $Parts[0].Trim().ToLowerInvariant()
        }
    }
    $Distinct = @($Hashes | Sort-Object -Unique)
    if ($Distinct.Count -ne 1) { return $null }
    if ($Distinct[0] -notmatch '^[0-9a-f]{64}$') { return $null }
    return $Distinct[0]
}

# 2. Fetch latest release from GitHub
Write-Host "Downloading latest release..." -ForegroundColor Yellow
$ApiUrl = "https://api.github.com/repos/kiacoder/blackout-kit/releases/latest"
$Release = Invoke-RestMethod -Uri $ApiUrl
$Asset = $Release.assets | Where-Object { $_.name -eq "blackout.exe" } | Select-Object -First 1

if (-not $Asset) {
    Stop-Install "Could not find blackout.exe in the latest release!"
}

# A SHA-256 checksum must be published with the release, and it is checked before
# the binary is downloaded. Prefer checksums.txt (all release assets), then fall back
# to blackout.exe.sha256.
$ChecksumAsset = $Release.assets | Where-Object { $_.name -eq "checksums.txt" } | Select-Object -First 1
if (-not $ChecksumAsset) {
    $ChecksumAsset = $Release.assets | Where-Object { $_.name -eq "blackout.exe.sha256" } | Select-Object -First 1
}
if (-not $ChecksumAsset) {
    Stop-Install "The latest release publishes no SHA-256 checksum (checksums.txt or blackout.exe.sha256). Refusing to install an unverified binary."
}

try {
    Invoke-WebRequest -UseBasicParsing -Uri $Asset.browser_download_url -OutFile $StagedPath
} catch {
    Stop-Install "Download of blackout.exe failed: $($_.Exception.Message)"
}

try {
    Invoke-WebRequest -UseBasicParsing -Uri $ChecksumAsset.browser_download_url -OutFile $ChecksumPath
    $ChecksumText = Get-Content -LiteralPath $ChecksumPath -Raw
} catch {
    Stop-Install "Could not download the release checksum file: $($_.Exception.Message)"
}

# 3. Verify the download before anything else touches it
$ExpectedHash = Get-ExpectedSha256 -Text $ChecksumText -FileName "blackout.exe"
if (-not $ExpectedHash) {
    Stop-Install "The release checksum for blackout.exe is missing, ambiguous, or malformed. The download was deleted."
}

$ActualHash = (Get-FileHash -LiteralPath $StagedPath -Algorithm SHA256).Hash
if (-not ($ActualHash.Trim() -ieq $ExpectedHash.Trim())) {
    Stop-Install "SHA-256 mismatch for blackout.exe (expected $ExpectedHash, got $ActualHash). The download was deleted."
}
Write-Host "[OK] SHA-256 checksum verified: $ActualHash" -ForegroundColor Green

Remove-Item -LiteralPath $ChecksumPath -Force -ErrorAction SilentlyContinue
try {
    Move-Item -LiteralPath $StagedPath -Destination $ExePath -Force
} catch {
    Stop-Install "Could not place the verified blackout.exe at $ExePath (is Blackout Kit running?): $($_.Exception.Message)"
}
Write-Host "Download complete." -ForegroundColor Green

# 4. Add to User PATH if not already present
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "Adding Blackout Kit to your PATH..." -ForegroundColor Yellow
    $NewPath = "$UserPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    $env:PATH = "$env:PATH;$InstallDir" # Update current session
}

# 5. Initialize and run doctor (read-only: it never changes Defender or firewall settings)
Write-Host "Initializing environment and checking dependencies..." -ForegroundColor Yellow
& $ExePath doctor

Write-Host ""
Write-Host "Installation successful!" -ForegroundColor Green
Write-Host "You can now open a new terminal and type 'blackout connect' to start bypassing!" -ForegroundColor Cyan
