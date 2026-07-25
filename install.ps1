$ErrorActionPreference = "Stop"

Write-Host "🚀 Installing Blackout Kit..." -ForegroundColor Cyan

# 1. Define installation directory
$InstallDir = "$env:LOCALAPPDATA\BlackoutKit"
if (-Not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ExePath = Join-Path -Path $InstallDir -ChildPath "blackout.exe"

# 2. Fetch latest release from GitHub
Write-Host "⬇️ Downloading latest release..." -ForegroundColor Yellow
$ApiUrl = "https://api.github.com/repos/kiacoder/blackout-kit/releases/latest"
$Release = Invoke-RestMethod -Uri $ApiUrl
$Asset = $Release.assets | Where-Object { $_.name -eq "blackout.exe" }

if (-not $Asset) {
    Write-Error "Could not find blackout.exe in the latest release!"
    exit 1
}

Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $ExePath
Write-Host "✅ Download complete!" -ForegroundColor Green

# 3. Add to User PATH if not already present
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "🔧 Adding Blackout Kit to your PATH..." -ForegroundColor Yellow
    $NewPath = "$UserPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    $env:PATH = "$env:PATH;$InstallDir" # Update current session
}

# 4. Initialize and run doctor
Write-Host "⚙️ Initializing environment and checking dependencies..." -ForegroundColor Yellow
& $ExePath doctor

Write-Host ""
Write-Host "🎉 Installation Successful!" -ForegroundColor Green
Write-Host "You can now open a new terminal and type 'blackout connect' to start bypassing!" -ForegroundColor Cyan
