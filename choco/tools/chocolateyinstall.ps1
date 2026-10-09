$ErrorActionPreference = 'Stop'
$packageName = 'blackout-kit'
$url64 = 'https://github.com/kiacoder/blackout-kit/releases/download/v1.1.1/blackout.exe'
# Placeholder digest: 64 zero characters. This is NOT a real artifact hash and is substituted with
# the release SHA-256 by release automation before the package is published. Because it can never
# match a real binary, the install fails closed instead of accepting an unverified download.
# Do not publish this package while the placeholder is still in place.
$checksum64 = '0' * 64
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

Get-ChocolateyWebFile -PackageName "$packageName" `
                      -FileFullPath "$toolsDir\blackout.exe" `
                      -Url "$url64" `
                      -Checksum "$checksum64" `
                      -ChecksumType 'sha256'

$configDir = "$env:APPDATA\blackout-kit"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

Install-ChocolateyPath "$toolsDir" -PathType 'Machine'
Write-Host "Blackout Kit installed! Run 'blackout' to get started."
