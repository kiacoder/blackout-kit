$ErrorActionPreference = 'Stop'
$packageName = 'blackout-kit'
$url64 = 'https://github.com/kiacoder/blackout-kit/releases/download/v1.1.1/blackout.exe'
$checksum64 = 'b4d8e4c3f2c0a1e5d7f9a8c2e4f6h8j0k2m4n6p8q0s2t4v6w8y0a2b4c6d8e0'
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
