$ErrorActionPreference = 'Stop'
$packageName = 'blackout-kit'
$url64 = 'https://github.com/kiacoder/blackout-kit/releases/download/v1.1.1/blackout.exe'

# SHA-256 digest of the packaged blackout.exe, in the exact shape a checksum
# verifier expects: 64 lowercase hexadecimal characters.
#
# This is a placeholder and it is deliberately useless: '0' * 64 does not
# describe any published binary. An earlier revision carried a value padded with
# non-hexadecimal characters, which static parsers could read as "a checksum is
# set" while no verifier could ever accept it. A well-formed placeholder keeps
# linters, parsers, and `choco pack` clean and still fails closed, and the guard
# below refuses the install before anything is downloaded.
#
# Replace it with the digest published for the release you are packaging
# (the `blackout.exe.sha256` asset) or supply it at install time:
#   choco install blackout-kit --package-parameters="checksum=<64 hex chars>"
$checksum64 = '0' * 64
$checksumPlaceholder = $checksum64

# Optional operator-supplied digest. Parsed here rather than trusted from the
# package body, so a repackaged install can pin a different release without
# editing this script - and a malformed value is rejected instead of ignored.
$packageParameters = @{}
if ($env:ChocolateyPackageParameters) {
    foreach ($pair in ($env:ChocolateyPackageParameters -split '[\s;]+')) {
        $key, $value = $pair -split '=', 2
        if ($key -and $value) {
            $packageParameters[$key.Trim().ToLowerInvariant()] = $value.Trim().Trim('"', "'")
        }
    }
}
if ($packageParameters.ContainsKey('checksum')) {
    $supplied = $packageParameters['checksum'].ToLowerInvariant()
    if ($supplied -notmatch '^[0-9a-f]{64}$') {
        throw "blackout-kit: 'checksum' must be exactly 64 hexadecimal characters (SHA-256). Nothing was downloaded."
    }
    $checksum64 = $supplied
}

if ($checksum64 -eq $checksumPlaceholder) {
    throw "blackout-kit: this package has no published SHA-256 digest. Refusing to install an unverified binary - set the digest in chocolateyinstall.ps1 from the release's blackout.exe.sha256 asset, or pass --package-parameters=""checksum=<64 hex chars>""."
}

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
Write-Host "Blackout Kit installed (SHA-256 verified: $checksum64)."
