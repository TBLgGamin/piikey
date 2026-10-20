<#
.SYNOPSIS
  Smoke test of the packaged release: the zip, then the installer and its uninstaller.

.DESCRIPTION
  For CI runners only (.github/workflows/release-assets.yml), after packaging\windows\package.ps1.
  Do not run it on a development machine: the installer stops a running piikey, and the uninstaller
  removes piikey's local CA from your Root store.

.PARAMETER Version
  The version that was packaged, as in Cargo.toml (for example 0.1.0).
#>
param([Parameter(Mandatory)][string]$Version)

$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
    throw 'smoke.ps1 installs and uninstalls piikey: run it on a CI runner only'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$zip = Join-Path $root "dist\piikey-$Version-windows-x64.zip"
$setup = Join-Path $root "dist\piikey-$Version-setup-x64.exe"
foreach ($file in $zip, $setup) {
    if (-not (Test-Path -LiteralPath $file)) {
        throw "missing ${file}: run packaging\windows\package.ps1 first"
    }
}

function Assert-CliVersion([string]$cli) {
    $out = (& $cli --version) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $out -ne "piikey-cli $Version") {
        throw "$cli --version printed '$out', expected 'piikey-cli $Version'"
    }
}

# 1. The zip: unzip anywhere and the CLI runs.
Write-Host '== zip'
$unzipped = Join-Path $env:RUNNER_TEMP 'zip'
if (Test-Path -LiteralPath $unzipped) {
    Remove-Item -LiteralPath $unzipped -Recurse -Force
}
Expand-Archive -LiteralPath $zip -DestinationPath $unzipped
$cli = Join-Path $unzipped 'piikey\piikey-cli.exe'
Assert-CliVersion $cli

# 2. The engine works without the model: an address is replaced by a stand-in.
Write-Host '== anonymize'
$address = 'jan.jansen@example.com'
$vault = Join-Path $env:RUNNER_TEMP 'v.pkv'
$masked = "Mail $address about it" | & $cli anonymize --vault $vault
if ($LASTEXITCODE -ne 0) {
    throw "anonymize exited with code $LASTEXITCODE"
}
$masked = $masked -join "`n"
if ($masked.Contains($address) -or -not $masked.Contains('about it')) {
    throw "anonymize did not mask the address as expected: '$masked'"
}

# 3. The installer, per user and silent.
Write-Host '== installer'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\piikey'
$log = Join-Path $env:RUNNER_TEMP 'setup.log'
$run = Start-Process -FilePath $setup -Wait -PassThru -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', "/LOG=""$log"""
if ($run.ExitCode -ne 0) {
    if (Test-Path -LiteralPath $log) {
        Get-Content -LiteralPath $log -Tail 40
    }
    throw "the installer exited with code $($run.ExitCode)"
}
Assert-CliVersion (Join-Path $installDir 'piikey-cli.exe')
$exe = Join-Path $installDir 'piikey.exe'
$product = (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion
if ($product -ne $Version) {
    throw "piikey.exe has ProductVersion '$product', expected '$Version'"
}

# 4. The uninstaller removes the app. Its first process hands over to a copy of itself, so wait for
# the result, not for the process.
Write-Host '== uninstaller'
$null = Start-Process -FilePath (Join-Path $installDir 'unins000.exe') -Wait -PassThru -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'
$deadline = (Get-Date).AddSeconds(60)
while ((Test-Path -LiteralPath $exe) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}
if (Test-Path -LiteralPath $exe) {
    throw "the uninstaller left $exe behind"
}

Write-Host "piikey ${Version}: zip, installer and uninstaller work"
