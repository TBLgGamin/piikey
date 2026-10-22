<#
.SYNOPSIS
  Packages a release build into dist\: the portable zip, the per-user installer, SHA256SUMS.txt and the MSIX package for the Microsoft Store.

.DESCRIPTION
  Build first:  cargo build --release --workspace --locked
  Needs:        cargo-about (cargo install cargo-about --locked --features cli), Inno Setup 6 and, for the
                MSIX, the Windows SDK (makeappx.exe).
  CI runs it from .github/workflows/release-assets.yml.

  Output:       dist\piikey\                           the release folder (what the zip and installer hold)
                dist\piikey-<Version>-windows-x64.zip  portable: unzip anywhere, run piikey.exe
                dist\piikey-<Version>-setup-x64.exe    installer
                dist\SHA256SUMS.txt                    SHA-256 of the zip and the installer
                dist\piikey-<Version>-x64.msix         the Microsoft Store package (package-msix.ps1), not in SHA256SUMS.txt

.PARAMETER Version
  The version of the build in target\release, as in Cargo.toml (for example 0.1.0).

.PARAMETER SkipMsix
  Leave out the MSIX package. CI does, and runs package-msix.ps1 in a step of its own.

.PARAMETER MsixIdentityName
.PARAMETER MsixPublisher
.PARAMETER MsixPublisherDisplayName
  The identity of the MSIX package, as package-msix.ps1 takes it (IdentityName, Publisher,
  PublisherDisplayName). Without them it is the identity of a test build, piikey.dev.

.EXAMPLE
  pwsh packaging/windows/package.ps1 -Version 0.1.0
#>
param(
    [Parameter(Mandatory)][string]$Version,
    [switch]$SkipMsix,
    [string]$MsixIdentityName,
    [string]$MsixPublisher,
    [string]$MsixPublisherDisplayName
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root

$src = Join-Path $root 'target\release'
$dist = Join-Path $root 'dist'
$stage = Join-Path $dist 'piikey'
$zip = Join-Path $dist "piikey-$Version-windows-x64.zip"
$setup = Join-Path $dist "piikey-$Version-setup-x64.exe"
$sums = Join-Path $dist 'SHA256SUMS.txt'

# 1. The release build must be there, and be the version being packaged.
foreach ($exe in 'piikey.exe', 'piikey-cli.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $src $exe))) {
        throw 'build first: cargo build --release --workspace --locked'
    }
}
$built = & (Join-Path $src 'piikey-cli.exe') --version
if ($LASTEXITCODE -ne 0 -or "$built" -ne "piikey-cli $Version") {
    throw "target\release holds '$built', not version ${Version}: rebuild with cargo build --release --workspace --locked"
}

# 2. A fresh release folder.
Remove-Item -LiteralPath $zip, $setup, $sums -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path $stage | Out-Null

# 3. The two exes, the Windows App SDK runtime next to them (DLLs, .pri indexes, locale and asset
# folders) and DirectML.dll. The rest of target\release is build output. File.Copy follows links:
# DirectML.dll is a link into the ort download cache and must be shipped as a file.
$skip = 'build', 'deps', 'examples', 'incremental', '.fingerprint'
Get-ChildItem -LiteralPath $src -File |
    Where-Object { $_.Name -in 'piikey.exe', 'piikey-cli.exe' -or $_.Extension -in '.dll', '.pri' } |
    ForEach-Object { [System.IO.File]::Copy($_.FullName, (Join-Path $stage $_.Name), $true) }
Get-ChildItem -LiteralPath $src -Directory -Force |
    Where-Object { $_.Name -notin $skip } |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $stage -Recurse }
$links = Get-ChildItem -LiteralPath $stage -Recurse -Force |
    Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint }
if ($links) {
    throw "the release folder holds links, not files: $($links.FullName -join ', ')"
}

# 4. License, notices and the license texts of the non-crate components, if any.
Copy-Item -LiteralPath 'LICENSE' -Destination (Join-Path $stage 'LICENSE.txt')
Copy-Item -LiteralPath 'NOTICE.md' -Destination $stage
$licenseDir = 'packaging\windows\licenses'
$licenseFiles = if (Test-Path -LiteralPath $licenseDir) { Get-ChildItem -LiteralPath $licenseDir -Force }
if ($licenseFiles) {
    $target = Join-Path $stage 'licenses'
    New-Item -ItemType Directory -Path $target | Out-Null
    $licenseFiles | Copy-Item -Destination $target -Recurse
}

# 5. The licenses of the Rust crates. --workspace: without it the app's crates are left out.
cargo about generate --locked --workspace packaging/windows/about.hbs -o (Join-Path $stage 'THIRD_PARTY_LICENSES.html')
if ($LASTEXITCODE -ne 0) {
    throw 'cargo about failed (cargo install cargo-about --locked --features cli)'
}

# 6. The portable zip. The folder itself goes in, so unzipping gives piikey\...
# Entry by entry with forward-slash names: Compress-Archive of Windows PowerShell 5.1 writes
# backslashes, which is not a valid zip.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::Open($zip, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File -Force) {
        $entry = 'piikey/' + $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entry, [System.IO.Compression.CompressionLevel]::Optimal)
    }
}
finally {
    $archive.Dispose()
}

# 7. The installer.
$iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
if (-not (Test-Path -LiteralPath $iscc)) {
    throw 'Inno Setup 6 not found'
}
& $iscc /Qp "/DAppVersion=$Version" "/DSourceDir=$stage" "/DOutputDir=$dist" 'packaging\windows\piikey.iss'
if ($LASTEXITCODE -ne 0) {
    throw "ISCC failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $setup)) {
    throw "ISCC did not write $setup"
}

# 8. SHA256SUMS.txt in the format of sha256sum: lowercase hash, two spaces, name; LF, no BOM.
$lines = foreach ($file in $zip, $setup) {
    '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant(), (Split-Path $file -Leaf)
}
[System.IO.File]::WriteAllText($sums, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

# 9. The MSIX package for the Microsoft Store. It is not in SHA256SUMS.txt: the Store, not a release,
# is where it is distributed.
if (-not $SkipMsix) {
    $identity = @{}
    if ($MsixIdentityName) { $identity.IdentityName = $MsixIdentityName }
    if ($MsixPublisher) { $identity.Publisher = $MsixPublisher }
    if ($MsixPublisherDisplayName) { $identity.PublisherDisplayName = $MsixPublisherDisplayName }
    & (Join-Path $PSScriptRoot 'package-msix.ps1') -Version $Version -StageDir $stage @identity
}

Get-ChildItem -LiteralPath $dist -File | Select-Object Name, Length | Format-Table -AutoSize
