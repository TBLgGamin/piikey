<#
.SYNOPSIS
  Packs the release folder into the MSIX package for the Microsoft Store: dist\piikey-<Version>-x64.msix.

.DESCRIPTION
  package.ps1 runs it last, with the identity of a test build. To make the package that goes to
  Partner Center, pass the identity of the app's Store listing (Partner Center: Product identity).
  Alone it needs dist\piikey\, the release folder package.ps1 stages, and the Windows SDK
  (makeappx.exe), which the Windows runners and every Visual Studio with the C++ tools have.

  The package is not signed: the Store signs it. packaging\windows\smoke-msix.ps1 signs a copy with a
  throwaway certificate to install it on a CI runner. It is not in SHA256SUMS.txt and not part of a
  GitHub release: the Store is where it is distributed.

  Output:  dist\piikey-<Version>-x64.msix   the package
           dist\msix\                       what it was packed from (the release folder, the filled-in
                                            AppxManifest.xml and Assets\)

.PARAMETER Version
  The version of the build, as in Cargo.toml (for example 0.2.1). The package version is
  (major + 1).minor.patch.0, here 1.2.1.0: the Store does not take a package whose first number is
  0, and piikey is 0.x; it keeps the fourth number for itself. The order of the versions is kept.

.PARAMETER IdentityName
  Package/Identity/Name. Test builds: piikey.dev.

.PARAMETER Publisher
  Package/Identity/Publisher, the distinguished name of the publisher (CN=...). Test builds:
  CN=piikey-dev. A package is signed with a certificate whose subject is exactly this.

.PARAMETER PublisherDisplayName
  Package/Properties/PublisherDisplayName, the publisher as users read it in the Store.

.PARAMETER StageDir
  The release folder to pack. Default: dist\piikey.

.EXAMPLE
  pwsh packaging/windows/package-msix.ps1 -Version 0.2.0

.EXAMPLE
  pwsh packaging/windows/package-msix.ps1 -Version 0.2.0 -IdentityName 12345TBLgGamin.piikey -Publisher 'CN=1A2B3C4D-0000-0000-0000-000000000000' -PublisherDisplayName TBLgGamin
#>
param(
    [Parameter(Mandatory)][string]$Version,
    [string]$IdentityName = 'piikey.dev',
    [string]$Publisher = 'CN=piikey-dev',
    [string]$PublisherDisplayName = 'TBLgGamin',
    [string]$StageDir
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dist = Join-Path $root 'dist'
if (-not $StageDir) {
    $StageDir = Join-Path $dist 'piikey'
}
$layout = Join-Path $dist 'msix'
$msix = Join-Path $dist "piikey-$Version-x64.msix"

# 1. What the manifest is filled with. The identity is the Store's: a wrong one is only found when
# Partner Center refuses the package, so check what can be checked here.
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "the version must be x.y.z (a package version is x.y.z.0), not '$Version'"
}
# The Store takes no package whose first number is 0, and piikey is 0.x: (major + 1).minor.patch.0
# keeps the order of the versions (1.0.0 becomes 2.0.0.0, after 1.9.9.0), and the fourth number
# is the Store's.
$parts = $Version.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] + 1 -gt 65535 -or $parts[1] -gt 65535 -or $parts[2] -gt 65535) {
    throw "'$Version' does not fit a package version: each number is at most 65535"
}
$packageVersion = '{0}.{1}.{2}.0' -f ($parts[0] + 1), $parts[1], $parts[2]
if ($IdentityName -notmatch '^[-A-Za-z0-9.]{3,50}$') {
    throw "'$IdentityName' is not a package name: 3 to 50 letters, digits, dots and dashes"
}
if ($Publisher -notmatch '^CN=') {
    throw "the publisher must be a distinguished name that starts with CN=, not '$Publisher'"
}
if ([string]::IsNullOrWhiteSpace($PublisherDisplayName)) {
    throw 'the publisher display name is empty'
}
foreach ($exe in 'piikey.exe', 'piikey-cli.exe') {
    $path = Join-Path $StageDir $exe
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing $path : run packaging\windows\package.ps1 first"
    }
}
$built = (Get-Item -LiteralPath (Join-Path $StageDir 'piikey.exe')).VersionInfo.ProductVersion
if ($built -ne $Version) {
    throw "$StageDir holds piikey.exe $built, not $Version"
}

# 2. makeappx.exe: the newest Windows SDK that has one.
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$makeappx = Get-ChildItem -LiteralPath $kits -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\makeappx.exe' } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $makeappx) {
    throw "makeappx.exe not found under $kits (install the Windows SDK)"
}

# 3. The layout: the release folder, the manifest and the logos.
if (Test-Path -LiteralPath $layout) {
    Remove-Item -LiteralPath $layout -Recurse -Force
}
Remove-Item -LiteralPath $msix -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $layout | Out-Null
Get-ChildItem -LiteralPath $StageDir -Force | Copy-Item -Destination $layout -Recurse
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'msix\Assets') -Destination (Join-Path $layout 'Assets') -Recurse

$values = @{
    IdentityName         = $IdentityName
    Publisher            = $Publisher
    Version              = $packageVersion
    PublisherDisplayName = $PublisherDisplayName
}
$manifest = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'msix\AppxManifest.xml'))
foreach ($name in $values.Keys) {
    $manifest = $manifest.Replace("{{$name}}", [System.Security.SecurityElement]::Escape($values[$name]))
}
$left = [regex]::Matches($manifest, '\{\{\w+\}\}')
if ($left.Count -gt 0) {
    throw "AppxManifest.xml has values nothing fills in: $($left.Value -join ', ')"
}
[System.IO.File]::WriteAllText((Join-Path $layout 'AppxManifest.xml'), $manifest, (New-Object System.Text.UTF8Encoding($false)))

# 4. Pack. makeappx checks the manifest against the schema and the files it names. It prints a
# line for each of the files it packs: only what is not one of those is worth reading.
$log = & $makeappx pack /d $layout /p $msix /o
$exit = $LASTEXITCODE
$log | Where-Object { $_ -and ($exit -ne 0 -or $_ -notmatch '^Processing ') } | ForEach-Object { Write-Host $_ }
if ($exit -ne 0) {
    throw "makeappx failed with exit code $exit"
}
if (-not (Test-Path -LiteralPath $msix)) {
    throw "makeappx did not write $msix"
}

Get-Item -LiteralPath $msix | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "package $IdentityName $packageVersion (piikey $Version) by $Publisher"
