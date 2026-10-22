<#
.SYNOPSIS
  Smoke test of the MSIX package: installs a signed copy, runs piikey inside the package, removes it.

.DESCRIPTION
  For CI runners only (.github/workflows/release-assets.yml), after packaging\windows\package-msix.ps1.
  Do not run it on a development machine: it trusts a throwaway certificate for the whole machine,
  installs the package, ends every running piikey and deletes piikey's data folder.

  dist\piikey-<Version>-x64.msix is not signed: the Store signs it. A copy is signed with a throwaway
  certificate whose subject is the publisher of the package, and that copy is installed. The unsigned
  package stays as it was; the copy and the certificate are removed again.

  What it checks, in this order:
    1. the identity and the version the package says it has
    2. a throwaway certificate, trusted for the machine, and a signed copy
    3. the VC++ framework the manifest depends on: installed, or supplied to Add-AppxPackage
    4. Add-AppxPackage
    5. the execution aliases piikey.exe and piikey-cli.exe, and piikey-cli --version through its alias
    6. piikey.exe, started through its alias: it stays up (the self-contained Windows App SDK runs
       inside a package), it has the identity of the package, and what it writes outside the package
       is real: the data folder and the Explorer verbs are not virtualized, and its watchdog runs
    7. every piikey process can be ended
    8. piikey.exe --restore-proxy reaches the real proxy settings and RunOnce key of Windows
    9. piikey.exe --unregister-shell removes the Explorer verbs
   10. Remove-AppxPackage removes the package and both aliases

  Every failure says what was expected and what was found, and prints what Windows logged.

.PARAMETER Version
  The version that was packaged, as in Cargo.toml (for example 1.0.0). The package says x.y.z.0:
  see package-msix.ps1.
#>
param([Parameter(Mandatory)][string]$Version)

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest and Add-AppxPackage draw progress bars, which only slow a CI log down.
$ProgressPreference = 'SilentlyContinue'

if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
    throw 'smoke-msix.ps1 installs a package and trusts a certificate for the whole machine: run it on a CI runner only'
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "the version must be x.y.z, not '$Version'"
}
# package-msix.ps1 packs x.y.z as x.y.z.0; the fourth number is the Store's.
$packageVersion = "$Version.0"

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$msix = Join-Path $root "dist\piikey-$Version-x64.msix"
if (-not (Test-Path -LiteralPath $msix)) {
    throw "missing ${msix}: run packaging\windows\package-msix.ps1 first"
}

# PowerShell 7 runs the Appx cmdlets in a Windows PowerShell session: load the module there, once.
# Windows PowerShell has the module itself (and no such parameter, which is never reached there).
if ($PSVersionTable.PSEdition -eq 'Core') {
    try {
        Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop
    }
    catch {
        Write-Host "Import-Module Appx -UseWindowsPowerShell failed ($($_.Exception.Message)); the first Appx cmdlet loads the module on its own"
    }
}

# Where things are. Windows puts the execution alias of every installed package in the first folder.
$aliasDir = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
$appAlias = Join-Path $aliasDir 'piikey.exe'
$cliAlias = Join-Path $aliasDir 'piikey-cli.exe'
$dataDir = Join-Path $env:LOCALAPPDATA 'piikey'
$work = Join-Path $env:RUNNER_TEMP 'msix-smoke'
$stdout = Join-Path $work 'piikey.stdout.txt'
$stderr = Join-Path $work 'piikey.stderr.txt'

# What the app writes to the registry of the user (app/src/sysproxy.rs and shell.rs), and where.
$hkcu = [Microsoft.Win32.Registry]::CurrentUser
$internetKey = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$runOnceKey = 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
$runOnceName = 'piikey proxy restore'
$proxyPort = 7979
$verbs = @(
    [pscustomobject]@{ Key = 'Software\Classes\*\shell\piikey.scan'; Argument = '%1' },
    [pscustomobject]@{ Key = 'Software\Classes\Directory\shell\piikey.scan'; Argument = '%1' },
    [pscustomobject]@{ Key = 'Software\Classes\Directory\Background\shell\piikey.scan'; Argument = '%V\.' }
)

# Set while the smoke test runs; the helpers below read them.
$app = $null
$package = $null
$started = Get-Date

# The text of a file that another process may still hold open for writing.
function Read-Text([string]$path) {
    try {
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            return (New-Object System.IO.StreamReader($stream)).ReadToEnd()
        }
        finally {
            $stream.Dispose()
        }
    }
    catch {
        return "(cannot read ${path}: $($_.Exception.Message))"
    }
}

function Show-File([string]$title, [string]$path) {
    Write-Host "--- $title"
    $text = (Read-Text $path).TrimEnd()
    if ($text) {
        Write-Host $text
    }
    else {
        Write-Host '(empty)'
    }
}

# Runs the condition every half second until it gives a value, and returns that value; $null once the
# seconds are up.
function Wait-For([int]$seconds, [scriptblock]$condition) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        $value = & $condition
        if ($value) {
            return $value
        }
        if ((Get-Date) -ge $deadline) {
            return $null
        }
        Start-Sleep -Milliseconds 500
    }
}

# The last events of a Windows log since a moment, as far as their text matches the pattern.
function Show-EventTail([string]$log, [datetime]$since, [string]$pattern = '.', [int]$max = 20) {
    Write-Host "--- log $log since $($since.ToString('HH:mm:ss'))"
    try {
        $found = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since } -MaxEvents 300 -ErrorAction Stop |
            Where-Object { $_.Message -match $pattern } |
            Select-Object -First $max)
    }
    catch {
        Write-Host "(nothing read: $($_.Exception.Message))"
        return
    }
    if ($found.Count -eq 0) {
        Write-Host '(no matching events)'
        return
    }
    [array]::Reverse($found)
    foreach ($entry in $found) {
        $text = $entry.Message -replace '\s+', ' '
        if ($text.Length -gt 600) {
            $text = $text.Substring(0, 600) + '...'
        }
        Write-Host ('{0:HH:mm:ss} {1} id {2}: {3}' -f $entry.TimeCreated, $entry.LevelDisplayName, $entry.Id, $text)
    }
}

# The identity and the dependencies an .msix or .appx says it has: read from the AppxManifest.xml in it.
function Read-PackageIdentity([string]$path) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($path)
    try {
        $entry = $archive.GetEntry('AppxManifest.xml')
        if (-not $entry) {
            throw "$path holds no AppxManifest.xml"
        }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try {
            $text = $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
    $xml = New-Object System.Xml.XmlDocument
    $xml.LoadXml($text)
    $identity = $xml.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Identity']")
    if (-not $identity) {
        throw "the AppxManifest.xml in $path has no Package/Identity"
    }
    $dependencies = @(foreach ($node in $xml.SelectNodes("/*[local-name()='Package']/*[local-name()='Dependencies']/*[local-name()='PackageDependency']")) {
            [pscustomobject]@{
                Name       = $node.GetAttribute('Name')
                MinVersion = $node.GetAttribute('MinVersion')
                Publisher  = $node.GetAttribute('Publisher')
            }
        })
    return @{
        Name         = $identity.GetAttribute('Name')
        Publisher    = $identity.GetAttribute('Publisher')
        Version      = $identity.GetAttribute('Version')
        Architecture = $identity.GetAttribute('ProcessorArchitecture')
        Dependencies = $dependencies
    }
}

# A framework package that could be handed to Add-AppxPackage, with the version it says it has.
function Get-FrameworkCandidate([string]$path, [string]$source) {
    $found = Read-PackageIdentity $path
    return [pscustomobject]@{
        Path    = $path
        Source  = $source
        Name    = $found.Name
        Version = [version]$found.Version
    }
}

# One registry value of the user: @{ Kind; Value }, or $null when it is not there. The name '' is the
# default value of the key.
function Get-UserValue([string]$subKey, [string]$name) {
    $key = $hkcu.OpenSubKey($subKey)
    if (-not $key) {
        return $null
    }
    try {
        if ($key.GetValueNames() -notcontains $name) {
            return $null
        }
        return @{
            Kind  = $key.GetValueKind($name)
            Value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    }
    finally {
        $key.Dispose()
    }
}

function Set-UserValue([string]$subKey, [string]$name, $value, [string]$kind) {
    $key = $hkcu.CreateSubKey($subKey)
    try {
        $key.SetValue($name, $value, [Microsoft.Win32.RegistryValueKind]$kind)
    }
    finally {
        $key.Dispose()
    }
}

function Remove-UserValue([string]$subKey, [string]$name) {
    $key = $hkcu.OpenSubKey($subKey, $true)
    if ($key) {
        try {
            $key.DeleteValue($name, $false)
        }
        finally {
            $key.Dispose()
        }
    }
}

# Puts a value back as Get-UserValue read it; $null means it was not there.
function Restore-UserValue([string]$subKey, [string]$name, $before) {
    if ($null -eq $before) {
        Remove-UserValue $subKey $name
    }
    else {
        Set-UserValue $subKey $name $before.Value "$($before.Kind)"
    }
}

function Test-UserKey([string]$subKey) {
    $key = $hkcu.OpenSubKey($subKey)
    if ($key) {
        $key.Dispose()
        return $true
    }
    return $false
}

function Format-UserValue($value) {
    if ($null -eq $value) {
        return '(absent)'
    }
    return "$($value.Value) ($($value.Kind))"
}

# An execution alias is a reparse point with no content: ask for the file itself, not for what it points at.
function Test-Alias([string]$path) {
    return ((Test-Path -LiteralPath $path) -or [System.IO.File]::Exists($path))
}

function Show-Aliases {
    Write-Host "files named piikey* in ${aliasDir}:"
    $found = @(Get-ChildItem -LiteralPath $aliasDir -Force -Filter 'piikey*' -ErrorAction SilentlyContinue)
    if ($found.Count -eq 0) {
        Write-Host '  (none)'
    }
    foreach ($item in $found) {
        Write-Host ('  {0}  {1} bytes  {2}  {3}' -f $item.Name, $item.Length, $item.Attributes, ($item.Target -join ', '))
    }
}

function Get-PiikeyProcess {
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name='piikey.exe'")
}

function Show-PiikeyProcess {
    $all = @(Get-PiikeyProcess)
    Write-Host "piikey.exe processes: $($all.Count)"
    foreach ($item in $all) {
        Write-Host ('  pid {0} (parent {1}) {2}' -f $item.ProcessId, $item.ParentProcessId, $item.CommandLine)
    }
}

# Ends every piikey.exe: the app, its watchdog and anything else that runs under that name.
function Stop-Piikey {
    $deadline = (Get-Date).AddSeconds(15)
    while ($true) {
        $left = @(Get-Process -Name piikey -ErrorAction SilentlyContinue)
        if ($left.Count -eq 0) {
            return
        }
        if ((Get-Date) -ge $deadline) {
            $ids = ($left | ForEach-Object { $_.Id }) -join ', '
            throw "expected no piikey.exe to be left 15 s after ending them, found pid $ids"
        }
        $left | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

# Runs a packaged exe through its alias, waits for it to end and returns its exit code and output.
function Invoke-Alias([string]$alias, [string[]]$arguments, [string]$label) {
    $out = Join-Path $work "$label.stdout.txt"
    $err = Join-Path $work "$label.stderr.txt"
    $run = Start-Process -FilePath $alias -ArgumentList $arguments -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    # Reading the handle keeps the exit code of a process that Start-Process did not wait for readable
    # in Windows PowerShell; a process that is gone already has nothing to keep.
    try {
        $null = $run.Handle
    }
    catch {
        Write-Host "(no handle on the process: $($_.Exception.Message))"
    }
    $line = '{0} {1}' -f (Split-Path $alias -Leaf), ($arguments -join ' ')
    if (-not $run.WaitForExit(60000)) {
        $run.Kill()
        throw "${label}: expected '$line' to end within 60 s, it did not (killed it)"
    }
    $result = [pscustomobject]@{
        ExitCode = $run.ExitCode
        Output   = (Read-Text $out).TrimEnd()
        Error    = (Read-Text $err).TrimEnd()
    }
    Write-Host "${label}: '$line' exited with code $($result.ExitCode)"
    if ($result.Output) {
        Write-Host "stdout: $($result.Output)"
    }
    if ($result.Error) {
        Write-Host "stderr: $($result.Error)"
    }
    return $result
}

# Throws when the piikey.exe that was started is gone, with what it left behind. A piikey.exe that
# cannot start its UI exits at once: the self-contained Windows App SDK is the first suspect.
function Assert-AppRunning([string]$when) {
    $app.Refresh()
    if (-not $app.HasExited) {
        return
    }
    $code = $app.ExitCode
    $hex = '0x{0:X8}' -f $code
    $since = $started.AddSeconds(-2)
    Write-Host "piikey.exe (pid $($app.Id)) exited with code $code ($hex) $when"
    Show-File 'stdout of piikey.exe' $stdout
    Show-File 'stderr of piikey.exe' $stderr
    Show-PiikeyProcess
    Show-EventTail 'Application' $since 'piikey' 20
    Show-EventTail 'Microsoft-Windows-AppModel-Runtime/Admin' $since '.' 20
    Show-EventTail 'Microsoft-Windows-AppXDeploymentServer/Operational' $since '.' 20
    throw ("piikey.exe exited with code $code ($hex) $when, expected it to keep running. " +
        'The self-contained Windows App SDK may not be usable inside the package: its activatable classes are ' +
        'registered by the side-by-side manifest of the exe, which a packaged process might not read. Remedies: ' +
        'register the classes in AppxManifest.xml (windows.activatableClass.inProcessServer), or switch to the ' +
        'framework package (a PackageDependency on the Windows App Runtime). The stderr of the app, the process ' +
        'list and the Windows logs are above.')
}

# An error message of the app (main.rs, ui/mod.rs) starts with "piikey:". The app shows a failure window
# after one of them, which keeps the process alive: a piikey.exe that stayed up is not yet a working one.
function Assert-NoAppErrors([string]$when) {
    $text = (Read-Text $stderr).TrimEnd()
    if ($text -match '(?m)^piikey:') {
        Show-File 'stdout of piikey.exe' $stdout
        Show-PiikeyProcess
        throw "expected nothing like 'piikey: <message>' on the stderr of piikey.exe $when, found: $text"
    }
}

# What to look at when Add-AppxPackage refuses the package.
function Show-InstallEvidence([datetime]$since, [string]$message) {
    Write-Host "publisher in the package:   $($identity.Publisher)"
    Write-Host "subject of the certificate: $($cert.Subject)"
    Write-Host '--- certificates in Cert:\LocalMachine\TrustedPeople'
    foreach ($item in @(Get-ChildItem -Path 'Cert:\LocalMachine\TrustedPeople' -ErrorAction SilentlyContinue)) {
        Write-Host "  $($item.Thumbprint)  $($item.Subject)"
    }
    Write-Host '--- the sideloading policy (a value that is not there is the default)'
    foreach ($path in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock') {
        $values = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if ($values) {
            foreach ($property in @($values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
                Write-Host "  $path $($property.Name) = $($property.Value)"
            }
        }
        else {
            Write-Host "  $path (not there)"
        }
    }
    $activity = [regex]::Match($message, '[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
    if ($activity.Success) {
        Write-Host "--- Get-AppPackageLog -ActivityID $($activity.Value)"
        try {
            Write-Host ((Get-AppPackageLog -ActivityID $activity.Value | Out-String).TrimEnd())
        }
        catch {
            Write-Host "(nothing read: $($_.Exception.Message))"
        }
    }
    Show-EventTail 'Microsoft-Windows-AppXDeploymentServer/Operational' $since '.' 40
    Show-EventTail 'Microsoft-Windows-AppXDeployment/Operational' $since '.' 40
}

# One step of the clean-up: a failure is only a warning, so it never hides the failure that led here.
function Invoke-Cleanup([string]$what, [scriptblock]$action) {
    try {
        & $action
    }
    catch {
        Write-Host "::warning::clean-up '$what' failed: $($_.Exception.Message)"
    }
}

# 1. What the package says about itself. The Store reads the same.
Write-Host '== identity'
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)) on Windows $([System.Environment]::OSVersion.Version)"
$identity = Read-PackageIdentity $msix
Write-Host ('{0}: {1} {2} ({3}) by {4}' -f (Split-Path $msix -Leaf), $identity.Name, $identity.Version, $identity.Architecture, $identity.Publisher)
foreach ($needs in $identity.Dependencies) {
    Write-Host ('depends on {0} {1} or newer, by {2}' -f $needs.Name, $needs.MinVersion, $needs.Publisher)
}
if ($identity.Version -ne $packageVersion) {
    throw "$msix says version $($identity.Version), expected $packageVersion (piikey $Version)"
}
$msixHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msix).Hash

$thumbprint = $null
try {
    # 2. A throwaway certificate whose subject is the publisher of the package, trusted for the machine,
    # and a signed copy of the package. signtool.exe: the newest Windows SDK that has one, as in
    # package-msix.ps1.
    Write-Host '== certificate'
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
    New-Item -ItemType Directory -Path $work | Out-Null

    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $signtool = Get-ChildItem -LiteralPath $kits -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    if (-not $signtool) {
        throw "signtool.exe not found under $kits (install the Windows SDK)"
    }
    Write-Host "signtool: $signtool"

    $cert = New-SelfSignedCertificate -Type Custom -Subject $identity.Publisher -KeyUsage DigitalSignature -FriendlyName 'piikey CI test' -CertStoreLocation 'Cert:\CurrentUser\My' -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    $thumbprint = $cert.Thumbprint
    Write-Host "certificate $thumbprint, subject $($cert.Subject)"

    $bytes = New-Object byte[] 24
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($bytes)
    }
    finally {
        $random.Dispose()
    }
    $password = [System.BitConverter]::ToString($bytes).Replace('-', '')
    $pfx = Join-Path $work 'piikey-test.pfx'
    $cer = Join-Path $work 'piikey-test.cer'
    $certPath = "Cert:\CurrentUser\My\$thumbprint"
    $null = Export-PfxCertificate -Cert $certPath -FilePath $pfx -Password (ConvertTo-SecureString -String $password -AsPlainText -Force)
    $null = Export-Certificate -Cert $certPath -FilePath $cer
    $null = Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'

    $signed = Join-Path $work 'piikey-signed.msix'
    Copy-Item -LiteralPath $msix -Destination $signed
    & $signtool sign /fd SHA256 /f $pfx /p $password $signed
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed with exit code $LASTEXITCODE (the subject of the certificate, $($cert.Subject), must be exactly the publisher of the package, $($identity.Publisher))"
    }
    Write-Host "signed a copy: $signed"

    # 3. The framework the manifest depends on. A copy that is installed and new enough is all that is
    # needed; otherwise Add-AppxPackage is given one: from the Windows SDK, else from Microsoft.
    Write-Host '== framework'
    $frameworkName = 'Microsoft.VCLibs.140.00.UWPDesktop'
    $frameworkArgs = @{}
    $needs = $identity.Dependencies | Where-Object { $_.Name -eq $frameworkName } | Select-Object -First 1
    if (-not $needs) {
        Write-Host "the package has no $frameworkName dependency: nothing to supply"
    }
    else {
        $minimum = [version]$needs.MinVersion
        $known = @(Get-AppxPackage -Name 'Microsoft.VCLibs*')
        Write-Host "installed Microsoft.VCLibs packages: $($known.Count)"
        foreach ($item in $known) {
            Write-Host ('  {0}  {1}' -f $item.PackageFullName, $item.Architecture)
        }
        $installed = @($known | Where-Object { $_.Name -eq $frameworkName -and "$($_.Architecture)" -eq 'X64' -and [version]"$($_.Version)" -ge $minimum })
        if ($installed.Count -gt 0) {
            Write-Host "using the installed framework $($installed[0].PackageFullName): it is $minimum or newer"
        }
        else {
            $candidates = @()
            $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Microsoft SDKs\Windows Kits\10\ExtensionSDKs\Microsoft.VCLibs.Desktop'
            if (Test-Path -LiteralPath $sdkRoot) {
                foreach ($file in @(Get-ChildItem -LiteralPath $sdkRoot -Recurse -File -Filter 'Microsoft.VCLibs.x64.14.00.Desktop.appx' -ErrorAction SilentlyContinue)) {
                    $candidates += Get-FrameworkCandidate $file.FullName 'Windows SDK'
                }
            }
            $chosen = $candidates | Where-Object { $_.Version -ge $minimum } | Sort-Object Version -Descending | Select-Object -First 1
            $downloadNote = ''
            if (-not $chosen) {
                $download = Join-Path $work 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
                try {
                    Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile $download -UseBasicParsing
                    $signature = Get-AuthenticodeSignature -LiteralPath $download
                    $signer = ''
                    if ($signature.SignerCertificate) {
                        $signer = $signature.SignerCertificate.Subject
                    }
                    if ($signature.Status -ne 'Valid' -or $signer -notmatch 'Microsoft Corporation') {
                        throw "expected a valid signature by Microsoft Corporation, found $($signature.Status) by '$signer'"
                    }
                    $candidates += Get-FrameworkCandidate $download 'download from aka.ms'
                }
                catch {
                    $downloadNote = " The download from aka.ms failed: $($_.Exception.Message)."
                    Write-Host "no usable download from aka.ms: $($_.Exception.Message)"
                }
                $chosen = $candidates | Where-Object { $_.Version -ge $minimum } | Sort-Object Version -Descending | Select-Object -First 1
            }
            if (-not $chosen) {
                $seen = 'none'
                if ($candidates.Count -gt 0) {
                    $seen = ($candidates | ForEach-Object { "$($_.Path) is $($_.Version) ($($_.Source))" }) -join '; '
                }
                $have = 'none'
                if ($known.Count -gt 0) {
                    $have = ($known | ForEach-Object { "$($_.PackageFullName)" }) -join ', '
                }
                throw ("the package needs $frameworkName $minimum or newer (MinVersion in packaging/windows/msix/AppxManifest.xml) " +
                    "and no copy that is installed or can be had is new enough. Candidates: $seen.$downloadNote Installed: $have. " +
                    'Lower the MinVersion in the manifest, or supply a newer Microsoft.VCLibs.x64.14.00.Desktop.appx ' +
                    '(the Windows SDK has one under ExtensionSDKs\Microsoft.VCLibs.Desktop).')
            }
            Write-Host "using $($chosen.Path): $($chosen.Name) $($chosen.Version) from $($chosen.Source)"
            $frameworkArgs = @{ DependencyPath = $chosen.Path }
        }
    }

    # 4. Install the signed copy.
    Write-Host '== install'
    foreach ($old in @(Get-AppxPackage -Name $identity.Name)) {
        Write-Host "removing $($old.PackageFullName), which an earlier run left behind"
        Remove-AppxPackage -Package $old.PackageFullName
    }
    $installStarted = Get-Date
    try {
        Add-AppxPackage -Path $signed @frameworkArgs
    }
    catch {
        $message = $_.Exception.Message
        Write-Host "Add-AppxPackage failed: $message"
        Show-InstallEvidence $installStarted.AddSeconds(-2) $message
        throw "Add-AppxPackage failed for $($identity.Name) $($identity.Version) by $($identity.Publisher): $message"
    }
    $package = @(Get-AppxPackage -Name $identity.Name | Where-Object { "$($_.Version)" -eq $identity.Version }) | Select-Object -First 1
    if (-not $package) {
        $names = ((Get-AppxPackage -Name $identity.Name | ForEach-Object { "$($_.PackageFullName)" }) -join ', ')
        throw "expected Get-AppxPackage to list $($identity.Name) $($identity.Version) after Add-AppxPackage, found: $names"
    }
    $dependencyNames = @($package.Dependencies | ForEach-Object { if ($_.Name) { $_.Name } else { "$_" } })
    Write-Host "Name:            $($package.Name)"
    Write-Host "PackageFullName: $($package.PackageFullName)"
    Write-Host "InstallLocation: $($package.InstallLocation)"
    Write-Host "IsFramework:     $($package.IsFramework)"
    Write-Host "Dependencies:    $($dependencyNames -join ', ')"

    # 5. Both execution aliases, and the CLI through its alias: stdout and the exit code come back.
    Write-Host '== aliases'
    Show-Aliases
    foreach ($alias in $appAlias, $cliAlias) {
        if (-not (Test-Alias $alias)) {
            throw "expected the execution alias $alias (the manifest declares it for the package), found no such file"
        }
    }
    $cliOut = (& $cliAlias --version) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $cliOut -ne "piikey-cli $Version") {
        throw "expected '$cliAlias --version' to exit with code 0 and print 'piikey-cli $Version', found exit code $LASTEXITCODE and '$cliOut'"
    }
    Write-Host "$cliAlias --version printed '$cliOut'"

    # 6. The app through its alias: the first time the self-contained Windows App SDK runs inside a
    # package. First a clean slate, so that whatever exists afterwards was written by the app itself and
    # not by an earlier step of the job (the CLI tests of smoke.ps1 make the data folder).
    Write-Host '== start'
    Stop-Piikey
    $removed = @()
    if (Test-Path -LiteralPath $dataDir) {
        $removed += $dataDir
        Remove-Item -LiteralPath $dataDir -Recurse -Force
    }
    foreach ($verb in $verbs) {
        if (Test-UserKey $verb.Key) {
            $removed += "HKCU\$($verb.Key)"
            $hkcu.DeleteSubKeyTree($verb.Key, $false)
        }
    }
    if ($removed.Count -gt 0) {
        Write-Host "removed what an earlier step left, so that what exists after the start is the app's own: $($removed -join ', ')"
    }

    $started = Get-Date
    try {
        $app = Start-Process -FilePath $appAlias -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }
    catch {
        $since = $started.AddSeconds(-2)
        Show-Aliases
        Show-EventTail 'Application' $since 'piikey' 20
        Show-EventTail 'Microsoft-Windows-AppModel-Runtime/Admin' $since '.' 20
        throw "could not start ${appAlias}: $($_.Exception.Message)"
    }
    try {
        $null = $app.Handle
    }
    catch {
        Write-Host "(no handle on the process: $($_.Exception.Message))"
    }
    Write-Host "started $appAlias as pid $($app.Id)"
    $seconds = 12
    for ($second = 1; $second -le $seconds; $second++) {
        Start-Sleep -Seconds 1
        Assert-AppRunning "after $second s"
    }
    Write-Host "piikey.exe stayed up for $seconds s inside the package"
    Assert-NoAppErrors "during its first $seconds s"

    # It has the identity of the package: tasklist /apps lists the package of every packaged process.
    $tasklist = (& tasklist.exe /apps /fo csv /fi 'imagename eq piikey.exe') -join "`n"
    if ($LASTEXITCODE -ne 0) {
        $tasklist = ((& tasklist.exe /apps /fo csv) | Where-Object { $_ -match 'piikey\.exe' }) -join "`n"
    }
    Write-Host 'tasklist /apps:'
    Write-Host $tasklist
    if ($tasklist -notlike "*$($identity.Name)*") {
        throw "expected tasklist /apps to list piikey.exe with the package $($identity.Name), found: $tasklist"
    }

    Assert-AppRunning 'before its identity was read'
    $live = Get-Process -Id $app.Id
    $live.Refresh()
    $livePath = '(unknown)'
    try {
        $livePath = $live.Path
    }
    catch {
        $livePath = "(unknown: $($_.Exception.Message))"
    }
    Write-Host "path: $livePath"
    Write-Host "main window: handle $($live.MainWindowHandle), title '$($live.MainWindowTitle)'"
    if ($live.MainWindowHandle.ToInt64() -eq 0) {
        Write-Host "::warning::piikey.exe has no main window $seconds s after its start (it may sit in the tray; check the log above)"
    }
    try {
        $modules = @($live.Modules | Where-Object { $_.ModuleName -match 'Microsoft\.ui\.xaml|WindowsAppRuntime|vcruntime|msvcp' })
        Write-Host "loaded runtime modules: $($modules.Count)"
        foreach ($module in $modules) {
            Write-Host "  $($module.ModuleName)  $($module.FileName)"
        }
    }
    catch {
        Write-Host "(cannot list the loaded modules: $($_.Exception.Message))"
    }

    # The data folder is the real one, not a private copy of the package: the app made it just now.
    $dataReady = Wait-For 20 {
        Assert-AppRunning 'while the smoke test waited for its data folder'
        (Test-Path -LiteralPath (Join-Path $dataDir 'guard.lock')) -and (Test-Path -LiteralPath (Join-Path $dataDir 'piikey.ico'))
    }
    Write-Host "data folder ${dataDir}:"
    if (Test-Path -LiteralPath $dataDir) {
        foreach ($item in @(Get-ChildItem -LiteralPath $dataDir -Force)) {
            Write-Host ('  {0}  {1} bytes' -f $item.Name, $item.Length)
        }
    }
    else {
        Write-Host '  (it does not exist)'
    }
    if (-not $dataReady) {
        $private = Join-Path $env:LOCALAPPDATA "Packages\$($package.PackageFamilyName)\LocalCache\Local\piikey"
        $where = 'and the private copy of the package is not there either'
        if (Test-Path -LiteralPath $private) {
            $where = "but the private copy of the package is: $private (the writes are virtualized: check the excluded folder in AppxManifest.xml)"
        }
        throw "expected guard.lock and piikey.ico in $dataDir within 20 s of the start, found the listing above, $where"
    }

    # The Explorer verbs are in the real registry, and run the alias, not the folder of the package.
    $null = Wait-For 20 {
        Assert-AppRunning 'while the smoke test waited for the Explorer verbs'
        @($verbs | Where-Object { Test-UserKey "$($_.Key)\command" }).Count -eq $verbs.Count
    }
    $problems = @()
    foreach ($verb in $verbs) {
        $command = Get-UserValue "$($verb.Key)\command" ''
        $expected = '"{0}" --scan "{1}"' -f $appAlias, $verb.Argument
        if ($null -eq $command) {
            $problems += "HKCU\$($verb.Key)\command is not there"
        }
        elseif ($command.Value -ne $expected) {
            $hint = ''
            if ("$($command.Value)" -like '*\WindowsApps\*' -and "$($command.Value)" -notlike '*\Microsoft\WindowsApps\*') {
                $hint = ' (it runs the folder of the package: the app did not see its package identity)'
            }
            $problems += "HKCU\$($verb.Key)\command is $($command.Value)$hint, expected $expected"
        }
        else {
            Write-Host "HKCU\$($verb.Key)\command = $($command.Value)"
        }
    }
    if ($problems.Count -gt 0) {
        throw ("expected the three Explorer verbs in the real registry of the user within 20 s of the start, found: $($problems -join '; '). " +
            'A verb that is not there was written to the private registry of the package: check the excluded keys in AppxManifest.xml.')
    }

    # The watchdog: a second piikey.exe that the app starts for its whole life. The first --watchdog
    # process only starts the one that stays (--watchdog --detached) and ends at once (app/src/ui/watchdog.rs).
    $watchdog = Wait-For 10 {
        Assert-AppRunning 'while the smoke test waited for its watchdog'
        @(Get-PiikeyProcess | Where-Object { $_.CommandLine -match '--watchdog' })
    }
    Show-PiikeyProcess
    if (-not $watchdog) {
        throw 'expected a piikey.exe with --watchdog in its command line within 10 s of the checks above (the list above is what runs), found none: the app could not start its watchdog inside the package'
    }

    # 7. Every piikey process can be ended, and what the app wrote to stderr is read for good.
    Write-Host '== stop'
    Stop-Piikey
    Write-Host 'no piikey.exe is left'
    Show-File 'stdout of piikey.exe' $stdout
    Show-File 'stderr of piikey.exe' $stderr
    Assert-NoAppErrors 'while it ran'

    # 8. --restore-proxy of a packaged process reaches the real settings of Windows. The values are put
    # back afterwards, whatever happens; none of them has to exist on the runner.
    Write-Host '== restore-proxy'
    $proxyNames = 'ProxyEnable', 'ProxyServer', 'ProxyOverride'
    $proxyBefore = @{}
    foreach ($name in $proxyNames) {
        $proxyBefore[$name] = Get-UserValue $internetKey $name
    }
    $runOnceBefore = Get-UserValue $runOnceKey $runOnceName
    Write-Host ('proxy settings before: ProxyEnable {0}, ProxyServer {1}, ProxyOverride {2}; RunOnce {3}' -f
        (Format-UserValue $proxyBefore['ProxyEnable']), (Format-UserValue $proxyBefore['ProxyServer']),
        (Format-UserValue $proxyBefore['ProxyOverride']), (Format-UserValue $runOnceBefore))
    try {
        # The state of a session the app did not end cleanly decides what --restore-proxy does: there must be none.
        $stale = Join-Path $dataDir 'proxy.prev'
        if (Test-Path -LiteralPath $stale) {
            Write-Host "removing ${stale}: the test needs a proxy that was left behind with nothing saved"
            Remove-Item -LiteralPath $stale -Force
        }
        Set-UserValue $internetKey 'ProxyEnable' 1 'DWord'
        Set-UserValue $internetKey 'ProxyServer' "127.0.0.1:$proxyPort" 'String'
        Set-UserValue $runOnceKey $runOnceName ('"{0}" --restore-proxy' -f $appAlias) 'String'
        $restore = Invoke-Alias $appAlias @('--restore-proxy') 'restore-proxy'
        $enable = Get-UserValue $internetKey 'ProxyEnable'
        $armed = Get-UserValue $runOnceKey $runOnceName
        $problems = @()
        if ($restore.ExitCode -ne 0) {
            $problems += "exit code $($restore.ExitCode), expected 0"
        }
        if ($null -eq $enable -or $enable.Value -ne 0) {
            $problems += "ProxyEnable is $(Format-UserValue $enable), expected 0"
        }
        if ($null -ne $armed) {
            $problems += "the RunOnce value '$runOnceName' is still there ($(Format-UserValue $armed)), expected it removed"
        }
        if ($problems.Count -gt 0) {
            throw ("expected piikey.exe --restore-proxy to switch the proxy off in the real registry (ProxyEnable 0, RunOnce value removed), found: $($problems -join '; '). " +
                'If only the registry is wrong, the package virtualized HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings or RunOnce: check the excluded keys in AppxManifest.xml.')
        }
        Write-Host 'ProxyEnable is 0 and the RunOnce value is gone: a packaged process writes to the real registry'
    }
    finally {
        Invoke-Cleanup 'restore the proxy settings' {
            foreach ($name in $proxyNames) {
                Restore-UserValue $internetKey $name $proxyBefore[$name]
            }
            Restore-UserValue $runOnceKey $runOnceName $runOnceBefore
        }
    }

    # 9. --unregister-shell takes the Explorer verbs away again.
    Write-Host '== unregister-shell'
    $unregister = Invoke-Alias $appAlias @('--unregister-shell') 'unregister-shell'
    $problems = @()
    if ($unregister.ExitCode -ne 0) {
        $problems += "exit code $($unregister.ExitCode), expected 0"
    }
    foreach ($verb in $verbs) {
        if (Test-UserKey $verb.Key) {
            $problems += "HKCU\$($verb.Key) is still there"
        }
    }
    if ($problems.Count -gt 0) {
        throw "expected piikey.exe --unregister-shell to remove the three Explorer verbs, found: $($problems -join '; ')"
    }
    Write-Host 'the three Explorer verbs are gone'

    # 10. The package and both aliases go. The data folder stays, as it is meant to.
    Write-Host '== remove'
    Remove-AppxPackage -Package $package.PackageFullName
    $left = @(Get-AppxPackage -Name $identity.Name)
    if ($left.Count -gt 0) {
        $names = ($left | ForEach-Object { "$($_.PackageFullName)" }) -join ', '
        throw "expected no $($identity.Name) package after Remove-AppxPackage, found: $names"
    }
    $aliasesGone = Wait-For 15 { -not ((Test-Alias $appAlias) -or (Test-Alias $cliAlias)) }
    if (-not $aliasesGone) {
        Show-Aliases
        throw "expected both execution aliases to be gone 15 s after Remove-AppxPackage, found the files above"
    }
    Write-Host 'the package and both execution aliases are gone'
    $hashNow = (Get-FileHash -Algorithm SHA256 -LiteralPath $msix).Hash
    if ($hashNow -ne $msixHash) {
        throw "expected $msix to stay as it was (SHA-256 $msixHash), found ${hashNow}: only a copy is signed"
    }
}
finally {
    Write-Host '== clean up'
    Invoke-Cleanup 'end piikey' { Stop-Piikey }
    Invoke-Cleanup 'remove the package' {
        foreach ($left in @(Get-AppxPackage -Name $identity.Name)) {
            Remove-AppxPackage -Package $left.PackageFullName
        }
    }
    Invoke-Cleanup 'remove the Explorer verbs' {
        foreach ($verb in $verbs) {
            $hkcu.DeleteSubKeyTree($verb.Key, $false)
        }
    }
    Invoke-Cleanup 'remove the data folder' {
        if (Test-Path -LiteralPath $dataDir) {
            Remove-Item -LiteralPath $dataDir -Recurse -Force
        }
    }
    Invoke-Cleanup 'remove the certificate from TrustedPeople' {
        if ($thumbprint -and (Test-Path -LiteralPath "Cert:\LocalMachine\TrustedPeople\$thumbprint")) {
            Remove-Item -Path "Cert:\LocalMachine\TrustedPeople\$thumbprint" -Force
        }
    }
    Invoke-Cleanup 'remove the certificate and its key from the personal store' {
        if ($thumbprint -and (Test-Path -LiteralPath "Cert:\CurrentUser\My\$thumbprint")) {
            Remove-Item -Path "Cert:\CurrentUser\My\$thumbprint" -DeleteKey -Force
        }
    }
    Invoke-Cleanup 'delete the work folder' {
        if (Test-Path -LiteralPath $work) {
            Remove-Item -LiteralPath $work -Recurse -Force
        }
    }
}

Write-Host "piikey ${Version}: the MSIX installs, runs and uninstalls"
