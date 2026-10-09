# Runs the vendored install.ps1 (unchanged copy of zoneaudit-lp
# public/install.ps1) against release artefacts, the way users run it:
# irm https://zoneaudit.com/install.ps1 | iex
#
#   test-install.ps1 -Mode local -Dist <dist-dir>   artefacts built in CI, served by fakerelease
#   test-install.ps1 -Mode live                     the latest published GitHub release
#
# Written for Windows PowerShell 5.1 as well as PowerShell 7. In local mode
# the GitHub URLs are rewritten to the fake server in memory only.
param(
  [Parameter(Mandatory = $true)][ValidateSet('local', 'live')][string]$Mode,
  [string]$Dist
)
$ErrorActionPreference = 'Stop'
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)) on $env:PROCESSOR_ARCHITECTURE"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Get-Content -Raw -Path (Join-Path $here 'install.ps1')
$work = Join-Path ([IO.Path]::GetTempPath()) ('zoneaudit-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$addr = '127.0.0.1:8765'
$server = $null

function Start-FakeRelease([string]$DistDir, [string[]]$Extra) {
  $exe = Join-Path $work 'fakerelease.exe'
  & go build -o $exe (Join-Path $here 'fakerelease')
  if ($LASTEXITCODE -ne 0) { throw 'could not build fakerelease' }
  $argList = @('-dist', "`"$DistDir`"", '-addr', $addr) + $Extra
  $p = Start-Process -FilePath $exe -ArgumentList $argList -PassThru -NoNewWindow
  for ($i = 0; $i -lt 50; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -Uri "http://$addr/healthz" | Out-Null; return $p } catch { Start-Sleep -Milliseconds 200 }
  }
  throw 'fake release server did not start'
}

function Invoke-Installer([string]$Code, [string]$InstallDir) {
  $env:ZONEAUDIT_INSTALL_DIR = $InstallDir
  try { $Code | Invoke-Expression } finally { Remove-Item Env:\ZONEAUDIT_INSTALL_DIR -ErrorAction SilentlyContinue }
}

try {
  if ($Mode -eq 'local') {
    $Dist = (Resolve-Path $Dist).Path
    $local = $script.Replace('https://api.github.com', "http://$addr").Replace('https://github.com', "http://$addr")
    $sums = Get-Content -Path (Join-Path $Dist 'checksums.txt')
    $expected = $null
    foreach ($line in $sums) {
      $name = ($line -split '\s+')[1]
      if ($name -match '^zoneaudit-cli_(.+)_windows_amd64\.zip$') { $expected = $Matches[1] }
    }
    if (-not $expected) { throw 'no windows archive listed in checksums.txt' }

    Write-Host '== tampered checksums must be refused'
    $server = Start-FakeRelease $Dist @('-tamper')
    $bad = Join-Path $work 'bad'
    $refused = $false
    try { Invoke-Installer $local $bad } catch { $refused = $true; Write-Host "refused as expected: $($_.Exception.Message)" }
    if (-not $refused) { throw 'FAIL: installer accepted a tampered checksum' }
    if (Test-Path (Join-Path $bad 'zoneaudit.exe')) { throw 'FAIL: binary installed despite checksum mismatch' }
    Stop-Process -Id $server.Id -Force; $server.WaitForExit(); $server = $null

    Write-Host '== install from CI artefacts (irm | iex)'
    $server = Start-FakeRelease $Dist @()
    $bin = Join-Path $work 'bin'
    Invoke-Installer $local $bin
    $got = (& (Join-Path $bin 'zoneaudit.exe') -version | Out-String).Trim()
    Write-Host "installed: $got"
    if ($got -ne "zoneaudit $expected") { throw "FAIL: expected 'zoneaudit $expected'" }
    $help = (& (Join-Path $bin 'zoneaudit.exe') -h 2>&1 | Out-String)
    if ($help -notmatch 'RESPONSIBLE USE') { throw 'FAIL: help lacks the responsible-use notice' }
  } else {
    Write-Host '== install the latest published release (irm | iex)'
    $bin = Join-Path $work 'bin'
    Invoke-Installer $script $bin
    $exe = Join-Path $bin 'zoneaudit.exe'
    if (-not (Test-Path $exe)) { throw 'FAIL: zoneaudit.exe was not installed' }
    $help = (cmd /c "`"$exe`" -h 2>&1" | Out-String)
    if ($help -notmatch '-d') { Write-Host $help; throw 'FAIL: installed binary did not run' }
  }
  Write-Host "PASS ($Mode, PowerShell $($PSVersionTable.PSVersion), $env:PROCESSOR_ARCHITECTURE)"
} finally {
  if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
  Remove-Item -Recurse -Force -Path $work -ErrorAction SilentlyContinue
}
