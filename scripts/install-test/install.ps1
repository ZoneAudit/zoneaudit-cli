# ZoneAudit CLI installer for Windows.
#
#   irm https://zoneaudit.com/install.ps1 | iex
#
# Downloads the latest release of github.com/ZoneAudit/zoneaudit-cli for
# this computer, checks it against the release's published SHA-256
# checksums, installs zoneaudit.exe to %LOCALAPPDATA%\Programs\zoneaudit
# (or $env:ZONEAUDIT_INSTALL_DIR) and adds that folder to your user PATH.
# No administrator rights are needed. It stops on the first error, and
# throws rather than exits, so your PowerShell window stays open.

& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $Repo = 'ZoneAudit/zoneaudit-cli'

  function Say([string]$Message) { Write-Host "zoneaudit-install: $Message" }

  $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "zoneaudit-install: unsupported processor architecture: $env:PROCESSOR_ARCHITECTURE" }
  }

  $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'zoneaudit-install' }
  $tag = [string]$release.tag_name
  if ($tag -notmatch '^v\d') { throw "zoneaudit-install: could not find the latest release (got '$tag')" }
  $version = $tag.Substring(1)

  $asset = "zoneaudit-cli_${version}_windows_${arch}.zip"
  $base = "https://github.com/$Repo/releases/download/$tag"

  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("zoneaudit-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Say "downloading ZoneAudit CLI $tag for windows/$arch"
    $zip = Join-Path $tmp $asset
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $zip

    if ($release.assets.name -contains 'checksums.txt') {
      $sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt").Content
      if ($sums -is [byte[]]) { $sums = [Text.Encoding]::UTF8.GetString($sums) }
      $line = $sums -split "`n" | Where-Object { ($_ -split '\s+')[1] -eq $asset } | Select-Object -First 1
      if (-not $line) { throw "zoneaudit-install: $asset is not listed in checksums.txt" }
      $expected = ($line -split '\s+')[0].ToLowerInvariant()
      $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
      if ($expected -ne $actual) { throw "zoneaudit-install: checksum mismatch for $asset; nothing was installed" }
      Say 'checksum verified (SHA-256)'
    } else {
      Say 'warning: this release publishes no checksums.txt, so the download was not verified'
    }

    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $exe = Join-Path $tmp 'zoneaudit.exe'
    if (-not (Test-Path $exe)) { throw "zoneaudit-install: zoneaudit.exe not found in $asset" }

    $installDir = if ($env:ZONEAUDIT_INSTALL_DIR) { $env:ZONEAUDIT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\zoneaudit' }
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $installDir 'zoneaudit.exe') -Force
    Say "installed $tag to $installDir\zoneaudit.exe"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $installDir) {
      $newPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
      [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
      $env:Path = "$env:Path;$installDir"
      Say "added $installDir to your user PATH (new terminals pick it up)"
    }
    Say 'run: zoneaudit --help'
  } finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
  }
}
