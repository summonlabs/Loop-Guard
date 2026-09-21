<#
.SYNOPSIS
  Runs a command inside a Visual Studio x64 developer environment.

.DESCRIPTION
  Locates the newest Visual Studio installation that provides the C++ toolchain,
  imports vcvars64.bat, and then runs the supplied command in the supplied working
  directory. The script contains no machine-specific paths: the installation is
  discovered with vswhere, and it fails loudly when no toolchain is present.

.EXAMPLE
  pwsh -File scripts/with-msvc.ps1 -Command "cmake --version"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Command,
  [string]$WorkDir = (Get-Location).Path,
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

function Find-VsWhere {
  $candidates = @()
  if (${env:ProgramFiles(x86)}) {
    $candidates += (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe')
  }
  if ($env:ProgramFiles) {
    $candidates += (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
  }
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  return $null
}

function Find-VcVars {
  $vswhere = Find-VsWhere
  if ($vswhere) {
    $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($install) {
      $vcvars = Join-Path $install.Trim() 'VC\Auxiliary\Build\vcvars64.bat'
      if (Test-Path -LiteralPath $vcvars) { return $vcvars }
    }
  }
  $roots = @()
  if ($env:ProgramFiles) { $roots += (Join-Path $env:ProgramFiles 'Microsoft Visual Studio') }
  if (${env:ProgramFiles(x86)}) { $roots += (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio') }
  foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $found = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
      Sort-Object Name -Descending |
      ForEach-Object { Join-Path $_.FullName 'VC\Auxiliary\Build\vcvars64.bat' } |
      Where-Object { Test-Path -LiteralPath $_ } |
      Select-Object -First 1
    if ($found) { return $found }
  }
  return $null
}

$vcvars = Find-VcVars
if (-not $vcvars) {
  Write-Error 'No Visual Studio C++ toolchain (vcvars64.bat) was found on this host.'
  exit 2
}

if (-not (Test-Path -LiteralPath $WorkDir)) {
  Write-Error "Working directory does not exist: $WorkDir"
  exit 2
}

$line = 'call "' + $vcvars + '" >nul 2>&1 && cd /d "' + $WorkDir + '" && ' + $Command
if (-not $Quiet) {
  Write-Host "toolchain: $vcvars"
}
& cmd.exe /d /s /c $line
exit $LASTEXITCODE
