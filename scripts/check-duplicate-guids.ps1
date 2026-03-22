<#
.SYNOPSIS
  Checks that no two interface GUIDs in *.pas files are identical.
.DESCRIPTION
  Extracts all ['{...}'] GUIDs from *.pas, groups by GUID, and exits with
  non-zero if any GUID appears more than once (reporting file:line for each).
.EXAMPLE
  .\scripts\check-duplicate-guids.ps1
#>

$ErrorActionPreference = 'Stop'

# Repo root: script lives in <repo>/scripts/check-duplicate-guids.ps1
$root = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { Get-Location }
$pasFiles = Get-ChildItem -Path $root -Filter '*.pas' -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch '\.git\\' }

# Use Select-String for fast single-pass scan over all files (no full file read per line)
$guidPattern = "\['\{([0-9A-Fa-f-]+)\}'\]"
$matches = Select-String -LiteralPath $pasFiles.FullName -Pattern $guidPattern -AllMatches -ErrorAction SilentlyContinue

$locationsByGuid = @{}
foreach ($m in $matches) {
  $guid = $m.Matches.Groups[1].Value.ToUpperInvariant()
  $relPath = $m.Path.Replace($root, '').TrimStart('\', '/')
  $entry = "${relPath}:$($m.LineNumber)"
  if (-not $locationsByGuid.ContainsKey($guid)) {
    $locationsByGuid[$guid] = [System.Collections.ArrayList]::new()
  }
  [void]$locationsByGuid[$guid].Add($entry)
}

$duplicates = $locationsByGuid.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
if ($duplicates) {
  Write-Host 'Duplicate interface GUIDs found. Each GUID must be unique across the codebase.' -ForegroundColor Red
  Write-Host ''
  foreach ($d in $duplicates) {
    Write-Host "GUID: {$($d.Key)}" -ForegroundColor Yellow
    foreach ($loc in $d.Value) {
      Write-Host "  $loc"
    }
    Write-Host ''
  }
  Write-Host 'Generate a new GUID: [guid]::NewGuid().ToString(''B'').ToUpperInvariant()' -ForegroundColor Cyan
  exit 1
}

Write-Host 'No duplicate interface GUIDs found.' -ForegroundColor Green
exit 0
