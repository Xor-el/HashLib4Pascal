<#
.SYNOPSIS
  Checks repo file-format rules: CRLF line endings, valid UTF-8, and BOM policy.
.DESCRIPTION
  Scans tracked source/text files (*.pas, *.inc, *.md, *.py, *.ps1, *.lpr)
  under HashLib, HashLib.Tests, scripts and docs. Fails (non-zero exit) if a
  file contains bytes that are not valid UTF-8, contains any line ending other
  than CRLF (bare LF or bare CR), or violates the BOM policy:
    - Pascal source (*.pas, *.inc, *.lpr): a UTF-8 BOM is REQUIRED when the file
      contains non-ASCII bytes (Delphi needs it to read the source as UTF-8) and
      FORBIDDEN otherwise.
    - Every other file (*.md, *.py, *.ps1): a UTF-8 BOM is forbidden.
.EXAMPLE
  .\scripts\maintenance\check-file-format.ps1
#>

$ErrorActionPreference = 'Stop'

# Repo root: script lives in <repo>/scripts/maintenance/check-file-format.ps1
$root = if ($PSScriptRoot) { Split-Path (Split-Path $PSScriptRoot -Parent) -Parent } else { Get-Location }

$patterns = @('*.pas', '*.inc', '*.md', '*.py', '*.ps1', '*.lpr')
# Pascal source the Delphi/FPC compilers read as source; only these may carry a
# UTF-8 BOM, and only when they contain non-ASCII bytes.
$pascalExts = @('.pas', '.inc', '.lpr')
$dirs = @('HashLib\src', 'HashLib.Tests\src', 'scripts', 'docs')

$files = foreach ($d in $dirs) {
  $p = Join-Path $root $d
  if (Test-Path $p) {
    Get-ChildItem -Path $p -Include $patterns -Recurse -File -ErrorAction SilentlyContinue
  }
}

$failures = @()
$utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)

foreach ($f in $files) {
  $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
  if ($bytes.Length -eq 0) { continue }

  $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
  $bodyStart = if ($hasBom) { 3 } else { 0 }
  $hasNonAscii = $false
  for ($j = $bodyStart; $j -lt $bytes.Length; $j++) {
    if ($bytes[$j] -ge 0x80) { $hasNonAscii = $true; break }
  }

  if ($pascalExts -contains $f.Extension.ToLowerInvariant()) {
    if ($hasNonAscii -and (-not $hasBom)) {
      $failures += "$($f.FullName): missing UTF-8 BOM (required for non-ASCII Pascal source)"
    } elseif ((-not $hasNonAscii) -and $hasBom) {
      $failures += "$($f.FullName): unexpected UTF-8 BOM (pure-ASCII file)"
    }
  } elseif ($hasBom) {
    $failures += "$($f.FullName): UTF-8 BOM present"
  }

  try {
    [void]$utf8Strict.GetString($bytes)
  } catch {
    $failures += "$($f.FullName): not valid UTF-8"
  }

  for ($i = 0; $i -lt $bytes.Length; $i++) {
    $b = $bytes[$i]
    if ($b -eq 10) {
      if ($i -eq 0 -or $bytes[$i - 1] -ne 13) {
        $failures += "$($f.FullName): bare LF at offset $i"
        break
      }
    } elseif ($b -eq 13) {
      if ($i -eq $bytes.Length - 1 -or $bytes[$i + 1] -ne 10) {
        $failures += "$($f.FullName): bare CR at offset $i"
        break
      }
    }
  }
}

if ($failures.Count -gt 0) {
  Write-Host 'File-format check FAILED (rules: CRLF, valid UTF-8, BOM policy):'
  $failures | ForEach-Object { Write-Host "  $_" }
  exit 1
}

Write-Host "File-format check passed ($(@($files).Count) files)."
exit 0
