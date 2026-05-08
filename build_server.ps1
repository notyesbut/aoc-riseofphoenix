# ============================================================================
#  build_server.ps1
#
#  Build aoc_server (the main NetDriver server) using MSBuild.
#
#  Resolves paths relative to this script's location, so it works for any
#  contributor regardless of where they cloned the repo.
#
#  Optional environment overrides:
#      $env:MSBUILD_PATH = 'C:\path\to\MSBuild.exe'   # if not on PATH
#      $env:CSC_PATH     = 'C:\path\to\csc.exe'       # for the EAC helper
# ============================================================================

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if ($PSScriptRoot -and ($MyInvocation.MyCommand.Path -like "$PSScriptRoot\*")) {
    # Script is at repo root
    $RepoRoot = $PSScriptRoot
}

# ── Resolve MSBuild ─────────────────────────────────────────────────────────
$msbuild = $env:MSBUILD_PATH
if (-not $msbuild -or -not (Test-Path $msbuild)) {
    $candidates = @(
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $msbuild = $c; break }
    }
}
if (-not $msbuild -or -not (Test-Path $msbuild)) {
    Write-Error "MSBuild.exe not found. Set `$env:MSBUILD_PATH or install Visual Studio 2022."
    exit 1
}

# ── Build aoc_server ────────────────────────────────────────────────────────
$proj = Join-Path $RepoRoot 'build\x64\aoc_server.vcxproj'
if (-not (Test-Path $proj)) {
    Write-Error "Project not found at $proj. Run scripts/build.ps1 -Configure first."
    exit 1
}
Write-Host "Building: $proj"
& $msbuild $proj /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# ── Optional: compile the EAC popup mover (small C# helper) ─────────────────
$csc = $env:CSC_PATH
if (-not $csc -or -not (Test-Path $csc)) {
    $cscDefault = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (Test-Path $cscDefault) { $csc = $cscDefault }
}
$cs  = Join-Path $RepoRoot 'src\eac_popup_mover.cs'
$out = Join-Path $RepoRoot 'dist\Release\eac_popup_mover.exe'
if ($csc -and (Test-Path $cs)) {
    Get-Process 'eac_popup_mover' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Building eac_popup_mover.exe ..."
    $outDir = Split-Path $out
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
    Push-Location $outDir
    & $csc /target:winexe /nologo /out:$out $cs
    Pop-Location
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "eac_popup_mover.exe failed to compile (non-fatal)"
    }
}
exit 0
