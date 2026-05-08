# ============================================================================
#  build_replay_inspect.ps1
#
#  Build the replay_inspect tool. Paths resolve relative to repo root.
# ============================================================================

$ErrorActionPreference = 'Stop'
$RepoRoot = $PSScriptRoot

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

$proj = Join-Path $RepoRoot 'build\x64\replay_inspect.vcxproj'
if (-not (Test-Path $proj)) {
    Write-Error "Project not found at $proj. Run scripts/build.ps1 -Configure first."
    exit 1
}

Write-Host "Building: $proj"
& $msbuild $proj /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
exit $LASTEXITCODE
