# ============================================================================
#  build.ps1 - portable build driver for AoC-RiseOfPhoenix
#
#  Finds MSBuild via vswhere, configures CMake if needed, then builds the
#  requested target(s).  Paths are derived from the script's location, so
#  this script works regardless of where the repo is cloned.
#
#  Usage:
#      .\scripts\build.ps1                  # build all default targets
#      .\scripts\build.ps1 -Target aoc_server
#      .\scripts\build.ps1 -Config Debug
#      .\scripts\build.ps1 -Clean           # clean first
#      .\scripts\build.ps1 -Test            # build + run all tests
# ============================================================================

[CmdletBinding()]
param(
    [string]   $Target  = 'all',
    [ValidateSet('Release','Debug','RelWithDebInfo','MinSizeRel')]
    [string]   $Config  = 'Release',
    [switch]   $Clean,
    [switch]   $Test,
    [switch]   $Configure
)

$ErrorActionPreference = 'Stop'

# ── Resolve paths from script location ──────────────────────────────────
$repoRoot   = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$buildDir   = Join-Path $repoRoot 'build\x64'
$distDir    = Join-Path $repoRoot "dist\$Config"

Write-Host "Repo root: $repoRoot"
Write-Host "Build dir: $buildDir"
Write-Host "Config   : $Config"

# ── Find MSBuild via vswhere ────────────────────────────────────────────
$vswhere = "$env:ProgramFiles (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    $vswhere = "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
}
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found - Visual Studio 2022 (Build Tools) required."
}
$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' |
           Select-Object -First 1
if (-not $msbuild) {
    throw "MSBuild.exe not found via vswhere."
}
Write-Host "MSBuild  : $msbuild"

# Find cmake (VS2022 ships it under Common7\IDE\CommonExtensions\...)
$cmake = Get-Command cmake -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
if (-not $cmake) {
    $cmakeCandidate = & $vswhere -latest -find 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' |
                      Select-Object -First 1
    if ($cmakeCandidate -and (Test-Path $cmakeCandidate)) { $cmake = $cmakeCandidate }
}
if (-not $cmake) {
    throw "cmake.exe not found. Install CMake or use the VS2022 CMake component."
}
Write-Host "cmake    : $cmake"

# ── Clean ────────────────────────────────────────────────────────────────
if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "Removing $buildDir ..."
    Remove-Item -Recurse -Force $buildDir
}

# ── Locate vcpkg ────────────────────────────────────────────────────────
# Check $env:VCPKG_ROOT first, then fall back to common locations including
# the VS2022-integrated vcpkg.
function Find-Vcpkg {
    if ($env:VCPKG_ROOT -and (Test-Path (Join-Path $env:VCPKG_ROOT 'scripts\buildsystems\vcpkg.cmake'))) {
        return $env:VCPKG_ROOT
    }
    $candidates = @(
        'C:\vcpkg',
        "$env:USERPROFILE\vcpkg",
        "$env:USERPROFILE\source\repos\vcpkg",
        'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\vcpkg',
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\vcpkg',
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\vcpkg'
    )
    foreach ($p in $candidates) {
        if (Test-Path (Join-Path $p 'scripts\buildsystems\vcpkg.cmake')) { return $p }
    }
    return $null
}

$vcpkgRoot = Find-Vcpkg
if ($vcpkgRoot) {
    Write-Host "vcpkg   : $vcpkgRoot"
} else {
    Write-Warning "vcpkg not found. Install from https://github.com/microsoft/vcpkg or set VCPKG_ROOT."
}

# ── Configure (CMake) if needed ─────────────────────────────────────────
$needConfigure = $Configure -or (-not (Test-Path (Join-Path $buildDir 'CMakeCache.txt')))
if ($needConfigure) {
    Write-Host "Running CMake configure ..."
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    Push-Location $buildDir
    try {
        $cmakeArgs = @(
            '-G', 'Visual Studio 17 2022',
            '-A', 'x64',
            $repoRoot
        )
        if ($vcpkgRoot) {
            $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$vcpkgRoot\scripts\buildsystems\vcpkg.cmake"
            $cmakeArgs += "-DVCPKG_TARGET_TRIPLET=x64-windows"
        }
        & $cmake @cmakeArgs
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configure failed."
        }
    } finally { Pop-Location }
}

# ── Build target(s) ──────────────────────────────────────────────────────
$targets = if ($Target -eq 'all') {
    @('aoc_server','auth_server','tether_server','launcher')
} else {
    @($Target)
}

foreach ($t in $targets) {
    $vcxproj = Join-Path $buildDir "$t.vcxproj"
    if (-not (Test-Path $vcxproj)) {
        Write-Warning "Project file not found: $vcxproj (skipping)"
        continue
    }
    Write-Host ""
    Write-Host "Building $t ..."
    & $msbuild $vcxproj /p:Configuration=$Config /p:Platform=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for target: $t"
    }
}

# ── Run tests if requested ──────────────────────────────────────────────
if ($Test) {
    $testExes = @(
        'test_replayout_codecs.exe',
        'test_replay_mutator.exe',
        'test_pkt104_round_trip.exe'
    )
    $allPass = $true
    foreach ($exe in $testExes) {
        $path = Join-Path $distDir $exe
        if (-not (Test-Path $path)) {
            Write-Warning "Test exe not found: $path (skipping)"
            continue
        }
        Write-Host ""
        Write-Host "=== $exe ==="
        & $path
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "$exe failed with exit $LASTEXITCODE"
            $allPass = $false
        }
    }
    if (-not $allPass) {
        Write-Warning "One or more tests failed."
        exit 1
    }
}

Write-Host ""
Write-Host "Build completed successfully."
Write-Host "Binaries: $distDir"
