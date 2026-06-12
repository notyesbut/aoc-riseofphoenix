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

# Some inherited PowerShell environments on this machine have PATHEXT reduced
# to ".CPL".  Native .exe calls can then succeed while leaving $LASTEXITCODE
# null, which makes the build wrapper report a false failure.
$defaultPathExts = @('.COM','.EXE','.BAT','.CMD','.VBS','.VBE','.JS','.JSE','.WSF','.WSH','.MSC','.CPL')
$currentPathExts = @($env:PATHEXT -split ';' | Where-Object { $_ })
if ($currentPathExts -notcontains '.EXE') {
    $env:PATHEXT = (($defaultPathExts + $currentPathExts) | Select-Object -Unique) -join ';'
}

# ── Resolve paths from script location ──────────────────────────────────
$repoRoot   = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$buildDir   = Join-Path $repoRoot 'build\x64'
$distDir    = Join-Path $repoRoot "dist\$Config"

Write-Host "Repo root: $repoRoot"
Write-Host "Build dir: $buildDir"
Write-Host "Config   : $Config"

# ── Find MSBuild via vswhere ────────────────────────────────────────────
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    $vswhere = "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
}
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found - Visual Studio 2022 (Build Tools) required."
}
$msbuildCandidates = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe'
$msbuild = $msbuildCandidates | Select-Object -First 1
if (-not $msbuild) {
    $msbuild = Get-ChildItem @(
        "$env:ProgramFiles\Microsoft Visual Studio",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
    ) -Recurse -Filter MSBuild.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*\MSBuild\Current\Bin\MSBuild.exe' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $msbuild) {
    throw "MSBuild.exe not found via vswhere."
}
Write-Host "MSBuild  : $msbuild"

# Pick the CMake VS generator matching the installed VS major version.
# Build Tools editions only appear with `-products *`; map the major
# version to the generator name (VS2019=16, VS2022=17, VS2026=18).
$vsInstallVersion = & $vswhere -latest -products '*' -property installationVersion
$vsInstallVersionFirst = $vsInstallVersion | Select-Object -First 1
if ($vsInstallVersionFirst) {
    $vsMajor = $vsInstallVersionFirst.Split('.')[0]
} else {
    $vsMajor = if ($msbuild -match '\\Microsoft Visual Studio\\(\d+)\\') {
        $Matches[1]
    } else {
        '17'
    }
}
$generator = switch ($vsMajor) {
    '18'    { 'Visual Studio 18 2026' }
    '17'    { 'Visual Studio 17 2022' }
    '16'    { 'Visual Studio 16 2019' }
    default { 'Visual Studio 17 2022' }
}
Write-Host "Generator: $generator (VS major $vsMajor)"

# Find cmake (VS2022 ships it under Common7\IDE\CommonExtensions\...)
$cmake = Get-Command cmake -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
if (-not $cmake) {
    $cmakeCandidates = & $vswhere -latest -products '*' -find 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
    $cmakeCandidate = $cmakeCandidates | Select-Object -First 1
    if ($cmakeCandidate -and (Test-Path $cmakeCandidate)) { $cmake = $cmakeCandidate }
}
if (-not $cmake) {
    $cmake = Get-ChildItem @(
        "$env:ProgramFiles\CMake\bin",
        "$env:ProgramFiles\Microsoft Visual Studio",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
    ) -Recurse -Filter cmake.exe -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
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
            '-G', $generator,
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

# ── Test target set ──────────────────────────────────────────────────────
# The full list of test_* executables registered with CTest in CMakeLists.txt.
# Keep in sync with the AOC_TEST_TARGETS list there.  The default `all` build
# does NOT build these, so -Test explicitly builds each one before running.
$testTargets = @(
    'test_player_controller_builder',
    'test_packet_parser',
    'test_schemas',
    'test_replayout_codecs',
    'test_pkt22_round_trip',
    'test_pkt104_round_trip',
    'test_name_update_bunch',
    'test_property_update_bunch_builder',
    'test_pawn_spawn_diff',
    'test_replay_mutator',
    'test_actor_builder',
    'test_simulation',
    'test_replication',
    'test_dispatcher',
    'test_live_server',
    'test_nmt_welcome',
    'test_nmt_challenge',
    'test_nmt_netguid_assign',
    'test_pc_spawn_diff',
    'test_package_map_export'
)

# ── Build target(s) ──────────────────────────────────────────────────────
$targets = if ($Target -eq 'all') {
    @('aoc_server','auth_server','tether_server','launcher')
} else {
    @($Target)
}

# When -Test is requested, also build every test_* target.  The default all
# build does not include them, so they must be built here before they can run.
if ($Test) {
    foreach ($tt in $testTargets) {
        if ($targets -notcontains $tt) { $targets += $tt }
    }
}

foreach ($t in $targets) {
    $vcxproj = Join-Path $buildDir "$t.vcxproj"
    if (-not (Test-Path $vcxproj)) {
        Write-Warning "Project file not found: $vcxproj (skipping)"
        continue
    }
    Write-Host ""
    Write-Host "Building $t ..."
    & $cmake --build $buildDir --config $Config --target $t -- /m /nr:false /v:minimal
    $buildExitCode = if ($null -eq $LASTEXITCODE) {
        if ($?) { 0 } else { 1 }
    } else {
        [int]$LASTEXITCODE
    }
    if ($buildExitCode -ne 0) {
        throw "Build failed for target: $t"
    }
}

# ── Run tests if requested ──────────────────────────────────────────────
# Each test_* target was built above; run its executable from dist/<Config>/
# and treat a non-zero exit as a failure.  Report a per-target pass/fail tally.
if ($Test) {
    $allPass = $true
    $passed  = @()
    $failed  = @()
    foreach ($t in $testTargets) {
        $path = Join-Path $distDir "$t.exe"
        if (-not (Test-Path $path)) {
            Write-Warning "Test exe not found: $path (skipping)"
            $failed += $t
            $allPass = $false
            continue
        }
        Write-Host ""
        Write-Host "=== $t ==="
        & $path
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "$t failed with exit $LASTEXITCODE"
            $failed += $t
            $allPass = $false
        } else {
            $passed += $t
        }
    }

    Write-Host ""
    Write-Host "── Test summary ──────────────────────────────────────────"
    Write-Host ("  passed: {0}/{1}" -f $passed.Count, $testTargets.Count)
    foreach ($t in $passed) { Write-Host "    PASS  $t" }
    foreach ($t in $failed) { Write-Host "    FAIL  $t" }

    if (-not $allPass) {
        Write-Warning "One or more tests failed."
        exit 1
    }
}

Write-Host ""
Write-Host "Build completed successfully."
Write-Host "Binaries: $distDir"
