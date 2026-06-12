<#
.SYNOPSIS
  Run one autonomous native-client probe against the retail AoC client.

.DESCRIPTION
  This is a black-box live test runner: it configures runtime probe files,
  starts aoc_server + tether_server + the retail client, waits for the native
  bootstrap/possession window, then prints the server/client oracle summary.

  It does not simulate the retail client.  It uses the real client because the
  authoritative verdict for ActorChannel / PackageMap / ClassNetCache framing is
  in the client's receiver and AOC.log.
#>
param(
    [uint32]$CrHandle = 45,
    [uint32]$CrMax = 1035,
    [int]$CalvSerializeInt = 1,
    [uint32]$CalvHandle = 21,
    [uint32]$CalvMax = 1035,
    [int]$CalvParamMode = 0,
    [uint32]$CalvBoolBits = 1,
    [uint32]$CalvFNameHandle = 1,
    [uint32]$CalvTxHandle = 2,
    [uint32]$CalvBoolHandle = 3,
    [uint32]$StreamingHandle = 151,
    [uint32]$StreamingMax = 216,
    [switch]$SnaOnly,
    [switch]$PawnSkipLevel,
    [switch]$PawnSkipLocation,
    [int]$SnaLevelGate = -1,
    [int]$PawnMinimal = 1,
    [int]$PawnPartialSplit = 0,
    [uint32]$PawnSplitBit = 9000,
    [int]$CbHasRep = 0,
    [int]$ContentBlockPayloadBits = 0,
    [int]$VectorMode = -1,
    [int]$VectorAxisBits = -1,
    [int]$VectorHeaderValue = -1,
    [int]$VectorHeaderMax = -1,
    [int]$PawnQuantizeLocation = 0,
    [switch]$NoMinimalTail,
    [switch]$NoTailBytepad,
    [int]$WaitSeconds = 95,
    [string]$GameRoot = $env:GAME_ROOT,
    [string]$ClientExtraArgs = $env:AOC_CLIENT_EXTRA_ARGS,
    [switch]$KeepRunning,
    [switch]$NoClient,
    [switch]$NoDriveClient,
    [int]$DriveSeconds = 110
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')
$dist = Join-Path $repoRoot 'dist\Release'
$certs = Join-Path $repoRoot 'certs'
$aocServer = Join-Path $dist 'aoc_server.exe'
$tetherServer = Join-Path $dist 'tether_server.exe'
$launcher = Join-Path $dist 'launcher.exe'

function Write-ProbeFile([string]$Name, [object]$Value) {
    Set-Content -Path (Join-Path $dist $Name) -Value ([string]$Value) -NoNewline -Encoding ASCII
}

function Stop-ByName([string]$Name) {
    $items = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq $Name })
    foreach ($item in $items) {
        Write-Host ("[stop] {0} pid={1}" -f $Name, $item.ProcessId)
        $null = $item | Invoke-CimMethod -MethodName Terminate -Arguments @{ Reason = 0 }
    }
}

function Wait-TcpListen([uint16]$Port, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $hit = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($hit) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Wait-UdpBound([uint16]$Port, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $hit = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue
        if ($hit) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Resolve-GameRoot {
    param([string]$Explicit)
    if ($Explicit) {
        $exe = Join-Path $Explicit 'AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe'
        if (Test-Path $exe) { return $Explicit }
    }
    $candidates = @()
    foreach ($root in @($env:AOC_GAME_ROOT, $env:GAME_ROOT)) {
        if ($root) { $candidates += $root }
    }
    $steamCommonRoots = @()
    if (${env:ProgramFiles(x86)}) {
        $steamCommonRoots += (Join-Path ${env:ProgramFiles(x86)} 'Steam\steamapps\common')
    }
    if ($env:ProgramFiles) {
        $steamCommonRoots += (Join-Path $env:ProgramFiles 'Steam\steamapps\common')
    }
    foreach ($steamCommon in $steamCommonRoots) {
        $candidates += (Join-Path $steamCommon 'Ashes of Creation Playtest\Game')
        $candidates += (Join-Path $steamCommon 'Ashes of Creation\Game')
    }
    $candidates += 'C:\Ashes of Creation\Game'
    foreach ($candidate in $candidates) {
        $exe = Join-Path $candidate 'AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe'
        if (Test-Path $exe) { return $candidate }
    }
    return $null
}

if (-not (Test-Path $aocServer)) { throw "Missing $aocServer" }
if (-not (Test-Path $tetherServer)) { throw "Missing $tetherServer" }

Write-Host "=== Native Probe Runner ==="
Write-Host ("repo       : {0}" -f $repoRoot)
Write-Host ("dist       : {0}" -f $dist)
Write-Host ("cr         : handle={0} max={1}" -f $CrHandle, $CrMax)
Write-Host ("calv       : serializeint={0} handle={1} max={2} param_mode={3} bool_bits={4} handles={5}/{6}/{7}" -f $CalvSerializeInt, $CalvHandle, $CalvMax, $CalvParamMode, $CalvBoolBits, $CalvFNameHandle, $CalvTxHandle, $CalvBoolHandle)
Write-Host ("streaming  : handle={0} max={1}" -f $StreamingHandle, $StreamingMax)
Write-Host ("pawn       : minimal={0} partial_split={1} split_bit={2}" -f $PawnMinimal, $PawnPartialSplit, $PawnSplitBit)
Write-Host ("sna        : only={0} skip_level={1} skip_location={2} level_gate={3}" -f $SnaOnly.IsPresent, $PawnSkipLevel.IsPresent, $PawnSkipLocation.IsPresent, $SnaLevelGate)
Write-Host ("vector     : mode={0} axis_bits={1} header_value={2} header_max={3} pawn_quantize={4}" -f $VectorMode, $VectorAxisBits, $VectorHeaderValue, $VectorHeaderMax, $PawnQuantizeLocation)
Write-Host ("tail       : minimal={0} cb_has_rep={1} cb_npb={2} bytepad={3}" -f (-not $NoMinimalTail.IsPresent), $CbHasRep, $ContentBlockPayloadBits, (-not $NoTailBytepad.IsPresent))

Write-ProbeFile 'probe_cr_handle.txt' $CrHandle
Write-ProbeFile 'probe_cr_max.txt' $CrMax
Write-ProbeFile 'probe_cr_objref_mode.txt' 0
Remove-Item -Path (Join-Path $dist 'probe_cr_fieldhandle.txt') -ErrorAction SilentlyContinue

Write-ProbeFile 'probe_calv_serializeint.txt' $CalvSerializeInt
Write-ProbeFile 'probe_calv_handle.txt' $CalvHandle
Write-ProbeFile 'probe_calv_max.txt' $CalvMax
Write-ProbeFile 'probe_calv_param_mode.txt' $CalvParamMode
Write-ProbeFile 'probe_calv_bool_bits.txt' $CalvBoolBits
Write-ProbeFile 'probe_calv_fname_handle.txt' $CalvFNameHandle
Write-ProbeFile 'probe_calv_tx_handle.txt' $CalvTxHandle
Write-ProbeFile 'probe_calv_bool_handle.txt' $CalvBoolHandle

Write-ProbeFile 'probe_streaming_keepalive_serializeint.txt' 1
Write-ProbeFile 'probe_streaming_keepalive_handle.txt' $StreamingHandle
Write-ProbeFile 'probe_streaming_keepalive_max.txt' $StreamingMax

Write-ProbeFile 'probe_pawn_minimal.txt' $PawnMinimal
Write-ProbeFile 'probe_pawn_partial_split.txt' $PawnPartialSplit
Write-ProbeFile 'probe_pawn_split_bit.txt' $PawnSplitBit
Write-ProbeFile 'probe_pawn_quantize_location.txt' $PawnQuantizeLocation

Remove-Item -Path (Join-Path $dist 'probe_vector_header_n.txt') -ErrorAction SilentlyContinue
if ($VectorMode -ge 0) {
    Write-ProbeFile 'probe_vector_mode.txt' $VectorMode
} else {
    Remove-Item -Path (Join-Path $dist 'probe_vector_mode.txt') -ErrorAction SilentlyContinue
}
if ($VectorAxisBits -ge 0) {
    Write-ProbeFile 'probe_vector_axis_bits.txt' $VectorAxisBits
} else {
    Remove-Item -Path (Join-Path $dist 'probe_vector_axis_bits.txt') -ErrorAction SilentlyContinue
}
if ($VectorHeaderValue -ge 0) {
    Write-ProbeFile 'probe_vector_header_value.txt' $VectorHeaderValue
} else {
    Remove-Item -Path (Join-Path $dist 'probe_vector_header_value.txt') -ErrorAction SilentlyContinue
}
if ($VectorHeaderMax -ge 0) {
    Write-ProbeFile 'probe_vector_header_max.txt' $VectorHeaderMax
} else {
    Remove-Item -Path (Join-Path $dist 'probe_vector_header_max.txt') -ErrorAction SilentlyContinue
}

$snaOnlyValue = 0
if ($SnaOnly) { $snaOnlyValue = 1 }
Write-ProbeFile 'probe_sna_only.txt' $snaOnlyValue

$skipLevelValue = 0
if ($PawnSkipLevel) { $skipLevelValue = 1 }
Write-ProbeFile 'probe_pawn_skip_level.txt' $skipLevelValue

$skipLocationValue = 0
if ($PawnSkipLocation) { $skipLocationValue = 1 }
Write-ProbeFile 'probe_pawn_skip_location.txt' $skipLocationValue

if ($SnaLevelGate -ge 0) {
    Write-ProbeFile 'probe_sna_level_gate.txt' $SnaLevelGate
} else {
    Remove-Item -Path (Join-Path $dist 'probe_sna_level_gate.txt') -ErrorAction SilentlyContinue
}

Write-ProbeFile 'probe_cb_has_rep.txt' $CbHasRep
Write-ProbeFile 'probe_cb_npb.txt' $ContentBlockPayloadBits
$minimalTailValue = 1
if ($NoMinimalTail) { $minimalTailValue = 0 }
Write-ProbeFile 'probe_minimal_tail.txt' $minimalTailValue
$tailBytepadValue = 1
if ($NoTailBytepad) { $tailBytepadValue = 0 }
Write-ProbeFile 'probe_tail_bytepad.txt' $tailBytepadValue

if (-not $KeepRunning) {
    Stop-ByName 'AOCClient-Win64-Shipping.exe'
    Stop-ByName 'launcher.exe'
    Stop-ByName 'aoc_server.exe'
    Stop-ByName 'tether_server.exe'
    Start-Sleep -Seconds 2
}

Write-Host "[start] aoc_server"
$aocArgs = @(
    '--tls-cert', (Join-Path $certs 'server.crt'),
    '--tls-key', (Join-Path $certs 'server.key'),
    '--native',
    '--replay', 'replay_data.bin',
    '--no-replay-loop'
)
$aoc = Start-Process -FilePath $aocServer -ArgumentList $aocArgs -WorkingDirectory $dist -WindowStyle Minimized -PassThru
Write-Host ("[start] aoc_server pid={0}" -f $aoc.Id)

if (-not (Wait-TcpListen 443 30)) { throw 'aoc_server did not bind TCP 443' }
if (-not (Wait-UdpBound 7777 30)) { throw 'aoc_server did not bind UDP 7777' }

Write-Host "[start] tether_server"
$tether = Start-Process -FilePath $tetherServer -WorkingDirectory $dist -WindowStyle Minimized -PassThru
Write-Host ("[start] tether_server pid={0}" -f $tether.Id)
if (-not (Wait-UdpBound 19021 15)) { throw 'tether_server did not bind UDP 19021' }

if (-not $NoClient) {
    if (Test-Path $launcher) {
        Write-Host "[start] launcher"
        $null = Start-Process -FilePath $launcher -WorkingDirectory $dist -PassThru
    }

    $root = Resolve-GameRoot -Explicit $GameRoot
    if (-not $root) {
        Write-Host '[warn] AoC client not found; server stack is running, but client was not launched.'
    } else {
        $w64 = Join-Path $root 'AOC\Binaries\Win64'
        $gameExe = Join-Path $w64 'AOCClient-Win64-Shipping.exe'
        Write-Host ("[start] client {0}" -f $gameExe)
        $clientArgs = '-LauncherTetherPort=19021'
        if ($ClientExtraArgs) {
            $clientArgs = "$clientArgs $ClientExtraArgs"
            Write-Host ("[start] client extra args: {0}" -f $ClientExtraArgs)
        }
        $game = Start-Process -FilePath $gameExe -ArgumentList $clientArgs -WorkingDirectory $w64 -PassThru
        Write-Host ("[start] client pid={0}" -f $game.Id)
        if ($env:AOC_PATCH_LOG_VERBOSITY -eq '1') {
            $patchScript = Join-Path $scriptDir 'patch_aoc_log_verbosity.ps1'
            if (Test-Path $patchScript) {
                Start-Sleep -Milliseconds 500
                & $patchScript -ClientPid $game.Id -Value 5
            } else {
                Write-Host ("[warn] patch script missing: {0}" -f $patchScript)
            }
        }
        if (-not $NoDriveClient) {
            $driveScript = Join-Path $scriptDir 'drive_aoc_client.ps1'
            if (Test-Path $driveScript) {
                $boundedDriveSeconds = [Math]::Max(1, [Math]::Min($DriveSeconds, $WaitSeconds - 5))
                Write-Host ("[drive] client ui for {0}s" -f $boundedDriveSeconds)
                $driveArgs = @(
                    '-NoProfile',
                    '-ExecutionPolicy', 'Bypass',
                    '-File', $driveScript,
                    '-DurationSeconds', $boundedDriveSeconds,
                    '-LogDir', (Join-Path $dist 'logs')
                )
                $null = Start-Process -FilePath 'powershell.exe' -ArgumentList $driveArgs -WindowStyle Minimized -PassThru
            } else {
                Write-Host ("[warn] client driver missing: {0}" -f $driveScript)
            }
        }
    }
}

Write-Host ("[wait] {0}s for bootstrap/oracle window" -f $WaitSeconds)
Start-Sleep -Seconds $WaitSeconds

Write-Host ''
Write-Host '=== PROCESSES ==='
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -in @('AOCClient-Win64-Shipping.exe', 'launcher.exe', 'aoc_server.exe', 'tether_server.exe') } |
    Select-Object ProcessId, Name, CreationDate |
    Format-Table -AutoSize

Write-Host ''
Write-Host '=== ORACLE ==='
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'check_possession_oracle.ps1') -Tail 20

Write-Host ''
Write-Host '=== SEQUENCE MAP ==='
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'map_sequence_to_server_log.ps1') -Tail 12
