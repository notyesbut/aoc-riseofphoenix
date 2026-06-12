<#
.SYNOPSIS
  Run ranked ClientAckUpdateLevelVisibility wire-layout probes and score them.

.DESCRIPTION
  This is the non-manual CALV feedback loop.  For each candidate param_mode it:
    1. starts a full native probe against the retail client,
    2. reads the newest emu log and the current retail AOC.log,
    3. classifies the client-side oracle,
    4. appends one JSONL row under dist\Release\logs.

  The goal is to compare wire layouts by evidence instead of by chat notes.
#>
[CmdletBinding()]
param(
    [string[]]$Modes = @('1', '4', '0', '6', '5'),
    [string[]]$Cases = @(),
    [int]$WaitSeconds = 150,
    [int]$DriveSeconds = 130,
    [uint32]$CalvHandle = 21,
    [uint32]$CalvMax = 1035,
    [uint32]$CalvBoolBits = 1,
    [uint32]$CalvFNameHandle = 1,
    [uint32]$CalvTxHandle = 2,
    [uint32]$CalvBoolHandle = 3,
    [switch]$SnaOnly,
    [switch]$StopOnNoCalvDecodeError
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')
$dist = Join-Path $repoRoot 'dist\Release'
$logDir = Join-Path $dist 'logs'
$runNative = Join-Path $scriptDir 'run_native_probe.ps1'

if (-not (Test-Path $runNative)) { throw "Missing $runNative" }
if (-not (Test-Path $dist)) { throw "Missing $dist" }
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonl = Join-Path $logDir "calv-probe-matrix-$stamp.jsonl"

$parsedModes = @()
foreach ($modeArg in $Modes) {
    foreach ($part in (([string]$modeArg) -split ',')) {
        $trimmed = $part.Trim()
        if (-not $trimmed) { continue }
        $parsedModes += [uint32]$trimmed
    }
}

function New-ProbeCase {
    param(
        [uint32]$Mode,
        [uint32]$FNameHandle,
        [uint32]$TxHandle,
        [uint32]$BoolHandle,
        [string]$Label
    )
    if (-not $Label) {
        $Label = "mode-$Mode-h$FNameHandle-$TxHandle-$BoolHandle"
    }
    return [pscustomobject]@{
        mode = $Mode
        fname_handle = $FNameHandle
        tx_handle = $TxHandle
        bool_handle = $BoolHandle
        label = $Label
    }
}

$probeCases = @()
foreach ($caseArg in $Cases) {
    foreach ($part in (([string]$caseArg) -split ',')) {
        $trimmed = $part.Trim()
        if (-not $trimmed) { continue }
        $pieces = $trimmed -split ':', 5
        if ($pieces.Count -ne 1 -and $pieces.Count -ne 4 -and $pieces.Count -ne 5) {
            throw "Invalid case '$trimmed'. Use mode or mode:fnameHandle:txHandle:boolHandle[:label]."
        }
        $mode = [uint32]$pieces[0]
        if ($pieces.Count -eq 1) {
            $probeCases += New-ProbeCase -Mode $mode `
                -FNameHandle $CalvFNameHandle `
                -TxHandle $CalvTxHandle `
                -BoolHandle $CalvBoolHandle `
                -Label "calv-param-mode-$mode"
        } else {
            $label = if ($pieces.Count -eq 5) { $pieces[4] } else { '' }
            $probeCases += New-ProbeCase -Mode $mode `
                -FNameHandle ([uint32]$pieces[1]) `
                -TxHandle ([uint32]$pieces[2]) `
                -BoolHandle ([uint32]$pieces[3]) `
                -Label $label
        }
    }
}
if ($probeCases.Count -eq 0) {
    foreach ($mode in $parsedModes) {
        $probeCases += New-ProbeCase -Mode $mode `
            -FNameHandle $CalvFNameHandle `
            -TxHandle $CalvTxHandle `
            -BoolHandle $CalvBoolHandle `
            -Label "calv-param-mode-$mode"
    }
}
if ($probeCases.Count -eq 0) { throw 'No CALV probe cases were provided.' }

function Stop-AocStack {
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -in @('AOCClient-Win64-Shipping.exe', 'launcher.exe',
                          'aoc_server.exe', 'tether_server.exe') -or
            $_.CommandLine -like '*run_native_probe.ps1*'
        } |
        ForEach-Object {
            Write-Host ("[matrix stop] {0} pid={1}" -f $_.Name, $_.ProcessId)
            $null = $_ | Invoke-CimMethod -MethodName Terminate -Arguments @{ Reason = 0 }
        }
}

function Get-LatestServerLog {
    Get-ChildItem $logDir -Filter 'emu-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Get-ClientLogPath {
    $path = Join-Path $env:LOCALAPPDATA 'AOC\Saved\Logs\AOC.log'
    if (Test-Path $path) { return $path }
    return $null
}

function Count-Matches {
    param([string]$Text, [string]$Pattern)
    if (-not $Text) { return 0 }
    return ([regex]::Matches($Text, $Pattern)).Count
}

function Last-MatchValue {
    param([string]$Text, [string]$Pattern, [int]$Group = 1)
    if (-not $Text) { return $null }
    $matches = [regex]::Matches($Text, $Pattern)
    if ($matches.Count -eq 0) { return $null }
    return $matches[$matches.Count - 1].Groups[$Group].Value
}

function Read-TextFile {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return '' }
    return Get-Content -Path $Path -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Get-FileByteLength {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return 0L }
    return ([System.IO.FileInfo]$Path).Length
}

function Read-TextFileFromOffset {
    param([string]$Path, [long]$Offset)
    if (-not $Path -or -not (Test-Path $Path)) { return '' }

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite)
    try {
        if ($Offset -lt 0) { $Offset = 0 }
        if ($Offset -gt $stream.Length) { $Offset = 0 }
        $null = $stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $remaining = [int]($stream.Length - $stream.Position)
        if ($remaining -le 0) { return '' }
        $bytes = New-Object byte[] $remaining
        $read = $stream.Read($bytes, 0, $remaining)
        return [System.Text.Encoding]::UTF8.GetString($bytes, 0, $read)
    } finally {
        $stream.Dispose()
    }
}

function Select-JsonLogLinesSince {
    param([string]$Text, [DateTime]$StartedAt)
    if (-not $Text) { return '' }

    $cutoff = ([DateTimeOffset]$StartedAt).ToUniversalTime().AddSeconds(-2)
    $selected = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ($Text -split "`r?`n")) {
        $match = [regex]::Match($line, '"timestamp":"([^"]+)"')
        if (-not $match.Success) { continue }
        try {
            $lineTime = [DateTimeOffset]::Parse($match.Groups[1].Value).ToUniversalTime()
        } catch {
            continue
        }
        if ($lineTime -ge $cutoff) {
            $selected.Add($line)
        }
    }
    return ($selected -join "`n")
}

function Analyze-Probe {
    param(
        [uint32]$Mode,
        [string]$Label,
        [DateTime]$StartedAt,
        [long]$ClientLogOffset = 0
    )

    $serverLog = Get-LatestServerLog
    $serverText = if ($serverLog) { Read-TextFile $serverLog.FullName } else { '' }
    $clientLog = Get-ClientLogPath
    $clientFullText = Read-TextFile $clientLog
    $clientText = Select-JsonLogLinesSince $clientFullText $StartedAt

    $calvMismatch = Count-Matches $clientText 'ReceivePropertiesForRPC - Mismatch read\. Function: ClientAckUpdateLevelVisibility'
    $calvReaderError = Count-Matches $clientText 'ReceivePropertiesForRPC - Reader\.IsError\(\) == true: Function: ClientAckUpdateLevelVisibility'
    $calvAnyRpcError = Count-Matches $clientText 'ReceivePropertiesForRPC.*ClientAckUpdateLevelVisibility'
    $contentBlockFail = Count-Matches $clientText 'ReadContentBlockPayload FAILED|ContentBlockFail|Error reading payload'
    $corruptPacket = Count-Matches $clientText 'Received corrupted packet data|ReceivedRawBunch'
    $invalidField = Count-Matches $clientText 'Invalid replicated field'
    $ackPossession = Count-Matches $clientText 'ServerAcknowledgePossession'
    $checkPossession = Count-Matches $clientText 'ServerCheckClientPossession'
    $wpWaiting = Count-Matches $clientText 'Waiting for World Partition Streaming'
    $noValidPawn = Count-Matches $clientText 'No valid pawn'

    $sulvStruct = Count-Matches $serverText '\[SULV-STRUCT\] ServerUpdateLevelVisibility'
    $calvSent = Count-Matches $serverText '>> ClientAckUpdateLevelVisibility'
    $calvFraming = Count-Matches $serverText 'CALV framing='
    $possessionPoll241 = Count-Matches $serverText 'BunchDataBits=241|ch=3 bits=241'
    $snlw834 = Count-Matches $serverText 'ch=3 bits=834|BunchDataBits=834'
    $serverAckPossession = Count-Matches $serverText 'ServerAcknowledgePossession'

    $classification = 'inconclusive'
    if ($ackPossession -gt 0 -or $serverAckPossession -gt 0) {
        $classification = 'possession_success'
    } elseif ($calvMismatch -gt 0) {
        $classification = 'calv_mismatch_read'
    } elseif ($calvReaderError -gt 0) {
        $classification = 'calv_reader_error'
    } elseif ($contentBlockFail -gt 0 -or $corruptPacket -gt 0) {
        $classification = 'packet_or_contentblock_failure'
    } elseif ($calvSent -gt 0 -and $calvAnyRpcError -eq 0) {
        $classification = 'calv_no_rpc_decode_error'
    } elseif ($calvSent -eq 0) {
        $classification = 'no_calv_sent'
    }

    $lastCalvLine = Last-MatchValue $serverText '(\[S>C\] CALV framing=.*)'
    $lastCalvSend = Last-MatchValue $serverText '(\[S>C\] >> ClientAckUpdateLevelVisibility.*)'
    $lastClientCalvError = Last-MatchValue $clientText '(ReceivePropertiesForRPC[^\r\n]*ClientAckUpdateLevelVisibility)'
    $lastLoading = Last-MatchValue $clientText '("message":"[^"]*(?:World Partition Streaming|No valid pawn)[^"]*")'

    return [pscustomobject]@{
        label = $Label
        mode = $Mode
        started_at = $StartedAt.ToString('o')
        analyzed_at = (Get-Date).ToString('o')
        classification = $classification
        server_log = if ($serverLog) { $serverLog.FullName } else { $null }
        client_log = $clientLog
        client_log_offset_bytes = $ClientLogOffset
        client_log_since_utc = ([DateTimeOffset]$StartedAt).ToUniversalTime().AddSeconds(-2).ToString('o')
        counts = [pscustomobject]@{
            sulv_struct = $sulvStruct
            calv_framing = $calvFraming
            calv_sent = $calvSent
            snlw_834 = $snlw834
            possession_poll_241 = $possessionPoll241
            client_calv_rpc_error = $calvAnyRpcError
            client_calv_mismatch = $calvMismatch
            client_calv_reader_error = $calvReaderError
            contentblock_fail = $contentBlockFail
            corrupt_packet = $corruptPacket
            invalid_field = $invalidField
            client_ack_possession = $ackPossession
            client_check_possession = $checkPossession
            wp_waiting = $wpWaiting
            no_valid_pawn = $noValidPawn
        }
        evidence = [pscustomobject]@{
            last_calv_framing = $lastCalvLine
            last_calv_send = $lastCalvSend
            last_client_calv_error = $lastClientCalvError
            last_loading = $lastLoading
        }
    }
}

Write-Host "=== CALV Probe Matrix ==="
Write-Host ("repo    : {0}" -f $repoRoot)
Write-Host ("jsonl   : {0}" -f $jsonl)
Write-Host ("cases   : {0}" -f (($probeCases | ForEach-Object {
    "{0}:mode={1}:handles={2}/{3}/{4}" -f $_.label, $_.mode,
        $_.fname_handle, $_.tx_handle, $_.bool_handle
}) -join ', '))
Write-Host ("wait    : {0}s drive={1}s" -f $WaitSeconds, $DriveSeconds)

foreach ($case in $probeCases) {
    $mode = [uint32]$case.mode
    $started = Get-Date
    $label = [string]$case.label
    $clientLogBefore = Get-ClientLogPath
    $clientLogOffset = Get-FileByteLength $clientLogBefore
    Write-Host ""
    Write-Host ("=== RUN {0} ===" -f $label) -ForegroundColor Cyan

    $nativeParams = @{
        WaitSeconds = $WaitSeconds
        DriveSeconds = $DriveSeconds
        CalvSerializeInt = 1
        CalvHandle = $CalvHandle
        CalvMax = $CalvMax
        CalvParamMode = $mode
        CalvBoolBits = $CalvBoolBits
        CalvFNameHandle = [uint32]$case.fname_handle
        CalvTxHandle = [uint32]$case.tx_handle
        CalvBoolHandle = [uint32]$case.bool_handle
    }
    if ($SnaOnly) { $nativeParams.SnaOnly = $true }

    & $runNative @nativeParams
    $runOk = $?
    $exitCode = if ($null -ne $LASTEXITCODE) {
        [int]$LASTEXITCODE
    } elseif ($runOk) {
        0
    } else {
        1
    }

    $result = Analyze-Probe -Mode $mode -Label $label -StartedAt $started `
        -ClientLogOffset $clientLogOffset
    $result | Add-Member -NotePropertyName case -NotePropertyValue ([pscustomobject]@{
        mode = $mode
        calv_handle = $CalvHandle
        calv_max = $CalvMax
        bool_bits = $CalvBoolBits
        fname_handle = [uint32]$case.fname_handle
        tx_handle = [uint32]$case.tx_handle
        bool_handle = [uint32]$case.bool_handle
    })
    $result | Add-Member -NotePropertyName runner_exit_code -NotePropertyValue $exitCode
    ($result | ConvertTo-Json -Compress -Depth 8) | Add-Content -Path $jsonl -Encoding UTF8

    $counts = $result.counts
    Write-Host ("[matrix] case={0} mode={1} handles={2}/{3}/{4} class={5} calv_sent={6} calv_rpc_err={7} mismatch={8} reader={9} cbfail={10} 241polls={11} wp={12}" -f `
        $label, $mode, $case.fname_handle, $case.tx_handle, $case.bool_handle, `
        $result.classification, $counts.calv_sent, $counts.client_calv_rpc_error, `
        $counts.client_calv_mismatch, $counts.client_calv_reader_error, `
        $counts.contentblock_fail, $counts.possession_poll_241, $counts.wp_waiting) -ForegroundColor Yellow

    Stop-AocStack
    Start-Sleep -Seconds 2

    if ($exitCode -ne 0) {
        Write-Host ("[matrix] run_native_probe exited with {0}; continuing to next mode." -f $exitCode) -ForegroundColor DarkYellow
    }

    if ($StopOnNoCalvDecodeError -and $result.classification -eq 'calv_no_rpc_decode_error') {
        Write-Host "[matrix] stopping: CALV reached client without ReceivePropertiesForRPC decode error." -ForegroundColor Green
        break
    }

    if ($result.classification -eq 'possession_success') {
        Write-Host "[matrix] stopping: possession succeeded." -ForegroundColor Green
        break
    }
}

Write-Host ""
Write-Host ("[matrix] wrote {0}" -f $jsonl) -ForegroundColor Cyan
