<#
.SYNOPSIS
  Map retail-client SequenceId errors back to the latest matching emu send line.

.DESCRIPTION
  Post-run network oracle helper. It reads AOC.log, groups the latest client
  packet/framing errors by SequenceId, attaches nearby UE error context, and
  maps each SequenceId to the latest emu log line with the same seq= value when
  possible.

  ContentBlockFail is classified as a framing/packet failure unless the nearby
  client context contains OutField or ReceivePropertiesForRPC evidence, which
  means the client reached a true RPC/property decoder verdict.

.PARAMETER ClientLog
  AOC.log path. Defaults to %LOCALAPPDATA%\AOC\Saved\Logs\AOC.log.

.PARAMETER ServerLog
  emu-*.log path. Defaults to latest <repo>\dist\Release\logs\emu-*.log.

.PARAMETER Backup
  Use the newest AOC-backup-*.log instead of live AOC.log.

.PARAMETER Tail
  Number of trailing SequenceId groups to print.
#>
[CmdletBinding()]
param(
    [string]$ClientLog,
    [string]$ServerLog,
    [switch]$Backup,
    [int]$Tail = 8,
    [int]$ContextBefore = 8,
    [int]$ContextAfter = 2
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path (Split-Path $PSCommandPath)

function Resolve-ClientLog {
    param(
        [string]$Path,
        [switch]$UseBackup
    )

    if ($Path) { return $Path }

    $logDir = Join-Path $env:LOCALAPPDATA 'AOC\Saved\Logs'
    if ($UseBackup) {
        $latest = Get-ChildItem $logDir -Filter 'AOC-backup-*.log' -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { return $latest.FullName }
        return $null
    }

    return (Join-Path $logDir 'AOC.log')
}

function Resolve-ServerLog {
    param([string]$Path)

    if ($Path) { return $Path }

    $serverLogDir = Join-Path $repoRoot 'dist\Release\logs'
    $latest = Get-ChildItem $serverLogDir -Filter 'emu-*.log' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) { return $latest.FullName }
    return $null
}

function Get-JsonishField {
    param(
        [string]$Line,
        [string]$Name
    )

    $match = [regex]::Match($Line, '"' + [regex]::Escape($Name) + '"\s*:\s*"([^"]*)"')
    if ($match.Success) { return $match.Groups[1].Value }

    $num = [regex]::Match($Line, '"' + [regex]::Escape($Name) + '"\s*:\s*([0-9 ]+)')
    if ($num.Success) { return $num.Groups[1].Value.Trim() }

    return $null
}

function Get-JsonishMessage {
    param([string]$Line)

    $needle = '"message":"'
    $idx = $Line.IndexOf($needle)
    if ($idx -lt 0) { return $Line.Trim() }

    $tail = $Line.Substring($idx + $needle.Length)
    $extraField = $tail.IndexOf('","CallingFunction"')
    if ($extraField -ge 0) {
        $tail = $tail.Substring(0, $extraField)
    } elseif ($tail.EndsWith('"}')) {
        $tail = $tail.Substring(0, $tail.Length - 2)
    }

    return $tail.Trim()
}

function New-ClientRecord {
    param(
        [int]$LineNumber,
        [string]$Line
    )

    $timestamp = Get-JsonishField $Line 'timestamp'
    $utcTime = $null
    if ($timestamp) {
        $parsed = [DateTime]::MinValue
        if ([DateTime]::TryParse($timestamp, [ref]$parsed)) {
            $utcTime = $parsed.ToUniversalTime()
        }
    }

    [pscustomobject]@{
        LineNumber = $LineNumber
        Timestamp  = $timestamp
        UtcTime    = $utcTime
        Frame      = Get-JsonishField $Line 'frame'
        Category   = Get-JsonishField $Line 'category'
        Message    = Get-JsonishMessage $Line
        Raw        = $Line.Trim()
    }
}

function Format-ClientRecord {
    param($Record)

    $parts = @()
    if ($Record.Timestamp) { $parts += $Record.Timestamp }
    if ($Record.Frame) { $parts += ("frame={0}" -f $Record.Frame) }
    if ($Record.Category) { $parts += $Record.Category }
    $prefix = ($parts -join ' ')
    if ($prefix) {
        return ("line {0}: {1} - {2}" -f $Record.LineNumber, $prefix, $Record.Message)
    }

    return ("line {0}: {1}" -f $Record.LineNumber, $Record.Raw)
}

function Get-ClientVerdict {
    param([string]$ContextText)

    if ($ContextText -match 'OutField:\s*[A-Za-z0-9_]+') {
        return 'RPC/PROPERTY VERDICT - OutField names a populated field'
    }

    if ($ContextText -match 'ReceivePropertiesForRPC') {
        return 'RPC/PROPERTY VERDICT - ReceivePropertiesForRPC was reached'
    }

    if ($ContextText -match 'Invalid replicated field') {
        return 'EMPTY SLOT - invalid replicated field'
    }

    if ($ContextText -match 'ReadContentBlockPayload FAILED|ContentBlockFail|Error reading payload') {
        return 'FRAMING/PACKET FAILURE - ContentBlockFail without RPC/property evidence'
    }

    if ($ContextText -match 'Received corrupted packet data|ReceivedRawBunch') {
        return 'CORRUPTED PACKET/FRAMING - no RPC/property verdict'
    }

    return 'CLIENT ERROR - no finer verdict'
}

function Get-ServerKind {
    param(
        [string]$Line,
        [string[]]$Context
    )

    $joined = (($Context + @($Line)) -join "`n")
    if ($joined -match 'ClientAckUpdateLevelVisibility') { return 'ClientAckUpdateLevelVisibility' }
    if ($joined -match 'ClientRestart') { return 'ClientRestart' }
    if ($joined -match 'Player Pawn ActorOpen|Pawn ActorOpen') { return 'Player Pawn ActorOpen' }
    if ($joined -match 'PC ActorOpen') { return 'PC ActorOpen' }
    if ($joined -match 'NMT_Welcome') { return 'NMT_Welcome' }
    if ($joined -match 'NMT_Challenge') { return 'NMT_Challenge' }
    if ($joined -match 'SPLICE') { return 'Replay splice' }
    if ($Line -match 'send_partial_open_chain') { return 'partial open chain' }
    if ($Line -match 'send_bunch_packet') { return 'bunch packet' }
    return 'send line'
}

function Get-ServerSeqMap {
    param([string]$Path)

    $map = @{}
    if (-not $Path -or -not (Test-Path $Path)) { return $map }

    $lines = Get-Content $Path -Encoding UTF8 -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $seqMatch = [regex]::Match($line, '\bseq=(\d+)\b')
        if (-not $seqMatch.Success) { continue }

        $isSend = $line -match '>>|send_|Sending|S>C|SPLICE|NATIVE'
        if (-not $isSend) { continue }

        $start = [Math]::Max(0, $i - 3)
        $end = [Math]::Min($lines.Count - 1, $i + 3)
        $context = @()
        for ($j = $start; $j -le $end; $j++) {
            if ($j -eq $i) { continue }
            $ctx = $lines[$j].Trim()
            if ($ctx -match 'ActorOpen|ClientRestart|ClientAckUpdateLevelVisibility|send_|>>|S>C|NMT_|SPLICE|PAWN|Pawn|PcEmitter|PlayerPawnEmitter') {
                $context += ("line {0}: {1}" -f ($j + 1), $ctx)
            }
        }

        $seq = $seqMatch.Groups[1].Value
        $map[$seq] = [pscustomobject]@{
            SequenceId = $seq
            LineNumber = $i + 1
            Kind = Get-ServerKind $line $context
            Text = $line.Trim()
            Context = $context
        }
    }

    return $map
}

function Get-ServerStartUtc {
    param([string]$Path)

    if (-not $Path -or -not (Test-Path $Path)) { return $null }

    $lines = Get-Content $Path -Encoding UTF8 -TotalCount 200 -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        $match = [regex]::Match($line, '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]')
        if (-not $match.Success) { continue }

        try {
            $local = [DateTime]::ParseExact(
                $match.Groups[1].Value,
                'yyyy-MM-dd HH:mm:ss.fff',
                [Globalization.CultureInfo]::InvariantCulture)
            return $local.ToUniversalTime()
        } catch {
            return $null
        }
    }

    return $null
}

function Convert-ServerLineUtc {
    param([string]$Line)

    $match = [regex]::Match($Line, '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]')
    if (-not $match.Success) { return $null }

    try {
        $local = [DateTime]::ParseExact(
            $match.Groups[1].Value,
            'yyyy-MM-dd HH:mm:ss.fff',
            [Globalization.CultureInfo]::InvariantCulture)
        return $local.ToUniversalTime()
    } catch {
        return $null
    }
}

function Get-ServerSendRecords {
    param([string]$Path)

    $records = @()
    if (-not $Path -or -not (Test-Path $Path)) { return $records }

    $lines = Get-Content $Path -Encoding UTF8 -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -notmatch '>> S>C|send_bunch_packet|NATIVE ClientRestart|ClientAckUpdateLevelVisibility') {
            continue
        }

        $start = [Math]::Max(0, $i - 3)
        $end = [Math]::Min($lines.Count - 1, $i + 3)
        $context = @()
        for ($j = $start; $j -le $end; $j++) {
            if ($j -eq $i) { continue }
            $ctx = $lines[$j].Trim()
            if ($ctx -match 'ActorOpen|ClientRestart|ClientAckUpdateLevelVisibility|CALV|send_|>>|S>C|PAWN|Pawn|PlayerPawnEmitter') {
                $context += ("line {0}: {1}" -f ($j + 1), $ctx)
            }
        }

        $seq = $null
        $seqMatch = [regex]::Match($line, '\bseq=(\d+)\b')
        if ($seqMatch.Success) {
            $seq = $seqMatch.Groups[1].Value
        }

        $records += [pscustomobject]@{
            LineNumber = $i + 1
            UtcTime = Convert-ServerLineUtc $line
            SequenceId = $seq
            Kind = Get-ServerKind $line $context
            Text = $line.Trim()
            Context = $context
        }
    }

    return $records
}

function Get-ClientSeqGroups {
    param(
        [string]$Path,
        [int]$Before,
        [int]$After,
        [object]$SinceUtc = $null
    )

    $groups = @{}
    if (-not $Path -or -not (Test-Path $Path)) { return @() }

    $lines = Get-Content $Path -Encoding UTF8 -ErrorAction SilentlyContinue
    $records = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $records += (New-ClientRecord ($i + 1) $lines[$i])
    }

    $relevant = 'Received corrupted packet data with SequenceId|UChannel::ReceivedRawBunch|ReadContentBlockPayload FAILED|ContentBlockFail|ObjectReplicatorReceivedBunchFail|Invalid replicated field|OutField:|ReceivePropertiesForRPC|Error reading payload'
    for ($i = 0; $i -lt $records.Count; $i++) {
        $record = $records[$i]
        $seqMatch = [regex]::Match($record.Raw, 'Received corrupted packet data with SequenceId:\s*(\d+)')
        if (-not $seqMatch.Success) { continue }
        if ($SinceUtc -and $record.UtcTime -and $record.UtcTime -lt $SinceUtc) { continue }

        $seq = $seqMatch.Groups[1].Value
        $start = [Math]::Max(0, $i - $Before)
        $end = [Math]::Min($records.Count - 1, $i + $After)
        $context = @()
        for ($j = $start; $j -le $end; $j++) {
            if ($records[$j].Raw -match $relevant) {
                $context += $records[$j]
            }
        }

        $contextText = (($context | ForEach-Object { $_.Raw }) -join "`n")
        if (-not $groups.ContainsKey($seq)) {
            $groups[$seq] = [pscustomobject]@{
                SequenceId = $seq
                Occurrences = 0
                LastLine = 0
                LastTimestamp = $null
                LastFrame = $null
                Verdict = $null
                Context = @()
            }
        }

        $groups[$seq].Occurrences += 1
        $groups[$seq].LastLine = $record.LineNumber
        $groups[$seq].LastTimestamp = $record.Timestamp
        $groups[$seq].LastFrame = $record.Frame
        $groups[$seq].Verdict = Get-ClientVerdict $contextText
        $groups[$seq].Context = $context
    }

    return @($groups.Values | Sort-Object LastLine)
}

function Get-ClientDecoderEvents {
    param(
        [string]$Path,
        [object]$SinceUtc = $null
    )

    $events = @()
    if (-not $Path -or -not (Test-Path $Path)) { return $events }

    $lines = Get-Content $Path -Encoding UTF8 -ErrorAction SilentlyContinue
    $patterns = 'OutField:|ReceivePropertiesForRPC|ReadContentBlockPayload FAILED|ContentBlockFail|Invalid replicated field|ServerAcknowledgePossession|ServerCheckClientPossession'
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch $patterns) { continue }

        $record = New-ClientRecord ($i + 1) $lines[$i]
        if ($SinceUtc -and $record.UtcTime -and $record.UtcTime -lt $SinceUtc) { continue }
        $events += $record
    }

    return $events
}

function Get-NearbyServerSends {
    param(
        [object[]]$ServerRecords,
        [object]$UtcTime,
        [int]$Limit = 3,
        [int]$WindowMs = 250
    )

    if (-not $UtcTime) { return @() }

    return @($ServerRecords |
        Where-Object { $_.UtcTime -and ([Math]::Abs(($_.UtcTime - $UtcTime).TotalMilliseconds) -le $WindowMs) } |
        Sort-Object @{ Expression = { [Math]::Abs(($_.UtcTime - $UtcTime).TotalMilliseconds) } } |
        Select-Object -First $Limit)
}

$clientPath = Resolve-ClientLog -Path $ClientLog -UseBackup:$Backup
$serverPath = Resolve-ServerLog -Path $ServerLog

Write-Host "=== SEQUENCE MAP (client -> server) ===" -ForegroundColor Cyan
if (-not $clientPath -or -not (Test-Path $clientPath)) {
    Write-Host "  (no client log found)" -ForegroundColor Yellow
    return
}

Write-Host "  client: $clientPath" -ForegroundColor DarkGray
if ($serverPath -and (Test-Path $serverPath)) {
    Write-Host "  server: $serverPath" -ForegroundColor DarkGray
} else {
    Write-Host "  server: (no emu log found)" -ForegroundColor Yellow
}

$serverMap = Get-ServerSeqMap $serverPath
$serverStartUtc = Get-ServerStartUtc $serverPath
if ($serverStartUtc) {
    Write-Host ("  client filter: errors at/after server start {0:yyyy-MM-ddTHH:mm:ss.fffZ}" -f $serverStartUtc) -ForegroundColor DarkGray
}

$groups = @(Get-ClientSeqGroups -Path $clientPath -Before $ContextBefore -After $ContextAfter -SinceUtc $serverStartUtc)
if (-not $groups -or $groups.Count -eq 0) {
    Write-Host "  (no client SequenceId errors found)" -ForegroundColor Yellow
} else {
    $selected = @($groups | Select-Object -Last $Tail)
    foreach ($group in $selected) {
        $color = 'Yellow'
        if ($group.Verdict -match '^RPC/PROPERTY') { $color = 'Magenta' }
        elseif ($group.Verdict -match '^EMPTY') { $color = 'Red' }

        Write-Host ""
        Write-Host ("  seq={0} occurrences={1} last_line={2} verdict={3}" -f $group.SequenceId, $group.Occurrences, $group.LastLine, $group.Verdict) -ForegroundColor $color

        $server = $serverMap[$group.SequenceId]
        if ($server) {
            Write-Host ("    server: line {0} kind={1}" -f $server.LineNumber, $server.Kind) -ForegroundColor Gray
            Write-Host ("      {0}" -f $server.Text) -ForegroundColor DarkGray
            $server.Context | Select-Object -First 4 | ForEach-Object {
                Write-Host ("      context: {0}" -f $_) -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    server: (no matching emu seq= send line found)" -ForegroundColor DarkYellow
        }

        $group.Context | Select-Object -Last 5 | ForEach-Object {
            Write-Host ("    client: {0}" -f (Format-ClientRecord $_)) -ForegroundColor Gray
        }
    }
}

$serverSendRecords = @(Get-ServerSendRecords $serverPath)
$decoderEvents = @(Get-ClientDecoderEvents -Path $clientPath -SinceUtc $serverStartUtc | Select-Object -Last $Tail)
if ($decoderEvents -and $decoderEvents.Count -gt 0) {
    Write-Host ""
    Write-Host "=== DECODER EVENTS (time-nearest server sends) ===" -ForegroundColor Cyan
    foreach ($event in $decoderEvents) {
        Write-Host ""
        Write-Host ("  client: {0}" -f (Format-ClientRecord $event)) -ForegroundColor Magenta
        $nearby = @(Get-NearbyServerSends -ServerRecords $serverSendRecords -UtcTime $event.UtcTime)
        if (-not $nearby -or $nearby.Count -eq 0) {
            Write-Host "    server: (no send within +/-250ms)" -ForegroundColor DarkYellow
            continue
        }

        foreach ($send in $nearby) {
            $delta = [int][Math]::Round(($send.UtcTime - $event.UtcTime).TotalMilliseconds)
            $seqText = ''
            if ($send.SequenceId) { $seqText = (" seq={0}" -f $send.SequenceId) }
            Write-Host ("    server: delta={0}ms line={1}{2} kind={3}" -f $delta, $send.LineNumber, $seqText, $send.Kind) -ForegroundColor Gray
            Write-Host ("      {0}" -f $send.Text) -ForegroundColor DarkGray
        }
    }
}
