<#
.SYNOPSIS
  Read the retail-client oracle (AOC.log) and the server log after a world-entry
  attempt, and print a one-line possession VERDICT plus the relevant context.

.DESCRIPTION
  The single fastest feedback loop for the possession blocker: after relogging
  the retail client and trying to enter the world, run this to see whether the
  ClientRestart / Pawn-property bunch was accepted.

  Oracle  = %LOCALAPPDATA%\AOC\Saved\Logs\AOC.log   (client side)
  Server  = <repo>\dist\Release\logs\emu-*.log      (what we sent)

  Verdict mapping (client side):
    "Invalid replicated field"           -> selector index landed on an EMPTY
                                            FClassNetCache slot (wrong value)
    "ServerAcknowledgePossession" sent   -> POSSESSION SUCCEEDED (client acked)
    "ServerCheckClientPossession" sent   -> index/field right, pawn GUID did not
                                            resolve (a different, later layer)
    (no possession lines at all)         -> bunch silently dropped / not reached

.PARAMETER Backup
  Inspect the most recent AOC-backup-*.log instead of the live AOC.log (the
  client rotates AOC.log to a timestamped backup on each launch, so after you
  close the client the attempt you care about is usually the latest backup).

.PARAMETER Tail
  How many trailing matching lines to show (default 25).

.EXAMPLE
  .\scripts\check_possession_oracle.ps1
  .\scripts\check_possession_oracle.ps1 -Backup
#>
[CmdletBinding()]
param(
    [switch]$Backup,
    [int]$Tail = 25
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path (Split-Path $PSCommandPath)

$logDir = Join-Path $env:LOCALAPPDATA 'AOC\Saved\Logs'
if ($Backup) {
    $oracle = Get-ChildItem $logDir -Filter 'AOC-backup-*.log' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $oraclePath = if ($oracle) { $oracle.FullName } else { $null }
} else {
    $oraclePath = Join-Path $logDir 'AOC.log'
}

Write-Host "=== ORACLE (client) ===" -ForegroundColor Cyan
if (-not $oraclePath -or -not (Test-Path $oraclePath)) {
    Write-Host "  (no oracle log found at $logDir)" -ForegroundColor Yellow
} else {
    Write-Host "  $oraclePath" -ForegroundColor DarkGray
    $pat = 'Invalid replicated field|ReadContentBlockPayload|ReceivedBunch|ReceivedRawBunch|SequenceId|RepIndex|ContentBlock|ObjectReplicatorReceivedBunchFail|OutField|ReceivePropertiesForRPC|Possess|Restart|AcknowledgedPawn|UNetConnection::Close|UChannel::Close|SendCloseReason|CloseBunch|ConnectionLost|timed out'
    $hits = Select-String -Path $oraclePath -Pattern $pat -ErrorAction SilentlyContinue
    if (-not $hits) {
        Write-Host "  (no possession-relevant lines matched)" -ForegroundColor Yellow
    } else {
        $hits | Select-Object -Last $Tail | ForEach-Object {
            $line = $_.Line.Trim()
            $color = 'Gray'
            if     ($line -match 'Invalid replicated field')   { $color = 'Red' }
            elseif ($line -match 'ServerAcknowledgePossession') { $color = 'Green' }
            elseif ($line -match 'ServerCheckClientPossession') { $color = 'Yellow' }
            elseif ($line -match 'timed out|Close')             { $color = 'DarkYellow' }
            Write-Host "  $line" -ForegroundColor $color
        }
    }

    Write-Host ""
    Write-Host "=== VERDICT ===" -ForegroundColor Cyan
    $all = (Get-Content $oraclePath -Raw -ErrorAction SilentlyContinue)
    # The client NAMES the resolved field on a populated slot — capture it.
    $outField = $null
    $m = [regex]::Match($all, 'OutField:\s*([A-Za-z0-9_]+)')
    if ($m.Success) { $outField = $m.Groups[1].Value }
    $hasRpcPropertyVerdict = ($outField -or $all -match 'ReceivePropertiesForRPC')
    $hasContentBlockFail = ($all -match 'ReadContentBlockPayload FAILED|ContentBlockFail|Error reading payload')
    if ($all -match 'ServerAcknowledgePossession') {
        Write-Host "  POSSESSION SUCCEEDED - client sent ServerAcknowledgePossession." -ForegroundColor Green
    } elseif ($all -match 'ServerCheckClientPossession') {
        Write-Host "  FIELD RIGHT, PAWN UNRESOLVED - client bounced ServerCheckClientPossession." -ForegroundColor Yellow
        Write-Host "  (Selector index is a valid field; the 128-bit pawn GUID did not resolve" -ForegroundColor DarkGray
        Write-Host "   in the client PackageMap - verify the pawn ActorOpen registered it first.)" -ForegroundColor DarkGray
    } elseif ($hasRpcPropertyVerdict) {
        Write-Host "  RPC/PROPERTY VERDICT - the client reached a field/property decoder:" -ForegroundColor Magenta
        if ($outField) {
            Write-Host "    OutField = $outField" -ForegroundColor Magenta
            Write-Host "  This is a CALIBRATION POINT: record (index -> $outField) in" -ForegroundColor DarkGray
            Write-Host "  docs/re-plan/poss/INDEX-NAME-MAP.md." -ForegroundColor DarkGray
        } else {
            Write-Host "    ReceivePropertiesForRPC present (no OutField captured)." -ForegroundColor Magenta
        }
        Write-Host "  Treat payload/type conclusions as valid only with this RPC/property evidence." -ForegroundColor DarkGray
    } elseif ($all -match 'Invalid replicated field') {
        Write-Host "  EMPTY SLOT - 'Invalid replicated field' (the index is a hole, no field there)." -ForegroundColor Red
        Write-Host "  Do NOT reuse this value. Probe the next rule-predicted index" -ForegroundColor DarkGray
        Write-Host "  (see docs/re-plan/poss/CR-INDEX-FROM-ANCHORS.md / INDEX-NAME-MAP.md)." -ForegroundColor DarkGray
    } elseif ($hasContentBlockFail) {
        Write-Host "  FRAMING/PACKET FAILURE - ContentBlockFail without OutField/ReceivePropertiesForRPC." -ForegroundColor Yellow
        Write-Host "  Do not classify this as a populated-slot payload verdict yet; map the" -ForegroundColor DarkGray
        Write-Host "  client SequenceId to the emu seq= line below first." -ForegroundColor DarkGray
    } else {
        Write-Host "  INCONCLUSIVE - no possession verdict lines found (bunch may not have" -ForegroundColor Yellow
        Write-Host "  reached the receiver, or the attempt is in a different log; try -Backup)." -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "=== SERVER (what we sent) ===" -ForegroundColor Cyan
$serverLogDir = Join-Path $repoRoot 'dist\Release\logs'
$serverLog = Get-ChildItem $serverLogDir -Filter 'emu-*.log' -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $serverLog) {
    Write-Host "  (no server log found at $serverLogDir)" -ForegroundColor Yellow
} else {
    Write-Host "  $($serverLog.FullName)" -ForegroundColor DarkGray
    $spat = 'ClientRestart RepIndex|CR-FUZZ|Pawn-property RepIndex|PAWN-PROP-FUZZ|NATIVE Pawn-property|ClientAckUpdateLevelVisibility'
    $shits = Select-String -Path $serverLog.FullName -Pattern $spat -ErrorAction SilentlyContinue
    if (-not $shits) {
        Write-Host "  (no CR/Pawn-property/CALV emit lines yet)" -ForegroundColor Yellow
    } else {
        $shits | Select-Object -Last 12 | ForEach-Object {
            Write-Host "  $($_.Line.Trim())" -ForegroundColor Gray
        }
    }
}

if ($oraclePath -and (Test-Path $oraclePath)) {
    $mapper = Join-Path $repoRoot 'scripts\map_sequence_to_server_log.ps1'
    if (Test-Path $mapper) {
        Write-Host ""
        $sequenceTail = [Math]::Min($Tail, 12)
        if ($serverLog) {
            & $mapper -ClientLog $oraclePath -ServerLog $serverLog.FullName -Tail $sequenceTail
        } else {
            & $mapper -ClientLog $oraclePath -Tail $sequenceTail
        }
    }
}
