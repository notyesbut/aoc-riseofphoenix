<#
.SYNOPSIS
  Run isolated ClientAckUpdateLevelVisibility field-loop probes.

.DESCRIPTION
  These cases intentionally send incomplete CALV param streams to isolate where
  the client's bounded RPC reader starts consuming the wrong bit count:
    mode 17: TransactionId only
    mode 18: bool only
    mode 19: PackageName FName token only
    mode 20: empty field-loop terminator only
    mode 21: one-bit prefix + TransactionId only
    mode 22: one-bit prefix + bool only
    mode 23: one-bit prefix + PackageName FName token only
    mode 24: one-bit prefix + empty field-loop terminator only
#>
[CmdletBinding()]
param(
    [int]$WaitSeconds = 150,
    [int]$DriveSeconds = 130
)

$scriptDir = Split-Path -Parent $PSCommandPath
$matrix = Join-Path $scriptDir 'run_calv_probe_matrix.ps1'

& $matrix `
    -Cases '24:1:2:3:prefixed-empty-field-loop','21:1:2:3:prefixed-only-tx','22:1:2:3:prefixed-only-bool','23:1:2:3:prefixed-only-fname-index' `
    -WaitSeconds $WaitSeconds `
    -DriveSeconds $DriveSeconds `
    -SnaOnly `
    -StopOnNoCalvDecodeError
