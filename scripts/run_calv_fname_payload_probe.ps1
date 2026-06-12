<#
.SYNOPSIS
  Run Ghidra/IDA-ranked CALV FName payload probes.

.DESCRIPTION
  Current reader evidence says custom RPC params consume one prefix bit before
  the 1-based field loop. These cases keep all three CALV fields present and
  vary only the PackageName FName leaf payload.
#>
[CmdletBinding()]
param(
    [int]$WaitSeconds = 150,
    [int]$DriveSeconds = 130
)

$scriptDir = Split-Path -Parent $PSCommandPath
$matrix = Join-Path $scriptDir 'run_calv_probe_matrix.ps1'

& $matrix `
    -Cases '25:1:2:3:prefixed-sip-fnameindex-directtx','26:1:2:3:prefixed-softfname-directtx' `
    -WaitSeconds $WaitSeconds `
    -DriveSeconds $DriveSeconds `
    -SnaOnly `
    -StopOnNoCalvDecodeError
