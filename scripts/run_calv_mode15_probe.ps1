<#
.SYNOPSIS
  Run the Ghidra-derived CALV mode 15 probe.

.DESCRIPTION
  Mode 15 emits the one-bit pre-field-list flag observed in the current
  Ghidra ReceivePropertiesForRPC path, followed by the 1/2/3 CALV field loop:
  PackageName as a 16-bit FName token, direct 32-bit TransactionId, and 1-bit
  bClientAckCanMakeVisible.
#>
[CmdletBinding()]
param(
    [int]$WaitSeconds = 150,
    [int]$DriveSeconds = 130
)

$scriptDir = Split-Path -Parent $PSCommandPath
$matrix = Join-Path $scriptDir 'run_calv_probe_matrix.ps1'

& $matrix `
    -Cases '15:1:2:3:prefixed-fnameindex-directtx-123' `
    -WaitSeconds $WaitSeconds `
    -DriveSeconds $DriveSeconds `
    -SnaOnly `
    -StopOnNoCalvDecodeError
