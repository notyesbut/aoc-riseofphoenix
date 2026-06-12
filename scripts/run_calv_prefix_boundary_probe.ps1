<#
.SYNOPSIS
  Probe whether the custom RPC prefix bit is outside NumPayloadBits.

.DESCRIPTION
  Modes 27/28 emit `[SerializeInt(handle)][prefix bit][SIP(param_bits)]`
  instead of putting the prefix inside the bounded param payload.
#>
[CmdletBinding()]
param(
    [int]$WaitSeconds = 150,
    [int]$DriveSeconds = 130
)

$scriptDir = Split-Path -Parent $PSCommandPath
$matrix = Join-Path $scriptDir 'run_calv_probe_matrix.ps1'

& $matrix `
    -Cases '27:1:2:3:pre-npb-prefix-sip-fnameindex','28:1:2:3:pre-npb-prefix-softfname' `
    -WaitSeconds $WaitSeconds `
    -DriveSeconds $DriveSeconds `
    -SnaOnly `
    -StopOnNoCalvDecodeError
