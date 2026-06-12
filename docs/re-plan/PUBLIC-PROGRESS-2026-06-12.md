# Public Progress Snapshot - 2026-06-12

This snapshot summarizes the sanitized native-server progress prepared for the
public fork. It intentionally excludes retail binaries, captured game assets,
local logs, local debugger databases, and one-off scratch dumps.

## Scope

The project remains a loopback wire-format emulator for the retail AoC client.
The current work advances the native synthesis path: server-built ActorOpen
bunches, PlayerController/Pawn NetGUID registration, streaming visibility RPCs,
ClientRestart probes, and live-client oracle tooling.

## Repository Sanitation

- Removed local automation state from the public branch.
- Removed the local automation-specific top-level instruction file from the public
  branch.
- Added ignore rules for local tool state, generated RE scratch files, and
  transient decompiler output.
- Left runtime memory patching and local log artifacts out of the public patch.
- Kept only source, tests, reusable probe scripts, and a small reusable Ghidra
  exporter as public artifacts.

## Implemented Progress

### Build Wrapper

- Hardened `scripts/build.ps1` for the current Visual Studio Build Tools layout.
- Fixed `${env:ProgramFiles(x86)}` expansion.
- Added MSBuild/CMake fallback discovery.
- Normalized `PATHEXT` so PowerShell process exit handling does not report false
  failures when `.EXE` is missing.
- Switched target builds through `cmake --build` with `/nr:false`.

### ActorOpen And SerializeNewActor

- Added rebuild-free probes for SerializeNewActor level GUID, location, and
  packed-vector hypotheses.
- Added the current AoC vector candidate path:
  `SerializeInt(header_value, header_max)` followed by per-axis bounded
  `SerializeInt` values.
- Added minimal actor-root content-tail support:
  `[bHasRepLayout=0][bIsActor=1][SIP NumPayloadBits=0]`.
- Kept full content-block emission probeable for later property/subobject
  fidelity work.
- Added optional, disabled-by-default ActorOpen payload dumps for byte-diffing.
- Preserved partial ActorOpen chain work so continuation bunches can carry the
  channel name when the client requires it.

### Possession And Streaming RPCs

- Updated ClientRestart defaults to the currently verified live-client
  FieldNetIndex window.
- Added a structured parser for client `ServerUpdateLevelVisibility` payloads.
- Records package names and visibility request IDs from live client traffic.
- Queues `ClientAckUpdateLevelVisibility` responses from structured SULV input.
- Changed `ClientUpdateLevelStreamingStatus` to default to bounded
  `SerializeInt` selector framing with rollback to the legacy SIP selector.
- Added CALV selector and parameter-layout probe modes for raw params, field
  loops, nested transaction layouts, FName/FString variants, empty-field cases,
  and prefix-boundary tests.

### Probe Automation

- Added `scripts/run_native_probe.ps1` for a full local native-client smoke run.
- Added `scripts/run_calv_probe_matrix.ps1` and focused wrappers for CALV layout
  sweeps.
- Added `scripts/map_sequence_to_server_log.ps1` to map retail-client
  `SequenceId` errors back to emulator send lines.
- Extended `scripts/check_possession_oracle.ps1` to separate content-block
  failures from true RPC/property decoder verdicts.

### RE Tooling

- Added `tools/ghidra/DecompAoCTargets.java`, a reusable targeted decompile
  exporter for the current client receive/read path.
- Kept reusable IDA/Python protocol helpers in `src/protocol/tools`.
- Excluded generated `_*.txt`, `_*.py`, and decompile-output scratch files.

## Live Evidence From The Local Client

The latest live matrix established these useful boundaries:

- The client reaches `ReceivePropertiesForRPC` for
  `ClientAckUpdateLevelVisibility`.
- The earlier repeated `ReadContentBlockPayload FAILED` symptom is gone for the
  successful outer CALV framing cases.
- Remaining CALV failures are consistent `Mismatch read` results, which means
  the outer RPC selector/content-block path is correct enough to enter the
  function parameter reader, but the declared parameter payload bit count still
  does not match the actual reader consumption.
- Prefix-before-`NumPayloadBits` probes fail differently, proving that boundary
  placement is wrong for that candidate.
- Empty-field and isolated-field probes do not satisfy the reader, so the next
  blocker is the exact property/leaf serialization used by CALV parameters,
  especially the package-name FName/FString path and transaction-id struct.

## Remaining Blockers

- The native server is not yet a stable playable server. The client can be driven
  farther into world entry, but CALV still blocks stable streaming visibility.
- CALV needs one more exact receiver-side derivation: how the client reader
  consumes `PackageName`, `VisibilityRequestId`, and the boolean within the
  bounded `NumPayloadBits` region.
- Full ActorOpen property/subobject fidelity remains behind the minimal-tail
  path. The minimal path is useful for NetGUID registration, not a complete
  replicated actor state.
- ClassNetCache indices and field counts are retail-client-version sensitive and
  must remain probeable.

## Next Technical Step

Use Ghidra/IDA against the current retail client to extract the exact
post-`ReceivePropertiesForRPC` leaf path for `ClientAckUpdateLevelVisibility`.
The target is not another blind payload guess; it is the bit-consumption order
inside the bounded parameter reader after the selector has already resolved to
CALV.
