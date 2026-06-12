# FClassNetCache index -> field-name map (GROUND TRUTH from the live client)

**Breakthrough (2026-06-09 session 2):** the retail client's log NAMES the resolved
field for every index we probe. This turns the possession blocker from "guess the
ClientRestart index" into "read the real table off the oracle." Two failure modes
distinguish a populated slot from an empty one:

- **EMPTY slot:** `LogRep Error: ReceivedBunch: Invalid replicated field <N> in AoCPlayerControllerBP_C`
  then `ObjectReplicatorReceivedBunchFail`.
- **POPULATED slot (property), wrong payload:** `LogNet Error: ReadFieldHeaderAndPayload:
  Error reading payload. ... OutField: <FieldName>` then `ReadContentBlockPayload FAILED.
  Bunch.IsError() == TRUE`. (Our 128-bit GUID payload mismatches the property's real type.)
- **POPULATED slot (the ClientRestart RPC), correct:** dispatch -> client sends
  `ServerAcknowledgePossession` (success) or `ServerCheckClientPossession` (pawn unresolved).

## Confirmed map (index -> field), read from the live client

### 2026-06-11 fixed-framing native run

After switching CALV/CUSLSS to SerializeInt framing and running a live native
session, the old CALV `ContentBlockFail` no longer reproduced at the CALV
sequence. The client later reported:

- `SequenceId=14281` -> server `Player Pawn ActorOpen` (`seq=14281`), corrupted
  packet/framing with no RPC/property verdict.
- `ReadFieldHeaderAndPayload ... OutField: ServerGMGetNodeTaxTable` in the
  post-bootstrap CR/CALV window (`ClientRestart seq=14306`, CALV `seq=14307`).

Treat the `ServerGMGetNodeTaxTable` attribution as a calibration point for the
CR/CALV window, not yet as a clean one-to-one `170 -> field` mapping, because CR
and CALV were sent back-to-back in the same live window. Next clean probe:
`probe_cr_handle=175`, `probe_cr_max=256`, compact object ref, with the same
CALV/CUSLSS SerializeInt defaults.

| index | client verdict | field | kind |
|------:|----------------|-------|------|
| 31 | Invalid replicated field | (empty hole) | — |
| 62 | accepted silently | `ReplicatedMovement` | AActor property (Net) |
| 69 | Invalid replicated field | (empty hole) | — |
| 73 | ReadContentBlockPayload FAILED, OutField | `AuthServerIDReplicated` | AActor property (Net, uint32 @0x84, AoC-added) |
| 129 | Invalid replicated field | (empty hole) | — |
| 170 | ReadContentBlockPayload FAILED, OutField | `AuthServerIDReplicated` | **SAME as 73 — the collapse clue** |
| 80 | Invalid replicated field 0 | (empty) | strided-sweep |
| 100 | OutField | `AuthServerIDReplicated` | strided-sweep |
| 120 | OutField | `AuthServerIDReplicated` | strided-sweep |
| 140 | OutField | `AuthServerIDReplicated` | strided-sweep |

## MASS-COLLAPSE confirmed (automated strided sweep, 2026-06-10)

The client auto-retries on each timeout, so the strided sweep self-advances with no
manual relogin (handled via computer-use to fix the realm re-handshake once, then the
client drives itself). The sweep revealed: **73, 100, 120, 140, 170 ALL → `AuthServerIDReplicated`**
(handle 0 = AActor's first net property), while 31, 69, 80, 129 → empty. Dozens of
distinct selector values collapse onto the SAME first property. This **confirms the
framing bug** (`REAL-RECEIVER-FRAMING.md` / `received-bunch-dispatcher.md`, over the
`collapse-73-170-explain.md` refutation): our content block is mis-parsed into the
RepLayout property stream, which always restarts at handle 0. A strided index sweep
therefore CANNOT reveal a clean function band — most values either hit an empty cache
slot ("Invalid field") or desync into the handle-0 property read. **The selector value
is moot until the content-block field framing (selector width = max(2,FieldCount) +
the RPC object-ref param shape) is corrected.** Next: fix the framing, not the index.

## CRITICAL REFRAME (2026-06-09 session 2): it is the FRAMING, not the index

`73` and `170` BOTH resolve to `AuthServerIDReplicated` (AActor's FIRST net property,
handle 0). A simulation proved no SerializeInt `max` makes 8-bit writes of 73 and 170
decode to the same flat value — so this is NOT a width/value problem. The real
(current-binary) receiver is `FUN_143f329d0` -> `FUN_143f30bf0`
(ReadContentBlockPayload) -> `FUN_143f30e10` (ReadFieldHeaderAndPayload, TWO paths
gated by `conn+0x48 +0xF0 & 1`) -> `FUN_143f3c090` (RepLayout ReceiveProperties,
handle 0 = AuthServerIDReplicated). ALL prior framing docs modeled the STALE receiver
`sub_143F2DC60`. Our content-block header bytes are wrong for the live binary, so the
client mis-parses our bunch as a RepLayout property stream and fails on the first
property. **The selector value was a red herring; the content-block FRAMING must be
re-derived from the real functions.** Decompiled C: `_ghidra_decomp_out.txt`,
`_ghidra_decomp_out2.txt`. Corrected framing -> `REAL-RECEIVER-FRAMING.md` (worker).

## What this proves about the table

- It is **sparse** (holes at 31/69/129 between populated 62/73).
- It is **NOT alphabetical** and **NOT memory-offset-ordered**: alphabetical or offset
  would place `AuthServerIDReplicated` BELOW `ReplicatedMovement`, but the live client
  puts it ABOVE (73 > 62). Consistent with the binary trace
  (`CLASSNETCACHE-BUILDER-RE.md`): the slot is keyed by each field's runtime
  `UField->RepIndex` (`entry+0x14 = *(record+0xc)`).
- `ClientRestart` is a FUNCTION; its index is in the same space. When hit it will
  DISPATCH (possession), not payload-fail — a third, distinct oracle signature.

## Method going forward (data-driven, minimal relogins)

1. Compute the RepIndex-assignment rule from the two anchors + the SDK net-field roster
   (worker `CR-INDEX-FROM-ANCHORS.md`), predict ClientRestart's index, test that ONE value.
2. Each relogin that lands on a populated slot tells us the field NAME — so any probe is
   also a calibration point. Read it with `scripts\check_possession_oracle.ps1 -Backup`
   (now surfaces `OutField:` and distinguishes empty vs populated-wrong-payload).
3. Stop probing the dead "+5 / dense-model" values (31/69/129 all empty — three models
   falsified). Only probe values predicted by the anchor-calibrated rule.
