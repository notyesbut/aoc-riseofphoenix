# Pure-Native Server Status — Road A Phase B.0

**Date:** 2026-04-26  
**Session goal:** Retire the captured-replay dependency in `--native` mode  
**Status:** Bootstrap pipeline functional; one specific RPC handshake (`ClientRestart`) blocks final world entry

---

## What works (today's deliverables)

### `WorldBootstrapEmitter` framework

A single-driver replacement for the legacy `replay_thread + native_sequencer` parallel model. One ordered plan walks the post-NMT bootstrap, dispatching each entry as either:

- `Skip` — sentinel keepalive (Maintain covers it)
- `Splice` — re-emit a captured packet via `host_.send_captured_packet(idx)`
- `NativePc0 / NativePc22 / NativePawn78` — native emitters

500-entry default plan in `src/net/world_bootstrap_plan.cpp` covering captured pkts 0-499 with proven-working pacing (~22s window, matches the working hybrid baseline).

**Files:**
- `src/net/world_bootstrap_emitter.{h,cpp}` (NEW) — the dispatcher
- `src/net/world_bootstrap_plan.cpp` (NEW) — ordered plan + per-entry pacing
- `src/net/native_connect_sequencer.{h,cpp}` — single `SendBootstrap` state replaces the M1.x chain

### NetGUID minting via `PlayerNetGuidBlock`

PC NetGUID is now server-minted (block base ≥ `0x01000000`) via `IGameServerHost::allocate_player_block(client_key)`. Per-client idempotent allocation. PC opens at minted GUID instead of captured `10341530`.

**Files:**
- `src/net/native_connect_sequencer.h` — added `allocate_player_block` and `send_captured_packet` to `IGameServerHost`
- `src/net/game_server.h` — added `native_pc_allocator_` member + impls
- `src/net/pc_emitter.cpp` — uses minted GUID

### NMT recognizers + reactive emit infrastructure

Two recognizers in the data-receive path:

1. **`ServerNotifyLoadedWorld`** — detects via shifted-by-1 `/Game/Levels` byte signature. On detection, currently emits captured pkt #134 (which turned out NOT to be the right `ClientRestart` — see "Open work" below). Idempotent per-client.
2. **`ServerUpdateLevelVisibility`** — detects via plain-ASCII `_Generated_/` signature. Logs first 5, then every 50th to avoid spam.

**Files:**
- `src/net/game_server.h` — recognizer block in `try_parse_bunch`

### Pure-native launch mode

`--no-replay-loop` CLI flag — loads the replay file (so `Splice` plan rows can pull from it) but disables the legacy replay thread. Sequencer becomes the SOLE driver of the post-NMT stream.

**Files:**
- `src/main.cpp` — CLI flag wiring
- `src/net/game_server.h` — `Config::disable_replay_loop` + thread gate
- `dist/Release/launch_all_native.bat` — pure-native config
- `dist/Release/launch_all_hybrid.bat` (NEW) — fallback to proven 10-min mode

---

## Test results progression

| Iteration | Plan | Pacing | Result |
|---|---|---|---|
| Phase A.3 | 4 native overlays + replay 150 (HYBRID) | adaptive | ✅ 10 min successful play, 2283 ServerMoves received |
| Phase B.0  | 150 entries, NativePc22 | 30/15ms | ❌ Floating rocks (chSeq desync 954 → 1979) |
| Phase B.0a | 150 entries, pkt #22 → Splice | 30/15ms | ❌ "Streaming 100% loop" (no flash) |
| Phase B.0b | 500 entries, all splice | 30/10ms | ⚠️ World flashes player briefly, then loops |
| Phase B.0c | 500 entries, slowed pacing | 30/50ms | ⚠️ Stuck at 100%, no flash |
| Phase B.0d | + NMT recognizers | 30/50ms | ✅ Detects ServerNotifyLoadedWorld at t+4s |
| Phase B.0e | + reactive emit pkt #134 | 30/50ms | ❌ Reactive emit fired but didn't unstick (pkt #134 wrong) |

---

## Confirmed protocol details (from IDA RE)

### Client receive-side (validated)

- **`sub_143F32E00`** = `UChannel::ReceivedNextBunch` — partial bunch reassembly, validates chSeq monotonic, tracks 8 distinct FaultDisconnect codes (56-63)
- **`sub_14427E810`** = `UPackageMapClient::ReceiveNetGUIDBunch` — PME wire format reader (matches our writer)
- **`sub_14427EF30`** = `InternalLoadObject` — accepts new GUIDs unconditionally (validates Phase A.3)
- **`sub_1442804D0`** = NetGUID register — TMap::Add under SRW lock, no validation
- **`sub_1442651A0`** = NetConnection telemetry/event-log dispatcher (16-byte payload = FIntrepidNetGUID)

### Server-emit side (this session)

- **`sub_144412AB0`** = `APlayerController::ClientRestart` — calls `ProcessRemoteFunction(this, UFunction*, &Pawn)` at vtable +0x2E8
- **`sub_144243740`** = High-level RPC dispatcher (named via `"ProcessRemoteFunctionForChannelPrivate"` debug string)
- **`sub_1444EC7B0`** = Property/parameter iteration (RepLayout walking)
- **`sub_143F45AD0`** = ★ Function ID writer ★
  - Mode A: function index = `*(uint32_t *)(uFunction + 8)` direct
  - Mode B: function index via shared-list lookup of `*(uint32_t *)(uFunction + 12)`
  - Both modes: written to bunch via `sub_1414F9D30` (SerializeIntPacked varint)
- **`sub_143F45A40`** = SendBunch invoker
- **`sub_141741E80`** = `UObject::FindFunction(FName)` — calls `UClass::FindFunctionByName`

### Wire format known pieces

```
[Bunch header — already implemented]
  bControl, bRP, bReliable, ChIdx (SIP), bExp, bGuid, bPart, ChSeq (10-bit ch=0 / 14-bit elsewhere)
  bHasChName, [bIsHardcoded, EName(SIP)] | [FString]
  BunchDataBits (13-bit C>S, 14-bit S>C)
[Bunch payload — for RPC bunches]
  Function index (SerializeIntPacked varint)         ← UNKNOWN VALUE for ClientRestart
  Parameter data (per UFunction.Children layout)
    For ClientRestart: 1× FIntrepidNetGUID (Pawn) = 128 bits
```

### Captured RPC bunch reference

Incoming `ServerNotifyLoadedWorld` from client (decoded from emu log):
```
ch=3 reliable=true chSeq=549 bytes=105 bits=834
| 86 31 70 d1 c2 30 b2 00 00 00  | 5e 8e c2 da ca 5e 98 ca ec ca d8 e6 ...
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  Function header (~10 bytes:      FName as FString shifted-by-1 bit:
   varint function ID + FName       "/Game/Levels/Verra_World_Master/..."
   length encoding)
```

The first `0x86` byte: SerializeIntPacked first byte. Decoding details are still TBD — this is what we'd normally compute when emitting RPCs.

---

## Open work — the function index gap

### What's missing
The single piece blocking native `ClientRestart` emission is the **uint32 function index** for ClientRestart in APlayerController's UFunction array. Per `sub_143F45AD0`, this lives at `UFunction + 8` (mode A) or is dynamically allocated via shared list (mode B).

Without it, we can't:
- Build a native `ClientRestart(NewPawn)` bunch
- Build native ACK bunches (`ClientAckUpdateLevelVisibility`)
- Emit ANY server→client RPC natively

### IDA targets to find it

#### Path 1 — `Z_Construct_UFunction_*` static initializers
- Search strings for `Z_Construct_UFunction` — UE5 typically preserves this
- Find one ending in `_ClientRestart` → F5 → look for `mov [rcx+8], 0xXX`

#### Path 2 — Trace from FName cache
- `qword_14D856340` = cached FName for "ClientRestart"
- 11 known XREFs (per earlier IDA proximity graph)
- Trace which reader resolves FName → UFunction → reads +8

#### Path 3 — Find ALL ch=3 reliable RPC bunches in replay_data.bin
- Scan all 29010 packets (not just 0-500)
- Find ones with bdb 200-300 bits (function header + 16-byte NetGUID)
- One IS the captured `ClientRestart` — splice IT instead of pkt #134

#### Path 4 — Empirical fuzz
- Modify `world_bootstrap_emitter` to splice captured packets in range [80-200] one at a time across test runs
- Find which packet (if any) is the captured ClientRestart

---

## Full RPC contract (from IDA strings dump)

### Server→Client RPCs we need to emit

| RPC | FName slot | Priority | Status |
|---|---|---|---|
| `ClientRestart` | `qword_14D856340` | P0 — blocks world entry | Splice attempt failed (pkt #134 was wrong) |
| `ClientAckUpdateLevelVisibility(PackageName, TransactionId, bClientAckCanMakeVisible)` | `qword_14D856280` | P1 — may block streaming complete | Not implemented |
| `ClientUpdateLevelStreamingStatus` | `qword_14D8563F0` | P1 | Not implemented |
| `ClientUpdateMultipleLevelsStreamingStatus` | `qword_14D8563F8` | P1 | Not implemented |

### Client→Server RPCs we receive (and should react to)

| RPC | FName slot | Status |
|---|---|---|
| `ServerNotifyLoadedWorld(WorldPackageName)` | `qword_14D856460` | ✅ Recognized, reactive emit attempted |
| `ServerUpdateLevelVisibility` | `qword_14D8564B8` | ✅ Recognized, no ACK yet |
| `ServerUpdateMultipleLevelsVisibility` | `qword_14D8564C0` | Not yet recognized |
| `ServerAcknowledgePossession` | `qword_14D856420` | Not yet recognized |

---

## Recommended next session plan

1. **Find ClientRestart function index** (1-2 hours of focused IDA work)
2. **Decode `sub_1414F9D30`** (SerializeIntPacked writer) — confirm our `ue5::write_sip` matches
3. **Build `IGameServerHost::send_client_rpc(client_key, addr, FName name, params...)`** — generic native RPC emitter (~150 lines)
4. **Wire reactive emission**: on `ServerNotifyLoadedWorld` detect → `send_client_rpc(client_key, addr, "ClientRestart", &Pawn_NetGUID)`
5. **Test pure-native end-to-end** — should now exit loading screen without depending on captured ClientRestart

---

## Fallback for production use

`launch_all_hybrid.bat` is the proven 10-minute working configuration:
- `--native --replay replay_data.bin --replay-max-packets 150 --custom-name NativePlayer`
- Replay sends 148 captured packets covering the full bootstrap
- Native sequencer + WorldBootstrapEmitter run in parallel
- User reaches gameplay with character visible, can move around freely

Use this for any actual gameplay testing while pure-native is unblocked.

---

## 🎯 Update — Function index found via binary RE (2026-04-26 late session)

Direct binary analysis of `AOCClient-Win64-Shipping.exe` revealed the
RPC descriptor table at `.data:0x14d29a518` (and surrounding entries).
Each descriptor is 48 bytes:
```
+0:  qword constructor function ptr
+8:  zero (padding)
+16: qword name string ptr
+24: qword aux ptr
+32: qword metadata: NumParms(u16) | ParmsSize(u16) | 0x45(u32 const)
+40: qword function flags
```

Walking the descriptor array alphabetically and filtering for `FUNC_Net`:

| RPC | RPC# (filtered) | Wire index (RPC#+5) | Validated |
|---|---|---|---|
| ClientAckUpdateLevelVisibility | 2 | 7 | (TBD) |
| ClientRestart | **26** | **31** | (TBD via test) |
| ClientUpdateLevelStreamingStatus | 48 | 53 | (TBD) |
| ServerNotifyLoadedWorld | 62 | 67 | ✅ matches captured bunch byte 0x86 |
| ServerUpdateLevelVisibility | 73 | 78 | (TBD) |

The +5 offset hypothesis is confirmed by ServerNotifyLoadedWorld:
- Captured first byte = `0x86`
- Decoded via AoC SIP (bit-0 continuation): `(0x86 >> 1) = 67`
- Table position 62 + 5 = 67 ✓

This unblocks native emission of ALL APlayerController RPCs.

**Next code task**: Build `IGameServerHost::send_client_rpc(rpc_name, params)` that
encodes the wire index + parameters into a bunch and sends via the actor channel.
