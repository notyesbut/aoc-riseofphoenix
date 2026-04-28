# Session Save — 2026-04-27 (continue tomorrow)

## State of the build

`aoc_server.exe` was rebuilt with the **reactive ClientRestart fuzz emission DISABLED**. The build is clean.

Path: `dist/Release/aoc_server.exe`
Source change: `src/net/game_server.h` line ~3256-3286 — replaced the `send_client_restart_native` reactive call with a single `info`-level log line and noop. Splice path (pkt#134's captured ClientRestart) is now the sole ClientRestart delivery.

**Untested**: the user has not yet run `launch_all_native.bat` after this change. Resume tomorrow by running it and reading the logs.

---

## What we proved today

### ✅ Sentinel-bit framing fix (Phase B.0o)
- Discovery: `send_keepalive` writes an extra `1`-bit before `add_termination` to satisfy AoC's PacketHandler. Other native paths (`send_client_restart_native`, `send_ch0_reliable_payload`) were missing it.
- Action: added the sentinel to both. Fuzz `1` removed (over-corrected for ClientRestart fuzz, see below).
- Result on test 3 (with sentinel everywhere): "0's in last byte" warnings dropped 21 → 1, and `AAoCPlayerController::ClientReceiveStorageEvent_Implementation` started firing on the client (PC alive, receiving inventory events).

### ✅ Captured Pawn NetGUID extracted (Gap A solved)
- Decoded `captured_pkt_78.bin` bunch 2 (ch=114, bdb=2963, payload bits [2319..5282)).
- **Pawn NetGUID = ObjectId 88**, encoded as a BARE reference: `SIP(88)` + flag byte `0x2a` (= bNoLoad=1, total ~16 bits on the wire).
- Our `send_client_restart_native` had been sending a **synthetic 128-bit triple** (obj=10341530, srv=60, rnd=1860730596) — a NetGUID the client has never registered. That's the entire "No valid pawn" cause.
- Decoder used: `src/protocol/tools/decode_pkt78.py` + a one-shot inline script using `phase1_parser.parse_packet`.

### 🎯 GOLD-MINE binary finding (Gap B mostly mapped)
From `C:\Users\xmaxt\Desktop\random finding.txt` we confirmed AoC has a **second packet protocol parallel to UE5 bunches**:

```
UDP :7777
  ├─ UNetConnection (standard UE5 bunches)         ← what we've been REing
  └─ FServicePacketRouter (AoC's custom service)   ← NEW
        ├─ UActorTrackingService          (server side)
        └─ UActorTrackingServiceHandler   (client side)
```

This is where movement, visibility, and spatial relevancy travel. **Not on UE5 ActorChannels.**

**Function-address map (now concrete, not just string addresses):**

| Symbol | Function |
|---|---|
| `sub_14625E710` | `UFilteredActorTrackingRegistry::GetLocationUpdatesForServer` ★ |
| `sub_14625D390` | `UFilteredActorTrackingRegistry::GetAllActorLocations` |
| `sub_1462C5ED0` | `UFilteredActorTrackingRegistry::UpdateServerRelevancyTable` |
| `sub_14625D890` | `FServicePacketRouter<UActorTrackingService>::GetConnectionFromServerId` |
| `sub_14624BD00` | `FServicePacketRouter<UActorTrackingService>::PollImpl` ★ server-side dispatcher |
| `sub_14624B430` | `FServicePacketRouter<UActorTrackingServiceHandler>::PollImpl` ★ client-side receive |
| `sub_14624D8A0` / `sub_14624D120` | `ProcessDisconnect_Internal` (server / client) |
| `sub_14624E480` / `sub_14624E760` | `UpdateMetrics` |
| `sub_146255990` / `sub_146255C10` | `AttemptFlushSendMetrics` |

**The 4-entry packet-type vtable** at `funcs_14625EDF1`:

```
funcs_14625EDF1 dq offset sub_1458A69A0   ; Packet type 0
                dq offset sub_1458A69B0   ; Packet type 1
                dq offset sub_146257AF0   ; Packet type 2  (different addr range — likely big payload)
                dq offset sub_1458A6A50   ; Packet type 3
```

`EActorTrackingPacketType` is a 4-value enum. F5'ing these 4 functions gives the **complete protocol vocabulary**.

**Named data structures** revealed by log strings: `FActorInformation`, `FActorTrackerRegistration`, `FServiceBroadcast`, plus fields `TrackerLocation=`, `OldBounds`, `NewBounds`, `OldConnection`, `NewConnection`, `ServerId`, `ReconnectedSecondsAgo`, `PacketId=`, `MaxPacketBytes=`, etc.

---

## Mid-save F5 result — `sub_1458A69A0` is a CONSTRUCTOR, not a handler

```c
__int64 (__fastcall **__fastcall sub_1458A69A0(_QWORD *a1))()
{
  *a1 = &off_14B0C0D28;
  return &off_14B0C0D28;
}
```

It just sets the object's vtable pointer to `off_14B0C0D28` and returns it. So `funcs_14625EDF1[]` is the **type-constructor table** for `EActorTrackingPacketType` values 0..3, NOT a dispatch table.

The four vtable addresses we now want to dump (real protocol methods live there):
- Type 0 vtable: `off_14B0C0D28`
- Type 1 vtable: (need to F5 `sub_1458A69B0` — same pattern, will reveal `off_xxx`)
- Type 2 vtable: (need to F5 `sub_146257AF0`)
- Type 3 vtable: (need to F5 `sub_1458A6A50`)

Each vtable has Serialize/Deserialize methods (the actual wire-format readers/writers). That's where the per-packet bit layout lives.

**Updated F5 priority list:**
1. F5 `sub_1458A69B0`, `sub_146257AF0`, `sub_1458A6A50` — get vtable addresses for types 1-3.
2. Dump 64 bytes (8 entries) at each of the 4 vtable addresses (`off_14B0C0D28` and its siblings) — gives all method pointers.
3. F5 the Serialize/Deserialize methods — those are the wire-format truth.

## Late-late update — F5 of `sub_146257AF0` (packet type 2 move-ctor)

```c
*(_QWORD *)a1 = off_14B0C0D40;                  // base vtable
*(_OWORD *)(a1+8)  = *(_OWORD *)(a2+8);         // 16B field A (NetGUID?)
*(_OWORD *)(a1+24) = *(_OWORD *)(a2+24);        // 16B field B (Location?)
*(_OWORD *)(a1+40) = *(_OWORD *)(a2+40);        // 16B field C (Velocity/Rotation?)
*(_QWORD *)(a1+56) = *(_QWORD *)(a2+56);        // 8B
*(_QWORD *)a1 = off_14B0C0D58;                  // derived vtable (final type)
*(_DWORD *)(a1+64) = *(_DWORD *)(a2+64);        // 4B
*(_QWORD *)(a1+72) = *(_QWORD *)(a2+72);        // TArray.Data ptr (move)
*(_QWORD *)(a2+72) = 0;
*(_DWORD *)(a1+80) = *(_DWORD *)(a2+80);        // TArray.Num
*(_DWORD *)(a1+84) = *(_DWORD *)(a2+84);        // TArray.Max
*(_QWORD *)(a2+80) = 0;
*(_DWORD *)(a1+88) = *(_DWORD *)(a2+88);        // 4B
```

**Type 2 packet layout (~92 B):**

| Off | Size | Field |
|---|---|---|
| +0 | 8 | vtable (`off_14B0C0D58` final) |
| +8 | 16 | likely `FIntrepidNetworkGUID` (actor) |
| +24 | 16 | likely Location (FVector+pad / NetQuantize) |
| +40 | 16 | likely Rotation or Velocity |
| +56 | 8 | qword (timestamp/seq?) |
| +64 | 4 | dword (flags?) |
| +72 | 16 | **`TArray<T>`** — variable-length payload |
| +88 | 4 | dword (count/id?) |

Type 2 is the **BIG packet** — matches "actor location update" semantics from `FFastActorLocationArray` + `UFilteredActorTrackingRegistry` strings. Type 0 (`sub_1458A69A0`) is a tiny default-ctor object — likely a sync/ack/metric packet.

The TArray at +72 is critical — it's where bulk per-element data lives. The Serialize method (in vtable `off_14B0C0D58`) will reveal whether each TArray element is itself a small struct (e.g., `{ItemId, NetDelta bytes}`) or raw bytes.

**Concrete next F5s (ordered):**
1. `sub_1458A69B0` (type 1 ctor) — should also show vtable addresses
2. `sub_1458A6A50` (type 3 ctor)
3. Dump bytes at `off_14B0C0D58 + 0..63` to get type 2's vtable methods → F5 the Serialize entry → wire format unlocked

## FULL INHERITANCE TREE (from F5 of all 4 constructors)

```
       EActorTrackingPacketType
            │
   ┌────────┼────────┬─────────────┬──────────────┐
   │        │        │             │              │
Type 0   Type 1   Type 2        Type 3
(D28)    (D40)    (D58)         (D70)
empty    base     base+TArray   base+qword
         64B      92B           72B
```

**Common base** (vtable `off_14B0C0D40`, set transiently by types 1/2/3, kept by type 1):

| Off | Size | Field |
|---|---|---|
| +0 | 8 | vtable ptr |
| +8 | 16 | likely FIntrepidNetGUID (Tracker?) |
| +24 | 16 | likely FIntrepidNetGUID (Actor?) or FVector |
| +40 | 16 | FVector / FRotator / GUID |
| +56 | 8 | qword (timestamp / seq) |

**Type 0** (vtable `off_14B0C0D28`, separate hierarchy): empty struct — likely sync/metric/heartbeat.

**Type 1** (vtable stays at `off_14B0C0D40`): base only. Actor enters/leaves relevancy event.

**Type 2** (final vtable `off_14B0C0D58`): base + (+64: dword flag, +72: TArray<T> [Data 8 + Num 4 + Max 4], +88: dword count). **The BULK delta packet — many per-actor updates per packet.**

**Type 3** (final vtable `off_14B0C0D70`): base + (+64: qword). Single-reference notification (bounds change?).

## TOMORROW'S PROTOCOL-RE PLAN (final ordered list)

1. Dump 64 B at `off_14B0C0D40` (base vtable) → 3-8 method ptrs incl. abstract Serialize.
2. Dump 64 B at `off_14B0C0D58` (type 2 vtable) → see if Serialize is overridden.
3. F5 the Serialize entries — **type 2's Serialize is the prize** (reveals TArray<T> on-wire format and what T is).
4. F5 the base Serialize — reveals the 64-byte common header's wire format.
5. With wire format known, write a small protocol parser to scan replay_data.bin and find the actual movement-update packets in the captured stream (probably on a high-numbered channel or as standalone UDP packets recognized by IntrepidNetDriver).

## ★★★ Receive + send sides BOTH decoded (`sub_14624B430` + `sub_14625E710`)

### PollImpl (receive, client side) — `sub_14624B430`

```
loop:
  vtable[32](a2, v53[0], true)   ← reads next packet header into v53; returns false on EOF
  v53[0] = packet TYPE byte (0/1/2/3)
  switch(v53[0]):
    case 2: vtable[8](a1, v53)                        // Handle Type 2 (big)
    case 0: sub_141462460(a1+800, v51, &v54, 0)       // Read extra
            vtable[16](a1, v53)                       // Handle Type 0
    case 1: sub_14624D120(a1, v60)                    // Handle Type 1 (disconnect-style)
    case 3: SIP-decode packetId into v45
            if v45 != 9998: sub_1462C3740(a1, v45, v54, v55)  // sub-dispatch
            else:           sub_1462D8940(...)                 // MAGIC end marker
```

**Wire format unlocked (receive):**
```
[1 B]    type ∈ {0,1,2,3}
if 0:    [variable] additional payload
if 1/2:  [type-specific body — see object layouts below]
if 3:    [SIP] packetId
           id == 9998 → end-of-stream/disconnect
           id != 9998 → sub-dispatch by id
```

### GetLocationUpdatesForServer (send, server side) — `sub_14625E710`

Bit-scans a relevancy mask, for each visible actor:
```
Look up FActorTrackerRegistration (240 B stride) at v37+152
Look up FActorInformation         ( 80 B stride) at v37+1600
Read packet-type byte from input  v124 = src[+136]
Allocate 224-B send-queue record at 224 * idx
Write 3×16B + 8B header to record  (matches our base layout)
Set type byte at record+136
Call funcs_14625EDF1[type] to construct the body at record+40
sub_141C52BB0(record+144, &v125)   ← ★ COPY 80-B PROPERTY DELTA BLOB
```

### Sizes now CONFIRMED via send-side strides

| Struct | Size | Evidence |
|---|---|---|
| `FActorInformation` | **80 B** | `*(QWORD*)(v42+1600) + 80*v44` |
| `FActorTrackerRegistration` | **240 B** | `*(QWORD*)(v37+152) + 240*v39` |
| Send-queue record | **224 B** | `224 * v60 + queueBase` |

### Three function tables (per-type lifecycle)

| Table | Role | Status |
|---|---|---|
| `funcs_14625EDF1[]` | construct (4 ctors) | ✓ all 4 decoded |
| `funcs_1458A6C67[]` | destruct (4 dtors) | ✓ types 1/2/3 decoded; type 0 dtor unknown |
| `funcs_1458A6DE7[]` | pre-construct / move-init | ❌ **NEW** — entries unread |

### Final 2 F5s needed

1. **Type 2 vtable at `off_14B0C0D58`** — slots [1]/[2]/[3]. Slot 1 is most likely `Serialize`. F5 → wire format of TArray content + 96-B object → complete.
2. **One entry from `funcs_1458A6DE7[]`** — confirms the lifecycle phase semantics.

After these two, we have everything needed to natively emit AoC actor-tracking packets.

## ★★★ VTABLE DUMP (from screenshot) — only ONE more F5 needed

All 3 vtables visible. Each is exactly 3 slots = 24 bytes apart.

| Vtable | [0] dtor (have) | [1] Serialize? | [2] Deserialize? |
|---|---|---|---|
| `off_14B0C0D40` (base, T1) | `sub_141F30E40` | **`sub_14625E0E0`** | `sub_14625F650` |
| `off_14B0C0D58` (T2 derived) | `sub_145029D60` | **`sub_14625E250`** ★★★ | `sub_14625F6A0` |
| `off_14B0C0D70` (T3 derived) | `sub_141F2B070` | **`sub_14625DE20`** | `sub_14625F5F0` |

The 6 unknown methods are clustered in the `14625Exxx`/`14625Fxxx` range (same compilation unit as `sub_14625E710` GetLocationUpdatesForServer, `sub_14625D390` GetAllActorLocations etc.) — confirming they're all part of `UFilteredActorTrackingRegistry` / FServicePacketRouter.

**Semantic discovery in screenshot:** between Type 3 vtable and the next vtable, there's the string `"ActiveTargetingState"`. This confirms the FServicePacketRouter protocol carries **combat/targeting state**, not just movement. Service is named `UActorTrackingService` for that reason.

(The vtable starting at `off_14B0C0DB8` immediately after is unrelated — `AK::WriteBytesCount::Reserve` is AudioKinetic Wwise middleware.)

### THE ONE F5 LEFT

`sub_14625E250` — Type 2 vtable slot 1 = bulk-location-update **Serialize**. That single function reveals:
- The bit-level wire format of the 96-byte object
- The TArray<T> element layout (what T is)
- Any bit-packing on the 3 NetGUID/Vector header slots
- Optional checksum/CRC

That's the complete wire format of AoC's movement protocol.

## Destructors confirmed all 3 derived sizes

| Dtor | Object size (from `operator delete`) | Owned alloc? | Type |
|---|---|---|---|
| `sub_141F30E40` | 64 B | — | Type 1 |
| `sub_145029D60` | **96 B** (was inferred 92, padding +4) | frees `*(this+72)` | Type 2 |
| `sub_141F2B070` | 72 B | — | Type 3 |

Each is `vtable[0]` of its respective type.

Two utilities now identified:
- `sub_1413B0B20` = `TArray::Free` / `FString::Free` (heap release)
- `sub_141322CC0(this, size)` = MSVC `operator delete(void*, size_t)` — **literal size constant in the call = exact class size**. Great primitive for class-size discovery.

Tomorrow's first action remains the same: dump 64 B (= 8 pointer slots) at each of the 3 vtables (`off_14B0C0D40` / D58 / D70). Slot 0 is the destructor we now have. Slot 1+ contains the abstract methods including Serialize.

## Original F5 priorities (still valid for the surrounding code)

If we still see loading-screen loop after the reactive-fuzz-disabled test:

1. **`sub_1458A69A0`** — packet type 0 handler. Smallest, easiest. Reveals header layout.
2. **`sub_146257AF0`** — packet type 2. Different address range = likely the big movement payload.
3. **`sub_14624B430`** — `FServicePacketRouter<Handler>::PollImpl`. Client's receive entry point. Tells us packet-ID width and dispatch.
4. **`sub_14625E710`** — `GetLocationUpdatesForServer`. Server's encoder = symmetric counterpart to write our own emitter.

Each F5 → paste back → decode format → update Gap (b).

---

## Pending TODO list

1. ⏳ **User test**: run `launch_all_native.bat` with reactive-fuzz disabled, paste new client log and `emu-*.log`.
2. If world loads → great, we're past the loop. Move to retiring more splice rows from the bootstrap plan.
3. If still looping → either:
   - a. Plumb captured Pawn NetGUID 88 (BARE format: `SIP(88)+0x2a`) into `send_client_restart_native` and re-enable reactive emit. Replace the 128-bit inline payload with the 16-bit BARE form.
   - b. F5 the 4 ActorTrackingService handlers above and start understanding the parallel-protocol handshake.

---

## Files changed this session (uncommitted)

- `src/net/game_server.h`:
  - Added sentinel `1`-bit before `add_termination` in `send_ch0_reliable_payload` (kept).
  - Added sentinel `1`-bit + later removed in `send_client_restart_native` (current state: sentinel still present but the function is now unreachable since reactive emit is disabled).
  - Reactive ClientRestart emission disabled at line ~3256-3286.
  - Diagnostic `last4=[...]` hex log added to every outgoing packet's `S>C #N` info line.
  - Multi-width × handle fuzz table (20 variants) still defined in `send_client_restart_native` but currently dead code.

No git commit yet. We can commit tomorrow after verifying the disabled-fuzz test result.

---

## Quick references for tomorrow

- Latest server log (last test, before disable): `dist/Release/logs/emu-20260427-000808.log`
- Latest client log: `C:\Users\xmaxt\AppData\Local\AOC\Saved\Logs\AOC.log`
- Pawn fixture: `src/protocol/tools/captured_pkt_78.bin`
- Pawn bunch stream (3 bunches, ready to splice): `src/net/captured_pkt78_bunch_stream.h`
- Decoder used today: `src/protocol/tools/decode_pkt78.py` (note: BUNCH_START hardcoded to 152, but actual is 127 from `parse_packet`; use parse_packet directly)

---

## One-liner summary if context is lost

> Disabled the reactive ClientRestart fuzz (which was overriding the captured one with a synthetic 128-bit Pawn NetGUID the client doesn't know — that's the "No valid pawn" cause). The captured pkt#134 carries the correct ClientRestart with NetGUID 88. Just-built `aoc_server.exe`, untested. Tomorrow: run `launch_all_native.bat`, read logs, decide between (a) plumb NetGUID 88 properly with BARE-GUID emit, or (b) F5 the 4 ActorTrackingService packet handlers (`sub_1458A69A0`, `sub_1458A69B0`, `sub_146257AF0`, `sub_1458A6A50`) to map AoC's parallel service protocol.
