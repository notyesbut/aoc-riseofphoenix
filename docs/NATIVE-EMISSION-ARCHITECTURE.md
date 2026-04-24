# Native Emission Architecture — Path B Master Plan

**Status:** Design | **Date:** 2026-04-24 | **Scope:** The final authoritative-server architecture for native world bootstrap.

---

## Problem statement

In replay mode, the AoC client enters the world and renders character at pkt#100. In native mode, we currently emit 4 essential bunches (PC ActorOpen, Name update, Pawn splice) — and the client shows floating rocks, disconnects at 30s.

User has empirically established:
- **<30 packets** → loading-screen loop (never exits)
- **30-50 packets** → loading screen, no world entry
- **~100 packets** → world loads, character visible, but HUD/names/equipment incomplete

The minimum for visible character is **~100 captured packets**. The question is how to emit an equivalent set natively so we control names/stats/positions.

---

## Ground truth: what's actually in the first 100 packets

Verified from `dist/Release/logs/bunches_bootstrap.log` (real parsed bunches, not speculation):

| Phase | Packets | Content | Total bits |
|---|---|---|---|
| Post-NMT handshake echoes | #0, #2 | AoC opcode 3 + NMT_Welcome re-emit on ch=0 (chSeq 954→955) | ~1.1K |
| Sentinel fillers | #1, #3-#21 | 21B keepalives while client loads map | ~0 |
| PC ActorOpen start | #22 | 784B, ch=3 ActorOpen chSeq=1978 (partial init) | 6104 |
| PC continuation | #23 | 508B, ch=3 continuation (PARSE_FAIL in scanner = opaque) | 3905 |
| Initial GUIDExports | #24-#28 | ch=85 GUIDExport (5 packets) + ch=2 GUIDExport + ch=30 ActorClose | ~24K |
| **Big PC partial stream** | **#29-#44** | **16 packets of ch=3 partials totaling ~75K bits** — PC's RepLayout tail + subobjects (HUD, CharacterInformation, etc.) | ~122K |
| ch=0 control at tail | #44 | ch=0 Control 2048 bits — end-of-PC-stream marker? | |
| PARSE_FAIL window | #45-#46 | Scanner opaque — likely PC tail final fragment | ~13K |
| ch=4 actor spawn | #47+ | New partial set on ch=4 begins | — |
| Continuing actors | #48-#99 | Additional NPCs / environment on ch=4, 5, 6, ... | ~300K |

**Total first 100 packets:** ~66KB, ~515K bunch bits, of which ~150K bits are PC-related (ch=3 + ch=85 exports), rest is other actors.

**Essential for character-visible:** empirically ~100 packets. ~30K bits is NOT enough; the PC's RepLayout tail alone needs ~75K bits across ~16 continuation packets.

---

## The architectural decision: progressive replacement

Two design choices were considered and rejected:
- **Pure IDA RE of every actor class** — 2-3 weeks minimum, blocks everything until done
- **Pure replay mode** — abandons authoritative server; can't customize name/stats

**Chosen: SPLICE-FIRST, NATIVE-LATER**

For every packet in the first 100:
- **Level 0 (Splice)**: Emit captured bytes verbatim via a new `WorldBootstrapEmitter`. Client accepts exactly what replay mode sends it. Character renders.
- **Level 1 (Parameterized splice)**: Bit-patch specific fields (our NetGUID substitutions, custom name) into the captured bytes.
- **Level 2 (Native emit)**: Fully native ActorBuilder-based emission that's byte-identical to captured (proven for PC via `test_pc_spawn_diff`).

Each packet progresses independently. The server always works — we just replace spliced packets with native ones one at a time, with byte-identity tests gating each replacement.

---

## Component architecture

```
┌────────────────────────────────────────────────────────────┐
│ NativeConnectSequencer (existing, extended)                │
│                                                              │
│ AwaitNmtJoin (wait for LoadMap)                             │
│     ↓                                                        │
│ SendBootstrap — NEW: hand off to WorldBootstrapEmitter      │
│     ↓                                                        │
│ Maintain (keepalives + input)                               │
└────────────────────────────────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────────────────────┐
│ WorldBootstrapEmitter (NEW)                                 │
│                                                              │
│ Emits pkts #0-99 in order, each packet tagged with:         │
│   - EmissionMode::SplicePureBytes                           │
│   - EmissionMode::SpliceWithPatches                         │
│   - EmissionMode::NativeBuild                               │
│                                                              │
│ Dispatches per-packet to:                                   │
│   - PcNativeEmitter (for pkt#22, proven byte-identical)     │
│   - PkgMapNativeEmitter (for ch=85 GUIDExports, M2)         │
│   - SpliceEmitter (default for unconverted packets)         │
└────────────────────────────────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────────────────────┐
│ IGameServerHost::send_bunch_packet (existing)               │
│   Wraps bunch bits in our session's seq/ack/PacketInfo      │
└────────────────────────────────────────────────────────────┘
```

### Key invariants

1. **chSeq must be captured-consistent within each channel** — ch=3 starts at 1978, ch=0 continues from our NMT handshake values. Reliable-channel protocol requires chSeq increments.

2. **Timing matters** — captured session spaces packets ~15ms apart during bootstrap. Sending 100 packets in <1s may overflow client's receive buffer (documented in replay Fix #36 at `game_server.h:3936`). Target: 500ms between packets.

3. **NetGUID references must resolve** — if pkt#22 says "PC's Pawn = NetGUID X", pkt#78 (or wherever the Pawn ActorOpen lives) must declare Pawn actor_netguid=X. Spliced captures do this naturally because NetGUIDs are consistent within the capture. Once we go native, our NetGUID allocator must preserve the mapping.

4. **Progressive conversion needs tests** — every native replacement must have a `test_<name>_spawn_diff` that achieves byte-identity against the captured fixture. Replay file stays as the oracle forever.

---

## NetGUID allocation strategy

Captured NetGUIDs used by the PC bunch (and everything downstream):

```
PC actor      = 10341530         (ObjectId, Srv=60, Rnd=1860730596) — EXACTLY matches our test_pc_spawn_diff output
PC archetype  = 3503756484819958835  (AoCPlayerControllerBP_C CDO)
Level         = 16442478405498561049 (Verra_World_Master PersistentLevel)
```

For splice-mode, we use these captured values as our NetGUIDs. Client's PackageMap resolves correctly because:
- Level NetGUID is stable (content-addressable — same map name → same NetGUID)
- Archetype NetGUIDs are stable (class CDO → deterministic NetGUID)
- Only actor_netguid is dynamic; we pin ours to the captured value until M2

Once we need multiple clients (M2+), we'll fork the allocator: static GUIDs for stable assets, dynamic per-client GUIDs for PC/Pawn. Until then, "captured GUID" works for a single client.

---

## Packet-by-packet emission plan

For each of the 100 packets, designate one of three modes:

### Splice-pure (SPLICE_BYTES)
Emit captured bytes verbatim. Fastest to implement. Works for everything we don't yet understand.

**Starting set (~95 of 100 packets):**
- pkt#0 (opcode 3, 42B) — opaque, session-specific; splice bytes unchanged
- pkt#2 (NMT_Welcome re-emit, 151B) — we already emit natively during NMT, may not need this re-emit; but splice as safety
- pkts #3-#21 (fillers) — SKIP entirely; our Maintain loop produces equivalent natural keepalives
- pkts #23-#46 (PC continuation + initial GUIDExports) — all splice
- pkts #47-#99 (ch=4+ actors) — all splice

### Splice-with-patches (SPLICE_PATCHED)
Emit captured bytes with specific bit ranges replaced (e.g. custom name).

**Candidates:**
- pkt#N where CharacterName is replicated — patch the FString bytes with our custom name
- Any packet containing references to our NetGUIDs — patch to match our allocator

### Native-build (NATIVE_BUILD)
Full native emission. Byte-identity test-gated.

**Starting set (1 packet today, 2 after M1.4.e):**
- pkt#22 — PC ActorOpen, byte-identical confirmed by `test_pc_spawn_diff` (4859/4859 matching bits)

**Soon (M2):**
- pkt#78 — Pawn ActorOpen (needs Pawn schema calibration — `pawn_schema.cpp` scaffolded, fixture `captured_pkt_78.bin` available)

**Later (M3+):**
- ch=85 GUIDExport bundles (one emitter class, parameterized)
- PlayerState bunch (fixture TBD)
- GameState bunch (fixture TBD)

---

## The `WorldBootstrapEmitter` implementation

```cpp
// src/net/world_bootstrap_emitter.h
namespace aoc { namespace net {

enum class EmissionMode {
    SpliceBytes,     // Level 0 — raw captured bytes
    SplicePatched,   // Level 1 — captured bytes with specific bit-patches
    NativeBuild,     // Level 2 — ActorBuilder-based emission
    Skip,            // Don't emit (e.g. sentinel fillers)
};

struct PacketEmissionSpec {
    uint32_t      replay_pkt_idx;   // which captured packet (for splicing)
    EmissionMode  mode;
    std::string   description;      // for logging: "PC ActorOpen", "ch=85 GUIDExport #1", etc.

    // For SplicePatched / NativeBuild
    std::function<std::vector<uint8_t>(const PatchContext&)> builder;

    // Pacing (matches captured timing)
    std::chrono::milliseconds delay_before_send{0};
};

class WorldBootstrapEmitter {
public:
    WorldBootstrapEmitter(IGameServerHost&      host,
                           const std::string&    client_key,
                           const sockaddr_in&    addr,
                           const ReplayData&     replay);  // uses captured packets for splice

    // Emit packets in order.  Returns true if all succeeded.
    bool emit_all(const std::vector<PacketEmissionSpec>& plan);

private:
    std::vector<uint8_t> extract_bunch_bits_from_replay(uint32_t pkt_idx);
    bool emit_one(const PacketEmissionSpec& spec);
    // ...
};

}} // namespace aoc::net
```

The sequencer invokes this with a hard-coded `PLAN` constant describing the 100-packet bootstrap:

```cpp
// src/net/world_bootstrap_plan.cpp (generated, ~100 rows)
const std::vector<PacketEmissionSpec> kDefaultBootstrapPlan = {
    {  0, EmissionMode::SpliceBytes,   "AoC opcode 3",                     nullptr, 10ms },
    {  2, EmissionMode::SpliceBytes,   "NMT_Welcome re-emit",              nullptr, 10ms },
    // 3-21 SKIPPED (keepalives)
    { 22, EmissionMode::NativeBuild,   "PC ActorOpen (byte-identical)",    &emit_pc_actor_open_native, 100ms },
    { 23, EmissionMode::SpliceBytes,   "PC continuation #1",               nullptr, 15ms },
    { 24, EmissionMode::SpliceBytes,   "ch=85 GUIDExport #1",              nullptr, 15ms },
    // ...
    { 99, EmissionMode::SpliceBytes,   "ch=? ActorUpdate",                 nullptr, 15ms },
};
```

As we complete RE of each actor, we flip that row's mode to `NativeBuild` and add a test.

---

## Pacing and backpressure

The captured session emitted packets at ~15ms intervals during bootstrap (computed from `replay_data.bin` timestamps). The replay loop uses adaptive pacing (1ms/5ms/15ms/50ms tiers based on `ahead` count — see `game_server.h:3952`).

Our `WorldBootstrapEmitter` should:
- Wait for `MAP LOADED` signal (already implemented in M1.4.d)
- Emit with 15ms cadence initially
- Throttle to 50ms if we detect ACK lag (TODO — measure `cs.out_ack_seq` lag)

---

## Progressive replacement workflow

Per-packet promotion from Splice → Native:

1. Write `test_<pkt>_spawn_diff.cpp` in `src/tools/`
2. Build the native emitter in `src/net/` (usually extends existing `ActorBuilder`)
3. Run test — target: byte-identical output to captured bunch
4. Iterate on schema / `EmitContext` settings until 100% match
5. Flip the row in `kDefaultBootstrapPlan` from `SpliceBytes` to `NativeBuild`
6. Live-test — character should still render identically
7. Commit, move to next packet

**Order of replacement (by tractability):**
1. pkt#22 (PC) — **DONE** via `test_pc_spawn_diff`
2. pkt#78 (Pawn) — scaffolded, needs handle calibration
3. pkt#24, #26, #28 (ch=85 GUIDExport × 3) — same structure, one emitter
4. pkt#25 (ch=2 GUIDExport) — similar
5. pkt#29-#44 (ch=3 PC RepLayout tail partials) — hardest; requires CustomDelta RE
6. pkt#47+ (other actors) — per-class effort

---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Captured NetGUIDs collide with future multi-client allocator | Partition: static (level, archetype) vs dynamic (actor per-client). Captured values → static slot. |
| chSeq drift accumulates across splice+native mix | Per-channel chSeq tracker in `ClientState`; every emit updates it. |
| Client times out during 100-packet emit window | Pace with 15-50ms delays; emit keepalive every 200ms even mid-bootstrap. |
| A spliced packet's bunch header refers to captured chSeq that conflicts with ours | Bit-patch the chSeq field in captured bytes before emit (Level 1 patched splice). |
| Partial bunch reassembly breaks across hybrid mix | Don't mix — either all partials for an actor are spliced, or all are native. |

---

## Delivery milestones

**M1.4.e (THIS SESSION): scaffold**
- `WorldBootstrapEmitter` class
- `kDefaultBootstrapPlan` with all 100 packets in SpliceBytes mode
- Wire into sequencer (replaces current `SendBootstrap` → `SendPcOpen` → `SendPcProps` → `SendPawn` chain)
- Verify character renders (matches replay-mode behavior)

**M2.0: replace pkt#22 with native**
- Use `test_pc_spawn_diff` pattern
- Flip row, test byte-identity, deploy

**M2.1: replace pkt#78 (Pawn)**
- Calibrate `pawn_schema.cpp`
- New `test_pawn_spawn_diff.cpp`

**M3.0: GUIDExport bundles (ch=85/ch=2)**
- One emitter class for all bulk GUID export packets

**M4.0: PC RepLayout tail (pkts #29-#44)**
- The big one — needs full handle catalog + CustomDelta decode
- 2-3 weeks of RE work

**M5.0: remaining NPCs/environment**
- Per-class effort; may remain spliced longer since it's not gating character render

---

## Success metric

**M1.4.e done** when: client enters Verra_World_Master, character visible with our custom name displayed in HUD, connection stable past 2 minutes.

**Full Path B done** when: `kDefaultBootstrapPlan` has zero `SpliceBytes` rows; all 100 packets are `NativeBuild` with byte-identity tests.
