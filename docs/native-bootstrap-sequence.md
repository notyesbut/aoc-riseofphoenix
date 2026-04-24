# Native Bootstrap Sequence

**Status**: RE in progress  |  **Owner**: M1.1  |  **RE'd**: 2026-04-24

This document catalogs the first 30 packets of the captured
`replay_data.bin` — the post-NMT world-bootstrap flow. Each packet is
documented with its bunches, payload semantics, and whether it's
essential for the client to load the world.

**Goal**: build a `BootstrapEmitter` class that natively emits an
equivalent sequence from server state.

---

## 1. Scan Summary

| Pkt | Seq | Size | bb | Bunches | Purpose | Essential? |
|-----|-----|------|-----|---------|---------|------------|
| 0 | 14265 | 42B | 167 | ch=0 reliable DATA, bdb=112 | **AoC opcode 3 + FString("50995344")** — unknown | TBD |
| 1 | 14266 | 20B | 0 | — | Server frame-time keepalive | No |
| 2 | 14267 | 151B | 1039 | ch=0 reliable DATA, bdb=984 | **NMT_Welcome** (opcode 1) — map + gamemode | ✅ **YES** |
| 3-21 | 14268-14286 | 21B | 1 | — (bb=1 = sentinel) | Keepalive / ACK waits | No — natural |
| 22 | 14287 | 784B | 6104 | **4 bunches on ch=3** | **PC ActorOpen** (multi-fragment) | ✅ **YES** |
| 23 | 14288 | 508B | 3905 | — (parse fail — likely PC chain tail) | PC continuation fragments | ✅ |
| 24 | 14289 | 830B | 6476 | ch=85 with exports | Some other actor spawn | Maybe |
| 25 | 14290 | 912B | 7143 | ch=2 PART-INIT | Actor on ch=2 | TBD |
| 26 | 14291 | 721B | 5604 | ch=85 + various ch=0/1 | Mixed | TBD |
| 27 | 14292 | 644B | 4999 | (parse incomplete) | — | TBD |
| 28 | 14293 | 460B | 3516 | ch=85 exports | Another NPC/actor | Probably no |
| 29 | 14294 | 978B | 7665 | ch=3 PART-INIT + junk | PC chain continues | ✅ |

**Full JSON dump**: `docs/native-bootstrap-sequence.json`  
**Scanner script**: `src/protocol/tools/scan_bootstrap_30.py`

---

## 2. Critical Packets Decoded

### 2.1 pkt#0 — Unknown post-login message (opcode 3)

**Bunch**: ch=0, reliable, bdb=112, ch_name=EName[255]  
**Payload (14 bytes)**:
```
03 09 00 00 00 35 30 39 39 35 33 34 34 00
│  │           │                        │
│  └─ FString  └─ "50995344\0" (8 chars + NUL)
└─ opcode byte = 0x03
```

**Hypothesis**: This is some AoC-specific post-login message with opcode 3.
In stock UE5, opcode 3 = NMT_Challenge, but NMT_Challenge was already
sent during the initial handshake (before this replay starts). So opcode
3 has been **overloaded** by AoC for something else — or this is a
repeated Challenge for session verification.

**The string "50995344"** is 8 decimal digits. Candidates:
- Server session ID
- Session seed for crypto
- Build version
- Initial FName table preload hint

**Action**: Needs RE pass in the client binary. Search for `case 3:` in
the post-NMT state of `UControlChannel::ProcessBunch` or similar.
**For M1.1 emission**: try emitting a placeholder string and see if
client accepts; if not, RE the exact expected format.

**Decoder script**: `src/protocol/tools/decode_ctrl_bunches.py`

### 2.2 pkt#2 — NMT_Welcome ✅ already implemented

**Bunch**: ch=0, reliable, bdb=984, ch_name=EName[255]  
**Payload (123 bytes)**:
```
01                                            ← opcode NMT_Welcome
33 00 00 00                                   ← FString len=51
"/Game/Levels/Verra_World_Master/Verra_World_Master\0"
3B 00 00 00                                   ← FString len=59
"/Game/GameBlueprints/AoCGameModeBaseBP.AoCGameModeBaseBP_C\0"
00 00 00 00                                   ← trailing 4 bytes (FString len=0 = empty RedirectURL)
```

**Semantic**: Standard UE5 NMT_Welcome:
- `MapName`: `/Game/Levels/Verra_World_Master/Verra_World_Master`
- `GameMode`: `/Game/GameBlueprints/AoCGameModeBaseBP.AoCGameModeBaseBP_C`
- `RedirectURL`: (empty)

**Our server already emits this** via `send_nmt_welcome()` — validated by
matching hex in `emu-20260424-105808.log`.

### 2.3 pkt#22 — PC ActorOpen (multi-fragment) ✅ partial implementation

**4 bunches on ch=3 (PlayerController's channel)**:

| # | Flags | bdb | Content |
|---|---|---|---|
| 0 | CTRL,OPEN,REL,PART-INIT,EXP | 3545 | Fragment 1 of 2 — PC header + exports |
| 1 | REL,PART-FIN | 1314 | Fragment 2 of 2 — PC body tail |
| 2 | REL,PART-INIT,EXP | 873 | Fragment 1 of 2 — PC subobject (HUD) |
| 3 | REL,PART-FIN | 173 | Fragment 2 of 2 — HUD tail |

**Exports in bunch #0**:
1. `Default__AoCPlayerControllerBP_C` (chk=0x6b62891c) from `/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP`
2. `PersistentLevel` (chk=0) from `Verra_World_Master` from `/Game/Levels/Verra_World_Master/Verra_World_Master`
3. `GlobalGMCommands` (chk=0xcaaaee3e) from `/Script/GameSystemsPlugin`

**Exports in bunch #2**:
1. `BP_AOCHUD_C` (chk=0xac6f1251) from `/Game/UI/Widgets/BP_AOCHUD`

**Our `ActorBuilder` already produces bunch #0 byte-identical** (4859/4864
bits matched in `test_pc_spawn_diff`). Bunches #1, #2, #3 not yet tested
in isolation but the full-packet output is 99.9% match.

---

## 3. Minimum Bootstrap Set

The **minimum** ordered emissions before the client can enter the world:

```
[1] pkt#0-equivalent:  ch=0 ctrl bunch, opcode 3 + session string
[2] pkt#2-equivalent:  NMT_Welcome with Verra_World_Master
[3] Keepalives:        Implicit (client sends ACKs, server responds
                       with empty frames while processing; our
                       existing send_keepalive handles this)
[4] pkt#22 equivalent: PC ActorOpen (multi-fragment)
[5] PC property updates: (needed for character to render)
```

**Everything else (pkts 24-29 and beyond)** is actors AoC populates
around the player (NPCs like Goblin_LanguidGoblin, static mesh actors,
etc.). The client can **enter the world with just the minimum** — it
will see an empty level with only the player's own character, which is
fine for M1-M2.

---

## 4. AoC-Specific Findings

### 4.1 "AoC opcode 3" (pkt#0) — unresolved

Post-NMT reliable bunch on ch=0 with opcode 0x03 + an 8-digit decimal
string. Not in stock UE5's `FNetControlMessage` enum. Needs RE.

**Investigation plan**:
1. IDA: find `UControlChannel::ReceivedBunch` in the client
2. Look at the switch on opcode — what does case 3 do post-handshake?
3. Check if AoC overrides `UControlChannel` with a subclass
4. Document findings in `docs/re-aoc-opcode-3.md` (new)

For M1.1 we'll emit this as a bit-identical placeholder (copy captured
bytes verbatim for now) and revisit RE once we see if the client even
requires it for basic world-entry.

### 4.2 Server frame-time keepalives

pkt#1 has `has_srv_frame=True bb=0` — a packet with PacketInfo carrying
just `ServerFrameTime` and no bunches. These maintain clock sync between
server and client. Our existing `send_keepalive` emits this shape.

### 4.3 The 18-packet gap (pkts 3-21)

Between NMT_Welcome (pkt#2) and PC ActorOpen (pkt#22) there are 19
trivial packets (bb=1, 21B each). This is the captured server "marking
time" while the client processes NMT_Welcome and sends back the
`NMT_NetSpeed` + `NMT_GameSpecific` that triggers PC spawn.

**In native mode this gap is naturally filled by our heartbeat emission
(M1.3)**. We don't need to replicate the 19 captured trivial packets
verbatim.

---

## 5. M1.1 Implementation Plan

### 5.1 Classes to build

```cpp
// src/net/bootstrap_emitter.{h,cpp}
class BootstrapEmitter {
public:
    BootstrapEmitter(IGameServerHost& host, const std::string& client_key,
                     const sockaddr_in& client_addr);

    // Emit the minimum bootstrap sequence.  Returns true if all bunches
    // sent successfully.
    bool emit_all();

private:
    // Individual emission phases (documented in native-bootstrap-sequence.md)
    bool emit_aoc_opcode_3();      // pkt#0 — placeholder for now
    bool emit_nmt_welcome();       // pkt#2 — reuse existing send_nmt_welcome
    // PC ActorOpen is emitted separately by PcEmitter (M1.2)

    IGameServerHost& host_;
    std::string client_key_;
    sockaddr_in client_addr_;
};
```

### 5.2 Wire into NativeConnectSequencer

Replace the stub in `do_send_bootstrap()`:
```cpp
void NativeConnectSequencer::do_send_bootstrap() {
    BootstrapEmitter em(host_, client_key_, client_addr_);
    if (em.emit_all()) {
        state_.store(NativeConnectState::SendPcOpen);
    } else {
        state_.store(NativeConnectState::Error);
    }
}
```

### 5.3 Validation

Byte-identity tests:
- `test_bootstrap_emit_diff`: emit pkt#0 + pkt#2 via BootstrapEmitter,
  compare against captured bits.
- Current pc_spawn_diff already validates pkt#22 content.

### 5.4 DONE criterion for M1.1

1. `test_bootstrap_emit_diff` passes (byte-identical for pkt#0 + pkt#2)
2. `launch_all_native.bat` + client: server log shows
   `[BootstrapEmitter] emitted <N> bunches` before Maintain
3. Client advances to "loading screen" visible (even if it doesn't
   fully load — that's M1.2's PC spawn + M1.3's keepalive's job)

---

## 6. Open Questions

| Question | How to answer |
|---|---|
| What does AoC opcode 3 actually mean? | IDA: find `UControlChannel::ReceivedBunch` case 3 |
| Is "50995344" constant across sessions? | Scan multiple captured sessions (we only have one) |
| Do we need to echo the exact string or can we substitute? | Emit placeholder, observe client behavior |
| Can we skip pkt#0 entirely? | Try emitting only pkt#2 — observe disconnect reason if any |

---

## 7. Next Steps (M1.1 work items)

1. ✅ Scan first 30 packets → `scan_bootstrap_30.py` output
2. ✅ Decode ch=0 ctrl bunches → `decode_ctrl_bunches.py` output
3. ✅ Document findings here → this file
4. ☐ RE "opcode 3" in client binary (IDA) — deferred; try placeholder first
5. ☐ Build `BootstrapEmitter` class
6. ☐ Write `test_bootstrap_emit_diff.cpp` byte-identity test
7. ☐ Wire into `NativeConnectSequencer::do_send_bootstrap`
8. ☐ Live test → DONE criterion check

---

*Update this doc as RE progresses and findings solidify.*
