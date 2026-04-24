# RE: Post-NMT Opcode 3 on Control Channel

**Status**: UNRESOLVED — needs IDA work  |  **RE'd**: 2026-04-24  |  **Priority**: Low

---

## Observation

Captured replay pkt#0 (seq=14265) contains a reliable data bunch on
ch=0 with 14 bytes of payload:

```
03 09 00 00 00 35 30 39 39 35 33 34 34 00
│  │           │
│  └─ FString length 9         └─ "50995344\0"
└─ opcode byte 0x03
```

The bunch arrives **AFTER NMT handshake is complete** (the replay starts
at seq=14265 after NMT finished). So this is post-login, but stock UE5
`FNetControlMessage` opcode 3 is `NMT_Challenge`, which is handshake-era.

## Why this matters

Our native flow currently does NOT emit this bunch. The client might
require it to proceed to world-loading; or it might be optional/ignored.

Without testing we don't know which. Testing = live-run the native flow
WITHOUT pkt#0 and observe:
- ✅ client loads world → pkt#0 is optional; skip it
- ❌ client disconnects / stays on loading → pkt#0 is required; RE it

## What we've tried

### Binary string search (negative results)

All stock UE5 NMT name strings (`NMT_Hello`, `NMT_Welcome`, etc.) are
**stripped from the Shipping binary** — they'd normally appear in UE_LOG
format strings and checkf() message buffers.

The string `"50995344"` is **not in the binary** either, confirming it's
not a hardcoded constant. Runtime-generated per session.

### XRef to ControlChannelMessageUnknown

The `ENetCloseResult::ControlChannelMessageUnknown` string at
VA `0x149F5C100` is the default-case of the opcode switch. It has
**1 reference** in `.rdata` at VA `0x149F5AE90` — this is an ENetCloseResult
lookup table, not the switch site itself.

To find the switch site, you'd need to:
1. Open `AOCClient-Win64-Shipping.exe` in IDA
2. Jump to VA `0x149F5C100`
3. Press `X` for cross-references
4. Follow the `.text` XRef (should be the default case of the switch)
5. Scroll up to see each `case N:` handler
6. Specifically read case 3

## Hypotheses

### H1: Secondary session challenge

AoC sends a second NMT_Challenge-like message after login for additional
session-level verification. The string "50995344" could be a session
token the client must echo back.

**Test**: emit opcode 3 + arbitrary 8-digit string, observe client ACK
behavior.

### H2: AoC-overloaded opcode

AoC overrides `UControlChannel` with `UAoCControlChannel` (class not
found by name — likely stripped) and repurposes opcode 3 post-handshake
for something specific.

**Test**: try common post-login messages (SessionID, AuthToken, etc.)
and see which the client expects.

### H3: Ignorable debug/telemetry

AoC sends this for server-side analytics/telemetry and the client
silently discards it if not understood.

**Test**: emit nothing for pkt#0 and see if world loads anyway.

## What to try NEXT (in order)

1. **Test H3 first** — run the native flow with only NMT_Welcome (native)
   + pkt#22 (native via ActorBuilder). If the world loads, pkt#0 was
   optional. **This is free to test; we already have the infrastructure.**

2. **If H3 fails** — open IDA, follow XRef from
   `"ControlChannelMessageUnknown"` to find the switch. Read case 3.
   Document findings here. Estimated: 30-60 minutes of IDA work.

3. **If needed, emit opcode 3** — use what we learn to build a proper
   reliable ch=0 bunch with the correct payload.

## Related files

- `src/protocol/tools/decode_ctrl_bunches.py` — decoder used to isolate this
- `docs/native-bootstrap-sequence.md` §2.1 — packet context
- Captured reference: `replay_data.bin` pkt#0 (first 14 bytes of bunch)

---

*Defer deep RE until H3 testing proves whether we need this opcode at
all. No point RE'ing something the client may not require.*
