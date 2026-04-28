# UE5 Packet Format: Exact Bit Sequence Between ACK History and Bunch Dispatch

## Summary

After the FPackedHeader (Seq, AckedSeq, HistoryWordCount) and the SequenceHistory words,
UE5 reads **two additional sections** before dispatching bunches:

1. **Jitter Clock Info** (read in `ReceivedPacket`, BEFORE ack processing)
2. **Packet Info Payload** (read in `ReadPacketInfo`, AFTER ack processing)

These are NOT part of `FNetPacketNotify::ReadHeader`. They are separate fields
managed by `UNetConnection` itself.

---

## Complete Packet Bit Layout (Current UE5, EngineNetVer >= JitterInHeader = 14)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PACKET HEADER                                │
├─────────────────────────────────────────────────────────────────────┤
│ 1. FPackedHeader (uint32, 32 bits)                                  │
│    ├─ Bits [0..3]   : HistoryWordCount - 1    (4 bits)             │
│    ├─ Bits [4..17]  : AckedSeq                (14 bits)            │
│    └─ Bits [18..31] : Seq                     (14 bits)            │
│                                                                     │
│ 2. SequenceHistory (variable: HistoryWordCount * 32 bits)           │
│    └─ 1 to 8 words × 32 bits = 32..256 bits                       │
│                                                                     │
├── ReadHeader() ends here ──────────────────────────────────────────┤
│                                                                     │
│ 3. bHasPacketInfoPayload                      (1 bit)              │
│                                                                     │
│ 4. IF bHasPacketInfoPayload == 1:                                   │
│    ├─ JitterClockTimeMS (SerializeInt, 10 bits)                    │
│    │   Max value = 1023, serialized with max = 1024                │
│    │                                                                │
├── ACK PROCESSING HAPPENS HERE (not reading from bitstream) ────────┤
│    │                                                                │
│    ├─ bHasServerFrameTime                     (1 bit)              │
│    │                                                                │
│    └─ IF bHasServerFrameTime == 1:                                 │
│       └─ ServerFrameTimeByte (uint8)          (8 bits)             │
│                                                                     │
│ 5. IF bHasPacketInfoPayload == 0:                                   │
│    └─ (nothing more in this section)                               │
│                                                                     │
├── PACKET INFO ENDS HERE ───────────────────────────────────────────┤
│                                                                     │
│ 6. BUNCH DATA (repeated, parsed by DispatchPacket)                  │
│    └─ while (!Reader.AtEnd()) { parse bunch header + data }        │
│                                                                     │
│ 7. Termination bit (1 bit, value = 1, written at send time)        │
│    └─ This bit + zero-padding to byte boundary makes AtEnd() true  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Field-by-Field Breakdown

### Phase 1: FNetPacketNotify::ReadHeader (NetPacketNotify.cpp)

| # | Field | Type | Bits | Notes |
|---|-------|------|------|-------|
| 1 | PackedHeader | uint32 | 32 | Contains Seq(14) + AckedSeq(14) + HistoryWordCount-1(4) |
| 2 | SequenceHistory | WordT[] | 32 × N | N = HistoryWordCount (1..8), each word is 32 bits |

**Total for ReadHeader**: 32 + (32 × HistoryWordCount) bits = 64..288 bits

### Phase 2: Jitter Clock (ReceivedPacket, lines ~3075-3103)

Read IMMEDIATELY after ReadHeader, BEFORE ack processing:

| # | Field | Type | Bits | Condition |
|---|-------|------|------|-----------|
| 3 | bHasPacketInfoPayload | bit | 1 | Only if EngineNetVer >= JitterInHeader (14) |
| 4 | PacketJitterClockTimeMS | SerializeInt(1024) | 10 | Only if bHasPacketInfoPayload == 1 |

**SerializeInt details**: `Reader.SerializeInt(val, MaxJitterClockTimeValue + 1)` where
`MaxJitterClockTimeValue = (1 << 10) - 1 = 1023`. So max = 1024, which requires exactly 10 bits.

The jitter value represents the millisecond portion of the sender's clock time (`GetClockTimeMilliseconds`).
If the delta between sends exceeds 1 second, MaxJitterClockTimeValue (1023) is sent and the receiver ignores jitter.

### Phase 3: ACK Processing (no bitstream reads)

Between the jitter clock read and ReadPacketInfo, the code processes acks:
- `PacketNotify.GetSequenceDelta(Header)`
- `PacketNotify.Update(Header, HandlePacketNotification)` — iterates ack history, calls ReceivedAck/ReceivedNak
- Updates InPacketId

**This does NOT read any additional bits from the packet.**

### Phase 4: ReadPacketInfo (NetConnection.cpp, lines ~2839-2935)

Called AFTER ack processing, only if `PacketSequenceDelta > 0`:

| # | Field | Type | Bits | Condition |
|---|-------|------|------|-----------|
| 5 | bHasServerFrameTime | bit | 1 | Only if bHasPacketInfoPayload == 1 |
| 6 | FrameTimeByte | uint8 | 8 | Only if bHasServerFrameTime == 1 AND sender is server |
| 7 | RemoteInKBytesPerSecondByte | uint8 | 8 | LEGACY: Only if EngineNetVer < JitterInHeader (14) |

### Phase 5: DispatchPacket — Bunch Parsing Begins

The `Reader` position is now at the first bunch. Bunches are parsed in a loop:
```
while (!Reader.AtEnd()) { ... parse bunch header + bunch data ... }
```

---

## Version-Dependent Data

| EngineNetVer | Behavior |
|---|---|
| < 14 (JitterInHeader) | No bHasPacketInfoPayload bit, no JitterClock. Instead, after ReadHeader, go straight to ReadPacketInfo which reads: bHasServerFrameTime(1 bit) + optional FrameTimeByte(8 bits) + RemoteInKBytesPerSecondByte(8 bits, always present) |
| >= 14 (JitterInHeader) | bHasPacketInfoPayload(1 bit) + conditional JitterClock(10 bits) + bHasServerFrameTime(1 bit) + conditional FrameTimeByte(8 bits). No RemoteInKBytesPerSecondByte. |

---

## SEND Side Verification (WriteDummyPacketInfo + WriteFinalPacketInfo)

The send path in `PrepareWriteBitsToSendBuffer` (line ~4105):
```
1. WritePacketHeader(SendBuffer)       — PacketNotify.WriteHeader() = PackedHeader + SequenceHistory
2. WriteDummyPacketInfo(SendBuffer)    — placeholder bits, overwritten later by WriteFinalPacketInfo
3. [Bunch data is appended by WriteBitsToSendBuffer calls from SendRawBunch]
```

In `FlushNet` (line ~2326), right before LowLevelSend:
```
1. SendBuffer.WriteBit(1)              — UNetConnection-level termination bit
2. WritePacketHeader(SendBuffer)       — REFRESH: rewrites the header in-place with latest ack data
3. WriteFinalPacketInfo(SendBuffer)    — OVERWRITES dummy PacketInfo with real timestamps
4. LowLevelSend(...)
```

### WriteDummyPacketInfo writes (line ~2732):
```
1. bHasPacketInfoPayload               (1 bit)  — true only for first packet in frame
   IF payload present:
2. DummyJitterClockTime                (10 bits) — placeholder zeros, overwritten later
3. bHasServerFrameTime                 (1 bit)
   IF bHasServerFrameTime AND server:
4. DummyFrameTimeByte                  (8 bits)  — placeholder zero
```

### WriteFinalPacketInfo overwrites (line ~2771):
Seeks back to the HeaderMarkForPacketInfo position and overwrites:
```
1. ClockTimeMilliseconds via SerializeInt(MaxJitterClockTimeValue+1)  (10 bits)
2. bHasServerFrameTime                 (1 bit)
   IF bHasServerFrameTime AND server:
3. FrameTimeByte = floor(FrameTime * 1000)  (8 bits)
```

---

## MAX_PACKET_INFO_HEADER_BITS Calculation

From NetConnection.h:
```cpp
enum { MAX_PACKET_INFO_HEADER_BITS = 1 /*bHasPacketInfo*/ + 10 /*JitterClock*/ + 1 /*bHasServerFrameTime*/ + 8 /*ServerFrameTime*/ };
// = 20 bits maximum
```

---

## Concrete Bit Patterns for Common Scenarios

### Scenario A: Normal game packet (server→client, with packet info, with frame time)
```
Offset  Field                           Bits   
0       PackedHeader                    32     
32      SequenceHistory[0]              32     (min 1 word)
64      bHasPacketInfoPayload           1      (= 1)
65      JitterClockTimeMS               10     
75      bHasServerFrameTime             1      (= 1, server sends frame time)
76      FrameTimeByte                   8      
84      --- BUNCH DATA STARTS HERE ---
```

### Scenario B: Normal game packet (server→client, with packet info, without frame time)
```
Offset  Field                           Bits   
0       PackedHeader                    32     
32      SequenceHistory[0]              32     
64      bHasPacketInfoPayload           1      (= 1)
65      JitterClockTimeMS               10     
75      bHasServerFrameTime             1      (= 0)
76      --- BUNCH DATA STARTS HERE ---
```

### Scenario C: Second packet in same frame (no packet info payload)
```
Offset  Field                           Bits   
0       PackedHeader                    32     
32      SequenceHistory[0]              32     
64      bHasPacketInfoPayload           1      (= 0)
65      --- BUNCH DATA STARTS HERE ---
```

### Scenario D: Client→server packet (client never writes FrameTimeByte even if bHasServerFrameTime=1)
The client sets `bHasServerFrameTime` based on `CVarPingExcludeFrameTime`, but only the SERVER writes the FrameTimeByte.
On the receive side, only `!Driver->IsServer()` (i.e., the client) reads FrameTimeByte.

So for client→server:
```
Offset  Field                           Bits   
0       PackedHeader                    32     
32      SequenceHistory[0]              32     
64      bHasPacketInfoPayload           1      (= 1)
65      JitterClockTimeMS               10     
75      bHasServerFrameTime             1      (= 0 or 1, but no FrameTimeByte follows)
76      --- BUNCH DATA STARTS HERE ---
```

Wait — the WRITE side: `WriteDummyPacketInfo` does `if (bHasServerFrameTime && Driver->IsServer())` to decide whether to write FrameTimeByte. So the client NEVER writes the FrameTimeByte, even if bHasServerFrameTime=1. And on READ, the server reads `bHasServerFrameTime` but does NOT attempt to read FrameTimeByte (it just stores it for later echo). So the bit is written but no data follows it on client→server packets.

---

## Key Answers to Your Questions

### Q1: After FPackedHeader and AckHistory, does UE5 read ANY additional data before bunches?
**YES.** There are up to 20 additional bits:
- `bHasPacketInfoPayload` (1 bit)
- `JitterClockTimeMS` (10 bits) — conditional
- `bHasServerFrameTime` (1 bit) — conditional
- `FrameTimeByte` (8 bits) — conditional

### Q2: Is there a "jitter clock" or "timestamp" field?
**YES.** `JitterClockTimeMS` is a 10-bit SerializeInt field representing the millisecond portion of the sender's clock time. It's used to measure packet jitter.

### Q3: Is there any version-dependent data?
**YES.** 
- If `EngineNetVer >= JitterInHeader (14)`: the current format with bHasPacketInfoPayload + JitterClock
- If `EngineNetVer < JitterInHeader (14)`: no bHasPacketInfoPayload bit, no JitterClock, but an extra `RemoteInKBytesPerSecondByte` (uint8, 8 bits) is read in ReadPacketInfo
- The jitter clock is read BEFORE ack processing, while bHasServerFrameTime/FrameTimeByte are read AFTER ack processing

### Q4: Does FNetPacketNotify::ReadHeader consume more than just the packed header?
**YES.** It reads:
1. The 32-bit PackedHeader (Seq + AckedSeq + HistoryWordCount)
2. The SequenceHistory words (HistoryWordCount × 32 bits)

That's ALL ReadHeader reads. Everything after is UNetConnection's responsibility.

### Q5: Is there any data written between WriteBitsToSendBuffer and the bunches in SendRawBunch?
**NO.** `SendRawBunch` calls `PrepareWriteBitsToSendBuffer` (which writes header + dummy packet info if buffer is empty), then `WriteBitsToSendBufferInternal` writes the bunch header + bunch data directly. No intermediate data is injected between bunches.

---

## Important: Read/Write Ordering Split

The packet info is split across two read phases:

```
ReceivedPacket():
  ├─ ReadHeader()                           ← reads PackedHeader + SequenceHistory
  ├─ Read bHasPacketInfoPayload (1 bit)     ← IMMEDIATELY after ReadHeader
  ├─ Read JitterClockTimeMS (10 bits)       ← still before ack processing
  ├─ [ACK PROCESSING — no bitstream reads]
  ├─ ReadPacketInfo()                       ← reads bHasServerFrameTime + FrameTimeByte
  └─ DispatchPacket()                       ← parses bunches
```

This split is important: the jitter clock is read BEFORE acks, but bHasServerFrameTime/FrameTimeByte are read AFTER acks. Both are part of the same "packet info" block in the bitstream, but the read is split by the ack processing logic.

---

## PacketHandler Note

`PacketHandler::OutgoingHigh()` and `PacketHandler::IncomingHigh()` are called but are **empty stubs** (both contain just `// @todo #JohnB`). They do not inject any additional data into the packet at the UNetConnection level.

The PacketHandler's encryption/compression operates at a LOWER level (on the entire packet bytes), not within the UNetConnection bitstream.
