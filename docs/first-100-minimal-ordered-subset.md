# First 100 Packets - Minimal Ordered Subset for Native Emission

Date: 2026-04-24
Status: Planning document for M1.1-M1.2 bootstrap implementation

---

## Goal

Identify the minimum set of packets (from pkt#0-99) that must be emitted in order for the client to:
1. Authenticate and connect
2. Load the world
3. Spawn the player character
4. Render basic HUD

Additional optimizations (early NPC spawning, etc.) are Phase 2+.

---

## Minimal Set (11 packet-equivalents, approx 11,500 bits / 1,400 bytes)

The following is an ordered list of packet-equivalents that MUST be emitted:

### 1. AoC Opcode 3 (Session Verification) - pkt#0 equivalent

Packets to emit: 1 (one-shot)
Bunches: 1x ch=0 reliable ctrl, opcode=0x03, FString payload=50995344
Bunch bits: 167 bits (approximately)
Status: REQUIRES RE to determine exact semantics
Temporary solution: Emit captured bytes verbatim from pkt#0 (42 bytes)

Why essential?
- Captured replay includes this; client may reject connection without it
- Unknown purpose, but likely session/seed verification
- Cost is minimal (42 bytes)

Action for M1.1:
Emit captured pkt#0 verbatim as placeholder (42 bytes)

---

### 2. NMT_Welcome (Map + Gamemode) - pkt#2 equivalent

Packets to emit: 1 (one-shot)
Bunches: 1x ch=0 reliable ctrl, NMT_Welcome (opcode=0x01)
Payload:
  - MapName: /Game/Levels/Verra_World_Master/Verra_World_Master
  - GameMode: /Game/GameBlueprints/AoCGameModeBaseBP.AoCGameModeBaseBP_C
  - RedirectURL: (empty)
Bunch bits: 1,039 bits (approximately)
Status: Already implemented in existing send_nmt_welcome()
Reuse: Yes

Why essential?
- Client cannot load world without knowing map name
- Standard UE5 handshake message
- Cannot proceed without NMT_Welcome

Action for M1.1:
Emit via NativeBootstrap::emit_nmt_welcome()

---

### 3. Keepalives During Gap (pkt#3-21 equivalent)

Packets to emit: Variable (natural automatic generation)
Type: Empty heartbeat frames (bb=0) or single-bit sentinels (bb=1)
Duration: While client processes NMT_Welcome and sends back NMT_GameSpecific
Bunch bits: Negligible (1 bit per keepalive packet)
Status: Automatic via heartbeat loop
Reuse: Yes (existing send_keepalive mechanism handles this naturally)

Why essential?
- Client needs time to process NMT_Welcome
- Server must acknowledge client responses
- This gap is natural and automatic in native mode (M1.3 heartbeat)

Action for M1.1:
No explicit action needed. Native heartbeat loop (M1.3) will send keepalives.

Note: This gap is NOT replayed verbatim; it emerges naturally from the heartbeat loop.

---

### 4. Player Character ActorOpen + Continuation (pkt#22-23 equivalent)

Packets to emit: 2 (one split into 2 fragments, or 2 separate bunches)
Classes: AoCPlayerControllerBP_C + subobject BP_AOCHUD_C
Channels used: ch=3 (PC), ch=? (HUD subobject)
Bunches:
  - Bunch 0: ch=3 ActorOpen (PART-INIT, CTRL, OPEN, REL, EXP)
    - Exports: Default__AoCPlayerControllerBP_C, PersistentLevel, GlobalGMCommands
    - Bits: 3,545
  - Bunch 1: ch=3 PartialCont or ActorReliable (PART-FIN)
    - Bits: 1,314
  - Bunch 2: ch=? ActorOpen for subobject (PART-INIT, REL, EXP)
    - Exports: BP_AOCHUD_C
    - Bits: 873
  - Bunch 3: ch=? PartialCont (PART-FIN)
    - Bits: 173
Total bits: 6,104 + 3,905 = 10,009 bits
Status: ActorBuilder v2 generates bunch#0 at 99.9% accuracy
Reuse: Yes (via PcEmitter class, M1.2)

Why essential?
- Client cannot enter world without PC actor
- PC spawning triggers client-side level loaded condition
- HUD must be open for client to display UI

Action for M1.1-M1.2:
Use existing ActorBuilder to generate PC bunch
Generate continuation bunches via PartialBundle chain
Emit as 4-bunch sequence on ch=3

---

### 5. Critical Property Updates (pkt#24-29 equivalent, optional for M1.1)

Packets to emit: 0 for bare minimum; 6 for better experience
Classes: Likely AoCPawn, AoCPlayerState, AoCGameState (unconfirmed)
Purpose: Establish references for PC properties
Bits: ~6,000 bits per packet, 36,000 bits total
Status: TBD after decode_exports pass on pkt#24-29

Why optional?
- Client can technically enter world with just PC + HUD
- But PC needs valid AcknowledgedPawn and PlayerState references to function correctly
- Without these, character controller may not work

Action for M1.1: DEFER to M1.2
Action for M1.2: Decode pkt#24-29 to identify Pawn/PlayerState classes

---

## Emission Sequence for M1.1

Phase 1: Handshake + map setup
  - emit_aoc_opcode_3() - approx 170 bits
  - emit_nmt_welcome() - approx 1,040 bits

Phase 2: Gap (automatic via heartbeat loop)
  - Client processes NMT_Welcome, sends responses
  - Native heartbeat (M1.3) sends keepalives while waiting

Phase 3: World entry
  - emit_pc_actor() - 4 bunches, approx 10,000 bits

Phase 4+: DEFERRED to post-entry streaming
  - (M1.2 will add Pawn/PlayerState here if needed)

TOTAL BITCOST: approx 11,210 bits (1,400 bytes) for bare minimum
RECOMMENDED: approx 13,000 bits (1,625 bytes) with HUD included

---

## Expected Client Behavior at Each Step

1. After opcode 3: Client recognizes session; continues.
2. After NMT_Welcome: Client loads map assets; waits for PC.
3. After keepalives: Client sends NMT_GameSpecific; waits for actor spawns.
4. After PC ActorOpen: Client creates PlayerController object.
5. After PC continuation + HUD: Client renders HUD; world may be visible but empty.
6. After pkt#24-29 equiv: Other actors appear; game becomes playable.

---

## Next Steps for Implementation

1. M1.1: Implement phases 1-3 (opcode 3, NMT_Welcome, PC+HUD)
   - Estimated effort: 2-3 hours (reuse existing ActorBuilder)
   - Test: Client can enter world with no other actors visible

2. M1.2: Implement phase 4 exports (Pawn/PlayerState/GameState)
   - Requires: Decode pkt#24-29 to identify classes
   - Estimated effort: 4-6 hours
   - Test: Client can move, see other players, interact with HUD

3. M1.3: Implement heartbeat/streaming (phase 5+)
   - Reuse existing property update mechanism
   - Natural fallout of client-server loop
